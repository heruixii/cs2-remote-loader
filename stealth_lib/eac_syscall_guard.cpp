// ============================================================
// eac_syscall_guard.cpp — EAC 内核级防御实现
// ============================================================
#include "platform.h"

#include "eac_syscall_guard.h"
#include "syscall_direct.h"
#include "module_resolver.h"  // ★ BUILD 550: GetModuleBaseFromPEB + ModNameHash (替代 GetModuleHandleW)
#include <sddl.h>      // ConvertStringSidToSidW

namespace stealth {

// ============================================================
// HandleACLGuard — 句柄私有 ACL 封锁
// ============================================================

bool HandleACLGuard::LockHandle(HANDLE hProcess) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
        return false;

    // ★ BUILD 501: 所有变量前置声明, 避免 goto 跨初始化
    typedef NTSTATUS(NTAPI* NtSetSecurityObject_t)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    bool result = false;
    BYTE* tokenUserBuf = nullptr;
    BYTE* sdBuf = nullptr;
    HANDLE hToken = nullptr;
    DWORD tokenUserSize = 0;
    PTOKEN_USER pTokenUser = nullptr;
    PSID userSid = nullptr;
    DWORD sidLen = 0;
    DWORD aclSize = 0;
    DWORD sdSize = 0;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pAcl = nullptr;
    DWORD allAccess = 0;
    SECURITY_INFORMATION secInfo = 0;
    HMODULE ntdll = nullptr;
    NtSetSecurityObject_t pNtSetSecurityObject = nullptr;
    NTSTATUS status = 0;

    // 1. 获取当前进程的 SID (安全标识符)
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenUserSize);
    if (tokenUserSize == 0) {
        CloseHandle(hToken);
        return false;
    }

    // ★ BUILD 501: VirtualAlloc 替代 std::vector<BYTE> — 避免 CRT 堆依赖
    tokenUserBuf = (BYTE*)VirtualAlloc(nullptr, tokenUserSize, MEM_COMMIT, PAGE_READWRITE);
    if (!tokenUserBuf) {
        CloseHandle(hToken);
        return false;
    }
    pTokenUser = reinterpret_cast<PTOKEN_USER>(tokenUserBuf);
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, tokenUserSize, &tokenUserSize)) {
        goto cleanup;
    }
    CloseHandle(hToken);
    hToken = nullptr;

    // 2. 构建安全描述符 (仅允许当前用户)
    userSid = pTokenUser->User.Sid;
    sidLen = GetLengthSid(userSid);

    // 计算安全描述符大小
    aclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sidLen - sizeof(DWORD);
    sdSize  = sizeof(SECURITY_DESCRIPTOR) + aclSize;

    // ★ BUILD 501: VirtualAlloc 替代 std::vector<BYTE> — 避免 CRT 堆依赖
    sdBuf = (BYTE*)VirtualAlloc(nullptr, sdSize, MEM_COMMIT, PAGE_READWRITE);
    if (!sdBuf) {
        goto cleanup;
    }
    pSD = reinterpret_cast<PSECURITY_DESCRIPTOR>(sdBuf);

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        goto cleanup;
    }

    pAcl = reinterpret_cast<PACL>(sdBuf + sizeof(SECURITY_DESCRIPTOR));
    if (!InitializeAcl(pAcl, aclSize, ACL_REVISION)) {
        goto cleanup;
    }

    // 添加允许当前用户的 ACE (包含所有可能的句柄权限)
    allAccess = PROCESS_ALL_ACCESS | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL;
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, allAccess, userSid)) {
        goto cleanup;
    }

    if (!SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE)) {
        goto cleanup;
    }

    // 3. 将安全描述符应用到句柄
    secInfo = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;

    ntdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    if (!ntdll) goto cleanup;

    pNtSetSecurityObject = reinterpret_cast<NtSetSecurityObject_t>(
        GetProcAddress(ntdll, "NtSetSecurityObject"));

    if (!pNtSetSecurityObject) goto cleanup;

    status = pNtSetSecurityObject(hProcess, secInfo, pSD);
    if (!NT_SUCCESS(status)) {
        // 尝试不带 PROTECTED_DACL flag
        status = pNtSetSecurityObject(hProcess, DACL_SECURITY_INFORMATION, pSD);
    }
    result = NT_SUCCESS(status);

cleanup:
    if (hToken) CloseHandle(hToken);
    // ★ BUILD 501: 清理 VirtualAlloc 缓冲区
    if (tokenUserBuf) VirtualFree(tokenUserBuf, 0, MEM_RELEASE);
    if (sdBuf) VirtualFree(sdBuf, 0, MEM_RELEASE);
    return result;
}

// ============================================================
// SyscallGuard — Syscall Stub 完整性验证 + 自愈
// ============================================================

// 被 EAC 核心关注的关键 syscall — 内存读写相关
const SyscallGuard::CriticalStub SyscallGuard::s_criticalStubs[] = {
    {"NtReadVirtualMemory",     true},
    {"NtWriteVirtualMemory",    true},
    {"NtProtectVirtualMemory",  false},
    {"NtQueryVirtualMemory",    true},
    {"NtOpenProcess",           false},
    {"NtQueryInformationProcess", true},
    {"NtQuerySystemInformation", true},
    {"NtAllocateVirtualMemory", false},
};
const int SyscallGuard::s_criticalStubCount = sizeof(s_criticalStubs) / sizeof(s_criticalStubs[0]);

bool SyscallGuard::IsStubIntact(const char* funcName) {
    HMODULE ntdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    if (!ntdll) return false;

    auto addr = reinterpret_cast<const uint8_t*>(
        GetProcAddress(ntdll, funcName));
    if (!addr) return false;

    // 合法 syscall stub 前 4 字节: 4C 8B D1 B8
    //   mov r10, rcx    = 4C 8B D1
    //   mov eax, SSN    = B8 xx xx xx xx
    if (addr[0] != 0x4C || addr[1] != 0x8B || addr[2] != 0xD1) {
        return false; // 被 Hook (开头是 jmp/call/push 等)
    }
    return true;
}

int SyscallGuard::VerifyKeyStubs() {
    int tamperedCount = 0;
    for (int i = 0; i < s_criticalStubCount; i++) {
        if (!IsStubIntact(s_criticalStubs[i].name)) {
            tamperedCount++;
        }
    }
    return tamperedCount;
}

bool SyscallGuard::RestoreSingleStub(const char* funcName, HMODULE hDiskNtdll) {
    // 注: 不实际修改 ntdll .text 段 — EAC 完整性扫描会检测到 RWX+memcpy
    // 改用 Halo's Gate 在间接 syscall 层面规避 Hook (由 syscall_direct 模块处理)
    // 这里仅报告: 若 stub 被篡改, 说明环境不安全
    HMODULE hLocalNtdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    if (!hLocalNtdll || !hDiskNtdll) return false;

    auto localAddr = reinterpret_cast<uint8_t*>(
        GetProcAddress(hLocalNtdll, funcName));
    auto diskAddr  = reinterpret_cast<const uint8_t*>(
        GetProcAddress(hDiskNtdll, funcName));

    if (!localAddr || !diskAddr) return false;

    // 仅比对, 不修改 — 若差异存在, Halo's Gate 自动用干净的 stub
    if (memcmp(localAddr, diskAddr, 20) != 0) {
        return false; // 被篡改, 无法安全恢复
    }
    return true;
}

int SyscallGuard::RestoreFromDisk() {
    // 从 System32 打开干净的 ntdll.dll
    wchar_t sysPath[MAX_PATH];
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\ntdll.dll");

    HMODULE hDiskNtdll = LoadLibraryExW(sysPath, nullptr,
        DONT_RESOLVE_DLL_REFERENCES); // 不加载依赖, 仅映射为数据

    if (!hDiskNtdll) {
        // 尝试完整路径
        hDiskNtdll = LoadLibraryExW(L"C:\\Windows\\System32\\ntdll.dll",
            nullptr, DONT_RESOLVE_DLL_REFERENCES);
    }

    if (!hDiskNtdll) return 0;

    int restored = 0;
    for (int i = 0; i < s_criticalStubCount; i++) {
        if (!IsStubIntact(s_criticalStubs[i].name)) {
            if (RestoreSingleStub(s_criticalStubs[i].name, hDiskNtdll)) {
                restored++;
            }
        }
    }

    FreeLibrary(hDiskNtdll);
    return restored;
}

bool SyscallGuard::VerifyAndRepair() {
    // v3.26: 此函数仅检测 stub 是否被篡改, 不做实际修复.
    //   原因: 向 ntdll .text 写入 (RWX+memcpy) 本身会触发 EAC 完整性扫描.
    //
    //   实际修复机制在 syscall_direct 层:
    //   - Halo's Gate (每5s): 从 disk ntdll 恢复 SSN 值
    //   - TartarusGate: 在自己的 VirtualAlloc 内存中生成独立 stub,
    //     不依赖被 hook 的 ntdll stub
    //   - StealthSleep toggle: RestoreAll→EkkoSleep→SilenceAll 清除 ETW/AMSI
    //
    //   因此即使 ntdll stub 被 hook, Indirect+StackSpoof 路径依然通过
    //   自生成 stub 正常工作. 本函数只是监控/告警.
    int tampered = VerifyKeyStubs();
    if (tampered > 0) {
        RestoreFromDisk();
        // 验证修复效果
        tampered = VerifyKeyStubs();
    }
    return tampered == 0; // 0 = 全部正常
}

} // namespace stealth
