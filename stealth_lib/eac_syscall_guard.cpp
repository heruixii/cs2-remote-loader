// ============================================================
// eac_syscall_guard.cpp — EAC 内核级防御实现
// ============================================================
#include "platform.h"

#include "eac_syscall_guard.h"
#include "syscall_direct.h"
#include <sddl.h>      // ConvertStringSidToSidW

namespace stealth {

// ============================================================
// HandleACLGuard — 句柄私有 ACL 封锁
// ============================================================

bool HandleACLGuard::LockHandle(HANDLE hProcess) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
        return false;

    // 1. 获取当前进程的 SID (安全标识符)
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    DWORD tokenUserSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenUserSize);
    if (tokenUserSize == 0) {
        CloseHandle(hToken);
        return false;
    }

    std::vector<BYTE> tokenUserBuf(tokenUserSize);
    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(tokenUserBuf.data());
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, tokenUserSize, &tokenUserSize)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    // 2. 构建安全描述符 (仅允许当前用户)
    // SECURITY_DESCRIPTOR → DACL → ACE (Allow, 当前用户, 所有权限)
    PSID userSid = pTokenUser->User.Sid;
    DWORD sidLen = GetLengthSid(userSid);

    // 计算安全描述符大小
    DWORD aclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sidLen - sizeof(DWORD);
    DWORD sdSize  = sizeof(SECURITY_DESCRIPTOR) + aclSize;

    std::vector<BYTE> sdBuf(sdSize);
    PSECURITY_DESCRIPTOR pSD = reinterpret_cast<PSECURITY_DESCRIPTOR>(sdBuf.data());

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        return false;
    }

    PACL pAcl = reinterpret_cast<PACL>(sdBuf.data() + sizeof(SECURITY_DESCRIPTOR));
    if (!InitializeAcl(pAcl, aclSize, ACL_REVISION)) {
        return false;
    }

    // 添加允许当前用户的 ACE (包含所有可能的句柄权限)
    DWORD allAccess = PROCESS_ALL_ACCESS | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL;
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, allAccess, userSid)) {
        return false;
    }

    if (!SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE)) {
        return false;
    }

    // 3. 将安全描述符应用到句柄
    // 使用 NtSetSecurityObject 替代 SetKernelObjectSecurity (更隐蔽)
    SECURITY_INFORMATION secInfo = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;

    // 通过 syscall 调用 NtSetSecurityObject
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    using NtSetSecurityObject_t = NTSTATUS(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    auto pNtSetSecurityObject = reinterpret_cast<NtSetSecurityObject_t>(
        GetProcAddress(ntdll, "NtSetSecurityObject"));

    if (!pNtSetSecurityObject) return false;

    NTSTATUS status = pNtSetSecurityObject(hProcess, secInfo, pSD);
    if (!NT_SUCCESS(status)) {
        // 尝试不带 PROTECTED_DACL flag
        status = pNtSetSecurityObject(hProcess, DACL_SECURITY_INFORMATION, pSD);
    }

    return NT_SUCCESS(status);
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
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
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
    HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
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
    int tampered = VerifyKeyStubs();
    if (tampered > 0) {
        RestoreFromDisk();
        // 验证修复效果
        tampered = VerifyKeyStubs();
    }
    return tampered == 0; // 0 = 全部正常
}

} // namespace stealth
