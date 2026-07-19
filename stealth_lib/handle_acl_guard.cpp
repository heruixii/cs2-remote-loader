// ============================================================
// handle_acl_guard.cpp — 句柄 ACL 私有化防护实现
//
// ★ BUILD 552: 从 eac_syscall_guard.cpp 拆分而来
//   删除了 EAC 专属的 SyscallGuard (s_criticalStubs[] 数组 + IsStubIntact +
//   RestoreSingleStub + VerifyKeyStubs + RestoreFromDisk + VerifyAndRepair)
//   原 SyscallGuard 部分含 8 个明文 Nt* API 名, 是 .rdata 残留根因之一
//   实际 stub 完整性自愈由 syscall_direct 模块的 Halo's Gate / Tartarus Gate 提供
// ============================================================
#include "platform.h"

#include "handle_acl_guard.h"
#include "module_resolver.h"  // GetModuleBaseFromPEB + ModNameHash
// ★ BUILD 551: STEALTH_GET_PROC_ADDRESS_NOREF 宏 (NtSetSecurityObject 加密解析)
#include "string_obfuscator.h"
// ★ BUILD 556: SysOpenProcessToken + SysQueryInformationToken (令牌 API syscall 替代)
#include "syscall_direct.h"

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
    // ★ BUILD 556: SysOpenProcessToken 替代 OpenProcessToken (消除 advapi32 IAT 导入)
    NTSTATUS tokenStatus = stealth::SysOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(tokenStatus))
        return false;

    // ★ BUILD 556: SysQueryInformationToken 替代 GetTokenInformation
    stealth::SysQueryInformationToken(hToken, TokenUser, nullptr, 0, &tokenUserSize);
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
    // ★ BUILD 556: SysQueryInformationToken 替代 GetTokenInformation
    if (!NT_SUCCESS(stealth::SysQueryInformationToken(hToken, TokenUser, pTokenUser, tokenUserSize, &tokenUserSize))) {
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
        STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "NtSetSecurityObject"));

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

} // namespace stealth
