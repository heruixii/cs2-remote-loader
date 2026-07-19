#pragma once
// ============================================================
// handle_acl_guard.h — 句柄 ACL 私有化防护（通用反检测）
//
// ★ BUILD 552: 从 eac_syscall_guard 拆分而来，删除 EAC 专属的 SyscallGuard 部分
//   仅保留 HandleACLGuard（句柄 ACL 私有化）— 通用反检测能力，对 PAC 仍有价值
//
// 防御向量:
//   句柄表隐身 (Handle ACL Hardening)
//   PAC/EAC 通过 NtQuerySystemInformation(SystemHandleInformation)
//   遍历系统所有句柄, 发现任何进程持有游戏进程的 VM_READ 句柄。
//   对策: 为句柄分配自定义安全描述符 (DACL), 仅允许自身进程
//   访问, 阻挡 PAC/EAC 的 SYSTEM 进程查询/复制我们的句柄。
// ============================================================

#include <Windows.h>
#include <cstdint>

namespace stealth {

// ============================================================
// HandleACLGuard — 句柄私有 ACL 封锁
// 原理: 默认句柄 DACL 为 NULL (所有人可访问)
//       设置显式 DACL, 仅允许我们的 SID 读取/复制该句柄
//       PAC (SYSTEM 权限) 尝试 DuplicateHandle 或 NtQueryObject
//       将失败并返回 ACCESS_DENIED
// ============================================================
class HandleACLGuard {
public:
    // 为指定的进程句柄设置私有 DACL
    // 返回 true 表示成功封锁
    static bool LockHandle(HANDLE hProcess);

    // 使用 SE_SECURITY_NAME 权限为句柄设置 SACL (审计)
    // 可选: PAC 尝试读取句柄时触发审计事件 (可作为蜜罐)
    static bool InstallAuditSACL(HANDLE hProcess);
};

} // namespace stealth
