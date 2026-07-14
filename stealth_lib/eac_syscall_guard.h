#pragma once
// ============================================================
// eac_syscall_guard.h — EAC 内核级防御最后两道防线
//
// 防御向量:
//   1. 句柄表隐身 (Handle ACL Hardening)
//      EAC 通过 NtQuerySystemInformation(SystemHandleInformation)
//      遍历系统所有句柄, 发现任何进程持有游戏进程的 VM_READ 句柄。
//      对策: 为句柄分配自定义安全描述符 (DACL), 仅允许自身进程
//      访问, 阻挡 EAC 的 SYSTEM 进程查询/复制我们的句柄。
//
//   2. Syscall Stub 完整性自愈
//      EAC 可在内核层安装 Instrumentation Callback, 拦截 syscall
//      并记录调用栈。对策: 定期验证 ntdll 的 syscall stub 完整性,
//      如检测到被篡改, 从磁盘上的干净 ntdll.dll 重新加载原始 stub。
//      (注: 我们使用 Hell's Gate + Halo's Gate 动态解析 SSN,
//       即使 stub 被修改也能正确调用, 但额外验证增加纵深防御)
// ============================================================

#include <Windows.h>
#include <cstdint>

namespace stealth {

// ============================================================
// 句柄 ACL 封锁
// 原理: 默认句柄 DACL 为 NULL (所有人可访问)
//       设置显式 DACL, 仅允许我们的 SID 读取/复制该句柄
//       EAC (SYSTEM 权限) 尝试 DuplicateHandle 或 NtQueryObject
//       将失败并返回 ACCESS_DENIED
// ============================================================
class HandleACLGuard {
public:
    // 为指定的进程句柄设置私有 DACL
    // 返回 true 表示成功封锁
    static bool LockHandle(HANDLE hProcess);

    // 使用 SE_SECURITY_NAME 权限为句柄设置 SACL (审计)
    // 可选: EAC 尝试读取句柄时触发审计事件 (可作为蜜罐)
    static bool InstallAuditSACL(HANDLE hProcess);
};

// ============================================================
// Syscall Stub 完整性验证 + 自愈
// 原理: ntdll.dll 的每个 Nt*/Zw* 函数前 4 字节应为:
//       4C 8B D1 B8 (mov r10, rcx; mov eax, SSN)
//       EAC 可能通过 Instrumentation Callback 或 Object Callback
//       在我们的进程中 Hook 这些 stub。
//       本类验证关键 stub 是否被篡改, 并从磁盘恢复。
// ============================================================
class SyscallGuard {
public:
    // 验证关键 syscall stub 完整性
    // 返回: 0 = 全部正常, N = 被篡改的 stub 数量
    static int VerifyKeyStubs();

    // 从磁盘恢复被篡改的 syscall stub
    // 打开 ntdll.dll (System32 下的原始副本), 逐函数比对并修复
    // 返回修复的函数数量
    static int RestoreFromDisk();

    // 单次调用: 验证 + 必要时自愈
    static bool VerifyAndRepair();

private:
    // 关键 syscall 列表 (用于 EAC 检测的核心函数)
    // 格式: 函数名, 预期 SSN (作为辅助校验)
    struct CriticalStub {
        const char* name;
        bool  isRead;         // 是否涉及内存读取
    };

    static const CriticalStub s_criticalStubs[];
    static const int         s_criticalStubCount;

    // 验证单个 stub
    static bool IsStubIntact(const char* funcName);

    // 从磁盘 ntdll 恢复单个 stub
    static bool RestoreSingleStub(const char* funcName, HMODULE hDiskNtdll);
};

} // namespace stealth
