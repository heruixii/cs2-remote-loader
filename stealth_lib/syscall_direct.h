#pragma once
// ============================================================
// syscall_direct.h — 高级系统调用接口 (2026版)
//
// 新增技术:
//   1. Halo's Gate — 当 ntdll stub 被 EDR/AC Hook 时寻找附近干净的 SSN
//   2. Indirect Syscalls — 跳转到 ntdll 中的 syscall;ret gadget, 
//      使调用栈中的返回地址指向 ntdll (规避 ETW Call Stack 分析)
//   3. Call Stack Spoofing — 构造伪造的调用栈帧, 
//      使 RtlVirtualUnwind 回溯到合法的调用链
//   4. Tartarus Gate — 通过 NtContinue 执行 syscall,
//      RIP/RSP 完全受控, 无污染调用栈
// ============================================================

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>

namespace stealth {

// ---- 系统调用号 ----
struct SyscallNumbers {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtOpenProcess;
    DWORD NtQuerySystemInformation;
    DWORD NtCreateThreadEx;
    DWORD NtQueryInformationProcess;
    DWORD NtClose;
    DWORD NtQueryVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtDelayExecution;
    DWORD NtContinue;
    DWORD NtWaitForSingleObject;
};

// ---- 系统调用解析器 (升级版: Hell's Gate + Halo's Gate) ----
class SyscallResolver {
public:
    static SyscallResolver& Instance();
    bool Initialize();

    const SyscallNumbers& GetNumbers() const { return m_numbers; }

    // ============================================================
    // Halo's Gate — 当目标函数被 Hook 时, 在相邻内存中查找干净的 stub
    //
    // 原理: EDR/AC 通常只 Hook 敏感函数 (NtWriteVirtualMemory 等), 
    //       但同一个 DLL 中相邻的不敏感函数 (如 NtQuerySection) 
    //       的 stub 仍然完整。通过计算相邻函数 SSN 的偏移,
    //       可以推导出目标函数的 SSN。
    //
    // 实现: 在目标函数 ± 64 条指令范围内搜索未 Hook 的 syscall stub,
    //       用其 SSN + 偏移 = 目标 SSN
    // ============================================================
    bool InitializeHaloGate();

    // 检查 ntdll 中指定函数是否被 Hook
    bool IsStubHooked(const char* funcName);

    // 使用 Halo's Gate 恢复被 Hook 函数的 SSN
    DWORD RecoverSSNviaHalo(const char* funcName);

    // 获取干净的 syscall;ret gadget 地址 (用于间接 syscall)
    uintptr_t GetSyscallRetGadget();

    // 获取干净的 ret 指令地址 (用于 call stack spoofing)
    uintptr_t GetRetGadget();

private:
    SyscallResolver() = default;
    DWORD ExtractSyscallNumber(const char* funcName);
    
    // 扫描相邻内存中的 syscall stub, 返回在函数表中的索引
    DWORD ScanNearbySyscall(BYTE* targetAddr, int searchRange);

    SyscallNumbers m_numbers = {};
    uintptr_t m_syscallRetGadget = 0; // syscall;ret 的地址
    uintptr_t m_retGadget = 0;        // ret 的地址
    bool m_initialized = false;
    bool m_haloInitialized = false;
};

// ============================================================
// Indirect Syscall — 跳转到 ntdll 中的 syscall 指令
//
// 规避: ETW Thread Suspension + Call Stack 回溯分析
//
// 传统直接 syscall: 调用栈中返回地址指向我们的代码 → 异常
// 间接 syscall:    跳转到 ntdll.dll 内的 syscall;ret gadget
//                   → 调用栈中的返回地址在 ntdll 内 → 合法
// ============================================================

// 执行间接 syscall 的核心汇编助记:
//   1. 设置参数到寄存器 (rcx, rdx, r8, r9 + stack)
//   2. 在栈上伪造返回地址 (指向 ntdll 内的合法地址)
//   3. jmp 到 ntdll 中的 syscall;ret gadget (不是 call!)
//   4. syscall 执行后 ret 回到伪造的返回地址
//   5. 最终返回到我们真正的 cleanup 代码

// ============================================================
// Call Stack Spoofing — 构造模拟合法调用链的栈帧
//
// 基于 SindriKit 1.3.0 技术 (2026):
//   1. 在 kernel32.dll 中找到 "Fat Frame" (≥120 bytes 栈分配)
//   2. 将伪造的返回地址写入栈帧
//   3. 使 RtlVirtualUnwind 回溯出合法的调用链:
//      我们的代码 → kernel32!FatFrameFunc → ntdll!syscall
// ============================================================

struct CallStackSpoofContext {
    uintptr_t originalReturnAddr;      // 真正的调用者返回地址
    uintptr_t trampolineGadget;         // RET 在 Fat Frame 中
    uintptr_t spoofFrameSize;           // Fat Frame 的大小
    uintptr_t spoofedCallSite;          // 伪造的调用点
};

class CallStackSpoofer {
public:
    static CallStackSpoofer& Instance();
    bool Initialize();

    // 扫描 kernel32.dll 寻找 Fat Frame (>120 bytes 栈分配)
    // 使用 .pdata 异常目录 + RUNTIME_FUNCTION / UNWIND_INFO
    bool FindFatFrames();

    // 随机选择一个 Fat Frame 用于 spoofing (避免固定特征)
    CallStackSpoofContext GetRandomSpoofContext();

    // 获取 spoof context
    const CallStackSpoofContext& GetContext() const { return m_context; }

private:
    CallStackSpoofer() = default;

    // 解析 .pdata 获取函数栈大小
    SIZE_T GetFunctionStackSize(uintptr_t funcAddr);

    CallStackSpoofContext m_context = {};
    std::vector<CallStackSpoofContext> m_fatFrames;
    bool m_initialized = false;
};

// ============================================================
// Tartarus Gate — NtContinue 驱动的 syscall
//
// 原理: 手动构造 CONTEXT 结构, 设置 RIP = syscall stub,
//       RSP = 伪造的栈, 然后调用 NtContinue 执行
//
// 优势: 调用栈完全受控, 无任何可疑返回地址
// 缺点: 需要 NtContinue 未被 Hook (但其 SSN 可通过 Halo's Gate 恢复)
// ============================================================

class TartarusGate {
public:
    static bool ExecuteViaNtContinue(
        uintptr_t syscallStubAddr,
        uintptr_t arg1, uintptr_t arg2,
        uintptr_t arg3, uintptr_t arg4);

    // 生成 syscall stub 到可执行内存
    static void* GenerateSyscallStub(DWORD ssn);
};

// ---- 高级 Syscall 函数 (集成多种技术, 自动降级) ----
// 优先级: Call Stack Spoofing > Indirect Syscall > Tartarus Gate > Direct Syscall
enum class SyscallMethod {
    Auto,            // 自动选择最佳方法
    Direct,          // 直接 syscall
    Indirect,        // 间接 syscall (跳转 ntdll gadget)
    StackSpoof,      // 调用栈伪造
    Tartarus         // NtContinue 执行
};

NTSTATUS SysAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect,
    SyscallMethod method = SyscallMethod::Auto);

NTSTATUS SysProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect,
    SyscallMethod method = SyscallMethod::Auto);

NTSTATUS SysWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten,
    SyscallMethod method = SyscallMethod::Auto);

NTSTATUS SysReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead,
    SyscallMethod method = SyscallMethod::Auto);

NTSTATUS SysOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId,
    SyscallMethod method = SyscallMethod::Auto);

NTSTATUS SysQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength,
    SyscallMethod method = SyscallMethod::Auto);

NTSTATUS SysQueryInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength,
    SyscallMethod method = SyscallMethod::Auto);

NTSTATUS SysClose(HANDLE Handle, SyscallMethod method = SyscallMethod::Auto);

} // namespace stealth
