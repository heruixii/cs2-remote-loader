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
// ★ BUILD 496: 移除 <vector> — Manual-Map DLL 中 CRT 堆未初始化

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
    // ★ BUILD 556: P0+P1 syscall 替代 — 新增 4 个 SSN
    //   NtOpenThread             — 替代 OpenThread (CleanupInjectionTraces)
    //   NtAdjustPrivilegesToken  — 替代 AdjustTokenPrivileges (EnsureDebugPrivilegeSilent)
    //   NtOpenProcessToken       — 替代 OpenProcessToken (EnsureDebugPrivilegeSilent / BypassPrivilegeCheck)
    //   NtQueryInformationToken  — 替代 GetTokenInformation (查询权限)
    DWORD NtOpenThread;
    DWORD NtAdjustPrivilegesToken;
    DWORD NtOpenProcessToken;
    DWORD NtQueryInformationToken;
    // ★ v3.296 FIX-19: NtTerminateProcess — 替代 ExitProcess, 绕过 LdrShutdownProcess
    DWORD NtTerminateProcess;
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
    // ★ BUILD 551: 改为接受函数地址 (调用方用 STEALTH_GET_PROC_ADDRESS_NOREF 解析)
    //   原因: 旧版 const char* funcName 在调用点传入明文字符串字面量, 进入 .rdata
    //   收益: 消除 8 处 "NtXxx" 明文 API 名 (NtAllocateVirtualMemory 等组合是注入器签名)
    bool IsStubHooked(BYTE* funcAddr);

    // 使用 Halo's Gate 恢复被 Hook 函数的 SSN
    // ★ BUILD 551: 同样改为接受函数地址
    DWORD RecoverSSNviaHalo(BYTE* funcAddr);

    // 获取干净的 syscall;ret gadget 地址 (用于间接 syscall)
    uintptr_t GetSyscallRetGadget();

    // 获取干净的 ret 指令地址 (用于 call stack spoofing)
    uintptr_t GetRetGadget();

    // 检查 StackSpoof 所需组件是否就绪 (ret gadget 列表已填充)
    bool IsStackSpoofReady() const { return m_stackSpoofReady; }
    void SetStackSpoofReady(bool ready) { m_stackSpoofReady = ready; }

private:
    SyscallResolver() = default;
    // ★ BUILD 551: 改为接受函数地址 (调用方用 STEALTH_GET_PROC_ADDRESS_NOREF 解析)
    DWORD ExtractSyscallNumber(BYTE* funcAddr);
    
    // 扫描相邻内存中的 syscall stub, 返回在函数表中的索引
    DWORD ScanNearbySyscall(BYTE* targetAddr, int searchRange);

    SyscallNumbers m_numbers = {};
    uintptr_t m_syscallRetGadget = 0; // syscall;ret 的地址
    uintptr_t m_retGadget = 0;        // ret 的地址
    bool m_initialized = false;
    bool m_haloInitialized = false;
    bool m_stackSpoofReady = false;   // StackSpoof 组件就绪
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

    // 获取已缓存的 Fat Frame 数量
    int GetFatFrameCount() const { return m_fatFrameCount; }

private:
    CallStackSpoofer() = default;

    // 解析 .pdata 获取函数栈大小
    SIZE_T GetFunctionStackSize(uintptr_t funcAddr);

    // ★ BUILD 496: 固定数组替代 std::vector — 避免 CRT 堆依赖
    static constexpr int MAX_FAT_FRAMES = 64;
    CallStackSpoofContext m_context = {};
    CallStackSpoofContext m_fatFrames[MAX_FAT_FRAMES];
    int m_fatFrameCount = 0;
    bool m_initialized = false;
};

// ============================================================
// RetGadget Scanner — 在合法模块中扫描 ret (C3) 指令
// 用于构造多层伪造调用栈 (ret-sled)
// RtlVirtualUnwind 回溯时将看到 ntdll→kernel32→user32 的合法调用链
// ============================================================
// ★ BUILD 496: 固定数组替代 std::vector — 避免 CRT 堆依赖
static constexpr int MAX_RET_GADGETS = 64;
bool FindRetGadgets(uintptr_t* outGadgets, int* outCount, int targetCount = 32);
// 便捷函数: 返回缓存的 gadget 数量
int GetRetGadgetCount();

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

// ★ BUILD 551: STEALTH_OPEN_PROCESS — OpenProcess 的 syscall 替代宏
//   用法: HANDLE h; STEALTH_OPEN_PROCESS(h, PROCESS_VM_READ, pid);
//   规避: kernel32!OpenProcess 触发 ObRegisterCallbacks 内核回调 (PAC 注册)
//         替换 6 处直接 OpenProcess 调用, 消除 IAT 中 OpenProcess 导入
//   注意: inherit 参数被忽略 (NtOpenProcess 不支持句柄继承, 不影响检测规避)
//   依赖: syscall_direct.h 已 include <winternl.h> (CLIENT_ID, OBJECT_ATTRIBUTES)
#define STEALTH_OPEN_PROCESS(handle_var, access, pid) do { \
    CLIENT_ID _stealth_cid_551 = {}; \
    _stealth_cid_551.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid)); \
    OBJECT_ATTRIBUTES _stealth_oa_551 = {}; \
    _stealth_oa_551.Length = sizeof(_stealth_oa_551); \
    handle_var = nullptr; \
    ::stealth::SysOpenProcess(&(handle_var), (access), &_stealth_oa_551, &_stealth_cid_551); \
} while(0)

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

// ============================================================
// ★ BUILD 556: P0+P1 syscall 替代 — 新增 6 个 Sys* 包装
//   目标: 消除 IAT 中 WriteProcessMemory/OpenThread/令牌 API 静态导入
//   实现模式: 与现有 Sys* 一致 (Initialize SSN → DecideMethod →
//             StackSpoof/Indirect/Tartarus/Direct 四级降级)
// ============================================================

// ---- SysCreateThreadEx (替代 CreateRemoteThread) ----
// SSN 已在 Initialize 中提取 (NtCreateThreadEx), 此前未封装
NTSTATUS SysCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartAddress, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList,
    SyscallMethod method = SyscallMethod::Auto);

// ---- SysFreeVirtualMemory (替代 VirtualFreeEx) ----
// SSN 已在 Initialize 中提取 (NtFreeVirtualMemory), 此前未封装
NTSTATUS SysFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType,
    SyscallMethod method = SyscallMethod::Auto);

// ---- SysOpenThread (替代 OpenThread) ----
// ★ BUILD 556 新提取 SSN (NtOpenThread)
//   规避: kernel32!OpenThread 触发 ObRegisterCallbacks 内核回调 (PAC 注册)
//   替换 payload.cpp L1296 CleanupInjectionTraces 中的 OpenThread 调用
NTSTATUS SysOpenThread(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId,
    SyscallMethod method = SyscallMethod::Auto);

// ---- SysOpenProcessToken (替代 OpenProcessToken) ----
// ★ BUILD 556 新提取 SSN (NtOpenProcessToken)
//   规避: advapi32!OpenProcessToken IAT 静态导入特征
//   替换 stealth_process.cpp L300/L363 EnsureDebugPrivilegeSilent / BypassPrivilegeCheck
NTSTATUS SysOpenProcessToken(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle,
    SyscallMethod method = SyscallMethod::Auto);

// ---- SysAdjustPrivilegesToken (替代 AdjustTokenPrivileges) ----
// ★ BUILD 556 新提取 SSN (NtAdjustPrivilegesToken)
//   规避: advapi32!AdjustTokenPrivileges IAT 静态导入特征
//   替换 stealth_process.cpp L350 EnsureDebugPrivilegeSilent 提权
NTSTATUS SysAdjustPrivilegesToken(
    HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
    PVOID NewState, ULONG BufferLength,
    PVOID PreviousState, PULONG ReturnLength,
    SyscallMethod method = SyscallMethod::Auto);

// ---- SysQueryInformationToken (替代 GetTokenInformation) ----
// ★ BUILD 556 新提取 SSN (NtQueryInformationToken)
//   规避: advapi32!GetTokenInformation IAT 静态导入特征
//   替换 stealth_process.cpp L313/L326/L366 权限查询
NTSTATUS SysQueryInformationToken(
    HANDLE TokenHandle, ULONG TokenInformationClass,
    PVOID TokenInformation, ULONG TokenInformationLength,
    PULONG ReturnLength,
    SyscallMethod method = SyscallMethod::Auto);

// ---- SysTerminateProcess (替代 ExitProcess) ----
// ★ v3.296 FIX-19: NtTerminateProcess syscall — 绕过 ExitProcess 的 LdrShutdownProcess
//   ExitProcess 流程: LdrShutdownProcess (DLL_PROCESS_DETACH) → NtTerminateProcess
//   NtTerminateProcess 直接调用内核, 跳过 LdrShutdownProcess
//   用途: CS2 退出后 loader.exe 安全退出, 避免 DLL_PROCESS_DETACH 触发蓝屏
//   参数: Handle = NtCurrentProcess() = (HANDLE)-1, ExitStatus = 0
NTSTATUS SysTerminateProcess(
    HANDLE ProcessHandle, NTSTATUS ExitStatus,
    SyscallMethod method = SyscallMethod::Auto);

// ★ BUILD 556: STEALTH_OPEN_THREAD — OpenThread 的 syscall 替代宏
//   用法: HANDLE h; STEALTH_OPEN_THREAD(h, THREAD_QUERY_INFORMATION, tid);
//   规避: kernel32!OpenThread 触发 ObRegisterCallbacks 内核回调 (PAC 注册)
//   仿照 STEALTH_OPEN_PROCESS (L236-243) 模式
//   注意: inherit 参数被忽略 (NtOpenThread 不支持句柄继承, 不影响检测规避)
//   依赖: syscall_direct.h 已 include <winternl.h> (CLIENT_ID, OBJECT_ATTRIBUTES)
#define STEALTH_OPEN_THREAD(handle_var, access, tid) do { \
    CLIENT_ID _stealth_cid_556 = {}; \
    _stealth_cid_556.UniqueThread = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(tid)); \
    OBJECT_ATTRIBUTES _stealth_oa_556 = {}; \
    _stealth_oa_556.Length = sizeof(_stealth_oa_556); \
    handle_var = nullptr; \
    ::stealth::SysOpenThread(&(handle_var), (access), &_stealth_oa_556, &_stealth_cid_556); \
} while(0)

} // namespace stealth
