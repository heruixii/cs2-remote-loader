#pragma once
// ============================================================
// anti_debug.h — 全面反调试/反分析套件
//
// 覆盖 17 项检测:
//   PEB:   BeingDebugged, NtGlobalFlag
//   Proc:  ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle
//   System: KernelDebugger, SystemKernelDebuggerInformation
//   Thread: ThreadHideFromDebugger (主动规避)
//   HWBP:  DR0-DR7 硬件断点检测
//   Time:  RDTSC / QueryPerformanceCounter 时间差检测
//   Int:   INT3 / INT 2D 断点扫描
//   Parent: 父进程检查
//   Heap:  堆标志检查 (ForceFlags, Flags)
//   CloseHandle: 反调试陷阱
//   OutputDebugString: 反调试漏洞
//   Object: 句柄权限枚举检测
//   TLS:   TLS 回调反调试
// ============================================================

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "platform.h"

namespace stealth {

// ============================================================
// 检测结果枚举
// ============================================================

enum class DebugCheckResult {
    Clean,          // 未检测到
    Suspicious,     // 可疑 (可能是误报)
    Debugged,       // 确认被调试
    Error           // 检测失败
};

struct DebugDetectionReport {
    bool isBeingDebugged = false;
    std::string triggerReason;
    std::vector<std::string> allTriggers;
};

// ============================================================
// AntiDebug — 反调试检测引擎
// ============================================================

class AntiDebug {
public:
    static AntiDebug& Instance();

    // ---- 主检测入口 ----
    // 执行全套检测, 返回是否存在调试器
    // aggressive=true: 还会执行主动规避 (如 ThreadHideFromDebugger)
    DebugDetectionReport FullCheck(bool aggressive = true);

    // ---- PEB 检测 (2项) ----
    // 1. BeingDebugged 标志
    static DebugCheckResult CheckBeingDebugged();
    // 2. NtGlobalFlag 堆标志
    static DebugCheckResult CheckNtGlobalFlag();

    // ---- 进程信息检测 (3项) ----
    // 3. ProcessDebugPort (CheckRemoteDebuggerPresent)
    static DebugCheckResult CheckDebugPort();
    // 4. ProcessDebugFlags (内核调试标志, 类号 0x1F)
    static DebugCheckResult CheckDebugFlags();
    // 5. ProcessDebugObjectHandle (类号 0x1E)
    static DebugCheckResult CheckDebugObjectHandle();

    // ---- 系统信息检测 (2项) ----
    // 6. SystemKernelDebuggerInformation (类号 0x23)
    static DebugCheckResult CheckKernelDebugger();
    // 7. NtQuerySystemInformation(KernelDebugger, 类号 35)
    static DebugCheckResult CheckSystemDebugger();

    // ---- 硬件断点检测 (1项) ----
    // 8. DR0-DR7 寄存器非零
    static DebugCheckResult CheckHardwareBreakpoints();

    // ---- 时间检测 (2项) ----
    // 9. RDTSC 时间差
    static DebugCheckResult CheckTimingRDTSC();
    // 10. QueryPerformanceCounter 时间差
    static DebugCheckResult CheckTimingQPC();

    // ---- 指令检测 (2项) ----
    // 11. INT3 断点扫描
    static DebugCheckResult CheckINT3Breakpoints();
    // 12. INT 2D 扫描
    static DebugCheckResult CheckINT2D();

    // ---- 环境检测 (4项) ----
    // 13. 父进程检查 (应为 explorer.exe 或等效)
    static DebugCheckResult CheckParentProcess();
    // 14. CloseHandle 陷阱 (向无效句柄调用 CloseHandle 触发异常)
    static DebugCheckResult CheckCloseHandleTrap();
    // 15. OutputDebugString 漏洞
    static DebugCheckResult CheckOutputDebugStringTrap();
    // 16. 堆标志检查
    static DebugCheckResult CheckHeapFlags();

    // ---- 句柄检测 (1项) ----
    // 17. 通过 NtQueryObject 检测调试器打开的句柄
    static DebugCheckResult CheckDebuggerHandles();

    // ---- 主动规避 ----
    // 隐藏所有线程 (使调试器无法接收线程事件)
    static void HideAllThreads();
    // 隐藏当前线程
    static void HideCurrentThread();
    // 终止调试器进程 (通过句柄回溯)
    static bool TerminateDebugger();
    // 制造反附加 (通过修改 PEB)
    static bool PreventDebuggerAttach();

private:
    AntiDebug() = default;

    // 辅助: 通过 NtQueryInformationProcess 获取指定信息类
    static NTSTATUS QueryProcessInfo(ULONG infoClass, PVOID buffer, ULONG size);

    // 辅助: 获取所有线程 ID
    static std::vector<DWORD> EnumerateAllThreads();
};

// ============================================================
// 反反汇编 — 控制流混淆原语
// ============================================================

class CodeObfuscator {
public:
    // 不透明谓词 — 始终为 true 的复杂条件, 但编译器/反汇编器难以推断
    // 用于插入假分支, 破坏反汇编线性扫描
    STEALTH_NOINLINE static bool OpaqueTrue();
    STEALTH_NOINLINE static bool OpaqueFalse();

    // 垃圾代码注入 — 在关键函数间插入无意义的指令序列
    // 用于破坏签名匹配
    STEALTH_NOINLINE static void JunkCode();

    // 控制流平坦化辅助 — 将 switch-case 转为间接跳转表
    // 用于破坏函数边界识别
};

} // namespace stealth
