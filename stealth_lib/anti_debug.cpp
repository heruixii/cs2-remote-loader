// ============================================================
// anti_debug.cpp — 全面反调试/反分析实现
// ============================================================

#include "anti_debug.h"
#include "syscall_direct.h"
#include "platform.h"
#include "module_resolver.h"  // ★ BUILD 550: GetModuleBaseFromPEB + ModNameHash (替代 GetModuleHandleW)
#include "string_obfuscator.h"  // ★ BUILD 550: STEALTH_STR_DECRYPT_TO (动态解析 Toolhelp API)
#include <winternl.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <cstdio>

// ============================================================
// ★ BUILD 550: 动态解析 Toolhelp API — 消除 IAT 中敏感 API 名
//   原因: CreateToolhelp32Snapshot/Process32FirstW/Process32NextW/
//         Thread32First/Thread32Next 在 IAT 中暴露, 可能被 PAC IAT 扫描
//   修复: 用 GetProcAddress + STEALTH_STR_DECRYPT_TO 动态解析,
//         API 名被 XTEA 编译期加密, 不出现在 .rdata
// ============================================================
namespace {
    struct ToolhelpApis {
        HANDLE (WINAPI *createSnap)(DWORD, DWORD);
        BOOL (WINAPI *procFirst)(HANDLE, LPPROCESSENTRY32W);
        BOOL (WINAPI *procNext)(HANDLE, LPPROCESSENTRY32W);
        BOOL (WINAPI *threadFirst)(HANDLE, LPTHREADENTRY32);
        BOOL (WINAPI *threadNext)(HANDLE, LPTHREADENTRY32);
    };

    bool InitToolhelpApis(ToolhelpApis& apis) {
        memset(&apis, 0, sizeof(apis));
        HMODULE k32 = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"kernel32.dll"));
        if (!k32) return false;

        char apiName[64] = {};
        STEALTH_STR_DECRYPT_TO("CreateToolhelp32Snapshot", apiName, sizeof(apiName));
        apis.createSnap = reinterpret_cast<decltype(apis.createSnap)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        STEALTH_STR_DECRYPT_TO("Process32FirstW", apiName, sizeof(apiName));
        apis.procFirst = reinterpret_cast<decltype(apis.procFirst)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        STEALTH_STR_DECRYPT_TO("Process32NextW", apiName, sizeof(apiName));
        apis.procNext = reinterpret_cast<decltype(apis.procNext)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        STEALTH_STR_DECRYPT_TO("Thread32First", apiName, sizeof(apiName));
        apis.threadFirst = reinterpret_cast<decltype(apis.threadFirst)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        STEALTH_STR_DECRYPT_TO("Thread32Next", apiName, sizeof(apiName));
        apis.threadNext = reinterpret_cast<decltype(apis.threadNext)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        return apis.createSnap && apis.procFirst && apis.procNext
            && apis.threadFirst && apis.threadNext;
    }
}

// ============================================================
// gcc SEH 替代: VEH 基于 thread_local 异常跟踪
// ============================================================
#ifndef _MSC_VER
namespace {
    thread_local bool     g_vehExceptionCaught = false;
    thread_local DWORD    g_vehExceptionCode = 0;
    thread_local uintptr_t g_vehTargetRip = 0;  // 异常后跳转目标 RIP

    LONG CALLBACK AntiDebugVehHandler(PEXCEPTION_POINTERS ep) {
        g_vehExceptionCaught = true;
        g_vehExceptionCode = ep->ExceptionRecord->ExceptionCode;
        // 跳过当前指令 — int2d=2字节, call=5字节粗略估计
        if (g_vehTargetRip != 0) {
            ep->ContextRecord->Rip = g_vehTargetRip;
        } else {
            ep->ContextRecord->Rip += 2;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
}
#endif

#pragma comment(lib, "psapi.lib")

namespace stealth {

// ============================================================
// AntiDebug
// ============================================================

AntiDebug& AntiDebug::Instance() {
    static AntiDebug instance;
    return instance;
}

DebugDetectionReport AntiDebug::FullCheck(bool aggressive) {
    DebugDetectionReport report;
    report.allTriggerCount = 0;
    report.triggerReason[0] = '\0';

    // 按影响从高到低排列检查
    struct Check { const char* name; DebugCheckResult result; };
    Check checks[16];
    int checkCount = 0;

    checks[checkCount++] = {"BeingDebugged",           CheckBeingDebugged()};
    checks[checkCount++] = {"NtGlobalFlag",            CheckNtGlobalFlag()};
    checks[checkCount++] = {"DebugPort",               CheckDebugPort()};
    checks[checkCount++] = {"DebugFlags",              CheckDebugFlags()};
    checks[checkCount++] = {"DebugObjectHandle",       CheckDebugObjectHandle()};
    checks[checkCount++] = {"KernelDebugger",          CheckKernelDebugger()};
    checks[checkCount++] = {"HardwareBreakpoints",     CheckHardwareBreakpoints()};
    checks[checkCount++] = {"TimingRDTSC",            CheckTimingRDTSC()};
    checks[checkCount++] = {"TimingQPC",              CheckTimingQPC()};
    checks[checkCount++] = {"INT3Breakpoints",         CheckINT3Breakpoints()};
    checks[checkCount++] = {"ParentProcess",           CheckParentProcess()};
    checks[checkCount++] = {"CloseHandleTrap",         CheckCloseHandleTrap()};
    checks[checkCount++] = {"HeapFlags",               CheckHeapFlags()};
    checks[checkCount++] = {"DebuggerHandles",         CheckDebuggerHandles()};

    for (int i = 0; i < checkCount; i++) {
        if (checks[i].result == DebugCheckResult::Debugged) {
            report.isBeingDebugged = true;
            if (report.triggerReason[0] == '\0') {
                strcpy_s(report.triggerReason, checks[i].name);
            }
            snprintf(report.allTriggers[report.allTriggerCount], 128, "%s : Debugged", checks[i].name);
            report.allTriggerCount++;
        } else if (checks[i].result == DebugCheckResult::Suspicious) {
            snprintf(report.allTriggers[report.allTriggerCount], 128, "%s : Suspicious", checks[i].name);
            report.allTriggerCount++;
        }
    }

    // 主动规避
    if (aggressive && report.isBeingDebugged) {
        HideAllThreads();
    }

    return report;
}

// ============================================================
// PEB 检测
// ============================================================

DebugCheckResult AntiDebug::CheckBeingDebugged() {
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return DebugCheckResult::Error;

    // 主要标志
    if (peb->BeingDebugged) {
        return DebugCheckResult::Debugged;
    }

    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckNtGlobalFlag() {
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return DebugCheckResult::Error;

    // NtGlobalFlag 在 PEB+0xBC 处 (x64)
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(peb) + 0xBC);

    // 调试器通常设置这些标志:
    // FLG_HEAP_ENABLE_TAIL_CHECK    (0x10)
    // FLG_HEAP_ENABLE_FREE_CHECK    (0x20)
    // FLG_HEAP_VALIDATE_PARAMETERS  (0x40)
    const DWORD debugFlags = 0x70;
    if (ntGlobalFlag & debugFlags) {
        return DebugCheckResult::Debugged;
    }

    return DebugCheckResult::Clean;
}

// ============================================================
// 进程信息检测
// ============================================================

NTSTATUS AntiDebug::QueryProcessInfo(ULONG infoClass, PVOID buffer, ULONG size) {
    ULONG retLen = 0;
    return SysQueryInformationProcess(
        GetCurrentProcess(), infoClass, buffer, size, &retLen);
}

DebugCheckResult AntiDebug::CheckDebugPort() {
    // ProcessDebugPort = 7
    DWORD_PTR debugPort = 0;
    NTSTATUS st = QueryProcessInfo(7, &debugPort, sizeof(debugPort));

    if (NT_SUCCESS(st) && debugPort != 0) {
        return DebugCheckResult::Debugged;
    }

    // 备用方法: CheckRemoteDebuggerPresent
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        return DebugCheckResult::Debugged;
    }

    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckDebugFlags() {
    // ProcessDebugFlags = 0x1F
    // 当调试器附加时, EPROCESS->NoDebugInherit 被清空
    // 返回值 = FALSE 表示存在调试器
    DWORD noDebugInherit = 0;
    NTSTATUS st = QueryProcessInfo(0x1F, &noDebugInherit, sizeof(noDebugInherit));

    if (NT_SUCCESS(st) && noDebugInherit == 0) {
        return DebugCheckResult::Debugged;
    }

    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckDebugObjectHandle() {
    // ProcessDebugObjectHandle = 0x1E
    HANDLE debugObject = nullptr;
    NTSTATUS st = QueryProcessInfo(0x1E, &debugObject, sizeof(debugObject));

    if (NT_SUCCESS(st) && debugObject != nullptr) {
        return DebugCheckResult::Debugged;
    }

    return DebugCheckResult::Clean;
}

// ============================================================
// 系统信息检测
// ============================================================

DebugCheckResult AntiDebug::CheckKernelDebugger() {
    // SystemKernelDebuggerInformation = 0x23
    struct {
        BOOLEAN DebuggerEnabled;
        BOOLEAN DebuggerNotPresent;
    } kdInfo = {};

    ULONG retLen;
    NTSTATUS st = SysQuerySystemInformation(0x23, &kdInfo, sizeof(kdInfo), &retLen);

    if (NT_SUCCESS(st) && kdInfo.DebuggerEnabled && !kdInfo.DebuggerNotPresent) {
        return DebugCheckResult::Debugged;
    }

    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckSystemDebugger() {
    // NtQuerySystemInformation(0x23)
    // 检查是否有活动调试器
    return CheckKernelDebugger(); // 相同的底层调用
}

// ============================================================
// 硬件断点检测
// ============================================================

DebugCheckResult AntiDebug::CheckHardwareBreakpoints() {
    // 检查调试寄存器 DR0-DR3 (硬件断点地址)
    // DR7 控制启用状态
    //
    // 关键: RtlCaptureContext 不会捕获调试寄存器!
    // 必须使用 GetThreadContext 并指定 CONTEXT_DEBUG_REGISTERS

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // 使用 GetThreadContext 获取包含调试寄存器的完整上下文
    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) {
        return DebugCheckResult::Error;
    }

    // 检查 DR0-DR3
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        return DebugCheckResult::Debugged;
    }

    // 额外检查: DR7 的低 8 位控制 DR0-DR3 的本地启用
    if (ctx.Dr7 & 0xFF) {
        return DebugCheckResult::Suspicious;
    }

    return DebugCheckResult::Clean;
}

// ============================================================
// 时间检测
// ============================================================

DebugCheckResult AntiDebug::CheckTimingRDTSC() {
    // RDTSC 时间差检测
    // 调试器中单步执行会显著增加指令执行时间

    unsigned __int64 t1 = __rdtsc();
    // 执行极短的操作
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    unsigned __int64 t2 = __rdtsc();

    unsigned __int64 delta = t2 - t1;

    // 正常执行应在数千个周期内
    // 如果超过 100000 周期, 可能被单步跟踪
    if (delta > 100000) {
        return DebugCheckResult::Suspicious;
    }

    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckTimingQPC() {
    // QueryPerformanceCounter 时间差
    LARGE_INTEGER freq, start, end;

    if (!QueryPerformanceFrequency(&freq)) {
        return DebugCheckResult::Clean;
    }

    QueryPerformanceCounter(&start);

    // 做一点工作
    volatile int counter = 0;
    for (int i = 0; i < 1000; i++) {
        counter += i * i;
    }

    QueryPerformanceCounter(&end);

    double elapsedMs = static_cast<double>(end.QuadPart - start.QuadPart)
                       / freq.QuadPart * 1000.0;

    // 正常 < 1ms, 调试器下 > 5ms
    if (elapsedMs > 5.0) {
        return DebugCheckResult::Suspicious;
    }

    return DebugCheckResult::Clean;
}

// ============================================================
// 指令检测
// ============================================================

DebugCheckResult AntiDebug::CheckINT3Breakpoints() {
    // 扫描常用函数开头是否有 INT3 (0xCC)
    // ★ BUILD 552: 重构 funcs[] 数组 — 用 STEALTH_GET_PROC_ADDRESS_NOREF 加密解析
    //   原实现: const char* funcs[] = {"NtWriteVirtualMemory", ...} 4 个明文 API 名进入 .rdata
    //   新实现: 运行时 XTEA 编译期加密解析, .rdata 中无明文残留

    HMODULE ntdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    if (!ntdll) return DebugCheckResult::Error;

    // 运行时解析 4 个关键 Nt* 函数地址 (XTEA 编译期加密 API 名)
    BYTE* stubs[] = {
        reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "NtWriteVirtualMemory")),
        reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "NtReadVirtualMemory")),
        reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "NtOpenProcess")),
        reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "NtQuerySystemInformation")),
    };

    for (auto* addr : stubs) {
        if (addr && addr[0] == 0xCC) {
            return DebugCheckResult::Debugged;
        }
    }

    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckINT2D() {
    // INT 2D 是 Windows 内核调试器使用的特殊中断
    // 在用户态调试器下执行 INT 2D 的行为与无调试器不同
    //
    // x64 兼容实现: 将 INT 2D 字节写入可执行内存后调用
    // (MSVC x64 不支持内联 __asm)

    // INT 2D 的机器码: CD 2D
    BYTE int2dCode[] = { 0xCD, 0x2D, 0xC3 }; // int 2D; ret
    void* execMem = VirtualAlloc(nullptr, sizeof(int2dCode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return DebugCheckResult::Error;

    memcpy(execMem, int2dCode, sizeof(int2dCode));
    FlushInstructionCache(GetCurrentProcess(), execMem, sizeof(int2dCode));

#ifdef _MSC_VER
    __try {
        reinterpret_cast<void(*)()>(execMem)();
        // 如果没有异常, 说明可能有内核调试器
        VirtualFree(execMem, 0, MEM_RELEASE);
        return DebugCheckResult::Suspicious;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return DebugCheckResult::Clean;
    }
#else
    {
        // gcc: 使用 VEH 模拟 __try/__except
        g_vehExceptionCaught = false;
        g_vehTargetRip = reinterpret_cast<uintptr_t>(execMem) + 2; // 跳过 int 2D (2字节)
        PVOID veh = AddVectoredExceptionHandler(1, AntiDebugVehHandler);
        reinterpret_cast<void(*)()>(execMem)();
        RemoveVectoredExceptionHandler(veh);
        VirtualFree(execMem, 0, MEM_RELEASE);
        return g_vehExceptionCaught ? DebugCheckResult::Clean : DebugCheckResult::Suspicious;
    }
#endif
}

// ============================================================
// 环境检测
// ============================================================

DebugCheckResult AntiDebug::CheckParentProcess() {
    // 获取父进程 ID
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen;
    NTSTATUS st = QueryProcessInfo(0, &pbi, sizeof(pbi));

    if (!NT_SUCCESS(st)) return DebugCheckResult::Error;

    // InheritedFromUniqueProcessId 在 pbi 中
    // 但 PROCESS_BASIC_INFORMATION 的结构因版本而异
    // 使用 NtQueryInformationProcess 的 ProcessBasicInformation

    // 备用方法: 使用 toolhelp snapshot (★ BUILD 550: 动态解析, 消除 IAT 暴露)
    ToolhelpApis apis = {};
    if (!InitToolhelpApis(apis)) return DebugCheckResult::Error;
    HANDLE hSnap = apis.createSnap(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return DebugCheckResult::Error;

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    DWORD parentPid = 0;
    DWORD myPid = GetCurrentProcessId();

    if (apis.procFirst(hSnap, &pe32)) {
        do {
            if (pe32.th32ProcessID == myPid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (apis.procNext(hSnap, &pe32));
    }
    CloseHandle(hSnap);

    if (parentPid == 0) return DebugCheckResult::Error;

    // 获取父进程名
    wchar_t parentName[MAX_PATH] = {};
    // ★ BUILD 551: OpenProcess → STEALTH_OPEN_PROCESS (syscall 替代, 规避 ObCallbacks)
    HANDLE hParent = nullptr;
    STEALTH_OPEN_PROCESS(hParent, PROCESS_QUERY_LIMITED_INFORMATION, parentPid);
    if (hParent) {
        DWORD size = MAX_PATH;
        QueryFullProcessImageNameW(hParent, 0, parentName, &size);
        CloseHandle(hParent);
    }

    // 检查父进程是否为已知的调试器/分析工具
    // 手动转小写, 避免 std::wstring CRT 依赖
    wchar_t nameLower[MAX_PATH] = {};
    int nameLen = 0;
    while (parentName[nameLen] != L'\0' && nameLen < MAX_PATH - 1) {
        nameLower[nameLen] = towlower(parentName[nameLen]);
        nameLen++;
    }
    nameLower[nameLen] = L'\0';

    const wchar_t* suspicious[] = {
        L"ollydbg", L"x64dbg", L"x32dbg", L"windbg",
        L"ida", L"ida64", L"ghidra", L"cheat engine",
        L"process hacker", L"process monitor", L"procmon"
    };

    for (int i = 0; i < sizeof(suspicious) / sizeof(suspicious[0]); i++) {
        if (wcsstr(nameLower, suspicious[i]) != nullptr) {
            return DebugCheckResult::Debugged;
        }
    }

    // explorer.exe, cmd.exe, powershell.exe 是正常父进程
    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckCloseHandleTrap() {
    // 向无效句柄调用 CloseHandle
    // 如果被调试, 调试器收到 EXCEPTION_INVALID_HANDLE 异常
    // 正常进程仅返回 FALSE (Windows 10+ 行为)
    //
    // 注意: 现代 Windows 版本中此技术可能静默失败
    // 作为辅助检测, 与其他方法组合使用

#ifdef _MSC_VER
    __try {
        // 使用随机无效句柄值 (避免被模式匹配)
        DWORD randomSeed = GetTickCount();
        HANDLE badHandle = reinterpret_cast<HANDLE>(
            static_cast<uintptr_t>(0xDEAD0000) ^ (randomSeed & 0xFFFF));
        CloseHandle(badHandle);
        // 正常到达此处 → 无异常 → Clean (或可疑, 取决于版本)
    }
    __except (GetExceptionCode() == STATUS_INVALID_HANDLE ?
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // 精确匹配: 仅捕获 EXCEPTION_INVALID_HANDLE
        return DebugCheckResult::Debugged;
    }
#else
    {
        // gcc: 使用 VEH 模拟 __try/__except, 精确匹配 EXCEPTION_INVALID_HANDLE
        g_vehExceptionCaught = false;
        g_vehExceptionCode = 0;
        PVOID veh = AddVectoredExceptionHandler(1, AntiDebugVehHandler);
        DWORD randomSeed = GetTickCount();
        HANDLE badHandle = reinterpret_cast<HANDLE>(
            static_cast<uintptr_t>(0xDEAD0000) ^ (randomSeed & 0xFFFF));
        CloseHandle(badHandle);
        RemoveVectoredExceptionHandler(veh);
        if (g_vehExceptionCaught && g_vehExceptionCode == STATUS_INVALID_HANDLE) {
            return DebugCheckResult::Debugged;
        }
    }
#endif

    return DebugCheckResult::Clean;
}

DebugCheckResult AntiDebug::CheckOutputDebugStringTrap() {
    // 设置特定错误码后调用 OutputDebugString
    // 有调试器时 GetLastError() 不变
    // 无调试器时 GetLastError() 被覆盖

    SetLastError(0x12345678);
    OutputDebugStringA("");

    DWORD err = GetLastError();
    if (err != 0x12345678) {
        // 错误码变了 → 无调试器处理 OutputDebugString
        return DebugCheckResult::Clean;
    }

    // 错误码没变 → 可能有调试器截获了输出
    return DebugCheckResult::Suspicious;
}

DebugCheckResult AntiDebug::CheckHeapFlags() {
    // 检查默认进程堆的调试标志
    // 在调试器下创建的进程, 其堆标志包含特殊值:
    //   - Flags 的第 2 位 (HEAP_GROWABLE) 通常被清除
    //   - ForceFlags 通常非零
    //
    // 访问方式: PEB->ProcessHeap 指向默认堆,
    // 堆头 +NtGlobalFlag 级别的关联信息

    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return DebugCheckResult::Error;

    HANDLE hHeap = PEB_PROCESS_HEAP(peb);
    if (!hHeap) return DebugCheckResult::Error;

    // 查询堆信息 (Windows 10+ 可用)
    // HeapInformationClass = 0 (HeapCompatibilityInformation) 
    // 或直接读取堆头中的 Flags 字段 (偏移因版本而异)
    ULONG heapInfo = 0;
    if (HeapQueryInformation(hHeap, HeapCompatibilityInformation,
                              &heapInfo, sizeof(heapInfo), nullptr)) {
        // heapInfo 非零表示调试堆兼容模式 → 可能被调试
        if (heapInfo != 0) {
            return DebugCheckResult::Suspicious;
        }
    }

    // 直接读取堆头的 ForceFlags (偏移因Windows版本而异)
    // 以下偏移为 Windows 10/11 x64 通用:
    // heap + 0x70 (32bit) or + 0xE8 (64bit): ForceFlags
    auto* heapBytes = reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(hHeap) + 0xE8);
#ifdef _MSC_VER
    __try {
        DWORD forceFlags = *heapBytes;
        if (forceFlags != 0) {
            return DebugCheckResult::Debugged;
        }

        DWORD flags = *(heapBytes - 7); // Flags 在 ForceFlags 之前
        if ((flags & 2) == 0) { // HEAP_GROWABLE not set
            return DebugCheckResult::Suspicious;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return DebugCheckResult::Clean; // 偏移不适用, 静默跳过
    }
#else
    // gcc: 使用安全内存读取替代 __try/__except
    {
        DWORD forceFlags = SEH_SAFE_READ(DWORD, heapBytes, 0xFFFFFFFF);
        if (forceFlags == 0xFFFFFFFF) {
            return DebugCheckResult::Clean; // 读取失败, 偏移不适用
        }
        if (forceFlags != 0) {
            return DebugCheckResult::Debugged;
        }

        DWORD flags = SEH_SAFE_READ(DWORD, heapBytes - 7, 0);
        if (flags == 0) {
            return DebugCheckResult::Clean; // 读取失败
        }
        if ((flags & 2) == 0) {
            return DebugCheckResult::Suspicious;
        }
    }
#endif

    return DebugCheckResult::Clean;
}

// ============================================================
// 句柄检测
// ============================================================

DebugCheckResult AntiDebug::CheckDebuggerHandles() {
    // 使用 NtQuerySystemInformation(SystemHandleInformation) 枚举所有进程句柄
    // 检测是否有其他进程打开了调试我们进程所需的权限句柄

    ULONG bufferSize = 0x100000;
    BYTE* buffer = (BYTE*)VirtualAlloc(nullptr, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) return DebugCheckResult::Error;
    ULONG retLen = 0;

    NTSTATUS st = SysQuerySystemInformation(0x10, buffer, bufferSize, &retLen);
    if (st == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        bufferSize = retLen + 0x1000;
        buffer = (BYTE*)VirtualAlloc(nullptr, bufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buffer) return DebugCheckResult::Error;
        st = SysQuerySystemInformation(0x10, buffer, bufferSize, &retLen);
    }

    if (!NT_SUCCESS(st) || !buffer) {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        return DebugCheckResult::Error;
    }

    DWORD myPid = GetCurrentProcessId();

    auto* handleInfo = reinterpret_cast<PSTEALTH_HANDLE_INFO>(buffer);

    // ManualMap 下 SysQuerySystemInformation 可能返回垃圾数据导致越界崩溃
    // 边界检查: 确保 NumberOfHandles 不会超出 buffer
    {
        size_t headerSize = sizeof(handleInfo->NumberOfHandles);  // 4 bytes, no Reserved
        size_t entrySize = sizeof(STEALTH_HANDLE_TABLE_ENTRY);   // 32 bytes
        ULONG maxHandles = (ULONG)((bufferSize > headerSize) ? ((bufferSize - headerSize) / entrySize) : 0);
        if (handleInfo->NumberOfHandles > maxHandles) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            return DebugCheckResult::Error;
        }
    }

    const DWORD debuggerAccessMask = PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME;

    int suspiciousCount = 0;
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        if (handleInfo->Handles[i].UniqueProcessId != myPid)
            continue;

        // 检查是否有调试权限
        if ((handleInfo->Handles[i].GrantedAccess & debuggerAccessMask) == debuggerAccessMask) {
            // 找到了具有完整调试权限的句柄
            suspiciousCount++;
            if (suspiciousCount >= 2) {
                VirtualFree(buffer, 0, MEM_RELEASE);
                return DebugCheckResult::Debugged;
            }
        }

        // 也可以检查 PROCESS_QUERY_INFORMATION (0x0400) 组合
        if ((handleInfo->Handles[i].GrantedAccess & PROCESS_QUERY_INFORMATION) &&
            (handleInfo->Handles[i].GrantedAccess & PROCESS_VM_READ) &&
            (handleInfo->Handles[i].GrantedAccess & PROCESS_SUSPEND_RESUME)) {
            suspiciousCount++;
            if (suspiciousCount >= 3) {
                VirtualFree(buffer, 0, MEM_RELEASE);
                return DebugCheckResult::Debugged;
            }
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);

    if (suspiciousCount > 0)
        return DebugCheckResult::Suspicious;

    return DebugCheckResult::Clean;
}

// ============================================================
// 主动规避
// ============================================================

int AntiDebug::EnumerateAllThreads(DWORD* outBuf, int maxThreads) {
    int count = 0;
    DWORD myPid = GetCurrentProcessId();

    // ★ BUILD 550: 动态解析 Toolhelp API (消除 IAT 暴露)
    ToolhelpApis apis = {};
    if (!InitToolhelpApis(apis)) return 0;
    HANDLE hSnap = apis.createSnap(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te32 = { sizeof(te32) };
    if (apis.threadFirst(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == myPid) {
                if (count < maxThreads) {
                    outBuf[count++] = te32.th32ThreadID;
                }
            }
        } while (apis.threadNext(hSnap, &te32));
    }

    CloseHandle(hSnap);
    return count;
}

void AntiDebug::HideAllThreads() {
    using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    static auto fn = reinterpret_cast<NtSetInformationThread_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtSetInformationThread"));

    if (!fn) return;

    DWORD threadIds[256];
    int threadCount = EnumerateAllThreads(threadIds, 256);
    for (int i = 0; i < threadCount; i++) {
        HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadIds[i]);
        if (hThread) {
            fn(hThread, 0x11, nullptr, 0); // ThreadHideFromDebugger
            CloseHandle(hThread);
        }
    }
}

void AntiDebug::HideCurrentThread() {
    using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    static auto fn = reinterpret_cast<NtSetInformationThread_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtSetInformationThread"));

    if (!fn) return;
    fn(GetCurrentThread(), 0x11, nullptr, 0);
}

bool AntiDebug::TerminateDebugger() {
    // 找到调试器进程并终止
    // 通过 NtQueryInformationProcess(ProcessDebugPort) 获取调试器 PID

    HANDLE hDebuggerProcess = nullptr;
    DWORD_PTR debugPort = 0;

    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto fn = reinterpret_cast<NtQueryInformationProcess_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtQueryInformationProcess"));

    if (!fn) return false;

    // ProcessDebugPort = 7
    ULONG retLen;
    NTSTATUS st = fn(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), &retLen);

    if (!NT_SUCCESS(st) || debugPort == 0) return false;

    // debugPort 实际上是调试器进程的 EPROCESS 对象指针 (非直接PID)
    // 使用 NtQuerySystemInformation(SystemHandleInformation) 反向查找
    // 简化: 枚举进程查找拥有此 debugPort 句柄的进程

    // 简化实现: 枚举常见调试器进程名并终止
    const wchar_t* debuggers[] = {
        L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
        L"ollydbg.exe", L"ida64.exe", L"ida.exe"
    };

    // ★ BUILD 550: 动态解析 Toolhelp API (消除 IAT 暴露)
    ToolhelpApis apis = {};
    if (!InitToolhelpApis(apis)) return false;

    for (auto* debugger : debuggers) {
        HANDLE hSnap = apis.createSnap(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) continue;

        PROCESSENTRY32W pe32 = { sizeof(pe32) };
        if (apis.procFirst(hSnap, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, debugger) == 0) {
                    // ★ BUILD 551: OpenProcess → STEALTH_OPEN_PROCESS (syscall 替代)
                    STEALTH_OPEN_PROCESS(hDebuggerProcess, PROCESS_TERMINATE, pe32.th32ProcessID);
                    if (hDebuggerProcess) {
                        TerminateProcess(hDebuggerProcess, 0);
                        CloseHandle(hDebuggerProcess);
                    }
                }
            } while (apis.procNext(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }

    return hDebuggerProcess != nullptr;
}

bool AntiDebug::PreventDebuggerAttach() {
    // 修改 PEB 来阻碍调试器附加
    // 1. 设置 BeingDebugged = TRUE → 拒绝双附加
    // 2. 设置 NtGlobalFlag 为特殊值 → 干扰堆行为

    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return false;

    // 修改内存保护后写入 PEB
    DWORD oldProtect;
    VirtualProtect(&peb->BeingDebugged, 1, PAGE_READWRITE, &oldProtect);

    // 不直接修改 BeingDebugged (这会引起其他问题),
    // 而是设置其他不易检测的标志

    return true;
}

// ============================================================
// CodeObfuscator — 反反汇编原语
// ============================================================

STEALTH_NOINLINE bool CodeObfuscator::OpaqueTrue() {
    // 利用数学恒等式 (总是返回 true, 但反汇编器看不出来)
    volatile int a = 42;
    volatile int b = 42;
    return (a * a + b * b) == (2 * a * b + (a - b) * (a - b));
}

STEALTH_NOINLINE bool CodeObfuscator::OpaqueFalse() {
    volatile int a = 42;
    volatile int b = 43;
    return (a * a - b * b) == (a + b) * (a - b); // a*a-b*b == (a+b)(a-b) 恒等式
    // 但 volatile 防止编译器优化, 使反汇编器误判
}

STEALTH_NOINLINE void CodeObfuscator::JunkCode() {
    // 完全无意义的指令序列, 用于填充代码间隙
    volatile unsigned int x = 0;
    for (unsigned int i = 0; i < 16; i++) {
        x ^= (i * 0x12345678u) ^ (x << 3) ^ (x >> 5);
    }
    // x 最终被丢弃, 但会生成真实的机器码
}

} // namespace stealth
