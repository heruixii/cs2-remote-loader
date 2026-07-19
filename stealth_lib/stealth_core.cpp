// ============================================================
// stealth_core.cpp — 规避引擎核心实现 (2026 升级版)
// ============================================================

#include "stealth_core.h"
#include "platform.h"
#include <cstdio>
#include <cstdarg>
// ★ BUILD 498: 移除 <chrono> <random> — CRT 堆依赖

// ★ v3.37: 本地诊断日志 (写 %TEMP%\sd.log)
//   ★ BUILD 549: 文件名 stealth_diag.log → sd.log (移除 "stealth" 特征)
//   ★ BUILD 550: 与 payload.cpp 统一使用 sd.log
//   ★ BUILD 552: CoreDiag 条件编译消除 (与 ProcDiag/ByovdDiag/DiagLog 同策略)
//     原因: 13 处 CoreDiag 调用包含 "AttachToProcess:"/"OpenProcessStealth"/
//           "ReopenProcessHandle:"/"FindWindowW" 等明文格式字符串, 在 .rdata 中暴露
//           "OpenProcessStealth" 是字符串扫描残留 0x4BF09 的根因
//     策略: NDEBUG 时宏化为 ((void)0), 字符串不进入 .rdata
//   ★ BUILD 567 v3.227: 时间戳前缀 + 10MB 日志轮转 (与 payload.cpp DiagLog 同步)
//     注: 辅助函数在 NDEBUG 时也会被宏消除 (随 CoreDiag 一起)
#ifdef NDEBUG
    #define CoreDiag(fmt, ...) ((void)0)
#else
// ★ BUILD 567 v3.227: 时间戳格式化 (与 payload.cpp DiagLog_FormatTimestamp 同实现)
static void CoreDiag_FormatTimestamp(char* buf, size_t bufSize) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, bufSize, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// ★ BUILD 567 v3.227: 日志轮转 (调用前文件句柄必须已关闭)
static void CoreDiag_RotateIfNeeded(const wchar_t* path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return;
    ULARGE_INTEGER fileSize;
    fileSize.LowPart  = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    if (fileSize.QuadPart < (10ULL * 1024 * 1024)) return;
    wchar_t path1[MAX_PATH], path2[MAX_PATH];
    wcscpy_s(path1, MAX_PATH, path);  wcscat_s(path1, MAX_PATH, L".1");
    wcscpy_s(path2, MAX_PATH, path);  wcscat_s(path2, MAX_PATH, L".2");
    MoveFileExW(path1, path2, MOVEFILE_REPLACE_EXISTING);
    MoveFileExW(path, path1, MOVEFILE_REPLACE_EXISTING);
}

static void CoreDiag(const char* fmt, ...) {
    char tsBuf[32];
    CoreDiag_FormatTimestamp(tsBuf, sizeof(tsBuf));
    int tsLen = (int)strlen(tsBuf);

    char buf[320];  // ★ BUILD 567: 256 → 320 (容纳时间戳)
    memcpy(buf, tsBuf, tsLen);
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf + tsLen, sizeof(buf) - tsLen, fmt, args);
    va_end(args);
    if (len < 0) return;
    // ★ BUILD 567 BUG 修复 (第 1 轮审查): vsnprintf 返回期望长度, 可能 > 缓冲区剩余空间
    //   未限制会导致 WriteFile 越界读取 buf 后面的内存
    if (len > (int)(sizeof(buf) - tsLen - 1)) len = (int)(sizeof(buf) - tsLen - 1);
    len += tsLen;

    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"sd.log");  // ★ BUILD 550: 文件名脱敏 (原 stealth_diag.log)
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);  // ★ v3.38: 强制落盘
        CloseHandle(h);
    }
    // ★ BUILD 567 v3.227: 日志轮转检查
    CoreDiag_RotateIfNeeded(path);
}
#endif  // NDEBUG

namespace stealth {

StealthEngine& StealthEngine::Instance() {
    static StealthEngine instance;
    return instance;
}

bool StealthEngine::Initialize(const StealthConfig& config) {
    m_config = config;

    // ============================================================
    // 第1层: 系统调用解析器 (Hell's Gate)
    // ============================================================
    if (m_config.useDirectSyscalls) {
        SyscallResolver::Instance().Initialize();

        // Halo's Gate: 检查 ntdll 是否被 Hook
        if (m_config.enableHaloGate) {
            SyscallResolver::Instance().InitializeHaloGate();
        }
    }

    // Call Stack Spoofing: 预扫描 kernel32 Fat Frames
    if (m_config.enableCallStackSpoof) {
        CallStackSpoofer::Instance().Initialize();
    }

    // ============================================================
    // 第2层: PE 自修改 (签名检测规避)
    // ============================================================
    if (m_config.stripRichHeader) {
        PeMutator::StripRichHeader();
    }
    if (m_config.randomizeTimestamp) {
        PeMutator::RandomizeTimestamp();
    }
    if (m_config.stripDebugInfo) {
        PeMutator::StripDebugInfo();
    }

    // ============================================================
    // 第3层: 完整性保护
    // ============================================================
    if (m_config.backupTextSection) {
        IntegrityBypass::BackupTextSection();
    }
    if (m_config.enableVACSafety) {
        IntegrityBypass::InstallVACSafetyHook();
    }

    // ============================================================
    // 第4层: ETW / AMSI 静默 (2026 新增)
    // ============================================================
    if (m_config.silenceETW) {
        TelemetrySilencer::DisableETW();
    }
    if (m_config.silenceAMSI) {
        TelemetrySilencer::DisableAMSI();
    }

    // ============================================================
    // 第5层: VACNet 对抗配置 (2026 新增)
    // ============================================================
    if (m_config.enableAimHumanization) {
        m_aimProfile = VACNetEvasion::GenerateHumanProfile();
    }

    // ============================================================
    // 第6层: 反调试检测 (anti_debug)
    // ============================================================
    if (m_config.enableAntiDebug) {
        DebugDetectionReport report = AntiDebug::Instance().FullCheck(
            m_config.aggressiveAntiDebug);
        if (report.isBeingDebugged) {
            // 被调试! 可以选择:
            // 1. 静默退出 (安全)
            // 2. 终止调试器 (激进)
            // 3. 继续但降低风险行为
            //
            // 当前策略: 仅在 aggressive 模式下隐藏线程, 不终止调试器
        }
    }

    // ============================================================
    // 第7层: PE 叠加数据 (改变哈希)
    // ============================================================
    // ★ BUILD 498: 自实现 LCG 替代 std::mt19937 + std::chrono
    {
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        ULONG rngSeed = (ULONG)(counter.LowPart ^ counter.HighPart);
        rngSeed = rngSeed * 1664525u + 1013904223u;
        size_t junkSize = 4096 + (rngSeed % 12288);
        PeMutator::AddJunkOverlay(junkSize);
    }

    m_initialized = true;
    return true;
}

bool StealthEngine::AttachToProcess(const wchar_t* processName) {
    if (!m_initialized) return false;

    CoreDiag("AttachToProcess: Enumerating '%ls'...\n", processName);
    // ★ BUILD 498: 固定数组替代 std::vector
    StealthProcess::ProcessInfo processes[32];
    int procCount = StealthProcess::EnumerateProcesses(processName, processes, 32);
    if (procCount == 0) {
        CoreDiag("AttachToProcess: process not found via enumeration\n");

        // ★ v3.112: 回退 — 通过 FindWindowW 查找 CS2 主窗口
        //   当 syscall 方式枚举进程失败时, 用 Win32 API 直接找窗口
        CoreDiag("AttachToProcess: trying FindWindowW fallback...\n");
        DWORD pidByWindow = 0;
        // ★ BUILD 550: 加密窗口类名和标题 (原 L"Valve001", L"Counter-Strike 2")
        //   STEALTH_STR_DECRYPT_TO 在栈上解密, 用完即毁, 二进制中不留明文
        //   注意: outBuf 必须是 char 数组 (左值), 不能用 (char*)wchar_t 数组
        wchar_t wClsNameW[32] = {};
        {
            char encBuf[32] = {};
            STEALTH_STR_DECRYPT_TO("Valve001", encBuf, sizeof(encBuf));
            for (int i = 0; i < 32 && encBuf[i]; i++) wClsNameW[i] = (wchar_t)(unsigned char)encBuf[i];
            StringObfuscator::SecureZero(encBuf, sizeof(encBuf));
        }
        wchar_t wTitleW[64] = {};
        {
            char encBuf[64] = {};
            STEALTH_STR_DECRYPT_TO("Counter-Strike 2", encBuf, sizeof(encBuf));
            for (int i = 0; i < 64 && encBuf[i]; i++) wTitleW[i] = (wchar_t)(unsigned char)encBuf[i];
            StringObfuscator::SecureZero(encBuf, sizeof(encBuf));
        }

        pidByWindow = StealthProcess::FindProcessByWindow(wClsNameW, wTitleW);
        if (pidByWindow == 0) {
            // 再试一次只匹配窗口标题 (不限制类名)
            pidByWindow = StealthProcess::FindProcessByWindow(nullptr, wTitleW);
        }
        // ★ BUILD 550: 清零栈上的解密字符串
        StringObfuscator::SecureZero(wClsNameW, sizeof(wClsNameW));
        StringObfuscator::SecureZero(wTitleW, sizeof(wTitleW));
        if (pidByWindow == 0) {
            CoreDiag("AttachToProcess: FindWindowW fallback FAILED\n");
            return false;
        }

        CoreDiag("AttachToProcess: FindWindowW found PID=%u\n", pidByWindow);
        m_pid = pidByWindow;

        // 直接尝试打开进程
        m_hProcess = StealthProcess::OpenProcessStealth(m_pid);
        if (m_hProcess) return true;
        m_hProcess = StealthProcess::OpenProcessMinimal(m_pid);
        return m_hProcess != nullptr;
    }

    auto& target = processes[0];
    m_pid = target.pid;
    CoreDiag("AttachToProcess: found PID=%u, calling ViaExistingHandle...\n", m_pid);

    // Strategy 1: OpenProcessStealth
    m_hProcess = StealthProcess::OpenProcessStealth(m_pid);
    CoreDiag("AttachToProcess: OpenProcessStealth returned %p\n", m_hProcess);
    if (m_hProcess) return true;

    // Strategy 2: OpenProcessStealth → SysOpenProcess (GetProcAddress NtOpenProcess 走ntdll原生, 不触发ObCallbacks)
    if (m_config.minimalProcessHandle) {
        m_hProcess = StealthProcess::OpenProcessStealth(m_pid);
    } else {
        m_hProcess = StealthProcess::DuplicateHandleFromLowRisk(m_pid);
    }

    // Strategy 3: OpenProcessMinimal
    if (!m_hProcess) {
        m_hProcess = StealthProcess::OpenProcessMinimal(m_pid);
    }

    return m_hProcess != nullptr;
}

bool StealthEngine::AttachToProcessByWindow(
    const wchar_t* className, const wchar_t* windowName) {
    m_pid = StealthProcess::FindProcessByWindow(className, windowName);
    if (m_pid == 0) return false;

    m_hProcess = StealthProcess::OpenProcessStealth(m_pid);
    return m_hProcess != nullptr;
}

// ★ BUILD 528: E+G — 周期性句柄重随机化
//   关闭现有 CS2 句柄并重新打开 (syscall NtOpenProcess),
//   缩短句柄可见窗口, 对抗 NtQuerySystemInformation(SystemHandleInformation) 枚举.
//   实现要点:
//   1. 先开新句柄, 成功后再关旧句柄 — 避免新句柄打开失败时无句柄可用
//   2. 使用 OpenProcessStealth (syscall) 而非 kernel32!OpenProcess, 不触发 ObCallbacks
//   3. 使用 SysClose (syscall NtClose) 关闭旧句柄, 不走 ntdll 用户态路径
//   4. 不使用 std::vector/std::string — manual-mapped DLL 上下文 CRT 堆未初始化
bool StealthEngine::ReopenProcessHandle() {
    if (m_pid == 0) {
        CoreDiag("ReopenProcessHandle: m_pid=0, not attached\n");
        return false;
    }

    // 先打开新句柄 (不立即替换 m_hProcess, 避免打开失败时丢失原句柄)
    HANDLE newHandle = StealthProcess::OpenProcessStealth(m_pid);
    if (!newHandle) {
        // 回退: OpenProcessMinimal (kernel32, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
        newHandle = StealthProcess::OpenProcessMinimal(m_pid);
    }
    if (!newHandle) {
        CoreDiag("ReopenProcessHandle: FAILED to open new handle (pid=%u)\n", m_pid);
        return false; // 保留旧句柄, 不替换
    }

    // 新句柄打开成功, 关闭旧句柄
    HANDLE oldHandle = m_hProcess;
    m_hProcess = newHandle;
    if (oldHandle) {
        SysClose(oldHandle);
    }

    CoreDiag("ReopenProcessHandle: OK (pid=%u old=%p new=%p)\n",
        m_pid, oldHandle, newHandle);
    return true;
}

void StealthEngine::OnFrame() {
    if (!m_initialized || !m_hProcess) return;

    // === VAC 完整性检查对抗 ===
    // v3.25: 移除了针对自身 .text 段的 Restore→Reapply 空循环
    //   原因: IntegrityBypass 操作的是 payload 自身 .text 段, 而 VAC 扫描
    //   cs2.exe/engine.dll/ntdll.dll. 且 patchedBytes==originalBytes 导致
    //   ReapplyTextPatches 是 nop, 循环无实际作用.
    //   实际的 ntdll ETW/AMSI 补丁保护由 StealthSleep 中的
    //   TelemetrySilencer::RestoreAll/SilenceAll 每500ms自动切换完成,
    //   以及 verifyHook 检测中的 VerifyAndRepairAll (每5s) 兜底.
    if (m_config.enableVACSafety) {
        // 不再执行 payload .text Restore→Reapply 无用循环
        // VAC 保护依赖 StealthSleep ETW toggle + ntdll stub 完整性检测
    }
    // ※ 不要直接删除这个分支 — 保留 enableVACSafety 配置项兼容性

    // === 验证关键 API 是否被 Hook ===
    if (m_config.detectInHooks || m_config.detectIATHooks) {
        static DWORD lastHookCheck = 0;
        DWORD currentTick = GetTickCount();
        if (currentTick - lastHookCheck > 5000) {
            lastHookCheck = currentTick;

            // 检查 ntdll stub 完整性
            // ★ BUILD 551: IsStubHooked 改为接受 BYTE* (用 STEALTH_GET_PROC_ADDRESS_NOREF 加密解析)
            auto& resolver = SyscallResolver::Instance();
            HMODULE ntdllHdl = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
            if (ntdllHdl) {
                if (resolver.IsStubHooked(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(ntdllHdl, "NtWriteVirtualMemory"))) ||
                    resolver.IsStubHooked(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(ntdllHdl, "NtReadVirtualMemory")))) {
                    // 重新用 Halo's Gate 恢复 SSN
                    resolver.InitializeHaloGate();
                }
            }

            // ★ 修复 P8: 检查 ETW/AMSI 补丁是否被EAC恢复, 是则自动重新Patch
            if (m_config.silenceETW) {
                TelemetrySilencer::VerifyAndRepairAll();
            }
        }
    }

    // === NMI 心跳: 周期性执行合法堆栈上下文刷新 ===
    // EAC 内核驱动通过 KeRegisterNmiCallback 发送 NMI 采样当前 RIP/RSP
    // 通过 CallStackSpoofer 执行无害 syscall, 将堆栈锚定到 ntdll gadget
    // 降低 NMI 命中时我们在手动映射代码中的概率
    {
        static DWORD lastNmiHeartbeat = 0;
        DWORD now = GetTickCount();
        if (now - lastNmiHeartbeat > 8000) { // 每8秒一次
            lastNmiHeartbeat = now;
            // SysClose 在无效句柄上安全失败, 但触发完整 CallStackSpoofer 路径
            // NtClose 内核处理极快, 堆栈回溯指向 ntdll gadget → 规避 NMI 采样
            SysClose(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1)),
                     SyscallMethod::Indirect);
        }
    }

    // === 虚表指针验证 ===
    if (m_config.validateVTablePtrs) {
        // 每帧可选: 验证关键接口的 VTable
    }
}

void StealthEngine::StealthSleep(DWORD milliseconds) {
    if (m_config.enableSleepObfuscation) {
        // ETW/AMSI 恢复/重补频率降低到每500ms一次, 避免每帧高频VirtualProtect
        static DWORD lastCloakToggle = 0;
        DWORD now = GetTickCount();
        bool shouldToggleETW = (now - lastCloakToggle >= 500);

        if (shouldToggleETW) {
            TelemetrySilencer::RestoreAll();
            lastCloakToggle = now;
        }

        // ★ v3.124: 仅使用 EkkoSleep (方法0)
        //   移除方法1-4 (NtDelayExecution/分片Sleep/SleepEx/WaitableTimer)，
        //   因为这些方法直接调用 EncryptAll()/DecryptAll()，
        //   而 StealthSleep 函数本身的代码页也在加密范围内，
        //   导致 EncryptAll() 返回后执行已加密的代码 → 崩溃。
        //   只有 EkkoSleep 内部通过 GetSelfPage() 豁免了自身代码页，是安全的。
        //   反检测方面: 仅使用 WaitableTimer 模式, 但 byovd 已移除 EAC 内核回调,
        //   无需担心 EAC 时序特征检测。
        SleepObfuscator::Instance().EkkoSleep(milliseconds);

        if (shouldToggleETW) {
            TelemetrySilencer::SilenceAll();
        }
    } else {
        Sleep(milliseconds);
    }
}

void StealthEngine::HumanizeAim(float& targetX, float& targetY) {
    if (m_config.enableAimHumanization) {
        VACNetEvasion::HumanizeAim(targetX, targetY, m_aimProfile);
    }
}

bool StealthEngine::IsAngleChangeSafe(float oldYaw, float oldPitch,
                                       float newYaw, float newPitch,
                                       float deltaTime) {
    if (m_config.enableAngleValidation) {
        return VACNetEvasion::IsAngleChangeSafe(
            oldYaw, oldPitch, newYaw, newPitch, deltaTime);
    }
    return true; // 不检查, 全部放行
}

void StealthEngine::ProtectMemoryRegion(void* addr, SIZE_T size, bool isCode) {
    if (isCode) {
        SleepObfuscator::Instance().RegisterProtectedCode(addr, size);
    } else {
        SleepObfuscator::Instance().RegisterProtectedRegion(addr, size);
    }
}

// ---- 反调试 ----

DebugDetectionReport StealthEngine::CheckForDebugger() {
    return AntiDebug::Instance().FullCheck(m_config.aggressiveAntiDebug);
}

void StealthEngine::HideFromDebugger() {
    AntiDebug::Instance().HideAllThreads();
}

bool StealthEngine::IsBeingAnalyzed() {
    auto report = AntiDebug::Instance().FullCheck(false);
    return report.isBeingDebugged;
}

// ---- 注入 ----

uintptr_t StealthEngine::ManualMapDll(const wchar_t* dllPath) {
    if (!m_hProcess) return 0;

    auto result = ManualMapper::MapDllFromFile(m_hProcess, dllPath);
    return result.success ? result.imageBase : 0;
}

uintptr_t StealthEngine::ManualMapDll(const void* dllData, SIZE_T dllSize) {
    if (!m_hProcess) return 0;

    auto result = ManualMapper::MapDllFromBuffer(m_hProcess, dllData, dllSize);
    return result.success ? result.imageBase : 0;
}

HANDLE StealthEngine::CreateStealthThread(
    LPTHREAD_START_ROUTINE start, PVOID param, bool hidden) {

    if (hidden && m_config.enableHiddenThreads) {
        return StealthThread::CreateHiddenThreadSelf(start, param);
    }

    return CreateThread(nullptr, 0, start, param, 0, nullptr);
}

HANDLE StealthEngine::InjectAndHideThread(
    HANDLE hTargetProcess, LPTHREAD_START_ROUTINE start, PVOID param) {

    if (!hTargetProcess || !m_config.enableHiddenThreads) {
        return CreateRemoteThread(hTargetProcess, nullptr, 0, start, param, 0, nullptr);
    }

    return StealthThread::CreateHiddenThread(hTargetProcess, start, param);
}

bool StealthEngine::DetectHostileEnvironment() {
    // 检查调试器
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (peb && peb->BeingDebugged) {
        return true;
    }

    return false;
}

void StealthEngine::CleanSelfTraces() {
    // 清除痕迹
}

void StealthEngine::SelfCloak() {
    if (!m_config.enableSelfCloaking) return;

    // 获取当前模块基址和大小
    // ★ BUILD 550: 从 PEB+0x10 (ImageBaseAddress) 读取 (替代 GetModuleHandleW(nullptr))
    //   规避 PAC 用户态 hook 对 GetModuleHandleW 的拦截
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return;
    HMODULE base = *reinterpret_cast<HMODULE*>(reinterpret_cast<BYTE*>(peb) + 0x10);
    if (!base) return;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(base, &mbi, sizeof(mbi))) return;

    // 从PE头读取 SizeOfImage
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    SIZE_T dllSize = nt->OptionalHeader.SizeOfImage;

    // 执行自隐藏: PE头擦除 + 假Ldr条目 + 页保护随机化
    SelfCloaker::CloakManualMap(base, dllSize);
}

void StealthEngine::Shutdown() {
    // 1. 恢复 .text 段
    if (m_config.backupTextSection) {
        IntegrityBypass::RestoreTextSection();
    }

    // 2. 恢复 ETW/AMSI
    TelemetrySilencer::RestoreAll();

    // 3. 加密并清理受保护内存
    SleepObfuscator::Instance().EncryptAll();

    // 5. 关闭句柄
    if (m_hProcess) {
        SysClose(m_hProcess);
        m_hProcess = nullptr;
    }

    m_initialized = false;
    m_pid = 0;
}

} // namespace stealth
