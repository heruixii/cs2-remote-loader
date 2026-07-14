// ============================================================
// stealth_core.cpp — 规避引擎核心实现 (2026 升级版)
// ============================================================

#include "stealth_core.h"
#include "platform.h"
#include <chrono>
#include <random>

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
    // 第7层: EAC 专用规避 (eac_bypass)
    // ============================================================
    if (m_config.enableEACStackSpoof) {
        // 预生成 32 帧深度调用链 (供所有 syscall 使用)
        eac::DeepStackSpoofer::Instance().GenerateFrameChain();
    }

    if (m_config.enableEACProcessDisguise) {
        // 进程名伪装 (避免 EAC 进程枚举检测)
        eac::ProcessDisguise::DisguiseAsSystemProcess();
    }

    // ============================================================
    // 第8层: EAC VM/内核反调试规避 (eac_vm_evasion)
    // ============================================================
    if (m_config.enableVMGateBypass) {
        // 安装VEH拦截EAC的INT 1/INT 3陷阱 + RDTSC归一化
        eac::VMGateBypass::Instance().InstallExceptionProxy();
    }

    if (m_config.enableNMISpoofing) {
        // 注册VEH链清理回调 (在EAC的VEH之后执行)
        eac::NMICallbackSpoofer::Instance().RegisterCleanupCallback();
    }

    if (m_config.enableVirtualization) {
        eac::CodeVirtualizer::Instance().Initialize();
    }

    // ============================================================
    // 第9层: PE 叠加数据 (改变哈希)
    // ============================================================
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    size_t junkSize = 4096 + (rng() % 12288);
    PeMutator::AddJunkOverlay(junkSize);

    m_initialized = true;
    return true;
}

bool StealthEngine::AttachToProcess(const wchar_t* processName) {
    if (!m_initialized) return false;

    auto processes = StealthProcess::EnumerateProcesses(processName);
    if (processes.empty()) return false;

    auto& target = processes[0];
    m_pid = target.pid;

    // ★ 策略优先级 (按隐蔽性排序):
    //    1. ViaExistingHandle — 借用已有句柄 → 零 ObRegisterCallbacks 触发
    //    2. OpenProcessStealth — 使用 SysOpenProcess 直接调用
    //    3. DuplicateHandleFromLowRisk — 从受信进程复制句柄
    //    4. OpenProcessMinimal — 最小权限回退

    // 策略1: 借用已有句柄 (最隐蔽, 不触发 EAC ObRegisterCallbacks)
    m_hProcess = eac::HandleBypass::ViaExistingHandle(m_pid);
    if (m_hProcess) return true;

    // 策略2: SysOpenProcess 绕过 Win32 API Hook
    if (m_config.minimalProcessHandle) {
        m_hProcess = StealthProcess::OpenProcessStealth(m_pid);
    } else {
        m_hProcess = StealthProcess::DuplicateHandleFromLowRisk(m_pid);
    }

    // 策略3: 最小权限 NtOpenProcess
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

void StealthEngine::OnFrame() {
    if (!m_initialized || !m_hProcess) return;

    // === VAC 扫描周期管理 ===
    if (m_config.enableVACSafety) {
        DWORD now = GetTickCount();
        if (now - m_lastVACCheck > m_vacScanInterval) {
            m_lastVACCheck = now;

            // 快速恢复 .text 段
            IntegrityBypass::RestoreTextSection();
            Sleep(150); // 等待扫描完成
            IntegrityBypass::ReapplyTextPatches();
        }
    }

    // === 验证关键 API 是否被 Hook ===
    if (m_config.detectInHooks || m_config.detectIATHooks) {
        static DWORD lastHookCheck = 0;
        DWORD currentTick = GetTickCount();
        if (currentTick - lastHookCheck > 5000) {
            lastHookCheck = currentTick;

            // 检查 ntdll stub 完整性
            auto& resolver = SyscallResolver::Instance();
            if (resolver.IsStubHooked("NtWriteVirtualMemory") ||
                resolver.IsStubHooked("NtReadVirtualMemory")) {
                // 重新用 Halo's Gate 恢复 SSN
                resolver.InitializeHaloGate();
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
        // === 缺口修复: 睡眠前恢复 ntdll 补丁, 防止 EAC 哈希检测 ===
        // EAC 常在 idle 期间扫描 ntdll .text 段完整性
        TelemetrySilencer::RestoreAll();

        SleepObfuscator::Instance().EkkoSleep(milliseconds);

        // 睡眠后重新 Patch
        TelemetrySilencer::SilenceAll();
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

// ---- EAC 专用 ----

HANDLE StealthEngine::AttachToProcessEAC(DWORD pid) {
    if (m_config.enableEACBypass) {
        return eac::HandleBypass::OpenProcessEAC(pid);
    }
    return StealthProcess::OpenProcessStealth(pid);
}

HANDLE StealthEngine::AttachToProcessEAC(const wchar_t* processName) {
    auto processes = StealthProcess::EnumerateProcesses(processName);
    if (processes.empty()) return nullptr;

    DWORD pid = processes[0].pid;
    m_pid = pid;

    HANDLE hProcess = AttachToProcessEAC(pid);
    if (hProcess) {
        m_hProcess = hProcess;

        // 启动 EAC 扫描预测
        if (m_config.enableEACScanPrediction) {
            eac::EACScanPredictor::Instance().StartMonitoring(pid);
        }
    }

    return hProcess;
}

bool StealthEngine::ExecuteInEACSafeWindow(std::function<void()> op, DWORD timeoutMs) {
    if (!m_config.enableEACTimingWindow) {
        op();
        return true;
    }

    return eac::EACScanPredictor::Instance().ExecuteInSafeWindow(op, timeoutMs);
}

uintptr_t StealthEngine::ManualMapAndStrip(const void* dllData, SIZE_T dllSize) {
    // 1. Manual Map
    auto result = ManualMapper::MapDllFromBuffer(m_hProcess, dllData, dllSize);
    if (!result.success) return 0;

    // 2. 擦除 PE 痕迹（顺序至关重要：MZ擦除必须在最后）
    if (m_config.enableEACPEStrip) {
        eac::PEHeaderStripper::ReplaceFF25Stubs(result.imageBase);       // 1. FF25替换（需MZ/PE签名完好）
        eac::PEHeaderStripper::ClearDosStub(result.imageBase);           // 2. DOS存根清空
        eac::PEHeaderStripper::ScrubSectionNames(result.imageBase);      // 3. 段名随机化
        eac::PEHeaderStripper::StripLoadedHeaders(result.imageBase);     // 4. MZ/PE签名最后擦除
    }

    return result.imageBase;
}

void StealthEngine::DisguiseForEAC() {
    if (m_config.enableEACProcessDisguise) {
        eac::ProcessDisguise::DisguiseAsSystemProcess();
    }
}

DWORD StealthEngine::GetEACSafeTimeMs() {
    if (!m_config.enableEACScanPrediction) return INFINITE;

    DWORD safeMs = eac::EACScanPredictor::Instance().GetSafeWindowMs();
    return safeMs > 0 ? safeMs : 200; // 最小 200ms
}

// ---- EAC VM/内核规避 (eac_vm_evasion) ----

bool StealthEngine::EnableVMGateProtection() {
    return eac::VMGateBypass::Instance().InstallExceptionProxy();
}

bool StealthEngine::EnableNMICleanup() {
    return eac::NMICallbackSpoofer::Instance().RegisterCleanupCallback();
}

bool StealthEngine::HideSelfFromPEB() {
    return eac::InstrumentationCallbackBypass::Instance().UnlinkSelfFromPEB();
}

uintptr_t StealthEngine::PlaceFakePEHeader(void* region, SIZE_T regionSize) {
    if (!region || !regionSize) return 0;
    return eac::FakePEBuilder::PlaceFakeHeader(region, regionSize);
}

bool StealthEngine::ExecuteVirtualized(const void* code, SIZE_T size,
                                        eac::CodeVirtualizer::VMContext& ctx) {
    if (!code || !size) return false;

    // 转换为VM字节码
    auto bytecode = eac::CodeVirtualizer::VirtualizeRegion(code, size);
    if (bytecode.empty()) return false;

    // 在VM中执行
    return eac::CodeVirtualizer::Instance().Execute(
        bytecode.data(), bytecode.size(), ctx);
}

SIZE_T StealthEngine::MutateCodeRegion(void* code, SIZE_T codeSize) {
    if (!code || !codeSize) return 0;
    return eac::PolymorphicCode::MutateCode(code, codeSize);
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
    HMODULE base = GetModuleHandleW(nullptr);
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

    // 3. 卸载 EAC VEH 处理器 (修复 P5: 防止句柄泄漏和VEH链残留)
    eac::VMGateBypass::Instance().UninstallExceptionProxy();
    eac::NMICallbackSpoofer::Instance().UnregisterCleanupCallback();

    // ★ 修复 H4: 停止 EAC 扫描预测, 释放缓存的 System 句柄
    eac::EACScanPredictor::Instance().StopMonitoring();

    // 4. 加密并清理受保护内存
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
