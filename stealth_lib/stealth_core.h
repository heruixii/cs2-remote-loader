#pragma once
// ============================================================
// stealth_core.h — 规避引擎主模块 (2026 升级版)
//
// 集成技术栈:
//   - syscall_direct:    Hell's Gate + Halo's Gate + Indirect Syscall 
//                         + Call Stack Spoofing + Tartarus Gate
//   - string_obfuscator: 编译期 XTEA 加密 + API 动态解析
//   - stealth_process:   隐蔽进程/内存操作
//   - pe_mutator:        PE 自修改 + 完整性绕过
//   - memory_cloak:      Sleep Obfuscation + Module Stomping
//                         + Phantom Sections + ETW/AMSI Patching
//                         + VACNet/VAC Live 行为规避
//   - stealth_injection: Manual Map + Reflective Loader
//                         + Thread Hijacking + APC Injection
//                         + Process Hollowing + StealthThread
//   - anti_debug:        17项反调试检测 + 主动规避
//   - eac_bypass:        EAC Handle Stripping 6策略绕过
//                         + 扫描周期预测 + PE头擦除
//                         + 32帧深栈伪造 + 进程伪装
//   - eac_vm_evasion:    EAC VM门控绕过 + NMI回调欺骗
//                         + Instrumentation回调规避
//                         + 假PE构造 + 代码虚拟化 + 多态代码
// ============================================================

#include "syscall_direct.h"
#include "string_obfuscator.h"
#include "stealth_process.h"
#include "pe_mutator.h"
#include "memory_cloak.h"
#include "stealth_injection.h"
#include "anti_debug.h"
#include "eac_bypass.h"
#include "eac_vm_evasion.h"

namespace stealth {

// ============================================================
// 规避引擎初始化配置 (扩展版)
// ============================================================

struct StealthConfig {
    // === 签名检测规避 ===
    bool stripRichHeader        = true;
    bool randomizeTimestamp     = true;
    bool stripDebugInfo         = true;
    bool obfuscateImports       = true;
    bool enableStringEncrypt    = true;

    // === 行为检测规避 ===
    bool useDirectSyscalls      = true;
    SyscallMethod syscallMethod = SyscallMethod::Auto; // 自动选择最佳方法
    bool enableCallStackSpoof   = true;  // 启用调用栈伪造
    bool enableHaloGate         = true;  // 启用 Halo's Gate SSN 恢复
    bool minimalProcessHandle   = true;
    bool avoidPrivilegeEscalation = true;
    bool useSystemInfoEnum      = true;

    // === 完整性检测规避 ===
    bool enableVACSafety        = true;
    bool backupTextSection      = true;
    bool validateVTablePtrs     = true;

    // === 用户态 Hook 检测规避 ===
    bool verifyExportsFromDisk  = true;
    bool detectInHooks          = true;
    bool detectIATHooks         = true;

    // === 2026 新增 ===
    // 内存隐身
    bool enableSleepObfuscation = true;  // Sleep 期间加密内存
    bool enableModuleStomping   = false; // 覆盖合法模块 (激进)
    bool enablePhantomSections  = true;  // VAD 伪装

    // 遥测禁用
    bool silenceETW             = true;  // 禁用 ETW
    bool silenceAMSI            = true;  // 禁用 AMSI

    // VACNet/VAC Live 对抗
    bool enableAimHumanization  = true;  // 瞄准拟人化
    bool enableAngleValidation  = true;  // 视角变化校验

    // 反调试 (anti_debug)
    bool enableAntiDebug        = true;  // 启用全套反调试
    bool aggressiveAntiDebug    = true;  // 主动规避 (HideAllThreads等)

    // 注入方法 (stealth_injection)
    bool enableManualMap        = false; // 使用 Manual Map 替代 LoadLibrary
    bool enableThreadHijack     = false; // 使用 Thread Hijacking
    bool enableHiddenThreads    = true;  // 使用隐藏线程创建

    // === EAC 专用 (eac_bypass) ===
    bool enableEACBypass        = true;  // 启用 EAC 多路径句柄绕过
    bool enableEACScanPrediction= true;  // 启用 EAC 扫描周期预测
    bool enableEACPEStrip       = true;  // Manual Map 后擦除 PE 头
    bool enableEACStackSpoof    = true;  // 32 帧深度调用栈伪造
    bool enableEACProcessDisguise = true; // 进程名称/父进程伪装
    bool enableEACTimingWindow  = true;  // 仅在 EAC 扫描间歇执行操作

    // === EAC VM/内核反调试规避 (eac_vm_evasion) ===
    bool enableVMGateBypass      = true;  // INT 1/INT 3/RDTSC 门控绕过
    bool enableNMISpoofing       = true;  // NMI 回调链清理
    bool enableInstrCallbackBypass = true; // Instrumentation 回调规避
    bool enableVirtualization    = false; // 代码虚拟化 (开销较大)
    bool enablePolymorphism      = false; // 多态代码生成 (开销较大)
    bool enableFakePEConstruction = true;  // 假PE头构造

    // === 自身内存隐身 (ManualMap 区域防护) ===
    bool enableSelfCloaking       = true;  // PE头擦除 + 假Ldr条目 + 页保护随机化
    const wchar_t* selfCloakDisguiseName = L"dxgi_adapter_cache.dll"; // 伪装模块名
};

// ============================================================
// 规避引擎核心类 (升级版)
// ============================================================

class StealthEngine {
public:
    static StealthEngine& Instance();

    // ---- 初始化 ----
    bool Initialize(const StealthConfig& config = StealthConfig());

    // ---- 目标进程绑定 ----
    bool AttachToProcess(const wchar_t* processName);
    bool AttachToProcessByWindow(const wchar_t* className, const wchar_t* windowName);

    // ---- 每帧调用 ----
    void OnFrame();

    // ---- 安全内存访问 ----
    template<typename T>
    T ReadMemory(uintptr_t address) {
        T value{};
        if (m_hProcess) {
            StealthMemory::Read(m_hProcess, address, &value, sizeof(T));
        }
        return value;
    }

    template<typename T>
    bool WriteMemory(uintptr_t address, const T& value) {
        if (!m_hProcess) return false;
        return StealthMemory::Write(m_hProcess, address, &value, sizeof(T));
    }

    bool ReadBytes(uintptr_t address, void* buffer, SIZE_T size) {
        if (!m_hProcess) return false;
        return StealthMemory::Read(m_hProcess, address, buffer, size);
    }

    bool WriteBytes(uintptr_t address, const void* buffer, SIZE_T size) {
        if (!m_hProcess) return false;
        return StealthMemory::Write(m_hProcess, address, buffer, size);
    }

    // ---- 安全 Sleep (自动加密内存) ----
    void StealthSleep(DWORD milliseconds);

    // ---- 瞄准拟人化 (VACNet 对抗) ----
    void HumanizeAim(float& targetX, float& targetY);
    bool IsAngleChangeSafe(float oldYaw, float oldPitch,
                           float newYaw, float newPitch, float deltaTime);

    // ---- 注册受保护内存区域 ----
    void ProtectMemoryRegion(void* addr, SIZE_T size, bool isCode = false);

    // ---- 反调试 (anti_debug) ----
    DebugDetectionReport CheckForDebugger();
    void HideFromDebugger();
    bool IsBeingAnalyzed();

    // ---- 注入 (stealth_injection) ----
    // 在目标进程中手动映射 DLL (绕过 LoadLibrary 检测)
    uintptr_t ManualMapDll(const wchar_t* dllPath);
    uintptr_t ManualMapDll(const void* dllData, SIZE_T dllSize);

    // 创建隐藏线程执行 payload
    HANDLE CreateStealthThread(LPTHREAD_START_ROUTINE start, PVOID param, bool hidden = true);

    // 注入并隐藏线程到目标进程
    HANDLE InjectAndHideThread(HANDLE hTargetProcess,
                                LPTHREAD_START_ROUTINE start, PVOID param);

    // ---- EAC 专用 (eac_bypass) ----
    // 使用 EAC 多策略句柄获取打开游戏进程
    HANDLE AttachToProcessEAC(DWORD pid);
    HANDLE AttachToProcessEAC(const wchar_t* processName);

    // 在 EAC 扫描安全窗口内执行操作
    bool ExecuteInEACSafeWindow(std::function<void()> op, DWORD timeoutMs = 5000);

    // Manual Map 并剥除 PE 痕迹 (EAC PE 扫描规避)
    uintptr_t ManualMapAndStrip(const void* dllData, SIZE_T dllSize);

    // 伪装当前进程 (EAC 进程枚举规避)
    void DisguiseForEAC();

    // 预测 EAC 扫描周期
    DWORD GetEACSafeTimeMs();

    // ---- EAC VM/内核规避 (eac_vm_evasion) ----
    // 安装 VM 门控绕过 (INT 1/INT 3/RDTSC)
    bool EnableVMGateProtection();
    // 注册 NMI 回调清理
    bool EnableNMICleanup();
    // 从 PEB Ldr 链表隐藏自身
    bool HideSelfFromPEB();
    // 在注入区域放置假 PE 头
    uintptr_t PlaceFakePEHeader(void* region, SIZE_T regionSize);
    // 将关键代码虚拟机化执行
    bool ExecuteVirtualized(const void* code, SIZE_T size,
                             eac::CodeVirtualizer::VMContext& ctx);
    // 生成多态代码替换
    SIZE_T MutateCodeRegion(void* code, SIZE_T codeSize);

    // ---- 状态查询 ----
    HANDLE GetProcessHandle() const { return m_hProcess; }
    DWORD  GetProcessId() const { return m_pid; }
    bool   IsInitialized() const { return m_initialized; }
    bool   IsAttached() const { return m_hProcess != nullptr; }

    // ---- 关闭 ----
    void Shutdown();

private:
    StealthEngine() = default;

    bool DetectHostileEnvironment();
    void CleanSelfTraces();

    HANDLE m_hProcess = nullptr;
    DWORD  m_pid = 0;
    bool   m_initialized = false;
    StealthConfig m_config;

    DWORD m_lastVACCheck = 0;
    DWORD m_vacScanInterval = 30000;

    VACNetEvasion::AimProfile m_aimProfile;
};

// ---- 便捷宏 ----
#define STEALTH_READ(addr, type) \
    stealth::StealthEngine::Instance().ReadMemory<type>(addr)
#define STEALTH_WRITE(addr, value) \
    stealth::StealthEngine::Instance().WriteMemory(addr, value)
#define STEALTH_SLEEP(ms) \
    stealth::StealthEngine::Instance().StealthSleep(ms)
#define S_STR(str) STEALTH_STR(str)

} // namespace stealth
