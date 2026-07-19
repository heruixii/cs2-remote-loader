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
// ============================================================

#include "syscall_direct.h"
#include "string_obfuscator.h"
#include "module_resolver.h"   // ★ BUILD 550: PEB Ldr 遍历 + 编译期模块名哈希 (替代 GetModuleHandleA/W)
#include "stealth_process.h"
#include "pe_mutator.h"
#include "memory_cloak.h"
#include "stealth_injection.h"
#include "anti_debug.h"


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
    // v3.26: enableVACSafety 默认 false — InstallVACSafetyHook 仅备份
    //   payload 自身 .text (无实际补丁需要保护), 且 VAC 扫描目标是
    //   cs2.exe/engine.dll/ntdll.dll 而非 payload 本身.
    //   真正的 VAC 保护由 StealthSleep 的 ETW/AMSI toggle + EkkoSleep
    //   加密 + VerifyAndRepairAll 自愈 (每5s) 提供.
    bool enableVACSafety        = false;
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
    bool enableAntiDebug        = true;
    bool aggressiveAntiDebug    = false;

    // 注入方法 (stealth_injection)
    bool enableManualMap        = false; // 使用 Manual Map 替代 LoadLibrary
    bool enableThreadHijack     = false; // 使用 Thread Hijacking
    bool enableHiddenThreads    = true;  // 使用隐藏线程创建

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

    // ---- 自我隐藏 (PE擦除 + 假Ldr + 断链 + 页保护随机化) ----
    void SelfCloak();

    // ---- 状态查询 ----
    HANDLE GetProcessHandle() const { return m_hProcess; }
    DWORD  GetProcessId() const { return m_pid; }
    bool   IsInitialized() const { return m_initialized; }
    bool   IsAttached() const { return m_hProcess != nullptr; }

    // ★ BUILD 528: E+G — 周期性句柄重随机化
    //   关闭现有 CS2 句柄并重新打开 (通过 syscall NtOpenProcess),
    //   缩短句柄可见窗口, 对抗 NtQuerySystemInformation 句柄枚举扫描.
    //   返回 true 表示重开成功 (m_hProcess 已更新为新句柄).
    bool ReopenProcessHandle();

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
