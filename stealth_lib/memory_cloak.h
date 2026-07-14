#pragma once
// ============================================================
// memory_cloak.h — 内存隐身模块 (2026版)
//
// 新技术:
//   1. Sleep Obfuscation (Ekko/Foliage) — Sleep 期间加密 payload
//   2. Module Stomping — 注入代码到合法模块地址空间
//   3. Phantom Sections — VAD伪装, 使分配的内存看似系统内存
//   4. ETW/AMSI Patching — 禁用 Windows 遥测
// ============================================================

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <functional>
#include <string>

namespace stealth {

// ============================================================
// Sleep Obfuscation — 休眠期内存加密
//
// 问题: VAC/EDR 会在 Sleep() 期间扫描进程内存,
//       加密的 payload 也会在内存中暴露特征
// 方案: 在 Sleep 前加密关键内存, Sleep 后解密
//       使用异步定时器 (Timer Queue) 而非 Sleep, 
//       使加密/解密不可被中断
// ============================================================

class SleepObfuscator {
public:
    static SleepObfuscator& Instance();

    // 注册需要保护的内存区域
    void RegisterProtectedRegion(void* addr, SIZE_T size);

    // 注册需要保护的可执行内存 (用于代码段)
    void RegisterProtectedCode(void* addr, SIZE_T size);

    // 替代 Sleep — 自动加密/解密
    // 规避: Sleep 期间的内存扫描
    void ObfuscatedSleep(DWORD milliseconds);

    // Ekko 风格: 使用 CreateTimerQueueTimer 实现 sleep obfuscation
    // 原理: 在计时器回调中加密内存, 然后真正睡眠极短时间,
    //       唤醒后解密, 如此循环
    void EkkoSleep(DWORD milliseconds);

    // Foliage 风格: 使用 APC (Asynchronous Procedure Call) 
    // 替代 Sleep, 完全避免 Sleep 调用
    void FoliageSleep(DWORD milliseconds);

    // 手动加密所有受保护区域
    void EncryptAll();
    void DecryptAll();

private:
    SleepObfuscator() = default;

    // RC4 流加密 (快速, 适合频繁加解密)
    static void RC4Crypt(void* data, SIZE_T size, const BYTE* key, SIZE_T keyLen);

    // XOR 轮转加密 (极快, 适合小区域)
    static void XorCrypt(void* data, SIZE_T size, BYTE key);

    struct ProtectedRegion {
        void*    addr;
        SIZE_T   size;
        BYTE     xorKey;     // 随机生成的 XOR 密钥
        bool     isCode;     // true: 代码段 (需要刷新 I-Cache)
    };

    std::vector<ProtectedRegion> m_regions;
    BYTE m_masterKey[16] = {}; // RC4 主密钥
    bool m_initialized = false;
};

// ============================================================
// Module Stomping — 覆盖合法模块的内存
//
// 原理: 不分配新的可执行内存, 而是找一个已加载的合法 DLL,
//       将其不重要的代码段覆盖为我们的 payload,
//       然后从该模块地址执行
//
// 优势: 内存扫描时, 我们的代码看起来属于合法 DLL
//       模块枚举时, 我们的 payload 不会出现
//       VAD 树中的条目指向合法模块, 不是可疑的 RWX 区域
// ============================================================

class ModuleStomper {
public:
    // 在目标进程中找到一个合适的"牺牲模块"
    // 要求: 不太可能被反作弊监控的 DLL (如特定游戏 DLL 的无用区域)
    struct StompCandidate {
        HMODULE  module;
        uintptr_t baseAddress;
        SIZE_T   moduleSize;
        uintptr_t targetAddress;  // 可覆盖的地址
        SIZE_T   availableSize;   // 可覆盖的大小
        std::wstring moduleName;
    };

    // 在当前进程中查找 stomp 候选
    static StompCandidate FindCandidateInSelf(SIZE_T requiredSize);

    // 在目标进程中查找 stomp 候选
    static StompCandidate FindCandidateInProcess(HANDLE hProcess, SIZE_T requiredSize);

    // 执行 stomp: 备份原始代码, 写入 payload, 修改保护
    static bool StompInto(StompCandidate& candidate,
                          const void* payload, SIZE_T payloadSize);

    // 恢复原始代码
    static bool RestoreStomped(const StompCandidate& candidate,
                               const std::vector<BYTE>& backup);

    // 检查一个内存地址是否属于合法模块
    static bool IsInLegitimateModule(uintptr_t addr);

private:
    ModuleStomper() = default;

    // 通过分析区段找可覆盖的空隙
    static SIZE_T FindWritableGap(HMODULE mod, SIZE_T minSize);
};

// ============================================================
// Phantom Sections — VAD 伪装
//
// 原理: 将我们分配的可执行内存伪装成合法系统分配
//       修改 VAD (Virtual Address Descriptor) 使其看起来
//       像 ntdll 或 kernel32 的正常映射
// ============================================================

class PhantomSection {
public:
    // 分配一块"幽灵"内存: 执行时是我们的代码,
    // 但扫描时指向干净页面
    static void* AllocatePhantom(SIZE_T size);

    // 使用 NtCreateSection + SEC_IMAGE 创建映射 (模仿 DLL 加载)
    // 使我们的内存看起来像是从磁盘加载的 DLL
    static void* AllocateAsImageSection(SIZE_T size, const wchar_t* disguiseName);

    // 在目标进程中分配幽灵内存
    static uintptr_t AllocatePhantomInProcess(HANDLE hProcess, SIZE_T size);

private:
    PhantomSection() = default;
};

// ============================================================
// ETW / AMSI Patching — 禁用遥测
//
// 2026 最新技术:
//   ETW (Event Tracing for Windows) 在 Windows 11 24H2 中增强
//   AMSI (Antimalware Scan Interface) 被反作弊用来扫描脚本/内存
//   通过 Patch EtwEventWrite 和 AmsiScanBuffer 禁用
// ============================================================

class TelemetrySilencer {
public:
    // 禁用 ETW — 阻止系统记录安全事件
    // 方法: Patch ntdll!EtwEventWrite 使其直接返回
    static bool DisableETW();

    // 禁用 AMSI — 阻止内存扫描
    // 方法: Patch AmsiScanBuffer 使其返回 AMSI_RESULT_CLEAN
    static bool DisableAMSI();

    // 恢复 ETW
    static bool RestoreETW();

    // 恢复 AMSI
    static bool RestoreAMSI();

    // 一次性全部禁用
    static bool SilenceAll();

    // 一次性全部恢复
    static bool RestoreAll();

    // 检查 ETW 是否已被 Patch
    static bool IsETWPatched();

    // 检查 AMSI 是否已被 Patch (修复 P8)
    static bool IsAMSIPatched();

    // ★ 修复 P8: 完整性验证 — EAC定期检查EtwEventWrite/AmsiScanBuffer完整性
    // 如果检测到Patch被恢复(EAC回写了原始字节), 自动重新Patch
    // 返回: true = Patch仍有效, false = 已恢复 (已自动重新Patch)
    static bool VerifyAndRepairAll();

private:
    TelemetrySilencer() = default;

    struct PatchRecord {
        void*    addr;
        SIZE_T   size;
        std::vector<BYTE> originalBytes;
    };

    static PatchRecord s_etwPatch;
    static PatchRecord s_amsiPatch;
};

// ============================================================
// VACNet/VAC Live 行为规避
//
// CS2 新增的反作弊层:
//   - VAC Live: 实时行为分析, 可以短时间内取消比赛
//   - VACNet:   AI 驱动的瞄准模式分析
//   - Trust Factor: 隐藏信用分
// ============================================================

class VACNetEvasion {
public:
    // ---- 瞄准拟人化 ----
    // 添加人类特征到瞄准移动中:
    //   - 微小的过冲/欠冲 (overshoot / undershoot)
    //   - 非线性的加速度曲线
    //   - 随机延迟 (100-300ms 反应时间)
    //   - 周期性失准 (模拟疲劳)

    struct AimProfile {
        float overshootAmount;      // 过冲比例 (0.0 - 0.15)
        float undershootAmount;     // 欠冲比例 (0.0 - 0.1)
        float smoothingFactor;      // 平滑因子 (0.3 - 0.7)
        float reactionTimeMs;       // 反应时间 (120 - 300ms)
        float fatigueInterval;      // 疲劳间隔 (秒)
        float fatigueDuration;      // 疲劳持续时间 (秒)
        float missChance;           // 失准概率 (0.01 - 0.05)
    };

    static AimProfile GenerateHumanProfile();

    // 对目标位置进行拟人化处理
    static void HumanizeAim(float& targetX, float& targetY,
                            const AimProfile& profile);

    // ---- 行为模式随机化 ----
    // VACNet 检测重复的行为模式
    // 通过添加随机噪声避免形成可识别的特征

    // 随机化查点路径
    static void RandomizePreAim(float& crosshairX, float& crosshairY,
                                float mapWidth, float mapHeight);

    // 随机化射击节奏
    static DWORD RandomizeFireInterval(float baseIntervalMs);

    // ---- 反 VAC Live 瞬移检测 ----
    // VAC Live 检测不自然的视角突变
    static bool IsAngleChangeSafe(float oldYaw, float oldPitch,
                                   float newYaw, float newPitch,
                                   float deltaTime);

private:
    VACNetEvasion() = default;
};

// ============================================================
// SelfCloaker — 自身手动映射内存隐身
//
// 问题: ManualMap 后的 DLL 位于 VirtualAlloc 分配的内存中,
//       PE 头可见、无 PEB Ldr 条目、Rx 保护明显,
//       EAC 内核驱动可以轻松对此区域做内存特征扫描
// 方案: 擦除 PE 头 → 插入假 Ldr 条目 → 页保护随机化
// ============================================================

class SelfCloaker {
public:
    struct CloakResult {
        bool peStripped;
        bool ldrCloaked;
        bool protectionMixed;
    };

    // 对当前进程中手动映射的 DLL 区域执行隐身
    // dllBase: 手动映射的基址
    // dllSize: 完整大小 (= SizeOfImage)
    static CloakResult CloakManualMap(HMODULE dllBase, SIZE_T dllSize);

    // 仅擦除 PE 头 (DOS头 + PE签名 + COFF头)
    // 保留区段头 (运行时可能仍需要)
    static bool StripPEHeaders(HMODULE base);

    // 在 PEB Ldr 三向链表中插入假的模块条目
    static bool AddFakeLdrEntry(HMODULE base, SIZE_T size, const wchar_t* disguiseName);

    // 从 PEB Ldr 三向链表中移除 EXE 自身的模块条目
    // (在假条目插入后调用, 隐藏 loader.exe 的模块名)
    static bool UnlinkSelfLdrEntry();

    // 随机化手动映射区域各页的保护属性
    static bool RandomizeProtections(HMODULE base, SIZE_T size);

private:
    SelfCloaker() = default;
};

} // namespace stealth
