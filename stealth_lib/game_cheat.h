#pragma once
// ============================================================
// game_cheat.h — CS2 透视外挂 (ESP + 规避引擎)
// 仅保留透视/可视化功能, 无自瞄/鼠标模拟
// 可被 integration_example.cpp 和 payload.cpp 共用
// ============================================================

#include "stealth_core.h"
#include "cs2_memory.h"
#include "cheat_overlay.h"
#include "game_esp.h"
#include "eac_syscall_guard.h"
#include "byovd_kernel.h"
#include <thread>
#include <chrono>
#include <random>

namespace game_cheat {

// 全局运行标志
inline bool g_cheat_running = true;

// ============================================================
// 完整外挂类
// ============================================================
class FullGameCheat {
public:
    FullGameCheat() = default;

    bool Initialize(HMODULE dllBase = nullptr, SIZE_T dllSize = 0) {
        using namespace stealth;

        // Step 1: 初始化规避引擎 (反检测层)
        StealthConfig config;
        config.stripRichHeader      = true;
        config.randomizeTimestamp   = true;
        config.stripDebugInfo       = true;
        config.useDirectSyscalls    = true;
        config.enableVACSafety      = true;
        config.enableSleepObfuscation = true;
        config.enableCallStackSpoof = true;
        config.silenceETW           = true;
        config.silenceAMSI          = true;
        config.detectInHooks        = true;
        config.minimalProcessHandle = true;
        config.enableSelfCloaking   = true;
        config.enableEACScanPrediction = true;
        config.enableEACPEStrip      = true;
        config.enableEACProcessDisguise = true;
        config.enableVMGateBypass   = true;
        config.enableNMISpoofing    = true;
        config.enableFakePEConstruction = true;

        if (!StealthEngine::Instance().Initialize(config)) {
            return false;
        }

        // Step 2: 附加到 CS2 进程
        if (!StealthEngine::Instance().AttachToProcess(L"cs2.exe")) {
            return false;
        }

        // Step 2.5: 封锁句柄 (DACL → 仅允许自身进程访问)
        // 阻止 EAC 通过 NtQuerySystemInformation 枚举到我们的句柄
        HANDLE hGame = StealthEngine::Instance().GetProcessHandle();
        if (hGame) {
            stealth::HandleACLGuard::LockHandle(hGame);
        }

        // Step 3: 备份 .text 段 (VAC 完整性检查保护)
        IntegrityBypass::BackupTextSection();

        // Step 4: 自我隐藏 (移除PE头/断开LDR/假模块)
        StealthEngine::Instance().SelfCloak();

        // Step 5: 初始化 CS2 内存管理器
        cs2::Offsets offsets;
        if (!cs2::Memory::Instance().Initialize(offsets)) {
            // 内存管理器初始化失败, 但不阻塞 (游戏可能尚未完全加载)
        }

        // Step 6: 创建透明覆盖层窗口 (ESP)
        cs2::OverlayConfig overlayCfg;
        overlayCfg.fontSize = 13;
        if (!cs2::CheatOverlay::Instance().Create(overlayCfg)) {
            return false;
        }

        // Step 6.5: BYOVD 内核防御 — 摘除 EAC 内核回调 (Ring-0)
        // 成功后 EAC 的 ObRegisterCallbacks/ProcessNotify/ImageNotify 全部失效
        auto kernelResult = stealth::KernelDefense::EnableAll();
        (void)kernelResult; // 非致命: 内核模块失败不阻塞外挂加载

        // Step 7: 配置 ESP
        cs2::ESPConfig espCfg;
        espCfg.drawBox       = true;
        espCfg.drawHealth    = true;
        espCfg.drawName      = true;
        espCfg.drawDistance  = true;
        espCfg.drawWeapon    = true;
        espCfg.drawSnaplines = false;
        espCfg.drawHeadDot   = true;
        espCfg.drawCrosshair = true;
        cs2::ESP::Instance().SetConfig(espCfg);

        m_initialized = true;
        return true;
    }

    void Run() {
        if (!m_initialized) {
            return;
        }

        auto& overlay   = cs2::CheatOverlay::Instance();
        auto& memory    = cs2::Memory::Instance();
        auto& esp       = cs2::ESP::Instance();
        auto& engine    = stealth::StealthEngine::Instance();

        // 时序随机化种子
        std::random_device rd;
        std::mt19937 rng(rd());

        int   targetFPS  = 144;
        DWORD frameTime  = 1000 / targetFPS;
        DWORD lastFrame  = GetTickCount();
        int   frameCount = 0;

        while (g_cheat_running) {
            DWORD now = GetTickCount();

            // 处理窗口消息
            overlay.PumpMessages();

            // 时序抖动 (±2ms), 破坏EAC行为图谱的精确时间匹配
            DWORD jitter = (rng() % 5); // 0-4ms
            DWORD adjustedFrameTime = frameTime + jitter - 2;
            if (now - lastFrame < adjustedFrameTime) {
                std::this_thread::sleep_for(std::chrono::microseconds(500 + rng() % 1000));
                continue;
            }
            lastFrame = now;

            // === 反检测帧维护 ===
            engine.OnFrame();

            // === EAC 纵深防御: Syscall Stub 完整性验证 (每 30 帧) ===
            if ((frameCount % 30) == 0) {
                stealth::SyscallGuard::VerifyAndRepair();
            }

            // === 读取游戏数据 ===
            auto entities = memory.GetAllPlayers(true);
            auto local    = memory.GetLocalPlayer();

            if (!local.isAlive || entities.empty()) {
                // 无实体时仍刷新 (避免窗口消失), 但保持伪装状态
                overlay.RestoreStyle();
                overlay.BeginDraw();
                overlay.EndDraw();
                overlay.CloakStyle();
                engine.StealthSleep(1);
                continue;
            }

            // === ESP 渲染 (仅渲染时恢复完整标志) ===
            overlay.RestoreStyle();       // 恢复 LAYERED + 动态 TOPMOST
            overlay.BeginDraw();
            esp.Render(local, entities);
            overlay.EndDraw();
            overlay.CloakStyle();         // 立即伪装: 剥离 LAYERED, 隐藏窗口特征

            // === 帧尾 ===
            frameCount++;
            engine.StealthSleep(1);
        }
    }

    void Shutdown() {
        g_cheat_running = false;
        cs2::CheatOverlay::Instance().Destroy();
        stealth::KernelDefense::DisableAll();
        stealth::StealthEngine::Instance().Shutdown();
    }

private:
    bool m_initialized = false;
};

} // namespace game_cheat
