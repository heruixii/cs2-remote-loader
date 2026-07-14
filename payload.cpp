// ============================================================
// payload.cpp — 远程加载 DLL Payload
//
// 编译为 DLL, 经 XTEA 加密后托管在 HTTP 服务器上,
// 由 loader.exe 下载 → 解密 → ManualMap 到内存中执行,
// 全程不落盘, 规避 EAC minifilter 文件扫描。
//
// DllMain 在 ManualMap 完成后被调用, 直接在当前线程启动主循环,
// 不创建额外线程 (规避 PsSetCreateThreadNotifyRoutine 内核回调)。
// ============================================================

#include "stealth_core.h"
#include "cheat_overlay.h"
#include "game_esp.h"
#include "cs2_memory.h"
#include "cs2_offsets.h"

// ============================================================
// 作弊主循环
// 直接在 DllMain 的调用线程上运行，不创建新线程
// ============================================================

static DWORD CheatMainLoop(HMODULE dllBase, SIZE_T dllSize) {
    using namespace stealth;

    // --- 阶段1: 初始化规避引擎 (9层) ---
    if (!StealthEngine::Instance().Initialize()) {
        return 1;
    }

    // --- 阶段2: 自身内存隐身 (跳过 UnlinkSelfLdr + RandomizeProtections, ManualMap 下不稳定) ---
    if (dllBase && dllSize > 0) {
        SelfCloaker::CloakManualMap(dllBase, dllSize);
    }

    // --- 阶段3: 附加到 CS2 进程 ---
    MessageBoxW(0, L"DBG3: AttachToProcess START...", L"DBG", 0);
    if (!StealthEngine::Instance().AttachToProcess(L"cs2.exe")) {
        MessageBoxW(0, L"FAIL: AttachToProcess", L"DBG", 0);
        StealthEngine::Instance().Shutdown();
        return 2;
    }
    MessageBoxW(0, L"DBG4: AttachToProcess OK", L"DBG", 0);

    // --- 阶段4: 初始化 CS2 内存读取 ---
    cs2::Offsets offsets;
    if (!cs2::Memory::Instance().Initialize(offsets)) {
        MessageBoxW(0, L"FAIL: MemoryInit", L"DBG", 0);
        StealthEngine::Instance().Shutdown();
        return 3;
    }
    MessageBoxW(0, L"MEM OK", L"DBG", 0);

    // --- 阶段5: 查找 CS2 窗口并创建 Overlay ---
    HWND cs2Hwnd = FindWindowW(nullptr, nullptr);
    while (cs2Hwnd) {
        DWORD pid = 0;
        GetWindowThreadProcessId(cs2Hwnd, &pid);
        if (pid == StealthEngine::Instance().GetProcessId()) {
            break;
        }
        cs2Hwnd = FindWindowExW(nullptr, cs2Hwnd, nullptr, nullptr);
    }
    if (!cs2Hwnd) {
        MessageBoxW(0, L"FAIL: FindWindow", L"DBG", 0);
        StealthEngine::Instance().Shutdown();
        return 4;
    }
    RECT cs2Rect = {};
    GetWindowRect(cs2Hwnd, &cs2Rect);
    wchar_t wmsg[128];
    _snwprintf_s(wmsg, 128, _TRUNCATE, L"CS2 HWND=%p RECT=%d,%d-%d,%d", cs2Hwnd, cs2Rect.left, cs2Rect.top, cs2Rect.right, cs2Rect.bottom);
    MessageBoxW(0, wmsg, L"DBG", 0);

    cs2::OverlayConfig overlayCfg;
    overlayCfg.width   = cs2Rect.right - cs2Rect.left;
    overlayCfg.height  = cs2Rect.bottom - cs2Rect.top;
    overlayCfg.screenX = cs2Rect.left;
    overlayCfg.screenY = cs2Rect.top;

    if (!cs2::CheatOverlay::Instance().Create(overlayCfg)) {
        MessageBoxW(0, L"FAIL: OverlayCreate", L"DBG", 0);
        StealthEngine::Instance().Shutdown();
        return 5;
    }
    MessageBoxW(0, L"OVERLAY OK. Starting ESP loop...", L"DBG", 0);

    // --- 阶段6: 配置 ESP ---
    cs2::ESPConfig espCfg;
    espCfg.drawBox       = true;
    espCfg.drawHealth    = true;
    espCfg.drawName      = true;
    espCfg.drawDistance  = true;
    espCfg.drawWeapon    = true;
    espCfg.drawSnaplines = false;
    espCfg.drawHeadDot   = true;
    espCfg.drawInfo      = true;
    espCfg.drawCrosshair = true;
    cs2::ESP::Instance().SetConfig(espCfg);

    // --- 阶段7: 主循环 (ESP 渲染) ---
    while (true) {
        // 隐身维护 (ETW/AMSI/VAC/Hook检测/NMI心跳)
        StealthEngine::Instance().OnFrame();

        // 读取玩家数据
        auto local   = cs2::Memory::Instance().GetLocalPlayer();
        auto players = cs2::Memory::Instance().GetAllPlayers(true);

        // 渲染 ESP
        {
            auto& overlay = cs2::CheatOverlay::Instance();
            overlay.BringToTop();
            overlay.CloakStyle();
            HDC dc = overlay.BeginDraw();
            if (dc) {
                // 清屏 (黑色透明)
                RECT r = {0, 0, overlay.Width(), overlay.Height()};
                FillRect(dc, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));

                cs2::ESP::Instance().Render(local, players);
            }
            overlay.RestoreStyle();
            overlay.EndDraw();
        }

        // 消息泵 (防止窗口卡死)
        cs2::CheatOverlay::Instance().PumpMessages();

        StealthEngine::Instance().StealthSleep(1);
    }

    StealthEngine::Instance().Shutdown();
    return 0;
}

// ============================================================
// DLL 入口点
// ManualMap 完成后由 loader 在主线程上调用。
// ============================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hinstDLL);

    SIZE_T dllSize = 0;
    {
        auto* image = reinterpret_cast<BYTE*>(hinstDLL);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                image + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                dllSize = nt->OptionalHeader.SizeOfImage;
            }
        }
    }

    return (CheatMainLoop(hinstDLL, dllSize) == 0) ? TRUE : FALSE;
}
