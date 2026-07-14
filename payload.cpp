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

// ============================================================
// 作弊主循环
// 直接在 DllMain 的调用线程上运行，不创建新线程
// ============================================================

static DWORD CheatMainLoop(HMODULE dllBase, SIZE_T dllSize) {
    using namespace stealth;

    // 初始化规避引擎 (全部9层)
    if (!StealthEngine::Instance().Initialize()) {
        return 1;
    }

    // === 自身内存隐身: PE头擦除 + 假Ldr条目 + 自断链 + 页保护随机化 ===
    if (dllBase && dllSize > 0) {
        SelfCloaker::CloakManualMap(dllBase, dllSize);
    }

    // 附加到游戏进程 (使用PROCESS_QUERY_LIMITED_INFORMATION最小权限打开)
    if (!StealthEngine::Instance().AttachToProcess(L"cs2.exe")) {
        StealthEngine::Instance().Shutdown();
        return 2;
    }

    // 主循环
    while (true) {
        StealthEngine::Instance().OnFrame();

        // === 在此处添加您的作弊逻辑 ===
        // STEALTH_READ / STEALTH_WRITE / StealthSleep 等
        // ===============================

        StealthEngine::Instance().StealthSleep(1);
    }

    StealthEngine::Instance().Shutdown();
    return 0;
}

// ============================================================
// DLL 入口点
//
// ManualMap 完成后由 loader 在主线程上调用。
// 直接在当前线程运行主循环, 不创建新线程,
// - 规避 EAC PsSetCreateThreadNotifyRoutine 内核线程创建回调
// - 规避 EAC PsGetNextProcessThread 线程枚举
// ============================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    // 禁用 DLL_THREAD_ATTACH/DETACH 通知
    DisableThreadLibraryCalls(hinstDLL);

    // 读取 DLL 的 SizeOfImage
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

    // 直接在当前线程运行主循环 (不创建新线程)
    // 手动映射的 DLL 无 Loader Lock 限制, 可以安全地在 DllMain 中运行长期循环
    return (CheatMainLoop(hinstDLL, dllSize) == 0) ? TRUE : FALSE;
}
