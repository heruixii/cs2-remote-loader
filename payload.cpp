// ============================================================
// payload.cpp — 远程加载 DLL Payload
//
// 编译为 DLL, 经 XTEA 加密后托管在 HTTP 服务器上,
// 由 loader.exe 下载 → 解密 → ManualMap → 在内存中执行,
// 全程不落盘, 规避 EAC minifilter 文件扫描。
//
// DllMain 在 ManualMap 完成后被调用, 阻止线程附加通知,
// 直接在当前线程运行 FullGameCheat 主循环。
// ============================================================

#include "../game_cheat.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hinstDLL);

    // 读取 DLL 的 SizeOfImage
    SIZE_T dllSize = 0;
    {
        auto* image = reinterpret_cast<BYTE*>(hinstDLL);
        auto* dos   = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                dllSize = nt->OptionalHeader.SizeOfImage;
            }
        }
    }

    // 创建完整外挂实例并运行
    game_cheat::FullGameCheat cheat;

    if (!cheat.Initialize(hinstDLL, dllSize)) {
        return TRUE; // 静默退出
    }

    cheat.Run();
    cheat.Shutdown();

    return TRUE;
}
