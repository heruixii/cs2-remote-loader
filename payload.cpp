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
#include "syscall_direct.h"
#include <cstdio>
#include <cstdarg>

// 轻量诊断: 写文件, 不弹 MessageBox 干扰游戏
static void DiagLog(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    va_end(args);
    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"stealth_diag.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        CloseHandle(h);
    }
}

// 崩溃捕获 — 帮助定位 Init 期间的 crash
static HMODULE g_diagDllBase;
static SIZE_T g_diagDllSize;
static LONG CALLBACK DiagVehHandler(PEXCEPTION_POINTERS ep) {
    uint64_t crashAddr = (uint64_t)ep->ExceptionRecord->ExceptionAddress;
    uint64_t dllBase   = (uint64_t)g_diagDllBase;
    uint64_t offset    = (dllBase && crashAddr >= dllBase) ? (crashAddr - dllBase) : 0;
    DiagLog("CRASH: code=0x%08X addr=0x%llX off=%llX\n",
        ep->ExceptionRecord->ExceptionCode, crashAddr, offset);
    return EXCEPTION_CONTINUE_SEARCH; // 让进程崩溃
}

// ============================================================
// 作弊主循环
// 直接在 DllMain 的调用线程上运行，不创建新线程
// ============================================================

static DWORD CheatMainLoop(HMODULE dllBase, SIZE_T dllSize) {
    using namespace stealth;

    // 清除旧日志
    wchar_t logPath[MAX_PATH];
    GetTempPathW(MAX_PATH, logPath);
    wcscat_s(logPath, L"stealth_diag.log");
    DeleteFileW(logPath);
    DiagLog("=== v3.8-e9ff50d DIAG START ===\n");
    DiagLog("BEFORE Init...\n");

    // 安装 VEH 崩溃捕获器
    g_diagDllBase = dllBase;
    g_diagDllSize = dllSize;
    PVOID vehHandle = AddVectoredExceptionHandler(1, DiagVehHandler);
    DiagLog("VEH registered, dllBase=0x%llX dllSize=%llu\n",
        (unsigned long long)dllBase, (unsigned long long)dllSize);

    // --- 阶段1: 初始化规避引擎 (9层) ---
    if (!StealthEngine::Instance().Initialize()) {
        DiagLog("FAIL: StealthEngine::Initialize\n");
        return 1;
    }
    DiagLog("OK: StealthEngine::Initialize\n");

    // --- 阶段2: 自身内存隐身 (跳过 UnlinkSelfLdr + RandomizeProtections, ManualMap 下不稳定) ---
    if (dllBase && dllSize > 0) {
        SelfCloaker::CloakManualMap(dllBase, dllSize);
    }
    DiagLog("OK: CLOAK done\n");

    // --- 阶段3: 附加到 CS2 进程 ---
    if (!StealthEngine::Instance().AttachToProcess(L"cs2.exe")) {
        DiagLog("FAIL: AttachToProcess\n");
        StealthEngine::Instance().Shutdown();
        return 2;
    }
    DiagLog("OK: AttachToProcess, PID=%u HANDLE=%p\n",
        StealthEngine::Instance().GetProcessId(),
        StealthEngine::Instance().GetProcessHandle());

    // 诊断: 直接测试 SysQueryInformationProcess
    {
        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG rl = 0;
        NTSTATUS st = SysQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), &rl, SyscallMethod::Indirect);
        DiagLog("SysQueryInfo: status=0x%08X PEB=0x%llX returnLen=%u NT_SUCCESS=%d\n",
            (unsigned)st, (unsigned long long)pbi.PebBaseAddress, rl, (int)NT_SUCCESS(st));

        // 测试 fallback
        DWORD pid = GetProcessId(hProc);
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        DiagLog("Snapshot: PID=%u hSnap=%p INVALID=%d\n",
            pid, (void*)hSnap, (int)(hSnap == INVALID_HANDLE_VALUE));
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = { sizeof(me) };
            if (Module32FirstW(hSnap, &me)) {
                int count = 0;
                do {
                    count++;
                    if (wcsstr(me.szModule, L"client") || wcsstr(me.szModule, L"engine"))
                        DiagLog("  [snap] %ls @ 0x%llX\n", me.szModule, (unsigned long long)me.modBaseAddr);
                } while (Module32NextW(hSnap, &me) && count < 16);
                DiagLog("  [snap] total first 16: %d modules\n", count);
            } else {
                DiagLog("  [snap] Module32First FAILED err=%u\n", (unsigned)GetLastError());
            }
            CloseHandle(hSnap);
        }
    }

    // 诊断: 列出 CS2 进程模块
    {
        auto modules = StealthProcess::GetProcessModules(
            StealthEngine::Instance().GetProcessHandle());
        DiagLog("GetProcessModules: %zu modules found\n", modules.size());
        for (auto& m : modules) {
            wchar_t buf[64];
            wcsncpy_s(buf, m.name.c_str(), 63);
            if (wcsstr(m.name.c_str(), L"client") || wcsstr(m.name.c_str(), L"engine"))
                DiagLog("  %ls @ 0x%llX\n", buf, (unsigned long long)m.baseAddress);
        }
    }

    // --- 阶段4: 初始化 CS2 内存读取 ---
    cs2::Offsets offsets;
    if (!cs2::Memory::Instance().Initialize(offsets)) {
        DiagLog("FAIL: Memory::Initialize (client.dll not found?)\n");
        StealthEngine::Instance().Shutdown();
        return 3;
    }
    DiagLog("OK: Memory::Initialize, clientBase=0x%llX\n",
        (unsigned long long)cs2::Memory::Instance().ClientBase());

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
        DiagLog("FAIL: FindWindow (cs2Hwnd)\n");
        StealthEngine::Instance().Shutdown();
        return 4;
    }
    RECT cs2Rect = {};
    GetWindowRect(cs2Hwnd, &cs2Rect);
    DiagLog("OK: CS2 HWND=%p, RECT=(%d,%d %dx%d)\n",
        cs2Hwnd, cs2Rect.left, cs2Rect.top,
        cs2Rect.right - cs2Rect.left,
        cs2Rect.bottom - cs2Rect.top);

    cs2::OverlayConfig overlayCfg;
    overlayCfg.width   = cs2Rect.right - cs2Rect.left;
    overlayCfg.height  = cs2Rect.bottom - cs2Rect.top;
    overlayCfg.screenX = cs2Rect.left;
    overlayCfg.screenY = cs2Rect.top;

    if (!cs2::CheatOverlay::Instance().Create(overlayCfg)) {
        DiagLog("FAIL: CheatOverlay::Create\n");
        StealthEngine::Instance().Shutdown();
        return 5;
    }
    DiagLog("OK: Overlay created %dx%d at (%d,%d)\n",
        overlayCfg.width, overlayCfg.height,
        overlayCfg.screenX, overlayCfg.screenY);

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
    // ---- 预检查: 直接用每种syscall方法读取clientBase的PE magic ----
    {
        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
        uintptr_t cb = cs2::Memory::Instance().ClientBase();

        // 方法1: TartarusGate (Direct Syscall)
        {
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)cb, &magic, 2, &bytesRead, SyscallMethod::Direct);
            DiagLog("TARTARUS: magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st));
        }

        // 方法2: Indirect Syscall (跳转ntdll syscall;ret gadget)
        {
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)cb, &magic, 2, &bytesRead, SyscallMethod::Indirect);
            DiagLog("INDIRECT: magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st));
        }

        // 方法3: StackSpoof (深度栈伪造)
        {
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)cb, &magic, 2, &bytesRead, SyscallMethod::StackSpoof);
            DiagLog("SPOOF:   magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st));
        }

        // 方法4: GetProcAddress fallback
        {
            using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
            auto fn = (Fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadVirtualMemory");
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = fn ? fn(hProc, (PVOID)cb, &magic, 2, &bytesRead) : (NTSTATUS)0xC0000002;
            DiagLog("GPA:      magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d fn=%p\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st), (void*)fn);
        }
    }

    DiagLog("=== MAIN LOOP START ===\n");
    int frameCount = 0;
    DWORD lastDiagTime = 0;
    while (true) {
        frameCount++;
        DWORD now = GetTickCount();

        // 每秒一次诊断
        if (now - lastDiagTime >= 1000) {
            lastDiagTime = now;
            auto local = cs2::Memory::Instance().GetLocalPlayer();
            auto players = cs2::Memory::Instance().GetAllPlayers(true);
            uintptr_t elBase = cs2::Memory::Instance().EntityList();
            DiagLog("F=%d localPawn=0x%llX players=%zu elBase=0x%llX clientBase=0x%llX\n",
                frameCount,
                (unsigned long long)local.address,
                players.size(),
                (unsigned long long)elBase,
                (unsigned long long)cs2::Memory::Instance().ClientBase());
            if (!players.empty()) {
                auto& p = players[0];
                DiagLog("  P0: team=%d hp=%d origin=(%.0f,%.0f,%.0f) screen=(%.0f,%.0f) boxH=%.0f\n",
                    p.team, p.health,
                    p.origin.x, p.origin.y, p.origin.z,
                    p.screenHead.x, p.screenHead.y, p.boxHeight);
            }
        }

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
            HDC dc = overlay.BeginDraw();   // 已清黑色背景 (色键=透明)
            if (dc) {
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
