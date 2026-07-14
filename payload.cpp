// ============================================================
// payload.cpp — 远程加载 DLL Payload
//
// 编译为 DLL, 经 XTEA 加密后托管在 HTTP 服务器上,
// 由 loader.exe 下载 → 解密 → ManualMap 到内存中执行,
// 全程不落盘, 规避 EAC minifilter 文件扫描。
//
// v3.32: 嵌入基础.exe, 注入后自动启动基础.exe 做 ESP 渲染,
//        本 DLL 只负责反检测 (BYOVD/Syscall/内存加密等),
//        ESP 渲染由基础.exe (GDI overlay) 完成。
//
// DllMain 在 ManualMap 完成后被调用, 直接在当前线程启动主循环,
// 不创建额外线程 (规避 PsSetCreateThreadNotifyRoutine 内核回调)。
// BUILD: 332
// ============================================================

#include "stealth_core.h"
#include "cheat_overlay.h"
#include "game_esp.h"
#include "cs2_memory.h"

#include <algorithm>  // std::sort (v3.24: 豁免页排序)
#include <vector>
#include "cs2_offsets.h"
#include "syscall_direct.h"
#include "eac_syscall_guard.h"
#include "byovd_kernel.h"
#include <cstdio>
#include <cstdarg>
#include <tlhelp32.h>

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
    // 卸载 BYOVD 驱动 (崩溃后残留内核驱动可被EAC扫描到)
    // 如果这里的卸载也崩溃, 进程本身已在崩溃中, 不影响
    stealth::KernelDefense::DisableAll();
    return EXCEPTION_CONTINUE_SEARCH; // 让进程崩溃
}

// v3.32: 基础.exe 进程句柄 (退出时清理)
static HANDLE g_hBasicProcess = nullptr;
static DWORD g_basicRestartBackoffMs = 1000;  // 退避时间, 防止快速重启循环

// v3.32: 从临时目录启动基础.exe (由 loader.exe 预先写入 %TEMP%\basic_esp.exe)
static bool LaunchBasicESP() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    wchar_t exePath[MAX_PATH];
    WIN32_FIND_DATAW fd;
    wsprintfW(exePath, L"%s\\basic_esp_*.exe", tempPath);
    HANDLE hFind = FindFirstFileW(exePath, &fd);
    bool found = false;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            // 检查文件大小 (基础.exe 约 51KB)
            LARGE_INTEGER sz;
            sz.LowPart = fd.nFileSizeLow;
            sz.HighPart = fd.nFileSizeHigh;
            if (sz.QuadPart > 40000 && sz.QuadPart < 60000) {
                wsprintfW(exePath, L"%s\\%s", tempPath, fd.cFileName);
                found = true;
                break;
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    if (!found) {
        // 备用: 直接尝试固定路径
        wsprintfW(exePath, L"%s\\basic_esp.exe", tempPath);
        if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) {
            DiagLog("FAIL: basic.exe not found in %%TEMP%%\n");
            return false;
        }
    }

    DiagLog("--- LaunchBasicESP: %ls ---\n", exePath);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(exePath, nullptr,
        nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW,
        nullptr, tempPath,
        &si, &pi);
    if (!ok) {
        DiagLog("FAIL: CreateProcessW, err=%u\n", GetLastError());
        return false;
    }

    g_hBasicProcess = pi.hProcess;
    CloseHandle(pi.hThread);
    DiagLog("OK: basic.exe launched, PID=%u\n", pi.dwProcessId);

    // 延迟后删除 (基础.exe 已加载到内存)
    Sleep(2000);
    // 基础.exe 已加载到内存, %TEMP% 中的文件由 Windows 自动清理
    return true;
}

// v3.32: 清理基础.exe 进程
static void TerminateBasicESP() {
    if (g_hBasicProcess) {
        DiagLog("--- Terminating basic.exe ---\n");
        TerminateProcess(g_hBasicProcess, 0);
        CloseHandle(g_hBasicProcess);
        g_hBasicProcess = nullptr;
    }
}

// v3.32-plus: 注入痕迹清理 — 基础.exe 注入到 cs2.exe 后, 从外部通过 handles
// 清除 PEB Ldr 链表中的注入模块条目, 防止 EAC 用户态模块枚举检测
// 同时清理注入线程的 TEB 痕迹
static void CleanupInjectionTraces() {
    using namespace stealth;
    HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
    if (!hProc) return;

    // 等待基础.exe 完成注入 (额外等待, 配合 LaunchBasicESP 中的 2s)
    Sleep(3000);
    DiagLog("CleanupInjectionTraces: scanning PEB Ldr...\n");

    // 1. 获取 PEB 地址
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG rl = 0;
    if (!NT_SUCCESS(SysQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), &rl, SyscallMethod::Indirect))) {
        DiagLog("CleanupInjectionTraces: QueryInfoProcess failed\n");
        return;
    }
    DiagLog("CleanupInjectionTraces: PEB=0x%llX\n", (unsigned long long)pbi.PebBaseAddress);

    // 2. 读取 PEB → Ldr
    BYTE pebBuf[0x200] = {};
    SIZE_T br = 0;
    if (!NT_SUCCESS(SysReadVirtualMemory(hProc, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &br, SyscallMethod::Indirect))) {
        DiagLog("CleanupInjectionTraces: Read PEB failed\n");
        return;
    }
    uintptr_t ldr = *(uintptr_t*)(pebBuf + 0x18);
    DiagLog("CleanupInjectionTraces: Ldr=0x%llX\n", (unsigned long long)ldr);
    if (!ldr) return;

    // 已知合法模块前缀 (CS2 + Windows系统)
    static const wchar_t* knownPrefixes[] = {
        L"ntdll", L"kernel", L"KERNEL", L"user32", L"gdi32",
        L"advapi", L"shell32", L"ole32", L"comctl", L"msvc",
        L"vcruntime", L"ucrtbase", L"bcrypt", L"crypt",
        L"setupapi", L"winhttp", L"ws2_32", L"iphlpapi",
        L"d3d", L"dxgi", L"nv", L"ati", L"amd",
        L"client.dll", L"engine2.dll", L"tier0", L"input",
        L"materials", L"vphysics", L"studiorender",
        L"scenesystem", L"resourcesystem", L"rendersystem",
        L"soundsystem", L"networksystem", L"animationsystem",
        L"particles", L"vscript", L"vstdlib", L"matchmaking",
        L"steamclient", L"gameoverlay", L"serverbrowser",
        L"msvcp", L"concrt", L"shcore", L"imm32",
        L"windows.", L"profapi", L"powrprof",
        L"umpdc", L"kernelbase", L"cfg", L"devobj",
        L"wintrust", L"msasn1", L"crypt32", L"wldp",
        L"ntmarta", L"fltlib", L"sechost", L"sspicli",
        L"gdi32full", L"win32u", L"msctf", L"textinput",
        L"msimg32", L"dbghelp", L"dbgcore",
        L"EasyAntiCheat", L"EAC",
        nullptr
    };

    auto isKnownModule = [&](const wchar_t* name) -> bool {
        if (!name[0]) return true; // 空名跳过
        for (int i = 0; knownPrefixes[i]; i++) {
            if (_wcsnicmp(name, knownPrefixes[i], wcslen(knownPrefixes[i])) == 0)
                return true;
        }
        return false;
    };

    // 3. 同时清理两个模块链表: InLoadOrder (Ldr+0x10) 和 InMemoryOrder (Ldr+0x20)
    struct ListCleanup { uintptr_t headAddr; const char* desc; };
    ListCleanup lists[] = {
        { ldr + 0x10, "InLoadOrder" },
        { ldr + 0x20, "InMemoryOrder" },
    };

    int totalCleaned = 0;
    for (auto& list : lists) {
        BYTE headBuf[16] = {};
        if (!NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)list.headAddr, headBuf, 16, &br, SyscallMethod::Indirect)))
            continue;

        uintptr_t headLink = list.headAddr;
        uintptr_t cur = *(uintptr_t*)(headBuf + 0); // FLink
        int walked = 0;

        while (cur && cur != headLink && walked < 256) {
            walked++;
            BYTE modBuf[0x200] = {};
            if (!NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)cur, modBuf, sizeof(modBuf), &br, SyscallMethod::Indirect)))
                break;

            uintptr_t flink = *(uintptr_t*)(modBuf + 0);
            uintptr_t dllBase = *(uintptr_t*)(modBuf + 0x30);
            uintptr_t nameBufAddr = *(uintptr_t*)(modBuf + 0x48);
            USHORT nameLen = *(USHORT*)(modBuf + 0x50);

            wchar_t modName[128] = {};
            if (nameBufAddr && nameLen > 0 && nameLen < 254) {
                SysReadVirtualMemory(hProc, (PVOID)nameBufAddr, modName,
                    (SIZE_T)(std::min((int)nameLen, 254)), &br, SyscallMethod::Indirect);
            }

            if (!isKnownModule(modName) && dllBase) {
                DiagLog("CleanupInjectionTraces: [%s] UNLINK %ls (base=0x%llX, flink=0x%llX)\n",
                    list.desc, modName, (unsigned long long)dllBase, (unsigned long long)cur);

                // 读取当前节点的 LIST_ENTRY
                uintptr_t nodeFlink = *(uintptr_t*)(modBuf + 0);
                uintptr_t nodeBlink = *(uintptr_t*)(modBuf + 8);

                if (nodeFlink && nodeBlink) {
                    // nodeBlink->FLink = nodeFlink
                    SIZE_T wb = 0;
                    SysWriteVirtualMemory(hProc, (PVOID)nodeBlink, &nodeFlink, 8, &wb, SyscallMethod::Indirect);
                    // nodeFlink->BLink = nodeBlink
                    SysWriteVirtualMemory(hProc, (PVOID)(nodeFlink + 8), &nodeBlink, 8, &wb, SyscallMethod::Indirect);
                    // 清理当前节点的链接 (预防性措施)
                    SysWriteVirtualMemory(hProc, (PVOID)(cur + 0), &cur, 8, &wb, SyscallMethod::Indirect);
                    SysWriteVirtualMemory(hProc, (PVOID)(cur + 8), &cur, 8, &wb, SyscallMethod::Indirect);
                    totalCleaned++;
                }
            }

            cur = flink;
        }
    }

    DiagLog("CleanupInjectionTraces: done, cleaned %d entries\n", totalCleaned);
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
    DiagLog("=== v3.32 DIAG START ===\n");
    DiagLog("BEFORE Init...\n");

    // 安装 VEH 崩溃捕获器
    g_diagDllBase = dllBase;
    g_diagDllSize = dllSize;
    PVOID vehHandle = AddVectoredExceptionHandler(1, DiagVehHandler);
    DiagLog("VEH registered, dllBase=0x%llX dllSize=%llu\n",
        (unsigned long long)dllBase, (unsigned long long)dllSize);

    // ============================================================
    // 注册 EkkoSleep 内存加密保护区
    // 必须在 PE 头剥离前完成, 否则无法解析 section 边界
    // Sleep 期间整段 DLL 被加密, 防止 EAC 内存扫描
    //
    // ★ v3.23: 跳过 EkkoSleep/EncryptAll/DecryptAll 自身所在页面
    // ★ v3.24: 同时跳过 VEH handler (DiagVehHandler) 所在页面,
    //   防止 EkkoSleep 加密期间触发异常 → CPU 执行已加密代码 → 双重错误
    // ============================================================
    {
        uintptr_t codeBase = (uintptr_t)dllBase + 0x1000;
        SIZE_T codeSize = (dllSize > 0x1000) ? (dllSize - 0x1000) : dllSize;
        uintptr_t codeEnd = codeBase + codeSize;

        uintptr_t ekkoPage = SleepObfuscator::GetSelfPage();
        uintptr_t vehPage  = reinterpret_cast<uintptr_t>(DiagVehHandler) & ~0xFFFULL;

        // 收集所有需要豁免的页面 (去重排序)
        std::vector<uintptr_t> exemptPages = { ekkoPage };
        if (vehPage != ekkoPage) exemptPages.push_back(vehPage);
        std::sort(exemptPages.begin(), exemptPages.end());

        SIZE_T totalProtected = 0;
        uintptr_t cursor = codeBase;

        for (uintptr_t skip : exemptPages) {
            if (skip < cursor || skip >= codeEnd) continue;
            if (skip > cursor) {
                SIZE_T segSz = skip - cursor;
                SleepObfuscator::Instance().RegisterProtectedRegion((void*)cursor, segSz);
                totalProtected += segSz;
            }
            cursor = skip + 0x1000;
        }
        if (cursor < codeEnd) {
            SIZE_T segSz = codeEnd - cursor;
            SleepObfuscator::Instance().RegisterProtectedRegion((void*)cursor, segSz);
            totalProtected += segSz;
        }

        DiagLog("OK: EkkoSleep protected %llu bytes (exempt: ekko@0x%llX veh@0x%llX)\n",
            (unsigned long long)totalProtected, (unsigned long long)ekkoPage, (unsigned long long)vehPage);
    }

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
        stealth::KernelDefense::DisableAll();
        StealthEngine::Instance().Shutdown();
        return 2;
    }
    DiagLog("OK: AttachToProcess, PID=%u HANDLE=%p\n",
        StealthEngine::Instance().GetProcessId(),
        StealthEngine::Instance().GetProcessHandle());

    // 封锁进程句柄 (DACL → 仅允许自身访问, 阻止EAC通过NtQuerySystemInformation枚举)
    {
        HANDLE hGame = StealthEngine::Instance().GetProcessHandle();
        if (hGame) {
            stealth::HandleACLGuard::LockHandle(hGame);
            DiagLog("OK: HandleACLGuard locked\n");
        } else {
            DiagLog("WARN: HandleACLGuard skipped (no handle)\n");
        }
    }

    // BYOVD 内核防御 — 加载漏洞驱动 + 摘除 EAC 内核回调 (Ring-0)
    // v3.24: 优先 System32\drivers, 回退嵌入提取到 %TEMP%
    // ObRegisterCallbacks/ProcessNotify/ImageNotify → 全部失效
    {
        auto kernelResult = stealth::KernelDefense::EnableAll();
        DiagLog("OK: BYOVD driver=%d ob=%d proc=%d img=%d thread=%d\n",
            (int)kernelResult.driverLoaded,
            kernelResult.obCallbacksRemoved,
            kernelResult.processCallbacksRemoved,
            kernelResult.imageCallbacksRemoved,
            kernelResult.threadCallbacksRemoved);
    }

    // v3.32: BYOVD 已加载(EAC内核回调已移除), 现在安全启动基础.exe
    //        基础.exe 将调用 OpenProcess+ReadProcessMemory,
    //        这些操作不再被 EAC 内核回调监控
    {
        bool basicOk = LaunchBasicESP();
        DiagLog("LaunchBasicESP: %s\n", basicOk ? "SUCCESS" : "FAILED");
        // v3.32-plus: 基础.exe 注入后清理痕迹 (PEB Ldr unlinking)
        if (basicOk) {
            CleanupInjectionTraces();
        }
    }

    {
        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();

        // 1. Query PEB
        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG rl = 0;
        NTSTATUS st = SysQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), &rl, SyscallMethod::Indirect);
        DiagLog("PEB: status=0x%08X peb=0x%llX\n", (unsigned)st, (unsigned long long)pbi.PebBaseAddress);

        // 2. Read PEB to get Ldr
        BYTE pebBuf[0x100] = {};
        SIZE_T br = 0;
        st = SysReadVirtualMemory(hProc, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &br, SyscallMethod::Indirect);
        DiagLog("ReadPEB: status=0x%08X bytes=%zu\n", (unsigned)st, br);
        if (NT_SUCCESS(st) && br >= 0x20) {
            uintptr_t ldrAddr = *(uintptr_t*)(pebBuf + 0x18);
            DiagLog("LDR: addr=0x%llX\n", (unsigned long long)ldrAddr);

            // 3. Read LDR data (PEB_LDR_DATA)
            BYTE ldrBuf[0x100] = {};
            st = SysReadVirtualMemory(hProc, (PVOID)ldrAddr, ldrBuf, sizeof(ldrBuf), &br, SyscallMethod::Indirect);
            DiagLog("ReadLDR: status=0x%08X bytes=%zu\n", (unsigned)st, br);

            // 4. Read InLoadOrderModuleList head
            uintptr_t listHead = ldrAddr + 0x10;
            BYTE listBuf[0x20] = {};
            st = SysReadVirtualMemory(hProc, (PVOID)listHead, listBuf, sizeof(listBuf), &br, SyscallMethod::Indirect);
            DiagLog("ReadList: status=0x%08X bytes=%zu flink=0x%llX\n",
                (unsigned)st, br, (unsigned long long)*(uintptr_t*)listBuf);

            // 5. Walk first entry
            uintptr_t flink = *(uintptr_t*)listBuf;
            if (flink) {
                BYTE modBuf[0x400] = {};
                st = SysReadVirtualMemory(hProc, (PVOID)flink, modBuf, sizeof(modBuf), &br, SyscallMethod::Indirect);
                DiagLog("ReadMod: status=0x%08X bytes=%zu base=0x%llX\n",
                    (unsigned)st, br, (unsigned long long)*(uintptr_t*)(modBuf + 0x30));
                // FullName
                uintptr_t fname = *(uintptr_t*)(modBuf + 0x48);
                DiagLog("FullNameVA=0x%llX\n", (unsigned long long)fname);
            }
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
        stealth::KernelDefense::DisableAll();
        StealthEngine::Instance().Shutdown();
        return 3;
    }
    DiagLog("OK: Memory::Initialize, clientBase=0x%llX engineBase=0x%llX\n",
        (unsigned long long)cs2::Memory::Instance().ClientBase(),
        (unsigned long long)cs2::Memory::Instance().EngineBase());

    {
        uintptr_t cb = cs2::Memory::Instance().ClientBase();
        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
        auto& off = cs2::Memory::Instance().GetOffsets();

        // 获取 client.dll 大小
        uintptr_t clientSize = 0;
        for (auto& mod : stealth::StealthProcess::GetProcessModules(hProc)) {
            if (mod.name == L"client.dll") {
                clientSize = mod.size;
                break;
            }
        }
        DiagLog("client.dll: base=0x%llX size=0x%llX (%lld MB) end=0x%llX\n",
            (unsigned long long)cb, (unsigned long long)clientSize,
            (long long)(clientSize / 1048576), (unsigned long long)(cb + clientSize));

        auto diagRead = [&](const char* name, uintptr_t addr) {
            uintptr_t val = 0;
            SIZE_T br = 0;
            SysReadVirtualMemory(hProc, (PVOID)addr, &val, 8, &br, SyscallMethod::Indirect);
            BYTE raw[32] = {};
            SIZE_T br2 = 0;
            SysReadVirtualMemory(hProc, (PVOID)(addr - 8), raw, 32, &br2, SyscallMethod::Indirect);
            DiagLog("  %s(off=0x%llX) addr=0x%llX val=0x%llX [hex:", name,
                (unsigned long long)(addr - cb), (unsigned long long)addr, (unsigned long long)val);
            if (br2 >= 8) {
                for (int i = 0; i < 24; i++) DiagLog("%02X ", raw[i]);
            }
            DiagLog("]");
            if (addr >= cb + clientSize) DiagLog(" *** OUT OF BOUNDS!");
            DiagLog("\n");
            return val;
        };

        diagRead("dwLocalPlayerCtl", cb + off.dwLocalPlayerController);
        diagRead("dwEntityList    ", cb + off.dwEntityList);
        diagRead("dwViewMatrix    ", cb + off.dwViewMatrix);

        // 宽扫: 从 viewMatrix 偏移到 entityList 偏移范围
        DiagLog("  -- scan for valid pointers in range 0x2300000..0x2600000 --\n");
        int found = 0;
        for (uintptr_t scanOff = 0x2300000; scanOff < 0x2600000 && found < 30; scanOff += 8) {
            if (cb + scanOff >= cb + clientSize) break; // 超出模块
            uintptr_t val = 0;
            SIZE_T br = 0;
            SysReadVirtualMemory(hProc, (PVOID)(cb + scanOff), &val, 8, &br, SyscallMethod::Indirect);
            if (val > cb && val < (cb + 0x20000000)) {
                DiagLog("  PTR: off=0x%llX val=0x%llX\n",
                    (unsigned long long)scanOff, (unsigned long long)val);
                found++;
            }
        }
        DiagLog("  -- found %d valid ptrs in range --\n", found);

        // Dump entity system raw memory to understand structure
        DiagLog("  -- entity system dump (first 512 bytes) --\n");
        {
            uintptr_t elBase = 0;
            SIZE_T br = 0;
            SysReadVirtualMemory(hProc, (PVOID)(cb + off.dwEntityList), &elBase, 8, &br, SyscallMethod::Indirect);
            if (elBase) {
                BYTE buf[512] = {};
                SIZE_T br2 = 0;
                SysReadVirtualMemory(hProc, (PVOID)elBase, buf, 512, &br2, SyscallMethod::Indirect);
                for (int row = 0; row < 32; row++) {
                    DiagLog("  +0x%03X: ", row * 16);
                    for (int col = 0; col < 16; col++) DiagLog("%02X ", buf[row * 16 + col]);
                    DiagLog("\n");
                }
                // Also read highest entity index at known offsets
                for (int offTry : {0x2090, 0x20A0, 0x20F0, 0x118, 0x20}) {
                    int hi = 0;
                    SysReadVirtualMemory(hProc, (PVOID)(elBase + offTry), &hi, 4, &br2, SyscallMethod::Indirect);
                    DiagLog("  highestIdx@+0x%X = %d\n", offTry, hi);
                }

                // Try: read identity list pointer at +0x10, mask tag, iterate
                uintptr_t idListTagged = 0;
                SysReadVirtualMemory(hProc, (PVOID)(elBase + 0x10), &idListTagged, 8, &br2, SyscallMethod::Indirect);
                uintptr_t idList = idListTagged & ~0xFULL; // strip tag
                DiagLog("  idList: tagged=0x%llX cleaned=0x%llX\n",
                    (unsigned long long)idListTagged, (unsigned long long)idList);

                // Try dumping first few entries at idList with various step sizes
                for (int stepSize : {0x78, 0x80, 0x88, 0x90, 0x120}) {
                    DiagLog("  -- iter with step=0x%X --\n", stepSize);
                    int valid = 0;
                    for (int i = 0; i < 5 && i <= 13; i++) {
                        uintptr_t addr = idList + i * stepSize;
                        uintptr_t val = 0;
                        SysReadVirtualMemory(hProc, (PVOID)addr, &val, 8, &br2, SyscallMethod::Indirect);
                        if (val > 0x10000) {
                            DiagLog("    [%d] @+0x%X val=0x%llX\n", i, i * stepSize, (unsigned long long)val);
                            valid++;
                        }
                    }
                    if (valid == 0) DiagLog("    (all zero)\n");
                }
            }
        }
    }
    // v3.32: 不创建自己的 Overlay — 基础.exe 负责 GDI overlay ESP 渲染
    //        设置屏幕尺寸供诊断使用
    {
        int w = GetSystemMetrics(SM_CXSCREEN);
        int h = GetSystemMetrics(SM_CYSCREEN);
        cs2::Memory::Instance().SetScreenSize(w, h);
        DiagLog("OK: screen=%dx%d (ESP rendered by basic.exe)\n", w, h);
    }

    // --- 阶段7: 主循环 (反检测维护 + 基础.exe 存活监控) ---
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

    // --- 诊断: 追踪 Controller->Handle->Pawn 链条 ---
    {
        auto& mem = cs2::Memory::Instance();
        auto& off = mem.GetOffsets();
        uintptr_t elBase = mem.EntityList();
        HANDLE hProcDiag = StealthEngine::Instance().GetProcessHandle();
        uintptr_t lpCtl = mem.LocalPlayerController();

        DiagLog("--- Entity Chain Trace ---\n");
        DiagLog("LocalPlayerController: 0x%llX\n", (unsigned long long)lpCtl);

        uint32_t rawHandle; SIZE_T br;
        NTSTATUS st = SysReadVirtualMemory(hProcDiag, (PVOID)(lpCtl + off.m_hPlayerPawn), &rawHandle, 4, &br, SyscallMethod::Indirect);
        DiagLog("pawnHandle raw: status=0x%08X bytes=%zu val=0x%08X idx=%u serial=0x%X\n",
            (unsigned)st, br, rawHandle, rawHandle & 0x7FFF, rawHandle >> 15);

        if (NT_SUCCESS(st) && br == 4 && rawHandle && rawHandle != 0xFFFFFFFF) {
            uintptr_t le;
            SysReadVirtualMemory(hProcDiag, (PVOID)(elBase + 8 * ((rawHandle & 0x7FFF) >> 9) + 16), &le, 8, &br, SyscallMethod::Indirect);
            DiagLog("  pawn chunk raw=0x%llX cleaned=0x%llX\n",
                (unsigned long long)le, (unsigned long long)(le & ~0xFULL));
            le &= ~0xFULL;
            if (le) {
                uintptr_t pawn;
                SysReadVirtualMemory(hProcDiag, (PVOID)(le + 120 * (rawHandle & 0x1FF)), &pawn, 8, &br, SyscallMethod::Indirect);
                DiagLog("  pawn resolved=0x%llX (idx=%u entryOff=0x%llX)\n",
                    (unsigned long long)pawn, rawHandle & 0x1FF,
                    (unsigned long long)(120 * (rawHandle & 0x1FF)));
            }
        }

        // 扫描 Controller 结构: 在 +0x700..+0x900 范围内找有效 pawnHandle
        DiagLog("--- Controller memory scan for pawnHandle (offset+0x700..0x900) ---\n");
        {
            BYTE ctlMem[0x200] = {};
            SIZE_T br2;
            NTSTATUS st2 = SysReadVirtualMemory(hProcDiag, (PVOID)(lpCtl + 0x700), ctlMem, sizeof(ctlMem), &br2, SyscallMethod::Indirect);
            if (NT_SUCCESS(st2)) {
                for (int off = 0; off < (int)sizeof(ctlMem) - 4; off += 4) {
                    uint32_t val = *(uint32_t*)(ctlMem + off);
                    if (val == 0 || val == 0xFFFFFFFF) continue;
                    uint32_t idx = val & 0x7FFF;
                    uint32_t serial = val >> 15;
                    // 有效 handle: index 在合理范围(1..511), serial 非零
                    if (idx >= 1 && idx <= 256 && serial > 0) {
                        DiagLog("  +0x%llX: handle=0x%08X idx=%u serial=0x%X\n",
                            (unsigned long long)(0x700 + off), val, idx, serial);
                    }
                }
            }
        }
        DiagLog("--- Entity Iteration (i=0..511) ---\n");
        for (int i = 0; i < 512; i++) {
            uintptr_t le; SIZE_T br2;
            st = SysReadVirtualMemory(hProcDiag, (PVOID)(elBase + 8 * ((i & 0x7FFF) >> 9) + 16), &le, 8, &br2, SyscallMethod::Indirect);
            le &= ~0xFULL;
            if (!le) { DiagLog("[%d] chunk=NULL\n", i); continue; }
            uintptr_t ctl = 0;
            SysReadVirtualMemory(hProcDiag, (PVOID)(le + 120 * (i & 0x1FF)), &ctl, 8, &br2, SyscallMethod::Indirect);
            if (!ctl) continue;
            bool isLocal = (ctl == lpCtl);
            DiagLog("[%d] ctl=0x%llX%s\n", i, (unsigned long long)ctl, isLocal ? " (LOCAL)" : "");
            uint32_t ph = 0;
            SysReadVirtualMemory(hProcDiag, (PVOID)(ctl + off.m_hPlayerPawn), &ph, 4, &br2, SyscallMethod::Indirect);
            DiagLog("    pawnHandle=0x%08X idx=%u serial=0x%X\n", ph, ph & 0x7FFF, ph >> 15);
            if (ph && ph != 0xFFFFFFFF) {
                uintptr_t le2 = 0;
                SysReadVirtualMemory(hProcDiag, (PVOID)(elBase + 8 * ((ph & 0x7FFF) >> 9) + 16), &le2, 8, &br2, SyscallMethod::Indirect);
                le2 &= ~0xFULL;
                uintptr_t pawn = 0;
                if (le2) SysReadVirtualMemory(hProcDiag, (PVOID)(le2 + 120 * (ph & 0x1FF)), &pawn, 8, &br2, SyscallMethod::Indirect);
                DiagLog("    pawn=0x%llX\n", (unsigned long long)pawn);
            }
        }
        DiagLog("--- End Entity Chain Trace ---\n");
    }

    DiagLog("=== MAIN LOOP START (v3.32: basic.exe ESP) ===\n");
    int frameCount = 0;
    DWORD lastDiagTime = 0;
    while (true) {
        frameCount++;

        // 隐身维护 (ETW/AMSI/VAC/Hook检测/NMI心跳)
        StealthEngine::Instance().OnFrame();

        // Syscall Stub 完整性验证 (每30帧, 防止EAC恢复hook)
        if ((frameCount % 30) == 0) {
            stealth::SyscallGuard::VerifyAndRepair();
        }

        // v3.32: 监控基础.exe 是否还活着 (带退避重试)
        if (g_hBasicProcess) {
            DWORD exitCode = STILL_ACTIVE;
            if (!GetExitCodeProcess(g_hBasicProcess, &exitCode) || exitCode != STILL_ACTIVE) {
                DiagLog("WARN: basic.exe exited (code=%u), restart in %ums...\n",
                    exitCode, g_basicRestartBackoffMs);
                CloseHandle(g_hBasicProcess);
                g_hBasicProcess = nullptr;
                Sleep(g_basicRestartBackoffMs);
                LaunchBasicESP();
                // v3.32-plus: 基础.exe 重启后重新清理注入痕迹
                CleanupInjectionTraces();
                // 指数退避: 每次重启失败后加倍等待 (上限30秒)
                if (g_basicRestartBackoffMs < 30000)
                    g_basicRestartBackoffMs *= 2;
            } else {
                // 基础.exe 正常运行, 重置退避时间
                g_basicRestartBackoffMs = 1000;
            }
        }

        // 每秒一次诊断
        DWORD now = GetTickCount();
        if (now - lastDiagTime >= 5000) {
            lastDiagTime = now;
            uintptr_t elBase = cs2::Memory::Instance().EntityList();
            DiagLog("F=%d basicAlive=%d elBase=0x%llX clientBase=0x%llX\n",
                frameCount,
                (g_hBasicProcess != nullptr) ? 1 : 0,
                (unsigned long long)elBase,
                (unsigned long long)cs2::Memory::Instance().ClientBase());
        }

        // v3.32: EkkoSleep 内存加密 (Sleep期间整段DLL被加密, 防EAC扫描)
        StealthEngine::Instance().StealthSleep(50); // 低频, 减少CPU占用
    }

    TerminateBasicESP();
    stealth::KernelDefense::DisableAll();
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
