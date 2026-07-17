// ============================================================
// payload.cpp — 远程加载 DLL Payload
//
// 编译为 DLL, 经 XTEA 加密后托管在 HTTP 服务器上,
// 由 loader.exe 下载 → 解密 → ManualMap 到内存中执行,
// 全程不落盘, 规避 minifilter 文件扫描。
//
// v3.32: 嵌入基础.exe, 注入后自动启动基础.exe 做 ESP 渲染,
//        本 DLL 只负责反检测 (BYOVD/Syscall/内存加密等),
//        ESP 渲染由基础.exe (GDI overlay) 完成。
//
// DllMain 在 ManualMap 完成后被调用, 直接在当前线程启动主循环,
// 不创建额外线程 (规避 PsSetCreateThreadNotifyRoutine 内核回调)。
// BUILD: 502 (v3.161: Win11 FLT_FRAME bypass — direct .data string scan for minifilter FLT_FILTER)
// ============================================================

#include "stealth_core.h"
#include "cheat_overlay.h"
#include "game_esp.h"
#include "cs2_memory.h"

// ★ BUILD 501: 移除 <algorithm> <vector> <cstdlib> <ctime> — CRT 堆依赖
//   保留 <cstdio> <csetjmp> — DiagLog/Hollowing 回退需要
#include "cs2_offsets.h"
#include "syscall_direct.h"
#include "eac_syscall_guard.h"
#include "byovd_kernel.h"
#include <cstdarg>
#include <cstdio>
#include <csetjmp>
#include <tlhelp32.h>

// ---- v3.34: 时序随机化 ----
static DWORD RandomJitter(DWORD baseMs, DWORD rangeMs) {
    return baseMs + (DWORD)(((uint64_t)rand() * rangeMs) / RAND_MAX);
}

// 轻量诊断: 写文件, 不弹 MessageBox 干扰游戏
// ★ v3.38: 加 FlushFileBuffers 确保崩溃日志实时落盘
static void DiagLog(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len < 0) len = 0; // vsnprintf error fallback
    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"stealth_diag.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);  // ★ v3.38: 强制落盘, 防止崩溃时缓存丢失
        CloseHandle(h);
    }
}

// 崩溃捕获 — 帮助定位 Init 期间的 crash
static HMODULE g_diagDllBase;
static SIZE_T g_diagDllSize;
// ★ v3.70/v3.78: VEH 自愈 — 备份缓冲区 (非 static, byovd_kernel.cpp 通过 extern 引用)
uint8_t* g_backupBuf = nullptr;
SIZE_T   g_backupLen = 0;
uint8_t* g_backupCodeBase = nullptr;
void* g_vehHandlerPageVA = nullptr; // ★ v3.78: VEH handler 所在页 VA (extern 导出)

// ★ v3.82: VEH 重入防护 — 防止恢复过程中自身触发异常导致无限递归
static volatile LONG g_vehRestoring = 0;
// ★ v3.126d: 崩溃计数 — 防止自愈后同一指令再次崩溃导致的无限循环
static volatile LONG g_vehCrashCount = 0;
static constexpr LONG MAX_VEH_RETRIES = 3;

// ★ v3.126f: Hollowing crash fallback — 用 setjmp/longjmp 捕获 ntdll 崩溃并回退到 CreateProcess
static jmp_buf g_hollowJmpBuf;
static bool g_hollowJmpSet = false;

// ★ v3.126g: BYOVD 驱动加载状态 — 当驱动成功加载时跳过 Process Hollowing
static bool g_byovdDriverLoaded = false;

static LONG CALLBACK DiagVehHandler(PEXCEPTION_POINTERS ep) {
    uint64_t crashAddr = (uint64_t)ep->ExceptionRecord->ExceptionAddress;
    uint64_t dllBase   = (uint64_t)g_diagDllBase;
    uint64_t offset    = (dllBase && crashAddr >= dllBase) ? (crashAddr - dllBase) : 0;
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    DiagLog("CRASH: code=0x%08X addr=0x%llX off=%llX\n",
        code, crashAddr, offset);

    // ★ v3.78: VEH 自愈 — 捕获 BYOVD IOCTL 导致的代码/数据污染
    //   STATUS_PRIVILEGED_INSTRUCTION (0xC0000096): 执行了被物理映射覆盖的代码页
    //   STATUS_ACCESS_VIOLATION (0xC0000005): 访问了被破坏的 .data/.bss 页
    bool isPrivInstr = (code == 0xC0000096);
    bool isAccessViol = (code == 0xC0000005);
    if ((isPrivInstr || isAccessViol) && g_backupBuf && g_backupCodeBase && g_backupLen > 0) {
        // ★ v3.126d: 检查崩溃地址是否在备份范围内 — 不在范围内则不自愈
        uintptr_t backupStart = (uintptr_t)g_backupCodeBase;
        uintptr_t backupEnd   = backupStart + g_backupLen;
        if (crashAddr < backupStart || crashAddr >= backupEnd) {
            // 崩溃不在 payload 代码区域, 不自愈 (可能是系统 DLL 或栈)
            DiagLog("VEH: crash outside backup range [0x%llX-0x%llX), skipping self-heal\n",
                (unsigned long long)backupStart, (unsigned long long)backupEnd);
            goto veh_fatal;
        }

        // ★ v3.82: 重入检测 — 如果已经在恢复中又触发异常, 说明恢复过程本身
        //   有页面无法正常操作 (PTE 损坏 / 栈被污染), 放弃恢复避免无限递归
        if (InterlockedExchange(&g_vehRestoring, 1)) {
            DiagLog("VEH-SELFHEAL: RECURSIVE! aborting restore, re-crash at off=0x%llX code=0x%08X\n",
                offset, code);
            // 放弃自愈, 让 MessageBox 弹出通知用户
            g_vehRestoring = 0;
            goto veh_fatal;
        }

        // ★ v3.126d: 自愈计数 — 同一指令连续崩溃超过 MAX_VEH_RETRIES 次即放弃
        if (InterlockedIncrement(&g_vehCrashCount) > MAX_VEH_RETRIES) {
            DiagLog("VEH-SELFHEAL: EXCEEDED MAX_RETRIES (%d), aborting\n", MAX_VEH_RETRIES);
            g_vehRestoring = 0;
            goto veh_fatal;
        }

        DiagLog("VEH-SELFHEAL: restoring %llu bytes from backup@0x%llX → code@0x%llX (cause=%s)\n",
            (unsigned long long)g_backupLen,
            (unsigned long long)g_backupBuf,
            (unsigned long long)g_backupCodeBase,
            isPrivInstr ? "PRIV_INSTR" : "ACCESS_VIOL");

        // ★ v3.70/v3.78: 逐页恢复, 保存/恢复原始保护
        //   v3.70: 跳过 VEH 处理器自身所在页面 (未被污染, 保护不变)
        //   v3.78: 不再强制全部 PAGE_EXECUTE_READ — .data/.bss 必须保持 PAGE_READWRITE
        //   v3.82: 逐页 FlushFileBuffers 确保崩溃页可定位
        uintptr_t handlerPage = ((uintptr_t)&DiagVehHandler) & ~0xFFFULL;
        g_vehHandlerPageVA = (void*)handlerPage;  // 导出供 byovd_kernel.cpp 使用
        uintptr_t codeBase = (uintptr_t)g_backupCodeBase;
        SIZE_T codeLen = g_backupLen;
        const SIZE_T PAGE = 0x1000;

        SIZE_T restored = 0;
        SIZE_T totalPages = (codeLen + PAGE - 1) / PAGE;
        DiagLog("VEH-SELFHEAL: starting per-page restore (%llu pages total)\n",
            (unsigned long long)totalPages);
        for (SIZE_T off = 0; off < codeLen; off += PAGE) {
            uintptr_t pageVA = codeBase + off;
            SIZE_T chunk = (off + PAGE <= codeLen) ? PAGE : (codeLen - off);

            // 跳过 VEH 处理器所在页 (未被污染, 保护不变)
            if ((uintptr_t)pageVA == (uintptr_t)handlerPage) {
                continue;
            }

            DWORD oldProt;
            if (!VirtualProtect((void*)pageVA, chunk, PAGE_READWRITE, &oldProt)) {
                // 页可能无效 (guard/未提交), 跳过
                continue;
            }
            memcpy((void*)pageVA, g_backupBuf + off, chunk);
            // ★ v3.78: 恢复原始保护, 而非强制 EXECUTE_READ
            DWORD restoreProt = (oldProt == PAGE_READWRITE || oldProt == PAGE_READONLY
                || oldProt == PAGE_WRITECOPY || oldProt == PAGE_EXECUTE_WRITECOPY)
                ? PAGE_READWRITE : PAGE_EXECUTE_READ;
            VirtualProtect((void*)pageVA, chunk, restoreProt, &oldProt);
            restored++;

            // ★ v3.83: 每16页输出一次进度日志 (避免撑爆日志但能定位进度)
            if ((restored & 0xF) == 0) {
                DiagLog("VEH-SELFHEAL: progress %llu/%llu pages (off=0x%llX)...\n",
                    (unsigned long long)restored, (unsigned long long)totalPages,
                    (unsigned long long)off);
            }
        }

        g_vehRestoring = 0;
        DiagLog("VEH-SELFHEAL: DONE %llu pages restored, retrying...\n",
            (unsigned long long)restored);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

veh_fatal:

    // ★ v3.126f: Hollowing crash — 用 longjmp 跳回 setjmp 点, 回退到 CreateProcess
    if (g_hollowJmpSet) {
        DiagLog("VEH: hollowing crash detected (addr=0x%llX), jumping to fallback\n",
            (unsigned long long)crashAddr);
        // 清理远程进程
        // 注意: longjmp 会跳转到 setjmp 点, 那里会执行 TerminateProcess
        g_hollowJmpSet = false;
        longjmp(g_hollowJmpBuf, 1);
        // 不会执行到这里
    }

    // ★ v3.68: 不在 VEH 上下文中直接调用 DisableAll (可能触发嵌套异常)
    //   仅记录崩溃信息并通过 MessageBox 通知用户
    //   DisableAll 会在 DllMain 退出路径中由 CheatMainLoop 的 return 分支调用
    wchar_t msg[300];
    swprintf_s(msg, L"崩溃代码: 0x%08X\n"
                     L"崩溃地址: 0x%llX\n"
                     L"DLL偏移:   0x%llX\n\n"
                     L"诊断日志: %%TEMP%%\\stealth_diag.log",
        code, crashAddr, offset);
    MessageBoxW(NULL, msg, L"CS2 Loader 崩溃", MB_OK | MB_ICONERROR | MB_TOPMOST);

    return EXCEPTION_CONTINUE_SEARCH;
}

// v3.32: 基础.exe 进程句柄 (退出时清理)
static HANDLE g_hBasicProcess = nullptr;
static DWORD g_basicRestartBackoffMs = 1000;  // 退避时间, 防止快速重启循环

// v3.34: NtUnmapViewOfSection 函数指针 (用于 Process Hollowing)
typedef LONG(NTAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);
static _NtUnmapViewOfSection g_pNtUnmapViewOfSection = nullptr;

// ★ v3.126f: 手动解析远程进程中的导入表 (IAT) — 批量写入, 减少 ntdll 调用
//   避免逐个 WriteProcessMemory 在 ntdll 中崩溃的问题。
static bool ResolveImportTable(HANDLE hProcess, void* remoteBase,
                                const BYTE* rawExe, const IMAGE_NT_HEADERS64* nt) {
    auto* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0 || importDir->VirtualAddress == 0) return true;

    uintptr_t baseVA = (uintptr_t)remoteBase;
    uintptr_t importRVA = importDir->VirtualAddress;

    DiagLog("ResolveIAT: importRVA=0x%X size=0x%X\n", importRVA, importDir->Size);

    // 第一遍: 统计 IAT 条目总数
    DWORD totalEntries = 0;
    for (DWORD idx = 0; ; idx++) {
        auto* desc = (const IMAGE_IMPORT_DESCRIPTOR*)(rawExe + importRVA + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (desc->Name == 0) break;
        uintptr_t iltRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        for (DWORD ti = 0; ; ti++) {
            uintptr_t* iltEntry = (uintptr_t*)(rawExe + iltRVA + ti * sizeof(uintptr_t));
            if (*iltEntry == 0) break;
            totalEntries++;
        }
    }
    DiagLog("ResolveIAT: %u total IAT entries\n", totalEntries);
    if (totalEntries == 0) return true;

    // ① 先解析所有 DLL 和函数, 填充本地缓冲区
    //   结构: [remoteAddr0, funcAddr0, remoteAddr1, funcAddr1, ...]
    //   每个条目 16 字节 (8 字节远程地址 + 8 字节函数地址)
    struct IATEntry { void* remoteAddr; void* funcAddr; };
    IATEntry* entries = (IATEntry*)VirtualAlloc(nullptr, totalEntries * sizeof(IATEntry),
        MEM_COMMIT, PAGE_READWRITE);
    if (!entries) return false;
    DWORD entryCount = 0;

    DiagLog("ResolveIAT: resolving DLLs...\n");
    for (DWORD idx = 0; ; idx++) {
        auto* desc = (const IMAGE_IMPORT_DESCRIPTOR*)(rawExe + importRVA + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (desc->Name == 0) break;

        const char* dllName = (const char*)(rawExe + desc->Name);
        HMODULE hMod = GetModuleHandleA(dllName);
        if (!hMod) {
            hMod = LoadLibraryA(dllName);
            if (!hMod) continue;
        }

        uintptr_t iatRVA = desc->FirstThunk;
        uintptr_t iltRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : iatRVA;

        for (DWORD ti = 0; ; ti++) {
            uintptr_t* iltEntry = (uintptr_t*)(rawExe + iltRVA + ti * sizeof(uintptr_t));
            uintptr_t entryVal = *iltEntry;
            if (entryVal == 0) break;

            void* funcAddr = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL64(entryVal)) {
                funcAddr = GetProcAddress(hMod, (LPCSTR)MAKEINTRESOURCEA(IMAGE_ORDINAL64(entryVal)));
            } else {
                auto* hintName = (const IMAGE_IMPORT_BY_NAME*)(rawExe + entryVal);
                funcAddr = GetProcAddress(hMod, (LPCSTR)hintName->Name);
            }
            if (funcAddr) {
                entries[entryCount].remoteAddr = (void*)(baseVA + iatRVA + ti * sizeof(uintptr_t));
                entries[entryCount].funcAddr = funcAddr;
                entryCount++;
            }
        }
    }
    DiagLog("ResolveIAT: resolved %u/%u entries\n", entryCount, totalEntries);
    if (entryCount == 0) { VirtualFree(entries, 0, MEM_RELEASE); return true; }

    // ② 批量写入 — 整合为连续缓冲区, 单次 WriteProcessMemory
    //   注意: IAT 条目在远程进程中可能不连续, 所以需要按地址排序写入
    //   将相邻条目合并为连续块, 每块单次写入
    //   先把 entries 按 remoteAddr 排序 (IAT 地址应该是递增的)
    //   简单冒泡排序 (条目数通常 < 100)
    bool sorted = false;
    while (!sorted) {
        sorted = true;
        for (DWORD i = 0; i < entryCount - 1; i++) {
            if ((uintptr_t)entries[i].remoteAddr > (uintptr_t)entries[i + 1].remoteAddr) {
                IATEntry tmp = entries[i];
                entries[i] = entries[i + 1];
                entries[i + 1] = tmp;
                sorted = false;
            }
        }
    }

    // 合并相邻条目为连续块
    DWORD blockStart = 0;
    while (blockStart < entryCount) {
        DWORD blockEnd = blockStart;
        // 扩展连续块: 下一个条目的地址 == 当前块末尾
        while (blockEnd + 1 < entryCount &&
               (uintptr_t)entries[blockEnd + 1].remoteAddr ==
               (uintptr_t)entries[blockEnd].remoteAddr + sizeof(void*)) {
            blockEnd++;
        }
        DWORD blockLen = blockEnd - blockStart + 1;
        SIZE_T blockBytes = blockLen * sizeof(void*);

        // 构建连续的函数地址缓冲区
            void** buf = (void**)VirtualAlloc(nullptr, blockBytes, MEM_COMMIT, PAGE_READWRITE);
            if (buf) {
                for (DWORD i = 0; i < blockLen; i++) {
                    buf[i] = entries[blockStart + i].funcAddr;
                }
                SIZE_T br = 0;
                WriteProcessMemory(hProcess, entries[blockStart].remoteAddr, buf, blockBytes, &br);
                VirtualFree(buf, 0, MEM_RELEASE);
            } else {
                // 逐个写入 (内存不足时回退)
                for (DWORD i = blockStart; i <= blockEnd; i++) {
                    SIZE_T br = 0;
                    WriteProcessMemory(hProcess, entries[i].remoteAddr, &entries[i].funcAddr, sizeof(void*), &br);
                }
            }
        blockStart = blockEnd + 1;
    }

    VirtualFree(entries, 0, MEM_RELEASE);
    DiagLog("ResolveIAT: OK\n");
    return true;
}

// v3.34: Process Hollowing 启动基础.exe
//   将 basic.exe 注入到一个合法的系统进程中 (svchost/rundll32),
//   基础.exe 永不在磁盘上独立运行, 消除二进制特征检测
static bool LaunchBasicESP() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    // Step 1: 找到 basic.exe 文件
    wchar_t exePath[MAX_PATH];
    WIN32_FIND_DATAW fd;
    wsprintfW(exePath, L"%s\\basic_esp_*.exe", tempPath);
    HANDLE hFind = FindFirstFileW(exePath, &fd);
    bool found = false;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
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
        wsprintfW(exePath, L"%s\\basic_esp.exe", tempPath);
        if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) {
            DiagLog("FAIL: basic.exe not found in %%TEMP%%\n");
            return false;
        }
    }

    // Step 2: 读取 basic.exe 到内存并解析 PE
    HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        DiagLog("FAIL: cannot open basic.exe, err=%u\n", GetLastError());
        return false;
    }
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize < sizeof(IMAGE_DOS_HEADER) || fileSize > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }
    // ★ v3.120: VirtualAlloc 替代 std::vector — 避免 CRT 堆依赖
    BYTE* rawExe = (BYTE*)VirtualAlloc(nullptr, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!rawExe) { CloseHandle(hFile); return false; }
    DWORD bytesRead = 0;
    ReadFile(hFile, rawExe, fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    auto* dos = (IMAGE_DOS_HEADER*)rawExe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DiagLog("FAIL: basic.exe invalid PE (bad MZ)\n");
        VirtualFree(rawExe, 0, MEM_RELEASE);
        return false;
    }
    auto* nt = (IMAGE_NT_HEADERS64*)(rawExe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DiagLog("FAIL: basic.exe invalid PE (bad NT sig)\n");
        VirtualFree(rawExe, 0, MEM_RELEASE);
        return false;
    }
    uintptr_t preferredBase = nt->OptionalHeader.ImageBase;
    DWORD    sizeOfImage    = nt->OptionalHeader.SizeOfImage;
    DWORD    sizeOfHeaders  = nt->OptionalHeader.SizeOfHeaders;
    uintptr_t entryRVA      = nt->OptionalHeader.AddressOfEntryPoint;
    DiagLog("basic.exe PE: base=0x%llX size=0x%X entry=0x%llX\n",
        (unsigned long long)preferredBase, sizeOfImage, (unsigned long long)entryRVA);

    // Step 3: 创建合法系统进程 (rundll32) SUSPENDED
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t hostPath[MAX_PATH];
    wsprintfW(hostPath, L"%s\\rundll32.exe", sysDir);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // v3.34: 隐藏窗口 (overlay 由 basic.exe 内部创建)
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(hostPath, nullptr,
        nullptr, nullptr, FALSE,
        CREATE_SUSPENDED,
        nullptr, nullptr, &si, &pi);
    // ★ BUILD 491: 永久跳过 Process Hollowing.
    //   ResolveImportTable 在 Win11 manual-mapped DLL 上下文中始终 ACCESS_VIOLATION,
    //   且 BYOVD 内核访问已可用, Hollowing 的隐蔽性无必要 (DKOM/回调移除更有效).
    //   直接 CreateProcess 启动 basic.exe, 可靠且稳定.
    bool canHollow = false;  // ★ BUILD 491: 永久禁用 Hollowing
    DiagLog("BYOVD driver=%d, skipping hollowing (direct CreateProcess)\n",
        g_byovdDriverLoaded ? 1 : 0);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!g_pNtUnmapViewOfSection) {
        g_pNtUnmapViewOfSection = (_NtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    }

    // 获取 PEB 地址 via NtQueryInformationProcess
    using _NtQueryInfoProc = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto pNtQIP = (_NtQueryInfoProc)GetProcAddress(ntdll, "NtQueryInformationProcess");

    struct PROCESS_BASIC_INFORMATION {
        LONG_PTR ExitStatus;
        PVOID PebBaseAddress;
        LONG_PTR AffinityMask;
        LONG_PTR BasePriority;
        ULONG_PTR UniqueProcessId;
        LONG_PTR InheritedFromUniqueProcessId;
    } pbi = {};

    LONG status = pNtQIP(pi.hProcess, 0, &pbi, sizeof(pbi), nullptr); // ProcessBasicInformation
    if (status < 0 || !pbi.PebBaseAddress) {
        DiagLog("FAIL: NtQueryInformationProcess, status=0x%X\n", status);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        canHollow = false;
    }

    // 读取远程 PEB → ImageBaseAddress (offset +0x10 on x64)
    uintptr_t remotePeb = (uintptr_t)pbi.PebBaseAddress;
    uintptr_t origImageBase = 0;
    SIZE_T br = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(remotePeb + 0x10), &origImageBase, 8, &br) || !origImageBase) {
        DiagLog("FAIL: cannot read remote ImageBase\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        canHollow = false;
    }
    DiagLog("Original ImageBase: 0x%llX\n", (unsigned long long)origImageBase);

    // Step 5: 跳过 NtUnmapViewOfSection (该函数在 ntdll 中崩溃)
    //   basic.exe 的 preferred base (0x140000000) 与 rundll32.exe 的 base (0x7FF7AAC60000)
    //   完全不同, 无需先 unmapping, 直接分配内存即可。
    // ★ v3.126d: 修复 — 跳过 NtUnmapViewOfSection 避免 ntdll 崩溃
    // ★ v3.126f: 恢复 Hollowing — 跳过 preferred base (直接用 nullptr 让系统分配),
    //   避免 VirtualAllocEx 在 ntdll 中崩溃。加细粒度日志精确定位崩溃点。
    //   用 setjmp/longjmp 捕获 ntdll 崩溃, 自动回退到 CreateProcess。
    bool hollowOk = canHollow;
    if (hollowOk) {
        g_hollowJmpSet = true;
        if (setjmp(g_hollowJmpBuf) != 0) {
            // ★ v3.126f: Hollowing 崩溃回退路径 — longjmp 跳回此处
            hollowOk = false;
            DiagLog("Hollowing crashed (ntdll), falling back to CreateProcess\n");
            if (pi.hProcess) {
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                pi.hProcess = nullptr;
            }
        }
    }
    if (hollowOk) {
        // Step 6: 分配内存 (跳过 preferred base, 用 nullptr 让系统选择地址)
        DiagLog("HollowStep6: VirtualAllocEx(nullptr, size=%u)...\n", sizeOfImage);
        PVOID remoteBase = VirtualAllocEx(pi.hProcess, nullptr, sizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            DiagLog("FAIL: VirtualAllocEx, err=%u\n", GetLastError());
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            hollowOk = false;
        } else {
            DiagLog("HollowStep6: OK remoteBase=0x%llX\n", (unsigned long long)remoteBase);
        }

        if (hollowOk) {
            // Step 7: 写入 PE 头
            DiagLog("HollowStep7: WriteProcessMemory(headers, size=%u)...\n", sizeOfHeaders);
            SIZE_T br = 0;
            WriteProcessMemory(pi.hProcess, remoteBase, rawExe, sizeOfHeaders, &br);
            DiagLog("HollowStep7: OK\n");

            // Step 8: 写入各节区
            DiagLog("HollowStep8: writing sections...\n");
            WORD numSections = nt->FileHeader.NumberOfSections;
            auto* firstSec = IMAGE_FIRST_SECTION(nt);
            for (WORD s = 0; s < numSections; s++) {
                if (firstSec[s].SizeOfRawData > 0) {
                    void* destAddr = (BYTE*)remoteBase + firstSec[s].VirtualAddress;
                    WriteProcessMemory(pi.hProcess, destAddr,
                        rawExe + firstSec[s].PointerToRawData,
                        firstSec[s].SizeOfRawData, &br);
                }
            }
            DiagLog("HollowStep8: OK\n");

            // Step 9: 解析导入表
            DiagLog("HollowStep9: ResolveImportTable...\n");
            ResolveImportTable(pi.hProcess, remoteBase, rawExe, nt);
            DiagLog("HollowStep9: OK\n");

            // Step 10: 修正 PEB ImageBase
            DiagLog("HollowStep10: fixing PEB...\n");
            uintptr_t newImageBase = (uintptr_t)remoteBase;
            WriteProcessMemory(pi.hProcess, (void*)(remotePeb + 0x10), &newImageBase, 8, &br);
            DiagLog("HollowStep10: OK\n");

            // Step 11: 设置入口点并恢复线程
            DiagLog("HollowStep11: setting entry + resuming...\n");
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_FULL;
            GetThreadContext(pi.hThread, &ctx);
            DiagLog("HollowStep11: old RIP=0x%llX\n", (unsigned long long)ctx.Rip);
            ctx.Rip = newImageBase + entryRVA;
            SetThreadContext(pi.hThread, &ctx);
            ResumeThread(pi.hThread);
            g_hBasicProcess = pi.hProcess;
            CloseHandle(pi.hThread);

            DiagLog("OK: basic.exe hollowed into rundll32.exe (PID=%u, 0x%llX)\n",
                pi.dwProcessId, (unsigned long long)newImageBase);
            g_hollowJmpSet = false;
            VirtualFree(rawExe, 0, MEM_RELEASE);
            Sleep(RandomJitter(1500, 3000));
            return true;
        }
    } // end if (canHollow)

    // 回退: 直接 CreateProcess (当 Hollowing 失败或不能时)
    // ★ v3.126c: 修复 — 移除 CREATE_NO_WINDOW, 使用 SW_SHOW
    DiagLog("--- FALLBACK: direct CreateProcess ---\n");
    {
        STARTUPINFOW si2 = { sizeof(si2) };
        si2.dwFlags = STARTF_USESHOWWINDOW;
        si2.wShowWindow = SW_SHOW;
        PROCESS_INFORMATION pi2 = {};
        BOOL ok2 = CreateProcessW(exePath, nullptr, nullptr, nullptr, FALSE,
            0, nullptr, tempPath, &si2, &pi2);
        if (!ok2) {
            DiagLog("FAIL: CreateProcessW fallback, err=%u\n", GetLastError());
            VirtualFree(rawExe, 0, MEM_RELEASE);
            return false;
        }
        g_hBasicProcess = pi2.hProcess;
        CloseHandle(pi2.hThread);
        g_hollowJmpSet = false; // 确保清除标志
        DiagLog("OK: basic.exe launched direct, PID=%u\n", pi2.dwProcessId);
    }
    VirtualFree(rawExe, 0, MEM_RELEASE);
    Sleep(RandomJitter(1500, 3000));
    return true;
}

// ★ v3.126: 查找基础.exe 窗口并置顶 — 确保 overlay 窗口在游戏之上
//   基础.exe 是预编译二进制，可能未调用 SetWindowPos(HWND_TOPMOST)
static void BringBasicToTop() {
    if (!g_hBasicProcess) {
        DiagLog("BringBasicToTop: no process handle\n");
        return;
    }
    DWORD targetPid = GetProcessId(g_hBasicProcess);
    if (!targetPid) {
        DiagLog("BringBasicToTop: cannot get PID\n");
        return;
    }
    DiagLog("BringBasicToTop: searching for windows of PID=%u\n", targetPid);

    struct EnumCtx { DWORD pid; HWND found; };
    EnumCtx ctx = { targetPid, nullptr };

    // 枚举所有顶层窗口，查找属于 targetPid 的窗口
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* ctx = reinterpret_cast<EnumCtx*>(lParam);
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == ctx->pid && IsWindowVisible(hwnd)) {
            ctx->found = hwnd;
            return FALSE; // 找到第一个可见窗口即停止
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));

    if (ctx.found) {
        // 置顶显示
        SetWindowPos(ctx.found, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        // 同时尝试 BringWindowToTop
        BringWindowToTop(ctx.found);
        SetForegroundWindow(ctx.found);
        DiagLog("BringBasicToTop: found HWND=0x%llX, brought to top\n",
                (unsigned long long)ctx.found);
    } else {
        DiagLog("BringBasicToTop: no visible window found for PID=%u\n", targetPid);
        // 重试: 等待 500ms 后再试一次 (窗口可能还在创建中)
        Sleep(500);
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* ctx = reinterpret_cast<EnumCtx*>(lParam);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == ctx->pid && IsWindowVisible(hwnd)) {
                ctx->found = hwnd;
                return FALSE;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&ctx));
        if (ctx.found) {
            SetWindowPos(ctx.found, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
            BringWindowToTop(ctx.found);
            SetForegroundWindow(ctx.found);
            DiagLog("BringBasicToTop: retry found HWND=0x%llX, brought to top\n",
                    (unsigned long long)ctx.found);
        } else {
            DiagLog("BringBasicToTop: retry still no window found\n");
        }
    }
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
// 清除 PEB Ldr 链表中的注入模块条目, 防止反作弊用户态模块枚举检测
// 同时清理 VAD PE 头部 + 注入线程的 TEB Win32StartAddress
// v3.33: 新增 VAD PE 头清零 (Method 1) + 线程 StartAddress 欺骗 (Method 2)
static void CleanupInjectionTraces() {
    using namespace stealth;
    HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
    if (!hProc) return;

    // v3.34: 随机等待基础.exe 完成注入
    Sleep(RandomJitter(2500, 2500));
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
        nullptr
    };

    auto isKnownModule = [&](const wchar_t* name) -> bool {
        if (!name[0]) return true; // 空名跳过

        // v3.32-plus: 文件名可能包含完整路径, 对末尾文件名做精确匹配
        const wchar_t* basename = name;
        // 跳过路径部分, 只保留最后一个 \ 之后
        const wchar_t* lastSlash = wcsrchr(name, L'\\');
        if (lastSlash) basename = lastSlash + 1;

        for (int i = 0; knownPrefixes[i]; i++) {
            if (_wcsnicmp(basename, knownPrefixes[i], wcslen(knownPrefixes[i])) == 0)
                return true;
            // 回退: 全路径前缀匹配
            if (_wcsnicmp(name, knownPrefixes[i], wcslen(knownPrefixes[i])) == 0)
                return true;
        }
        return false;
    };

    // 3. 同时清理两个模块链表: InLoadOrder (Ldr+0x10) 和 InMemoryOrder (Ldr+0x20)
    // v3.33: 记录被摘除模块的 dllBase, 后续做 PE 头清零 + 线程欺骗
    struct ListCleanup { uintptr_t headAddr; const char* desc; };
    ListCleanup lists[] = {
        { ldr + 0x10, "InLoadOrder" },
        { ldr + 0x20, "InMemoryOrder" },
    };

    uintptr_t cleanedBases[32] = {};  // v3.33: 记录摘除的模块基址
    int numCleaned = 0;

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
                DiagLog("CleanupInjectionTraces: [%s] UNLINK %ls (base=0x%llX)\n",
                    list.desc, modName, (unsigned long long)dllBase);

                // 记录基址用于后续 PE 头清零 + 线程欺骗
                bool alreadyRecorded = false;
                for (int k = 0; k < numCleaned; k++) {
                    if (cleanedBases[k] == dllBase) { alreadyRecorded = true; break; }
                }
                if (!alreadyRecorded && numCleaned < 32) {
                    cleanedBases[numCleaned++] = dllBase;
                }

                // 读取当前节点的 LIST_ENTRY
                uintptr_t nodeFlink = *(uintptr_t*)(modBuf + 0);
                uintptr_t nodeBlink = *(uintptr_t*)(modBuf + 8);

                if (nodeFlink && nodeBlink) {
                    SIZE_T wb = 0;
                    SysWriteVirtualMemory(hProc, (PVOID)nodeBlink, &nodeFlink, 8, &wb, SyscallMethod::Indirect);
                    SysWriteVirtualMemory(hProc, (PVOID)(nodeFlink + 8), &nodeBlink, 8, &wb, SyscallMethod::Indirect);
                    SysWriteVirtualMemory(hProc, (PVOID)(cur + 0), &cur, 8, &wb, SyscallMethod::Indirect);
                    SysWriteVirtualMemory(hProc, (PVOID)(cur + 8), &cur, 8, &wb, SyscallMethod::Indirect);
                    totalCleaned++;
                }
            }

            cur = flink;
        }
    }

    DiagLog("CleanupInjectionTraces: Ldr done, cleaned %d entries, %d unique bases\n",
        totalCleaned, numCleaned);

    // ============================================================
    // v3.33 Method 1: VAD 区域 PE 头清零
    // 即使反作弊绕过 PEB Ldr 直接扫描 MEM_PRIVATE 可执行页,
    // 也找不到 PE 头 (MZ/PE 签名), 无法确认为注入 DLL
    // ============================================================
    for (int i = 0; i < numCleaned; i++) {
        uintptr_t base = cleanedBases[i];
        if (!base || base < 0x10000) continue;

        // 读取 DLL 基址的 PE 头验证
        BYTE peSig[0x1000] = {};
        SIZE_T rbytes = 0;
        NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)base, peSig, sizeof(peSig), &rbytes, SyscallMethod::Indirect);

        if (NT_SUCCESS(st) && rbytes >= 0x200) {
            // 验证 MZ 签名 (前2字节 = "MZ")
            if (peSig[0] == 'M' && peSig[1] == 'Z') {
                DiagLog("CleanupInjectionTraces: [PE-ZERO] base=0x%llX, zeroing PE header (0x1000 bytes)\n",
                    (unsigned long long)base);

                // 清零 PE 头 (前 0x1000 字节: DOS头 + PE签名 + Optional Header + Section Headers)
                BYTE zeros[0x1000] = {};
                SIZE_T wb = 0;
                NTSTATUS ws = SysWriteVirtualMemory(hProc, (PVOID)base, zeros, 0x1000, &wb, SyscallMethod::Indirect);
                DiagLog("CleanupInjectionTraces: [PE-ZERO] write status=0x%08X bytes=%zu\n",
                    (unsigned)ws, wb);

                // 改保护: MEM_PRIVATE 可执行页 → EXECUTE_READ (模拟 mapped image 的 .text 段)
                // 反作弊 VAD 扫描: mapped image = MEM_MAPPED + EXECUTE_READ; injected = MEM_PRIVATE + EXECUTE_READWRITE
                // 我们无法改 MEM 类型, 但把 protection 改成 EXECUTE_READ 降低可疑程度
                ULONG oldProt = 0;
                SIZE_T regionSize = 0x1000;
                PVOID protAddr = (PVOID)base;
                SysProtectVirtualMemory(hProc, &protAddr, &regionSize, PAGE_EXECUTE_READ, &oldProt,
                    SyscallMethod::Indirect);
            } else {
                DiagLog("CleanupInjectionTraces: [PE-ZERO] base=0x%llX SKIP (no MZ signature)\n",
                    (unsigned long long)base);
            }
        } else {
            DiagLog("CleanupInjectionTraces: [PE-ZERO] base=0x%llX read failed status=0x%08X\n",
                (unsigned long long)base, (unsigned)st);
        }
    }

    // ============================================================
    // v3.33 Method 2: 线程 StartAddress 欺骗
    // 基础.exe 注入后在 cs2.exe 中有额外线程,
    // 反作弊可通过 NtQueryInformationThread → Win32StartAddress 发现
    // 未知范围内的线程 → 判定为注入线程
    // 策略: 将注入线程的 Win32StartAddress 改写为 ntdll!RtlUserThreadStart
    // ============================================================
    if (numCleaned > 0) {
        // 获取 ntdll.dll 在 cs2.exe 中的基址 (从 PEB→Ldr 读取)
        // 使用 RtlUserThreadStart 作为合法启动地址
        // 偏移: ntdll.dll + RtlUserThreadStart offset
        // RtlUserThreadStart 是已知偏移: Win10=0x1E150, Win11=0x21C50 附近
        // 使用更通用的方法: 从我们的 ntdll 获取 RtlUserThreadStart 地址,
        // 再计算 RVA

        // 获取本地 ntdll 的 RtlUserThreadStart 地址
        HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
        uint64_t localRtlUserThreadStart = 0;
        if (hLocalNtdll) {
            localRtlUserThreadStart = (uint64_t)GetProcAddress(hLocalNtdll, "RtlUserThreadStart");
        }

        // 从 cs2.exe 的 PEB 获取 ntdll.dll 基址
        uint64_t remoteNtdllBase = 0;
        {
            BYTE headBuf2[16] = {};
            if (NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)(ldr + 0x10), headBuf2, 16, &br, SyscallMethod::Indirect))) {
                uintptr_t cur2 = *(uintptr_t*)(headBuf2 + 0);
                int w2 = 0;
                while (cur2 && cur2 != (ldr + 0x10) && w2 < 256) {
                    w2++;
                    BYTE modBuf2[0x200] = {};
                    if (!NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)cur2, modBuf2, sizeof(modBuf2), &br, SyscallMethod::Indirect)))
                        break;
                    uintptr_t fl2 = *(uintptr_t*)(modBuf2 + 0);
                    uintptr_t db2 = *(uintptr_t*)(modBuf2 + 0x30);
                    uintptr_t nm = *(uintptr_t*)(modBuf2 + 0x48);
                    USHORT nl = *(USHORT*)(modBuf2 + 0x50);
                    wchar_t mname[64] = {};
                    if (nm && nl > 0 && nl < 128) {
                        SysReadVirtualMemory(hProc, (PVOID)nm, mname, nl, &br, SyscallMethod::Indirect);
                    }
                    if (wcsstr(mname, L"ntdll") || wcsstr(mname, L"NTDLL")) {
                        remoteNtdllBase = db2;
                        break;
                    }
                    cur2 = fl2;
                }
            }
        }
        DiagLog("CleanupInjectionTraces: remote ntdll=0x%llX\n", (unsigned long long)remoteNtdllBase);

        // 计算 RtlUserThreadStart 在远程 ntdll 中的地址
        uint64_t localNtdllBase = 0;
        if (hLocalNtdll) {
            localNtdllBase = (uint64_t)hLocalNtdll;
        }
        uint64_t rvaRtlUserStart = localRtlUserThreadStart - localNtdllBase;
        uint64_t remoteRtlUserThreadStart = remoteNtdllBase ? (remoteNtdllBase + rvaRtlUserStart) : 0;

        DiagLog("CleanupInjectionTraces: local ntdll=0x%llX RtlUserThreadStart=0x%llX rva=0x%llX remote=0x%llX\n",
            (unsigned long long)localNtdllBase, (unsigned long long)localRtlUserThreadStart,
            (unsigned long long)rvaRtlUserStart, (unsigned long long)remoteRtlUserThreadStart);

        // 枚举 cs2.exe 的所有线程
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            DWORD cs2Pid = GetProcessId(hProc);
            THREADENTRY32 te = { sizeof(te) };

            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID != cs2Pid) continue;

                    HANDLE hTh = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
                    if (!hTh) continue;

                    // 查询 Win32StartAddress (class 9)
                    PVOID startAddr = nullptr;
                    ULONG ql = 0;
                    HMODULE localNtdll2 = GetModuleHandleW(L"ntdll.dll");
                    if (localNtdll2) {
                        using NtQIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                        auto pNtQIT = (NtQIT_t)GetProcAddress(localNtdll2, "NtQueryInformationThread");
                        if (pNtQIT) {
                            pNtQIT(hTh, 9, &startAddr, sizeof(startAddr), &ql);
                        }
                    }

                    // 检查 startAddr 是否在注入模块范围内
                    bool isInjected = false;
                    if (startAddr) {
                        uint64_t sa = (uint64_t)startAddr;
                        // 排除 ntdll.dll 和 cs2.exe 自己
                        if (remoteNtdllBase && sa >= remoteNtdllBase && sa < remoteNtdllBase + 0x300000) {
                            // 在 ntdll 范围内 → 合法线程
                        } else {
                            for (int k = 0; k < numCleaned; k++) {
                                if (sa >= cleanedBases[k] && sa < cleanedBases[k] + 0x2000000) {
                                    isInjected = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (isInjected && remoteRtlUserThreadStart) {
                        DiagLog("CleanupInjectionTraces: [THREAD] TID=%lu StartAddr=0x%llX → spoof=0x%llX\n",
                            te.th32ThreadID, (unsigned long long)startAddr,
                            (unsigned long long)remoteRtlUserThreadStart);

                        // 写入 TEB->Win32StartAddress (偏移 0x1C8 in TEB)
                        // 需要先获取线程的 TEB 地址
                        // TEB 地址 = NtQueryInformationThread(ThreadBasicInformation) → TebBaseAddress
                        THREAD_BASIC_INFORMATION tbi = {};
                        ULONG tbiLen = 0;
                        HMODULE localNtdll3 = GetModuleHandleW(L"ntdll.dll");
                        if (localNtdll3) {
                            using NtQIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                            auto pNtQIT2 = (NtQIT_t)GetProcAddress(localNtdll3, "NtQueryInformationThread");
                            if (pNtQIT2) {
                                NTSTATUS tbiSt = pNtQIT2(hTh, 0, &tbi, sizeof(tbi), &tbiLen);
                                if (NT_SUCCESS(tbiSt) && tbi.TebBaseAddress) {
                                    SIZE_T wt = 0;
                                    uintptr_t tebWin32StartAddr = (uintptr_t)tbi.TebBaseAddress + 0x1C8;
                                    SysWriteVirtualMemory(hProc, (PVOID)tebWin32StartAddr,
                                        &remoteRtlUserThreadStart, 8, &wt, SyscallMethod::Indirect);
                                }
                            }
                        }
                    }

                    CloseHandle(hTh);
                } while (Thread32Next(hSnap, &te));
            }

            CloseHandle(hSnap);
        }
    }

    // v3.34 Scheme 1: VAD 节点伪装 (MEM_PRIVATE → MEM_MAPPED)
    //   通过 BYOVD 内核 R/W 修改 cs2.exe 的 VAD 树,
    //   使注入区域看起来像正常模块映射
    if (numCleaned > 0) {
        DWORD cs2Pid = GetProcessId(StealthEngine::Instance().GetProcessHandle());
        int vadOk = VADConcealer::ConcealAllRegions(cs2Pid, cleanedBases, numCleaned);
        DiagLog("CleanupInjectionTraces: [VAD-CONCEAL] %d/%d regions masked\n", vadOk, numCleaned);
    }

    DiagLog("CleanupInjectionTraces: done (PE zero + thread spoof + VAD conceal)\n");
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
    DiagLog("=== v3.158 DIAG START (BUILD 493: PAC probe mode, full .text FltGlobals scan) ===\n");
    DiagLog("BEFORE Init...\n");

    // ★ BUILD 493: PAC Probe 模式 — 当 %TEMP%\pac_probe.flag 存在时,
    //   仅加载驱动 + 验证 FLT 管线 + 尝试中和 PAC, 不触碰 CS2 任何内存/进程.
    //   用于安全验证 PAC 拦截是否有效, 避免在未中和前触发反作弊检测.
    {
        wchar_t probePath[MAX_PATH];
        GetTempPathW(MAX_PATH, probePath);
        wcscat_s(probePath, L"pac_probe.flag");
        bool isPacProbe = (GetFileAttributesW(probePath) != INVALID_FILE_ATTRIBUTES);
        if (isPacProbe) {
            DiagLog("=== PAC PROBE MODE: no CS2 interaction, FLT neutralization only ===\n");
            DiagLog("PAC PROBE: flag found at %ls\n", probePath);

            // 仅初始化 BYOVD (加载驱动 + FLT 管线验证 + PAC 中和)
            auto kr = stealth::KernelDefense::EnableAll();
            DiagLog("PAC PROBE: EnableAll done — driver=%d ob=%d proc=%d img=%d thread=%d pac=%d\n",
                (int)kr.driverLoaded,
                kr.obCallbacksRemoved,
                kr.processCallbacksRemoved,
                kr.imageCallbacksRemoved,
                kr.threadCallbacksRemoved,
                (int)kr.pacDisabled);

            // 检查 FLT 管线验证状态
            if (kr.pacDisabled) {
                DiagLog("PAC PROBE: ✅ PAC neutralization SUCCESS — safe to reboot and run full tool\n");
            } else {
                DiagLog("PAC PROBE: ❌ PAC neutralization FAILED — do NOT run full tool with PAC active\n");
            }

            // 清理并退出
            stealth::KernelDefense::DisableAll();
            DiagLog("=== PAC PROBE EXIT ===\n");
            return 0;
        }
    }

    // v3.34: 随机种子 (基于 PID+TID+TickCount, 规避可预测性)
    srand((unsigned)(GetTickCount() ^ GetCurrentProcessId() ^ GetCurrentThreadId()));

    // 安装 VEH 崩溃捕获器
    g_diagDllBase = dllBase;
    g_diagDllSize = dllSize;
    PVOID vehHandle = AddVectoredExceptionHandler(1, DiagVehHandler);
    DiagLog("VEH registered, dllBase=0x%llX dllSize=%llu\n",
        (unsigned long long)dllBase, (unsigned long long)dllSize);

    // ============================================================
    // 注册 EkkoSleep 内存加密保护区
    // 必须在 PE 头剥离前完成, 否则无法解析 section 边界
    // Sleep 期间整段 DLL 被加密, 防止反作弊内存扫描
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
        // ★ v3.120: 固定数组, 避免 std::vector CRT 堆依赖
        uintptr_t exemptPages[2] = { ekkoPage, vehPage };
        int exemptPageCount = (vehPage != ekkoPage) ? 2 : 1;
        if (exemptPageCount == 2 && exemptPages[0] > exemptPages[1]) {
            uintptr_t tmp = exemptPages[0];
            exemptPages[0] = exemptPages[1];
            exemptPages[1] = tmp;
        }

        SIZE_T totalProtected = 0;
        uintptr_t cursor = codeBase;

        for (int ei = 0; ei < exemptPageCount; ei++) {
            uintptr_t skip = exemptPages[ei];
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
        // ★ v3.111: 提示用户启动 CS2
        MessageBoxW(NULL,
            L"未找到 CS2 进程 (cs2.exe)。\n\n"
            L"请先启动 Counter-Strike 2，然后重新运行 loader.exe。",
            L"CS2 未运行", MB_OK | MB_ICONINFORMATION);
        return 2;
    }
    DiagLog("OK: AttachToProcess, PID=%u HANDLE=%p\n",
        StealthEngine::Instance().GetProcessId(),
        StealthEngine::Instance().GetProcessHandle());

    // 封锁进程句柄 (DACL → 仅允许自身访问, 阻止反作弊通过NtQuerySystemInformation枚举)
    {
        HANDLE hGame = StealthEngine::Instance().GetProcessHandle();
        if (hGame) {
            stealth::HandleACLGuard::LockHandle(hGame);
            DiagLog("OK: HandleACLGuard locked\n");
        } else {
            DiagLog("WARN: HandleACLGuard skipped (no handle)\n");
        }
    }

    // BYOVD 内核防御 — 加载漏洞驱动 + 摘除 PAC 内核回调 (Ring-0)
    // v3.24: 优先 System32\drivers, 回退嵌入提取到 %TEMP%
    // ObRegisterCallbacks/ProcessNotify/ImageNotify → 全部失效
    //
    // ★ v3.79: BYOVD 初始化块 — 重新排序以修复备份缓冲区被 IOCTL 覆盖的致命 bug
    //   BUILD 377/378 的 bug: 备份在 Guard scan 之后分配 → 备份 VA 在 scan 范围外
    //   → IOCTL 映射物理内存到备份 VA → 备份腐败 → VEH 用腐败备份恢复 → 二次崩溃
    //   v3.79 修复: (1) 先分配备份 (2) Guard scan 扩展覆盖备份 VA
    {
        // ★ v3.79 Step 0: 先分配备份缓冲区 — 必须在 Guard scan 之前
        //   否则 Guard scan 不知道备份的 VA, 无法保护备份
        uint32_t preChecksum = 0;
        uint8_t* codeBackupBuf = nullptr;
        SIZE_T   codeLen = 0;  // 供 guard scan 使用
        if (dllBase && dllSize > 0x1000) {
            uint8_t* code = (uint8_t*)dllBase + 0x1000;
            codeLen = dllSize - 0x1000;
            codeBackupBuf = (uint8_t*)VirtualAlloc(nullptr, codeLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (codeBackupBuf) {
                memcpy(codeBackupBuf, code, codeLen);
                g_backupBuf = codeBackupBuf;
                g_backupLen = codeLen;
                g_backupCodeBase = code;
                for (SIZE_T i = 0; i < codeLen; i += 4) {
                    preChecksum ^= *(uint32_t*)(code + i);
                }
                DiagLog("BYOVD: code backup saved [0x%llX, %llu bytes] checksum=0x%08X\n",
                    (unsigned long long)codeBackupBuf, (unsigned long long)codeLen, preChecksum);
                // ★ v3.78: 注册备份缓冲区为保护区 (检测 IOCTL 重叠)
                stealth::KernelMemoryAccessor::RegisterCodeRegion(codeBackupBuf, codeLen);
            }
        }

        // ★ v3.74/v3.79 Layer 1: 强化 Guard Pages — 在 BYOVD IOCTL 之前
        //   v3.79: 扩展扫描范围同时覆盖 DLL 和备份缓冲区
        // ★ v3.120: 固定数组, 避免 std::vector CRT 堆依赖
        struct GuardRegion { void* addr; SIZE_T size; };
        static constexpr size_t MAX_GUARD_REGIONS = 4096;
        GuardRegion guardRegions[MAX_GUARD_REGIONS];
        int guardRegionCount = 0;

        if (dllBase && dllSize > 0x1000) {
            uintptr_t dllStart = (uintptr_t)dllBase;
            uintptr_t dllEnd   = dllStart + dllSize;
            const SIZE_T SCAN_MARGIN = 0x4000000; // ±64MB

            // ★ v3.79: 扩展扫描范围覆盖备份缓冲区
            //   备份与 DLL 可能相距甚远 (VirtualAlloc 可能分配到 DLL+89MB),
            //   需要确保扫描范围同时覆盖两者
            uintptr_t backupStart = codeBackupBuf ? (uintptr_t)codeBackupBuf : 0;
            uintptr_t backupEnd   = (codeBackupBuf && codeLen > 0) ? (backupStart + codeLen) : 0;
            uintptr_t minAddr = dllStart;
            uintptr_t maxAddr = dllEnd;
            if (backupStart && backupStart < minAddr) minAddr = backupStart;
            if (backupEnd   && backupEnd   > maxAddr) maxAddr = backupEnd;

            uintptr_t scanStart = (minAddr > SCAN_MARGIN) ? (minAddr - SCAN_MARGIN) : 0x10000;
            uintptr_t scanEnd   = maxAddr + SCAN_MARGIN;
            if (scanEnd < maxAddr) scanEnd = (uintptr_t)-1; // overflow guard

            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t addr = scanStart;
            while (addr < scanEnd) {
                SIZE_T qr = VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi));
                if (qr == 0) break;

                if (mbi.State == MEM_FREE) {
                    uintptr_t freeStart = (uintptr_t)mbi.BaseAddress;
                    SIZE_T freeSize = mbi.RegionSize;
                    if (freeStart < scanStart) {
                        freeSize -= (scanStart - freeStart);
                        freeStart = scanStart;
                    }
                    if (freeStart + freeSize > scanEnd)
                        freeSize = scanEnd - freeStart;
                    if (freeSize >= 0x1000) {
                        void* r = VirtualAlloc((void*)freeStart, freeSize, MEM_RESERVE, PAGE_NOACCESS);
                        if (r && guardRegionCount < MAX_GUARD_REGIONS) {
                            guardRegions[guardRegionCount].addr = r;
                            guardRegions[guardRegionCount].size = freeSize;
                            guardRegionCount++;
                        }
                    }
                }
                addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            }
            DiagLog("BYOVD: reserved %d guard regions [0x%llX - 0x%llX] (backup@0x%llX dll@0x%llX)\n",
                guardRegionCount,
                (unsigned long long)scanStart, (unsigned long long)scanEnd,
                (unsigned long long)backupStart, (unsigned long long)dllStart);
        }

        // 注册所有 DLL 代码页为保护区 (跳过 PE 头第0页)
        if (dllBase && dllSize > 0x1000) {
            stealth::KernelMemoryAccessor::RegisterCodeRegion(
                (void*)((uintptr_t)dllBase + 0x1000), dllSize - 0x1000);
            DiagLog("BYOVD: registered DLL code region [0x%llX - 0x%llX]\n",
                (unsigned long long)((uintptr_t)dllBase + 0x1000),
                (unsigned long long)((uintptr_t)dllBase + dllSize));
        }

        auto kernelResult = stealth::KernelDefense::EnableAll();

        // ★ v3.75: 后校验 — 仅诊断，不自动恢复
        //   校验覆盖整个 DLL 镜像 (.data/.bss 运行时变化是正常的),
        //   真正的代码污染会触发 STATUS_PRIVILEGED_INSTRUCTION → VEH 自愈
        if (dllBase && dllSize > 0x1000) {
            uint32_t postChecksum = 0;
            uint8_t* code = (uint8_t*)dllBase + 0x1000;
            SIZE_T codeLen = dllSize - 0x1000;
            for (SIZE_T i = 0; i < codeLen; i += 4) {
                postChecksum ^= *(uint32_t*)(code + i);
            }
            if (preChecksum != postChecksum) {
                DiagLog("WARN: DLL checksum changed pre=0x%08X post=0x%08X (data changes during init are normal)\n",
                    preChecksum, postChecksum);
            } else {
                DiagLog("BYOVD: code integrity OK (checksum=0x%08X)\n", postChecksum);
            }
            // ★ v3.78: 永久保留备份 — 主循环中 DKOM/IOCTL 仍可能污染代码,
            //   VEH handler 和 MapPhysical 重叠恢复依赖此备份
            //   同时也保留 g_backupBuf/g_backupLen/g_backupCodeBase 给 byovd_kernel.cpp 使用
            //   (不再释放 codeBackupBuf, 由进程退出时 OS 自动回收)
        }

        g_byovdDriverLoaded = kernelResult.driverLoaded;

        DiagLog("OK: BYOVD driver=%d ob=%d proc=%d img=%d thread=%d pac=%d\n",
            (int)kernelResult.driverLoaded,
            kernelResult.obCallbacksRemoved,
            kernelResult.processCallbacksRemoved,
            kernelResult.imageCallbacksRemoved,
            kernelResult.threadCallbacksRemoved,
            (int)kernelResult.pacDisabled);

        // v3.32: BYOVD 已加载(PAC内核回调已移除), 现在安全启动基础.exe
        //        基础.exe 将调用 OpenProcess+ReadProcessMemory,
        //        这些操作不再被 PAC 内核回调监控
        // ★ v3.80: 移到 guard 释放之前, 确保 CleanupInjectionTraces 中的
        //   DKOM/VAD 操作受 guard pages 保护
        {
            bool basicOk = LaunchBasicESP();
            DiagLog("LaunchBasicESP: %s\n", basicOk ? "SUCCESS" : "FAILED");
            // v3.32-plus: 基础.exe 注入后清理痕迹 (PEB Ldr unlinking)
            if (basicOk) {
                CleanupInjectionTraces();
                // ★ v3.126: 将基础.exe 窗口置顶
                BringBasicToTop();
            }
        }

        // ★ v3.80: 释放 guard pages — 延迟到 CleanupInjectionTraces 之后
        //   防止 DKOM/VAD 操作的 IOCTL 映射腐败 DLL 代码或 VEH handler
        for (int gi = 0; gi < guardRegionCount; gi++) {
            VirtualFree(guardRegions[gi].addr, 0, MEM_RELEASE);
        }
        DiagLog("BYOVD: freed %d guard regions\n",
            guardRegionCount);
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
        StealthProcess::ModuleInfo modules[64];
        int modCount = StealthProcess::GetProcessModules(
            StealthEngine::Instance().GetProcessHandle(), modules, 64);
        DiagLog("GetProcessModules: %d modules found\n", modCount);
        for (int i = 0; i < modCount; i++) {
            if (wcsstr(modules[i].name, L"client") || wcsstr(modules[i].name, L"engine"))
                DiagLog("  %ls @ 0x%llX\n", modules[i].name, (unsigned long long)modules[i].baseAddress);
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
        {
            StealthProcess::ModuleInfo modules[64];
            int modCount = stealth::StealthProcess::GetProcessModules(hProc, modules, 64);
            for (int i = 0; i < modCount; i++) {
                if (wcscmp(modules[i].name, L"client.dll") == 0) {
                    clientSize = modules[i].size;
                    break;
                }
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

    DiagLog("=== MAIN LOOP START (v3.37: VirtualProtect fix + crash protection) ===\n");
    int frameCount = 0;
    DWORD lastDiagTime = 0;
    DWORD lastRetryTime = 0;
    bool  g_basicDone = false;  // v3.48: 正常退出后禁止重连

    while (true) {
        frameCount++;

        // 隐身维护 (ETW/AMSI/VAC/Hook检测/NMI心跳)
        StealthEngine::Instance().OnFrame();

        // v3.34: Syscall Stub 验证间隔随机化 (25-35帧, 固定30帧可被时序分析)
        static int syscallCheckInterval = (int)RandomJitter(25, 10);
        if ((frameCount % syscallCheckInterval) == 0) {
            stealth::SyscallGuard::VerifyAndRepair();
            syscallCheckInterval = (int)RandomJitter(25, 10); // 每次重随机
        }

        // ★ v3.126g: PAC 周期性监控 — 每500-1500ms 检查反作弊驱动是否加载,
        //   如果加载则自动摘除内核回调, 解决反作弊在 BYOVD 之后启动的问题
        //   短随机间隔确保反作弊初始化未完成时就被摘除, 不给反作弊可乘之机
        //   注意: 使用 GetTickCount 而非 frameCount, 避免 Sleep 波动影响
        {
            static DWORD lastPacCheck = 0;
            DWORD nowTick = GetTickCount();
            static DWORD pacCheckInterval = RandomJitter(500, 1000);
            if (nowTick - lastPacCheck >= pacCheckInterval) {
                lastPacCheck = nowTick;
                pacCheckInterval = RandomJitter(500, 1000);
                if (stealth::KernelMemoryAccessor::Instance().IsActive()) {
                    stealth::KernelDefense::ReapplyAllCallbacks();
                }
            }
        }

        // 监控基础.exe 是否还活着
        if (g_hBasicProcess && !g_basicDone) {
            DWORD exitCode = STILL_ACTIVE;
            if (!GetExitCodeProcess(g_hBasicProcess, &exitCode) || exitCode != STILL_ACTIVE) {
                // v3.48: code=0 = normal exit (ESP injected), don't retry
                if (exitCode == 0) {
                    DiagLog("INFO: basic.exe exited normally (code=0), ESP injected. No retry.\n");
                    CloseHandle(g_hBasicProcess);
                    g_hBasicProcess = nullptr;
                    g_basicDone = true; // permanent no-retry
                } else {
                    DiagLog("WARN: basic.exe crashed (code=%u), will retry...\n", exitCode);
                    CloseHandle(g_hBasicProcess);
                    g_hBasicProcess = nullptr;
                    lastRetryTime = GetTickCount() - g_basicRestartBackoffMs;
                }
            } else {
                g_basicRestartBackoffMs = RandomJitter(800, 400);
            }
        }

        // 重试启动 (仅非正常退出时)
        if (!g_hBasicProcess && !g_basicDone) {
            DWORD nowTick = GetTickCount();
            if (nowTick - lastRetryTime >= g_basicRestartBackoffMs) {
                lastRetryTime = nowTick;
                bool restartOk = LaunchBasicESP();
                DiagLog("basic.exe retry: %s (backoff=%ums)\n",
                    restartOk ? "OK" : "FAILED", g_basicRestartBackoffMs);
                if (restartOk) {
                    CleanupInjectionTraces();
                    // ★ v3.126: 重启后也置顶窗口
                    BringBasicToTop();
                    g_basicRestartBackoffMs = RandomJitter(800, 400);

                    // v3.34 Scheme 4: DKOM 隐藏 basic.exe 进程
                    stealth::DKOMProcessHider::Instance().HideProcess();
                } else {
                    if (g_basicRestartBackoffMs < 30000)
                        g_basicRestartBackoffMs *= 2;
                }
            }
        }

        // v3.34: 诊断间隔随机化 (4-6秒, 规避固定节奏)
        DWORD now = GetTickCount();
        static DWORD diagInterval = RandomJitter(4000, 2000);
        if (now - lastDiagTime >= diagInterval) {
            lastDiagTime = now;
            diagInterval = RandomJitter(4000, 2000);
            uintptr_t elBase = cs2::Memory::Instance().EntityList();
            DiagLog("F=%d basicAlive=%d elBase=0x%llX clientBase=0x%llX\n",
                frameCount,
                (g_hBasicProcess != nullptr) ? 1 : 0,
                (unsigned long long)elBase,
                (unsigned long long)cs2::Memory::Instance().ClientBase());
        }

        // v3.34: EkkoSleep 随机间隔 30-170ms (规避固定周期时序特征)
        DWORD sleepMs = RandomJitter(40, 130);
        // DiagLog("SLEEP: entering StealthSleep(%u)\n", sleepMs); // 太频繁, 仅调试时启用
        StealthEngine::Instance().StealthSleep(sleepMs);
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
