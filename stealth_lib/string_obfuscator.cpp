// string_obfuscator.cpp — 字符串混淆实现
#include "platform.h"

#include "string_obfuscator.h"
#include <string>
#include <vector>
#include <random>
#include <winternl.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

namespace stealth {

// ============================================================
// StringObfuscator
// ============================================================

std::vector<uint8_t> StringObfuscator::Encrypt(const std::string& str, uint8_t key) {
    std::vector<uint8_t> result(str.begin(), str.end());
    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= key ^ static_cast<uint8_t>(i * 0xAD);
    }
    return result;
}

// 使用 volatile 防止编译器将 memset 优化掉
void StringObfuscator::SecureZero(void* ptr, size_t size) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    // 内存屏障, 确保写入完成
    MemoryBarrier();
}

// ============================================================
// ApiResolver
// ============================================================

uint32_t ApiResolver::HashString(const char* str) {
    uint32_t hash = 5381; // djb2
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str++);
    }
    return hash;
}

FARPROC ApiResolver::ResolveApi(const char* dllName, const char* funcName) {
    // 使用已知的干净函数指针链
    // 1. 从 PEB 获取 kernel32 基址 (不用 LoadLibrary, 规避导入表)
    HMODULE kernel32 = GetModuleBase("kernel32.dll");
    if (!kernel32) return nullptr;

    // 2. 通过 kernel32 的 GetProcAddress / LoadLibrary 解析
    // 注意: 这两个调用本身会经过 kernel32, 但因为 kernel32 是几乎所有程序都加载的,
    // 所以单独存在并不构成特征
    using LoadLibraryA_t = HMODULE(WINAPI*)(const char*);
    using GetProcAddress_t = FARPROC(WINAPI*)(HMODULE, const char*);

    auto pLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(
        GetProcAddress(kernel32, "LoadLibraryA"));
    auto pGetProcAddress = reinterpret_cast<GetProcAddress_t>(
        GetProcAddress(kernel32, "GetProcAddress"));

    if (!pLoadLibraryA || !pGetProcAddress) return nullptr;

    HMODULE mod = pLoadLibraryA(dllName);
    if (!mod) return nullptr;

    return pGetProcAddress(mod, funcName);
}

HMODULE ApiResolver::GetModuleBase(const char* moduleName) {
    // 从 PEB_LDR_DATA 遍历已加载模块 (不调用任何 API)
    // 规避: 对 CreateToolhelp32Snapshot/Module32First 等 API 的监控

    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));

    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return nullptr;

    PLIST_ENTRY head = LDR_MEMORY_HEAD(ldr);
    PLIST_ENTRY entry = head->Flink;

    uint32_t targetHash = HashString(moduleName);

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY dataEntry =
            CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        PUNICODE_STRING baseName = LDR_ENTRY_BASE_NAME(dataEntry);
        if (baseName->Buffer) {
            // 将宽字符转为小写 ASCII 进行哈希比较
            char ansiBuf[256] = {};
            int i = 0;
            for (; i < static_cast<int>(baseName->Length / sizeof(WCHAR)) && i < 255; i++) {
                WCHAR wch = baseName->Buffer[i];
                ansiBuf[i] = static_cast<char>((wch >= L'A' && wch <= L'Z') ? wch + 32 : wch);
            }
            ansiBuf[i] = '\0';

            if (HashString(ansiBuf) == targetHash) {
                return static_cast<HMODULE>(LDR_ENTRY_DLLBASE(dataEntry));
            }
        }

        entry = entry->Flink;
    }

    return nullptr;
}

bool ApiResolver::IsAddressInLegitModule(uintptr_t addr) {
    // 获取地址所在模块信息
    HMODULE hMod = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        hMod = static_cast<HMODULE>(mbi.AllocationBase);
    }

    if (!hMod) return false;

    // 获取模块路径
    WCHAR modPath[MAX_PATH] = {};
    GetModuleFileNameW(hMod, modPath, MAX_PATH);

    // 验证路径在 System32 内 (合法系统模块)
    // 规避: 外部注入 DLL 的 VTable Hook 往往不在 System32 范围内
    std::wstring path(modPath);
    for (auto& c : path) c = towlower(c);

    bool inSystem32 = (path.find(L"\\system32\\") != std::wstring::npos ||
                       path.find(L"\\syswow64\\") != std::wstring::npos);

    bool inKnownGood = (path.find(L"\\steam\\") != std::wstring::npos ||
                        path.find(L"\\counter-strike") != std::wstring::npos);

    return inSystem32 || inKnownGood;
}

FARPROC ApiResolver::ReloadFromDisk(const char* dllName, const char* funcName) {
    // 从磁盘读取 DLL 文件的原始 .rdata 导出表
    // 规避: 运行时被 hook 的内存版本

    WCHAR sysPath[MAX_PATH];
    GetSystemDirectoryW(sysPath, MAX_PATH);

    std::wstring fullPath(sysPath);
    fullPath += L"\\";

    // 转换 DLL 名到宽字符
    std::string dllNameStr(dllName);
    fullPath += std::wstring(dllNameStr.begin(), dllNameStr.end());

    // 映射文件到内存 (只读方式, 绕过任何运行时修改)
    HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return nullptr;

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr,
        PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(hFile);

    if (!hMapping) return nullptr;

    LPVOID baseAddr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);

    if (!baseAddr) return nullptr;

    // 解析 PE 导出表获取原始函数 RVA, 然后加上当前模块基址
    PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(baseAddr);
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(baseAddr) + dos->e_lfanew);

    auto exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) {
        UnmapViewOfFile(baseAddr);
        return nullptr;
    }

    PIMAGE_EXPORT_DIRECTORY expDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<uintptr_t>(baseAddr) + exportRva);

    auto* names = reinterpret_cast<DWORD*>(reinterpret_cast<uintptr_t>(baseAddr) + expDir->AddressOfNames);
    auto* ordinals = reinterpret_cast<WORD*>(reinterpret_cast<uintptr_t>(baseAddr) + expDir->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<DWORD*>(reinterpret_cast<uintptr_t>(baseAddr) + expDir->AddressOfFunctions);

    uint32_t targetHash = HashString(funcName);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        const char* name = reinterpret_cast<const char*>(reinterpret_cast<uintptr_t>(baseAddr) + names[i]);
        if (HashString(name) == targetHash) {
            DWORD funcRva = funcs[ordinals[i]];

            // 获取当前进程中 ntdll.dll 的基址
            HMODULE ntdll = GetModuleBase(dllName);
            if (ntdll) {
                FARPROC result = reinterpret_cast<FARPROC>(
                    reinterpret_cast<uintptr_t>(ntdll) + funcRva);
                UnmapViewOfFile(baseAddr);
                return result;
            }
            break;
        }
    }

    UnmapViewOfFile(baseAddr);
    return nullptr;
}

} // namespace stealth
