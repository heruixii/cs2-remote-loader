// find_ntdll_offset.cpp — 查找 ntdll+0x2152 对应的函数
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>

#pragma comment(lib, "psapi.lib")

int main() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("Failed to get ntdll handle\n");
        return 1;
    }
    uintptr_t base = (uintptr_t)hNtdll;
    uintptr_t target = base + 0x2152;
    printf("ntdll base: 0x%llX\n", (unsigned long long)base);
    printf("target addr (base+0x2152): 0x%llX\n", (unsigned long long)target);

    // 枚举 ntdll 导出函数, 找到包含 target 地址的函数
    MODULEINFO mi = {};
    GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi));
    printf("ntdll SizeOfImage: 0x%X\n", mi.SizeOfImage);

    // 读取 PE 导出表
    auto* dos = (IMAGE_DOS_HEADER*)base;
    auto* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.Size == 0) {
        printf("No export directory\n");
        return 1;
    }
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);

    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);

    // 遍历所有命名导出, 找到 RVA <= 0x2152 且最接近的
    // 寻找 targetRva 所在的函数 (RVA <= targetRva 的最大者)
    // ★ BUILD 534 崩溃: 0x7FFF2C1F2152 - 0x7FFF2C180000 = 0x72152 (非 0x2152)
    DWORD targetRva = 0x72152;
    DWORD bestRva = 0;
    const char* bestName = nullptr;
    DWORD bestSize = 0;

    printf("\nSearching for function containing offset 0x2152...\n");
    printf("Total named exports: %u\n", exp->NumberOfNames);

    // 先收集所有 (RVA, name) 对并按 RVA 排序
    struct ExportEntry { DWORD rva; const char* name; };
    ExportEntry* entries = new ExportEntry[exp->NumberOfNames];
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        entries[i].rva = funcs[ords[i]];
        entries[i].name = (const char*)(base + names[i]);
    }
    // 简单冒泡排序
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        for (DWORD j = i + 1; j < exp->NumberOfNames; j++) {
            if (entries[j].rva < entries[i].rva) {
                ExportEntry tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }

    // 找到 targetRva 所在的函数 (RVA <= targetRva 的最大者)
    int targetIdx = -1;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (entries[i].rva <= targetRva) {
            targetIdx = (int)i;
        } else {
            break;
        }
    }

    if (targetIdx >= 0) {
        DWORD funcRva = entries[targetIdx].rva;
        const char* funcName = entries[targetIdx].name;
        DWORD nextRva = (targetIdx + 1 < (int)exp->NumberOfNames) ? entries[targetIdx + 1].rva : mi.SizeOfImage;
        DWORD size = nextRva - funcRva;
        DWORD offsetInFunc = targetRva - funcRva;
        printf("\n>>> FOUND: %s\n", funcName);
        printf("    RVA: 0x%X (offset +0x%X in function)\n", funcRva, offsetInFunc);
        printf("    Approx size: 0x%X bytes\n", size);
        printf("    VA: 0x%llX\n", (unsigned long long)(base + funcRva));
    } else {
        printf("No function found at or before offset 0x2152\n");
    }

    // 额外: 打印 0x72000-0x73000 范围内的所有函数
    printf("\n--- Functions in RVA range [0x72000, 0x73000) ---\n");
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (entries[i].rva >= 0x72000 && entries[i].rva < 0x73000) {
            DWORD nextRva = (i + 1 < exp->NumberOfNames) ? entries[i + 1].rva : mi.SizeOfImage;
            DWORD sz = nextRva - entries[i].rva;
            printf("  0x%05X  size=0x%-4X  %s\n", entries[i].rva, sz, entries[i].name);
        }
    }

    // 同时打印 0x2000-0x3000 (原假设范围, 用于对比)
    printf("\n--- Functions in RVA range [0x2000, 0x3000) for comparison ---\n");
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (entries[i].rva >= 0x2000 && entries[i].rva < 0x3000) {
            DWORD nextRva = (i + 1 < exp->NumberOfNames) ? entries[i + 1].rva : mi.SizeOfImage;
            DWORD sz = nextRva - entries[i].rva;
            printf("  0x%05X  size=0x%-4X  %s\n", entries[i].rva, sz, entries[i].name);
        }
    }

    delete[] entries;
    return 0;
}
