#pragma once
// ============================================================
// module_resolver.h — PEB Ldr 遍历 + 编译期模块名哈希
//
// ★ BUILD 550: 共享模块解析工具 (替代 GetModuleHandleA/W)
//   规避: PAC 用户态 hook GetModuleHandleA/W, 通过 PEB 直接读取模块基址
//   二进制中: 不出现 "client.dll"/"ntdll.dll" 等明文模块名 (使用编译期 djb2 哈希)
//
// x64 内存布局:
//   GS:0x60                     → PEB
//   PEB+0x18                    → PEB_LDR_DATA* Ldr
//   Ldr+0x20                    → LIST_ENTRY InMemoryOrderModuleList (Flink/Blink)
//   LDR_DATA_TABLE_ENTRY+0x10   → InMemoryOrderLinks (Flink 指向此处)
//   LDR_DATA_TABLE_ENTRY+0x30   → DllBase
//   LDR_DATA_TABLE_ENTRY+0x58   → BaseDllName (UNICODE_STRING, Buffer@+0x08)
// ============================================================

#include <Windows.h>
#include <winternl.h>  // ★ BUILD 550: UNICODE_STRING 定义
#include <cstdint>

namespace stealth {

// 编译期 djb2 哈希 (wchar_t, 不区分大小写)
//   用法: constexpr uint32_t h = stealth::ModNameHash(L"client.dll");
//         二进制中只出现 h 的常量值, 不出现 L"client.dll"
constexpr uint32_t ModNameHash(const wchar_t* s, uint32_t h = 5381) {
    return (!*s) ? h : ModNameHash(s + 1,
        ((h << 5) + h) + (uint32_t)(
            (*s >= L'A' && *s <= L'Z') ? (*s + (L'a' - L'A')) : *s
        ));
}

// 运行时 djb2 哈希 (用于动态字符串, 如 ResolveImportTable 的 dllName)
inline uint32_t ModNameHashRT(const wchar_t* s) {
    if (!s) return 0;
    uint32_t h = 5381;
    while (*s) {
        wchar_t c = *s;
        if (c >= L'A' && c <= L'Z') c = c + (L'a' - L'A');
        h = ((h << 5) + h) + (uint32_t)c;
        s++;
    }
    return h;
}

// 通过 PEB Ldr 遍历获取模块基址 (替代 GetModuleHandleA/W)
//   nameHash: 编译期或运行时计算的 djb2 哈希 (不区分大小写)
//   返回: 模块基址 (HMODULE), 未找到返回 nullptr
inline HMODULE GetModuleBaseFromPEB(uint32_t nameHash) {
    if (!nameHash) return nullptr;

    // x64: PEB 在 GS:0x60 (TEB+0x60 = PEB)
    uint64_t peb;
#if defined(_MSC_VER)
    peb = __readgsqword(0x60);
#elif defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
#else
    return nullptr;
#endif
    if (!peb) return nullptr;

    // PEB->Ldr (PEB+0x18)
    uint8_t* ldr = *(uint8_t**)(peb + 0x18);
    if (!ldr) return nullptr;

    // Ldr->InMemoryOrderModuleList (Ldr+0x20) — LIST_ENTRY, Flink 指向下一个 entry 的 InMemoryOrderLinks
    auto* listHead = (LIST_ENTRY*)(ldr + 0x20);
    auto* entry = listHead->Flink;
    if (!entry) return nullptr;

    // 遍历链表 (InMemoryOrderLinks 在 LDR_DATA_TABLE_ENTRY+0x10)
    while (entry != listHead) {
        auto* dataTableEntry = (uint8_t*)entry - 0x10;  // 回退到 LDR_DATA_TABLE_ENTRY 起始
        auto dllBase = *(HMODULE*)(dataTableEntry + 0x30);  // DllBase
        auto* baseDllName = (UNICODE_STRING*)(dataTableEntry + 0x58);  // BaseDllName

        if (dllBase && baseDllName->Buffer && baseDllName->Length > 0) {
            // 运行时计算 djb2 哈希 (不区分大小写)
            uint32_t hash = 5381;
            USHORT nameLen = baseDllName->Length / sizeof(WCHAR);
            for (USHORT i = 0; i < nameLen; i++) {
                WCHAR c = baseDllName->Buffer[i];
                if (c >= L'A' && c <= L'Z') c = c + (L'a' - L'A');
                hash = ((hash << 5) + hash) + (uint32_t)c;
            }
            if (hash == nameHash) return dllBase;
        }
        entry = entry->Flink;
    }

    return nullptr;
}

} // namespace stealth
