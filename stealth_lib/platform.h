#pragma once
// ============================================================
// platform.h — MSVC/MinGW 跨编译器兼容层
// 补充 MinGW-w64 缺失的 NT 结构、常量、宏定义
// ============================================================

#ifndef STEALTH_PLATFORM_H
#define STEALTH_PLATFORM_H

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winternl.h>
// ★ BUILD 501: 移除 <algorithm> <cstring> — 避免 CRT 堆依赖
//   std::min/max 替换为自定义模板, memcpy/memset 由 Windows.h 提供

// ============================================================
// min/max 模板 — 替代 std::min/std::max (避免 <algorithm> CRT 依赖)
// ============================================================
namespace stealth_platform {
    template<typename T>
    inline const T& min(const T& a, const T& b) { return (b < a) ? b : a; }
    template<typename T>
    inline const T& max(const T& a, const T& b) { return (a < b) ? b : a; }
}

// ============================================================
// PUNWIND_INFO — MinGW 的 <winnt.h> 可能未定义此类型
// ============================================================
#ifndef _MSC_VER
#ifndef PUNWIND_INFO_DEFINED
#define PUNWIND_INFO_DEFINED
typedef struct _UNWIND_INFO* PUNWIND_INFO;
#endif
#endif

// ============================================================
// NTSTATUS 常量 (MinGW <winternl.h> 可能缺失)
// ============================================================
#ifndef STATUS_INFO_LENGTH_MISMATCH
    #define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_NOT_SUPPORTED
    #define STATUS_NOT_SUPPORTED         ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_UNSUCCESSFUL
    #define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)
#endif

// ============================================================
// 其他缺失常量
// ============================================================
#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
    #define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x4
#endif

// ============================================================
// MinGW 缺失/不完整的 NT 结构体
// ============================================================

#ifndef _MSC_VER

// ---- THREAD_BASIC_INFORMATION (ThreadInformationClass=0) ----
#ifndef THREAD_BASIC_INFORMATION_DEFINED
#define THREAD_BASIC_INFORMATION_DEFINED
typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
#endif

// ---- SYSTEM_HANDLE_INFORMATION 完整版 (x64 Windows 10/11) ----
// SystemHandleInformation (0x10) 返回 32-byte 条目:
//   ULONG UniqueProcessId(4) + USHORT CreatorBackTraceIndex(2) + UCHAR ObjectTypeIndex(1)
//   + UCHAR HandleAttributes(1) + USHORT HandleValue(2) → 共 10 bytes
//   + 6 bytes pad → PVOID Object 在 offset 16
//   + ULONG GrantedAccess(4) → 共 24 bytes → +4 pad → 总共 32 bytes
typedef struct _STEALTH_HANDLE_TABLE_ENTRY {
    ULONG    UniqueProcessId;       // offset 0 (4 bytes)
    USHORT   CreatorBackTraceIndex; // offset 4 (2 bytes)
    UCHAR    ObjectTypeIndex;       // offset 6
    UCHAR    HandleAttributes;      // offset 7
    USHORT   HandleValue;           // offset 8 (2 bytes)
    // 6 bytes implicit padding here for 8-byte alignment
    PVOID    Object;                // offset 16 (8 bytes)
    ACCESS_MASK GrantedAccess;      // offset 24 (4 bytes)
    // 4 bytes implicit pad → total 32 bytes
} STEALTH_HANDLE_TABLE_ENTRY, *PSTEALTH_HANDLE_TABLE_ENTRY;

typedef struct _STEALTH_HANDLE_INFO {
    ULONG    NumberOfHandles;       // offset 0 (4 bytes)
    STEALTH_HANDLE_TABLE_ENTRY Handles[1];  // offset 4 — 直接, 无 Reserved!
} STEALTH_HANDLE_INFO, *PSTEALTH_HANDLE_INFO;

// ---- LDR_DATA_TABLE_ENTRY 完整版 ----
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct { PVOID SectionPointer; ULONG CheckSum; };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID      EntryPointActivationContext;
    PVOID      PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// ---- PEB/LDR 偏移访问辅助函数 (x64) ----

// 辅助: 从 _PEB* 获取 ProcessHeap
inline HANDLE PEB_GetProcessHeap(void* pebPtr) {
    // x64 PEB::ProcessHeap 在偏移 0x30
    return *reinterpret_cast<HANDLE*>(reinterpret_cast<BYTE*>(pebPtr) + 0x30);
}

// 辅助: 从 _PEB_LDR_DATA* 获取 InLoadOrderModuleList 的地址 (偏移 0x10)
inline PLIST_ENTRY LDR_GetInLoadOrderHead(void* ldrPtr) {
    return reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<BYTE*>(ldrPtr) + 0x10);
}
// 辅助: 从 _PEB_LDR_DATA* 获取 InMemoryOrderModuleList 的地址 (偏移 0x20)
inline PLIST_ENTRY LDR_GetInMemoryOrderHead(void* ldrPtr) {
    return reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<BYTE*>(ldrPtr) + 0x20);
}
// 辅助: 从 _PEB_LDR_DATA* 获取 InInitializationOrderModuleList 的地址 (偏移 0x30)
inline PLIST_ENTRY LDR_GetInInitOrderHead(void* ldrPtr) {
    return reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<BYTE*>(ldrPtr) + 0x30);
}

// 辅助: LDR_DATA_TABLE_ENTRY 偏移访问
inline PLIST_ENTRY LDR_ENTRY_LoadLinks(void* entryPtr) {
    return reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<BYTE*>(entryPtr));
}
inline PLIST_ENTRY LDR_ENTRY_MemoryLinks(void* entryPtr) {
    return reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<BYTE*>(entryPtr) + 0x10);
}
inline PLIST_ENTRY LDR_ENTRY_InitLinks(void* entryPtr) {
    return reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<BYTE*>(entryPtr) + 0x20);
}
inline PVOID LDR_ENTRY_DllBase(void* entryPtr) {
    return *reinterpret_cast<PVOID*>(reinterpret_cast<BYTE*>(entryPtr) + 0x30);
}
inline PUNICODE_STRING LDR_ENTRY_BaseDllName(void* entryPtr) {
    return reinterpret_cast<PUNICODE_STRING>(reinterpret_cast<BYTE*>(entryPtr) + 0x48);
}

#endif // !_MSC_VER

// ============================================================
// PEB/LDR 跨编译器统一访问宏
// ============================================================
#ifdef _MSC_VER
    #define PEB_PROCESS_HEAP(peb)        ((peb)->ProcessHeap)
    #define PEB_LDR_PTR(peb)             ((peb)->Ldr)
    #define PEB_BEING_DEBUGGED(peb)      ((peb)->BeingDebugged)
    #define PEB_NT_GLOBAL_FLAG(peb)      ((peb)->NtGlobalFlag)
    #define LDR_INLOAD_HEAD(ldr)         (&(ldr)->InLoadOrderModuleList)
    #define LDR_MEMORY_HEAD(ldr)         (&(ldr)->InMemoryOrderModuleList)
    #define LDR_INIT_HEAD(ldr)           (&(ldr)->InInitializationOrderModuleList)
    
    #define LDR_ENTRY_LOAD_LINKS(e)      (&(e)->InLoadOrderLinks)
    #define LDR_ENTRY_MEMORY_LINKS(e)    (&(e)->InMemoryOrderLinks)
    #define LDR_ENTRY_INIT_LINKS(e)      (&(e)->InInitializationOrderLinks)
    #define LDR_ENTRY_DLLBASE(e)         ((e)->DllBase)
    #define LDR_ENTRY_FULL_NAME(e)       (&(e)->FullDllName)
    #define LDR_ENTRY_BASE_NAME(e)       (&(e)->BaseDllName)
    #define LDR_ENTRY_SIZE_OF_IMAGE(e)   ((e)->SizeOfImage)

    // 句柄信息直接用 MSVC 原生类型
    #define STEALTH_HANDLE_INFO_CAST(ptr)  reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(ptr)
    inline HANDLE PEB_GetProcessHeap(void* peb) { return ((PPEB)peb)->ProcessHeap; }
    inline PLIST_ENTRY LDR_GetInLoadOrderHead(void* ldr) { return &((PPEB_LDR_DATA)ldr)->InLoadOrderModuleList; }
#else
    #define PEB_PROCESS_HEAP(peb)        PEB_GetProcessHeap(peb)
    #define PEB_LDR_PTR(peb)             (reinterpret_cast<PPEB_LDR_DATA>((peb)->Ldr))
    #define PEB_BEING_DEBUGGED(peb)      ((peb)->BeingDebugged)
    #define PEB_NT_GLOBAL_FLAG(peb)      ((peb)->NtGlobalFlag)
    #define LDR_INLOAD_HEAD(ldr)         LDR_GetInLoadOrderHead(ldr)
    #define LDR_MEMORY_HEAD(ldr)         LDR_GetInMemoryOrderHead(ldr)
    #define LDR_INIT_HEAD(ldr)           LDR_GetInInitOrderHead(ldr)
    
    #define LDR_ENTRY_LOAD_LINKS(e)      LDR_ENTRY_LoadLinks(e)
    #define LDR_ENTRY_MEMORY_LINKS(e)    LDR_ENTRY_MemoryLinks(e)
    #define LDR_ENTRY_INIT_LINKS(e)      LDR_ENTRY_InitLinks(e)
    #define LDR_ENTRY_DLLBASE(e)         LDR_ENTRY_DllBase(e)
    #define LDR_ENTRY_FULL_NAME(e)       (&(reinterpret_cast<LDR_DATA_TABLE_ENTRY_FULL*>(e))->FullDllName)
    #define LDR_ENTRY_BASE_NAME(e)       LDR_ENTRY_BaseDllName(e)
    #define LDR_ENTRY_SIZE_OF_IMAGE(e)   (reinterpret_cast<LDR_DATA_TABLE_ENTRY_FULL*>(e)->SizeOfImage)

    // MinGW: 使用完整版句柄结构
    #define STEALTH_HANDLE_INFO_CAST(ptr)  reinterpret_cast<PSTEALTH_HANDLE_INFO>(ptr)
#endif

// ============================================================
// __declspec(noinline) -> 跨编译器宏
// ============================================================
#ifdef _MSC_VER
    #define STEALTH_NOINLINE __declspec(noinline)
#else
    #define STEALTH_NOINLINE __attribute__((noinline))
#endif

// ============================================================
// 安全内存检查辅助函数 (gcc 替代 __try/__except 读/写)
// ============================================================
#ifndef _MSC_VER
    inline bool SEH_IsMemoryReadable(const void* addr) {
        if (!addr) return false;
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        DWORD prot = mbi.Protect;
        return !(prot & (PAGE_NOACCESS | PAGE_GUARD));
    }

    inline bool SEH_IsMemoryWritable(const void* addr) {
        if (!addr) return false;
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        DWORD prot = mbi.Protect;
        if (prot & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        if (prot == PAGE_READONLY || prot == PAGE_EXECUTE_READ) return false;
        return true;
    }
#endif

// ============================================================
// SEH_SAFE_READ / SEH_SAFE_WRITE — 安全内存访问宏
// ============================================================
#ifdef _MSC_VER
    #define SEH_SAFE_READ(type, ptr, fallback) \
        ([&]() -> type { \
            __try { return *reinterpret_cast<const type*>(ptr); } \
            __except(EXCEPTION_EXECUTE_HANDLER) { return (type)(fallback); } \
        }())

    #define SEH_SAFE_WRITE(type, ptr, value) \
        ([&]() -> bool { \
            __try { *reinterpret_cast<type*>(ptr) = (value); return true; } \
            __except(EXCEPTION_EXECUTE_HANDLER) { return false; } \
        }())
#else
    #define SEH_SAFE_READ(type, ptr, fallback) \
        (SEH_IsMemoryReadable(ptr) ? *reinterpret_cast<const type*>(ptr) : (type)(fallback))

    #define SEH_SAFE_WRITE(type, ptr, value) \
        (SEH_IsMemoryWritable(ptr) ? (*reinterpret_cast<type*>(ptr) = (value), true) : false)
#endif

#endif // STEALTH_PLATFORM_H
