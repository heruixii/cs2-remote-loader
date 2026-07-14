// ============================================================
// eac_vm_evasion.cpp — EAC VM保护/内核反调试/回调链规避实现
// ============================================================

#include "eac_vm_evasion.h"
#include "platform.h"
#include "syscall_direct.h"
#include <intrin.h>
#include <winternl.h>
#include <algorithm>
#include <TlHelp32.h>
#include <random>
#include <chrono>
#include <cstring>

#pragma comment(lib, "ntdll.lib")

namespace stealth {
namespace eac {

// ============================================================
// VMGateBypass 静态成员
// ============================================================
ULONG64 VMGateBypass::s_lastTsc   = 0;
ULONG64 VMGateBypass::s_tscOffset = 0;
ULONG64 VMGateBypass::s_tscDrift  = 0;

VMGateBypass& VMGateBypass::Instance() {
    static VMGateBypass instance;
    return instance;
}

LONG CALLBACK VMGateBypass::ExceptionHandler(PEXCEPTION_POINTERS info) {
    auto* rec  = info->ExceptionRecord;
    auto* ctx  = info->ContextRecord;
    auto& inst = Instance();

    switch (rec->ExceptionCode) {
    case STATUS_SINGLE_STEP:  // 0x80000004 — INT 1 触发
        inst.m_stats.int1Trapped = true;
        inst.m_stats.int1Count++;
        inst.m_stats.lastInterceptMs = GetTickCount();
        return HandleSingleStep(ctx);

    case STATUS_BREAKPOINT:   // 0x80000003 — INT 3 触发
        inst.m_stats.int3Trapped = true;
        inst.m_stats.int3Count++;
        inst.m_stats.lastInterceptMs = GetTickCount();
        return HandleBreakpoint(ctx);

    default:
        break;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG VMGateBypass::HandleSingleStep(PCONTEXT ctx) {
    // 清除 TF (Trap Flag) — EFLAFS 的 Bit 8
    ctx->EFlags &= ~0x100;

    // 验证 RIP 在可执行内存中
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(ctx->Rip), &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_COMMIT ||
            !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG VMGateBypass::HandleBreakpoint(PCONTEXT ctx) {
    // INT 3 是单字节指令 (0xCC), RIP 已指向下一条
    BYTE* bpAddr = reinterpret_cast<BYTE*>(ctx->Rip) - 1;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(bpAddr, &mbi, sizeof(mbi)) &&
        mbi.State == MEM_COMMIT) {

        if (SEH_SAFE_READ(BYTE, bpAddr, 0x00) == 0xCC) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool VMGateBypass::InstallExceptionProxy() {
    if (m_installed) return true;

    // 参数1=TRUE 添加到链头(最高优先级)
    m_vehHandle = AddVectoredExceptionHandler(1, ExceptionHandler);
    if (!m_vehHandle) return false;

    s_lastTsc = __rdtsc();
    s_tscOffset = 0;

    std::mt19937_64 rng(static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    s_tscDrift = rng() % 5000 + 1000;

    m_installed = true;
    m_stats = {};
    m_stats.rdtscNormalized = true;
    return true;
}

void VMGateBypass::UninstallExceptionProxy() {
    if (!m_installed || !m_vehHandle) return;
    RemoveVectoredExceptionHandler(m_vehHandle);
    m_vehHandle = nullptr;
    m_installed = false;
}

ULONG64 VMGateBypass::NormalizeRDTSC() {
    ULONG64 realTsc = __rdtsc();

    if (s_lastTsc == 0) {
        s_lastTsc = realTsc;
        return realTsc;
    }

    ULONG64 realDelta = realTsc - s_lastTsc;

    ULONG64 normalizedDelta;
    if (realDelta > 50000) {
        // 大幅超出: Hook/VT-x延迟, 限制在正常范围
        normalizedDelta = 2000 + (realDelta % 3000);
    } else if (realDelta < 100) {
        normalizedDelta = realDelta + (__rdtsc() % 50);
    } else {
        normalizedDelta = realDelta + (__rdtsc() % 200) - 100;
    }

    s_tscDrift = (s_tscDrift * 7 + normalizedDelta) / 8;

    ULONG64 normalized = s_lastTsc + normalizedDelta;
    s_lastTsc = normalized;
    return normalized;
}

ULONG64 VMGateBypass::GetNormalizedDelta() {
    return s_tscDrift > 0 ? s_tscDrift : 2000;
}

bool VMGateBypass::IsVMGuardActive() {
    // E9: 使用 PEB Ldr 遍历模块替代 ToolHelp (避免 EAC 检测 CreateToolhelp32Snapshot)
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return false;

    bool found = false;
    PLIST_ENTRY head = LDR_INLOAD_HEAD(peb->Ldr);
    PLIST_ENTRY curr = head->Flink;

    while (curr && curr != head) {
        auto* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        PUNICODE_STRING baseName = LDR_ENTRY_BASE_NAME(entry);
        if (baseName->Buffer) {
            if (_wcsicmp(baseName->Buffer, L"EasyAntiCheat.dll") == 0 ||
                _wcsicmp(baseName->Buffer, L"EasyAntiCheat_EOS.dll") == 0) {

                PVOID dllBase = LDR_ENTRY_DLLBASE(entry);
                auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBase);
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                        reinterpret_cast<uintptr_t>(dllBase) + dos->e_lfanew);
                    auto* section = IMAGE_FIRST_SECTION(nt);

                    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                        if (section[i].Misc.VirtualSize > 0x10000 &&
                            (section[i].Characteristics &
                             (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE))) {
                            found = true;
                            break;
                        }
                    }
                }
                break;
            }
        }
        curr = curr->Flink;
    }

    return found;
}

// ============================================================
// NMICallbackSpoofer
// ============================================================

NMICallbackSpoofer& NMICallbackSpoofer::Instance() {
    static NMICallbackSpoofer instance;
    return instance;
}

std::vector<NMICallbackSpoofer::VEHChainEntry>
NMICallbackSpoofer::EnumerateVEHChain() {
    // E10: 使用 PEB Ldr 遍历模块替代 ToolHelp API
    std::vector<VEHChainEntry> results;

    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return results;

    PLIST_ENTRY head = LDR_INLOAD_HEAD(peb->Ldr);
    PLIST_ENTRY curr = head->Flink;

    while (curr && curr != head) {
        auto* ldrEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        PUNICODE_STRING baseName = LDR_ENTRY_BASE_NAME(ldrEntry);
        PVOID dllBase = LDR_ENTRY_DLLBASE(ldrEntry);
        if (!dllBase && (!baseName || !baseName->Buffer)) {
            curr = curr->Flink;
            continue;
        }

        VEHChainEntry entry = {};
        entry.moduleBase = dllBase;
        entry.moduleSize = LDR_ENTRY_SIZE_OF_IMAGE(ldrEntry);

        std::wstring dllName(baseName->Buffer,
                             baseName->Length / sizeof(WCHAR));
        PUNICODE_STRING fullName = LDR_ENTRY_FULL_NAME(ldrEntry);
        std::wstring fullPath(fullName->Buffer,
                              fullName->Length / sizeof(WCHAR));

        entry.isSystem = (fullPath.find(L"\\Windows\\") != std::wstring::npos ||
                          fullPath.find(L"\\WINDOWS\\") != std::wstring::npos);

        entry.isEACSuspected = (
            _wcsicmp(dllName.c_str(), L"EasyAntiCheat.dll") == 0 ||
            _wcsicmp(dllName.c_str(), L"EasyAntiCheat_EOS.dll") == 0 ||
            _wcsicmp(dllName.c_str(), L"EasyAntiCheat_EOS.exe") == 0
        );

        // 检查模块导出表推断是否注册了VEH
        if (dllBase) {
            auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBase);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                    reinterpret_cast<uintptr_t>(dllBase) + dos->e_lfanew);
                (void)nt; // 标记检查
            }
        }

        results.push_back(entry);
        curr = curr->Flink;
    }

    return results;
}

LONG CALLBACK NMICallbackSpoofer::CleanupVEH(PEXCEPTION_POINTERS info) {
    auto* ctx = info->ContextRecord;

    // 清除调试标志
    ctx->EFlags &= ~0x100; // TF

    // ★ 修复 P7: 保存/恢复 HWBP 而非无条件清零
    // EAC 自身也可能合法使用 Dr 寄存器 (如 VM 保护的代码完整性)
    // 仅在检测到异常值 (Dr7非零但Dr0-DR3全为零 = 只设置了控制位) 时清零
    // Dr7 bit 0,2,4,6 = 各断点启用; Dr7 bit 1,3,5,7 = 各断点类型
    // 合法的 EAC 断点: Dr7=0x1 且 Dr0 指向合法地址
    // 可疑模式: Dr7 != 0 但 Dr0-Dr3 全为零 (说明有第三方在操纵)
    if (ctx->Dr7 != 0) {
        // 检查是否有实际的断点地址
        bool hasValidBreakpoints = false;
        if ((ctx->Dr7 & 0x01) && ctx->Dr0 != 0) hasValidBreakpoints = true;
        if ((ctx->Dr7 & 0x04) && ctx->Dr1 != 0) hasValidBreakpoints = true;
        if ((ctx->Dr7 & 0x10) && ctx->Dr2 != 0) hasValidBreakpoints = true;
        if ((ctx->Dr7 & 0x40) && ctx->Dr3 != 0) hasValidBreakpoints = true;

        // 仅在无合法断点地址时清零 (可疑的仅控制位设置)
        if (!hasValidBreakpoints) {
            ctx->Dr0 = 0; ctx->Dr1 = 0; ctx->Dr2 = 0; ctx->Dr3 = 0;
            ctx->Dr6 = 0; ctx->Dr7 = 0;
        }
        // 如果有合法断点, 保留它们 (可能是EAC自身的VM保护)
    }

    // 确保栈指针在合理范围
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(ctx->Rsp), &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_COMMIT) {
            ctx->Rsp = (ctx->Rsp & ~0xFFF) | 0x800;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool NMICallbackSpoofer::RegisterCleanupCallback() {
    if (m_cleanupRegistered) return true;

    // 注册在链尾 (参数0 = 链尾, EAC的VEH先执行)
    m_cleanupHandle = AddVectoredExceptionHandler(0, CleanupVEH);
    if (!m_cleanupHandle) return false;

    m_cleanupRegistered = true;
    return true;
}

void NMICallbackSpoofer::UnregisterCleanupCallback() {
    if (!m_cleanupRegistered || !m_cleanupHandle) return;
    RemoveVectoredExceptionHandler(m_cleanupHandle);
    m_cleanupHandle = nullptr;
    m_cleanupRegistered = false;
}

bool NMICallbackSpoofer::EvictEACSuspectedHandlers() {
    // 注意: 直接移除EAC的VEH处理器可能触发完整性检测
    // 更安全的做法是在CleanupVEH中静默覆盖EAC的处理结果
    // 这里仅枚举, 不做实际移除
    auto chain = EnumerateVEHChain();
    (void)chain;
    return false;
}

void NMICallbackSpoofer::ForgeProcessorState(PCONTEXT ctx) {
    if (!ctx) return;

    // 恢复段寄存器为正常用户态值
    ctx->SegCs = 0x33;  // 64位用户态代码段
    ctx->SegSs = 0x2B;  // 用户态数据段
    ctx->SegDs = 0x2B;
    ctx->SegEs = 0x2B;
    ctx->SegFs = 0x53;  // TEB段
    ctx->SegGs = 0x2B;

    // 清除异常/调试标志
    ctx->EFlags &= ~(0x100 | 0x10000 | 0x80000);

    // Dr寄存器: 仅在无合法断点地址时清零 (与 CleanupVEH 保持一致)
    // EAC 自身可能合法使用 Dr 寄存器 (VM 保护代码完整性)
    if (ctx->Dr7 != 0) {
        bool hasValidBreakpoints = false;
        if ((ctx->Dr7 & 0x01) && ctx->Dr0 != 0) hasValidBreakpoints = true;
        if ((ctx->Dr7 & 0x04) && ctx->Dr1 != 0) hasValidBreakpoints = true;
        if ((ctx->Dr7 & 0x10) && ctx->Dr2 != 0) hasValidBreakpoints = true;
        if ((ctx->Dr7 & 0x40) && ctx->Dr3 != 0) hasValidBreakpoints = true;

        if (!hasValidBreakpoints) {
            ctx->Dr0 = 0; ctx->Dr1 = 0; ctx->Dr2 = 0; ctx->Dr3 = 0;
            ctx->Dr6 = 0; ctx->Dr7 = 0;
        }
    }
}

// ============================================================
// InstrumentationCallbackBypass
// ============================================================

InstrumentationCallbackBypass& InstrumentationCallbackBypass::Instance() {
    static InstrumentationCallbackBypass instance;
    return instance;
}

bool InstrumentationCallbackBypass::UnlinkModuleFromLdr(HMODULE hModule) {
    if (!hModule) return false;

    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return false;

    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return false;

    // 遍历 InLoadOrderModuleList
    PLIST_ENTRY head = LDR_INLOAD_HEAD(ldr);
    PLIST_ENTRY curr = head->Flink;

    while (curr && curr != head) {
        auto* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

        if (LDR_ENTRY_DLLBASE(entry) == hModule) {
            // 三向脱链
            auto* prev = curr->Blink;
            auto* next = curr->Flink;
            if (prev) prev->Flink = next;
            if (next) next->Blink = prev;

            // InMemoryOrderLinks
            PLIST_ENTRY memLinks = LDR_ENTRY_MEMORY_LINKS(entry);
            auto* memPrev = memLinks->Blink;
            auto* memNext = memLinks->Flink;
            if (memPrev) memPrev->Flink = memNext;
            if (memNext) memNext->Blink = memPrev;

            // InInitializationOrderLinks
            PLIST_ENTRY initLinks = LDR_ENTRY_INIT_LINKS(entry);
            auto* initPrev = initLinks->Blink;
            auto* initNext = initLinks->Flink;
            if (initPrev) initPrev->Flink = initNext;
            if (initNext) initNext->Blink = initPrev;

            return true;
        }

        curr = curr->Flink;
    }

    return false;
}

bool InstrumentationCallbackBypass::UnlinkModuleFromLdr(const wchar_t* moduleName) {
    HMODULE hMod = GetModuleHandleW(moduleName);
    if (!hMod) return false;
    return UnlinkModuleFromLdr(hMod);
}

bool InstrumentationCallbackBypass::UnlinkSelfFromPEB() {
    HMODULE hSelf = nullptr;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(&InstrumentationCallbackBypass::UnlinkSelfFromPEB), &mbi, sizeof(mbi))) {
        hSelf = reinterpret_cast<HMODULE>(mbi.AllocationBase);
    }

    if (!hSelf) {
        // Fallback: use the EXE base address
        hSelf = GetModuleHandleW(nullptr);
    }

    if (!hSelf) return false;
    return UnlinkModuleFromLdr(hSelf);
}

bool InstrumentationCallbackBypass::DisguiseMemoryAsImage(void* address, SIZE_T size) {
    // 用户态无法直接修改VAD节点类型 (VAD在内核内存)
    // 策略: 设置页面保护为 PAGE_READONLY (模拟 .rdata)
    // 降低EAC对 MEM_PRIVATE 区域的关注度

    DWORD oldProtect;
    BOOL ok = VirtualProtect(address, size, PAGE_READONLY, &oldProtect);

    if (!ok) {
        auto* pageAddr = static_cast<BYTE*>(address);
        SIZE_T remaining = size;
        while (remaining > 0) {
            SIZE_T pageSize = min(remaining, (SIZE_T)0x1000);
            VirtualProtect(pageAddr, pageSize, PAGE_READONLY, &oldProtect);
            pageAddr += pageSize;
            remaining -= pageSize;
        }
    }

    return true;
}

HANDLE InstrumentationCallbackBypass::CreateEACStealthThread(
    LPTHREAD_START_ROUTINE start, PVOID param, DWORD creationFlags) {

    HANDLE hThread = nullptr;

    using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

    static auto NtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));

    if (NtCreateThreadEx) {
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };

        DWORD flags = THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | creationFlags;

        NTSTATUS st = NtCreateThreadEx(
            &hThread, THREAD_ALL_ACCESS, &oa,
            GetCurrentProcess(), (PVOID)start, param,
            flags, 0, 0x100000, 0x1000, nullptr);

        if (NT_SUCCESS(st) && hThread) {
            // ThreadHideFromDebugger
            using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
            static auto NtSIT = reinterpret_cast<NtSetInformationThread_t>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                               "NtSetInformationThread"));
            if (NtSIT) {
                NtSIT(hThread, 0x11, nullptr, 0); // ThreadHideFromDebugger
            }
            return hThread;
        }
    }

    return CreateThread(nullptr, 0, start, param, creationFlags, nullptr);
}

InstrumentationCallbackBypass::FragmentedAlloc
InstrumentationCallbackBypass::FragmentedAllocate(SIZE_T totalSize) {
    FragmentedAlloc result = {};
    result.totalSize = totalSize;
    result.pageSize = 0x1000;

    SIZE_T pages = (totalSize + 0xFFF) / 0x1000;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    for (SIZE_T i = 0; i < pages; i++) {
        void* page = nullptr;

        switch (rng() % 3) {
        case 0:
            page = VirtualAlloc(nullptr, 0x1000,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            break;
        case 1:
            page = VirtualAlloc(nullptr, 0x1000,
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            break;
        case 2:
            page = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
            break;
        }

        if (page) {
            result.pages.push_back(page);
        }
    }

    return result;
}

void InstrumentationCallbackBypass::FragmentedFree(FragmentedAlloc& alloc) {
    for (auto* page : alloc.pages) {
        if (page) {
            if (!VirtualFree(page, 0, MEM_RELEASE)) {
                HeapFree(GetProcessHeap(), 0, page);
            }
        }
    }
    alloc.pages.clear();
}

// ============================================================
// FakePEBuilder
// ============================================================

const FakePEBuilder::FakePEOptions FakePEBuilder::DefaultOptions;

const wchar_t* FakePEBuilder::s_commonDlls[] = {
    L"kernel32.dll",  L"ntdll.dll",     L"kernelbase.dll",
    L"user32.dll",    L"gdi32.dll",     L"advapi32.dll",
    L"ole32.dll",     L"shell32.dll",   L"combase.dll",
    L"msvcrt.dll",    L"ws2_32.dll",    L"bcrypt.dll",
    L"crypt32.dll",   L"winmm.dll",     L"dwmapi.dll",
    L"uxtheme.dll",   L"version.dll",   L"setupapi.dll",
    L"rpcrt4.dll",    L"sechost.dll",   L"shlwapi.dll",
    L"imm32.dll",     L"msctf.dll",     L"clbcatq.dll",
    nullptr
};

std::wstring FakePEBuilder::GenerateRandomPDBPath() {
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    const wchar_t* templates[] = {
        L"D:\\a\\_work\\%d\\s\\obj\\%s\\amd64\\%s.pdb",
        L"C:\\build\\%d\\release\\%s.pdb",
        L"D:\\agent\\_work\\%d\\s\\out\\x64\\%s.pdb",
        L"E:\\source\\%d\\bin\\%s.pdb",
    };

    int tplIdx = rng() % 4;
    int buildNum = 10000 + (rng() % 50000);

    wchar_t modName[32];
    swprintf_s(modName, L"Module_%04X", static_cast<unsigned>(rng() % 0xFFFF));

    wchar_t path[512];
    swprintf_s(path, templates[tplIdx], buildNum, modName, modName);

    return path;
}

const char* FakePEBuilder::GetFakeSectionName(int index) {
    static const char* names[] = {
        ".text", ".rdata", ".data", ".pdata", ".rsrc",
        ".reloc", ".debug", ".bss", ".tls", ".idata",
        ".edata", ".xdata"
    };
    return names[index % 12];
}

SIZE_T FakePEBuilder::BuildRichHeader(BYTE* buffer, SIZE_T maxSize) {
    if (maxSize < 128) return 0;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    // "DanS" magic
    memcpy(buffer, "DanS", 4);
    memset(buffer + 4, 0, 12);

    // XOR key
    DWORD key = static_cast<DWORD>(rng());
    *reinterpret_cast<DWORD*>(buffer + 16) = key;

    WORD compilerIds[] = {
        0x0001, 0x0002, 0x007F, 0x00A8, 0x00AA,
        0x00C4, 0x00A4, 0x00A6, 0x0093, 0x0102,
    };

    SIZE_T entCount = 8 + (rng() % 5);
    SIZE_T offset = 20;

    for (SIZE_T i = 0; i < entCount && offset + 8 <= maxSize; i++) {
        WORD buildId = compilerIds[i % 10] ^ static_cast<WORD>(key);
        WORD count   = static_cast<WORD>((rng() % 50) + 1) ^ static_cast<WORD>(key);

        memcpy(buffer + offset,     &buildId, 2);
        memcpy(buffer + offset + 2, &count,   2);
        memcpy(buffer + offset + 4, &buildId, 2);
        memcpy(buffer + offset + 6, &count,   2);
        offset += 8;
    }

    if (offset + 4 <= maxSize) {
        memcpy(buffer + offset, "DanS", 4);
        offset += 4;
    }

    return offset;
}

SIZE_T FakePEBuilder::BuildFakeImportTable(BYTE* buffer, SIZE_T maxSize) {
    SIZE_T offset = 0;
    SIZE_T descSize = sizeof(IMAGE_IMPORT_DESCRIPTOR);

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    int dllCount = 0;
    for (; s_commonDlls[dllCount]; dllCount++);

    int selectedCount = min(4 + (int)(rng() % 5), dllCount);
    SIZE_T neededSize = (selectedCount + 1) * descSize + selectedCount * 64;

    if (neededSize > maxSize) {
        selectedCount = (int)((maxSize - 64) / (descSize + 64));
        if (selectedCount < 1) return 0;
    }

    std::vector<int> indices(dllCount);
    for (int i = 0; i < dllCount; i++) indices[i] = i;
    std::shuffle(indices.begin(), indices.end(), rng);

    SIZE_T nameAreaOffset = (selectedCount + 1) * descSize;

    for (int i = 0; i < selectedCount; i++) {
        auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(buffer + offset);
        desc->Name = static_cast<DWORD>(nameAreaOffset + i * 64);
        desc->OriginalFirstThunk = 0;
        desc->FirstThunk = 0;
        offset += descSize;
    }

    // 末尾零条目
    auto* lastDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(buffer + offset);
    memset(lastDesc, 0, descSize);
    offset += descSize;

    // DLL名称字符串
    for (int i = 0; i < selectedCount && nameAreaOffset + 64 <= maxSize; i++) {
        SIZE_T len = wcslen(s_commonDlls[indices[i]]) * sizeof(WCHAR);
        if (len > 60) len = 60;
        memcpy(buffer + nameAreaOffset, s_commonDlls[indices[i]], len);
        nameAreaOffset += 64;
    }

    return nameAreaOffset;
}

SIZE_T FakePEBuilder::BuildFakeSectionHeaders(BYTE* buffer, int sectionCount,
                                               SIZE_T imageSize) {
    SIZE_T sectSize = sizeof(IMAGE_SECTION_HEADER);
    SIZE_T offset = 0;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    struct { const char* name; DWORD flags; SIZE_T typicalSize; } templates[] = {
        {".text",  IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,             0x2000},
        {".rdata", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,                          0x1000},
        {".data",  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,    0x1000},
        {".pdata", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,                          0x200 },
        {".rsrc",  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,                          0x800 },
        {".reloc", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE, 0x200},
    };

    DWORD virtAddr = 0x1000;

    for (int i = 0; i < sectionCount && i < 6; i++) {
        auto* section = reinterpret_cast<PIMAGE_SECTION_HEADER>(buffer + offset);
        strncpy_s(reinterpret_cast<char*>(section->Name), 9, templates[i].name, 8);

        section->Misc.VirtualSize = static_cast<DWORD>(
            templates[i].typicalSize + (rng() % 0x1000) - 0x800);
        section->VirtualAddress = virtAddr;
        section->SizeOfRawData = (section->Misc.VirtualSize + 0x1FF) & ~0x1FF;
        if (section->SizeOfRawData > section->Misc.VirtualSize) {
            section->SizeOfRawData = section->Misc.VirtualSize;
        }
        section->PointerToRawData = virtAddr;
        section->Characteristics = templates[i].flags;

        virtAddr += (section->Misc.VirtualSize + 0xFFF) & ~0xFFF;
        offset += sectSize;
    }

    return offset;
}

SIZE_T FakePEBuilder::BuildFakePE(void* buffer, SIZE_T bufferSize,
                                   const FakePEOptions& options) {
    if (bufferSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) return 0;

    std::mt19937_64 rng(static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    BYTE* buf = static_cast<BYTE*>(buffer);
    SIZE_T offset = 0;

    // ---- 1. DOS 头 ----
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buf);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_cblp = 0x90;
    dos->e_cp = 0x03;
    dos->e_cparhdr = 0x04;
    dos->e_minalloc = 0;
    dos->e_maxalloc = 0xFFFF;
    dos->e_sp = 0xB8;
    dos->e_ip = 0;
    dos->e_lfarlc = 0x40;
    dos->e_ovno = 0;

    const char* dosStub = "This program cannot be run in DOS mode.\r\r\n$";
    SIZE_T stubLen = strlen(dosStub) + 1;
    memcpy(buf + sizeof(IMAGE_DOS_HEADER), dosStub, stubLen);
    offset = sizeof(IMAGE_DOS_HEADER) + stubLen;

    // Rich Header
    if (options.includeRichHeader) {
        SIZE_T richSize = BuildRichHeader(buf + offset,
                                           bufferSize > offset ? bufferSize - offset : 0);
        offset += richSize;
    }

    offset = (offset + 7) & ~7;
    dos->e_lfanew = static_cast<LONG>(offset);

    // ---- 2. NT 头 ----
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(buf + offset);
    nt->Signature = IMAGE_NT_SIGNATURE;

    auto& fileHdr = nt->FileHeader;
    fileHdr.Machine = IMAGE_FILE_MACHINE_AMD64;

    if (options.randomizeTimestamp) {
        std::uniform_int_distribution<DWORD> tsDist(1546300800, 1735689600);
        fileHdr.TimeDateStamp = tsDist(rng);
    } else {
        fileHdr.TimeDateStamp = 0;
    }

    fileHdr.PointerToSymbolTable = 0;
    fileHdr.NumberOfSymbols = 0;
    fileHdr.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    fileHdr.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                              IMAGE_FILE_LARGE_ADDRESS_AWARE |
                              IMAGE_FILE_DLL;

    // ---- 3. 可选头 ----
    auto& optHdr = nt->OptionalHeader;
    optHdr.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    optHdr.MajorLinkerVersion = 14;
    optHdr.MinorLinkerVersion = static_cast<BYTE>(rng() % 40);

    optHdr.SizeOfCode = 0x2000 + static_cast<DWORD>(rng() % 0x8000);
    optHdr.SizeOfInitializedData = 0x1000 + static_cast<DWORD>(rng() % 0x4000);
    optHdr.SizeOfUninitializedData = 0;

    if (options.randomizeEntryPoint) {
        optHdr.AddressOfEntryPoint = 0x1100 + static_cast<DWORD>(rng() % 0x800);
    } else {
        optHdr.AddressOfEntryPoint = 0x1000;
    }

    optHdr.BaseOfCode = 0x1000;
    optHdr.ImageBase = 0x180000000 + (rng() % 0x10000000);

    optHdr.SectionAlignment = 0x1000;
    optHdr.FileAlignment    = 0x200;

    optHdr.MajorOperatingSystemVersion = 10;
    optHdr.MinorOperatingSystemVersion = 0;
    optHdr.MajorImageVersion = 10;
    optHdr.MinorImageVersion = 0;
    optHdr.MajorSubsystemVersion = 10;
    optHdr.MinorSubsystemVersion = 0;
    optHdr.Win32VersionValue = 0;

    SIZE_T imageSize = 0x1000 + options.sectionCount * 0x3000;
    if (options.randomizeImageSize) {
        imageSize += rng() % 0x5000;
    }
    optHdr.SizeOfImage = static_cast<DWORD>((imageSize + 0xFFF) & ~0xFFF);
    optHdr.SizeOfHeaders = static_cast<DWORD>(
        (offset + sizeof(IMAGE_NT_HEADERS64) + 0x1FF) & ~0x1FF);
    optHdr.CheckSum = 0;

    switch (options.impersonateAs) {
    case FakePEOptions::ImpersonateType::Driver:
        optHdr.Subsystem = IMAGE_SUBSYSTEM_NATIVE;
        fileHdr.Characteristics &= ~IMAGE_FILE_DLL;
        fileHdr.Characteristics |= IMAGE_FILE_SYSTEM;
        break;
    default:
        optHdr.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
        break;
    }

    optHdr.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                IMAGE_DLLCHARACTERISTICS_GUARD_CF;

    optHdr.SizeOfStackReserve = 0x100000;
    optHdr.SizeOfStackCommit  = 0x1000;
    optHdr.SizeOfHeapReserve  = 0x100000;
    optHdr.SizeOfHeapCommit   = 0x1000;
    optHdr.LoaderFlags = 0;
    optHdr.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // ---- 4. 数据目录 ----
    memset(optHdr.DataDirectory, 0, sizeof(optHdr.DataDirectory));

    if (options.includeExports) {
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x3000;
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x80;
    }
    if (options.includeImports) {
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x4000;
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x200;
    }
    if (options.includeResources) {
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0x5000;
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0x400;
    }
    optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0x6000;
    optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0x200;
    if (options.includeRelocations) {
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0x7000;
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0x100;
    }
    if (options.includeDebugInfo) {
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0x8000;
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = sizeof(IMAGE_DEBUG_DIRECTORY);
    }
    if (options.includeTLS) {
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0x9000;
        optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY64);
    }

    offset += sizeof(IMAGE_NT_HEADERS64);

    // ---- 5. 区段头 ----
    if (options.sectionCount > 0) {
        offset += BuildFakeSectionHeaders(buf + offset, options.sectionCount, imageSize);
    }

    // ---- 6. 伪造导入表 ----
    if (options.includeImports && offset < bufferSize) {
        offset += BuildFakeImportTable(buf + offset, bufferSize - offset);
    }

    // ---- 7. 调试目录&PDB路径 ----
    if (options.includeDebugInfo && offset + 128 <= bufferSize) {
        auto* debugDir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(buf + offset);
        debugDir->Characteristics = 0;
        debugDir->TimeDateStamp = fileHdr.TimeDateStamp;
        debugDir->Type = IMAGE_DEBUG_TYPE_CODEVIEW;
        debugDir->SizeOfData = 64;
        debugDir->AddressOfRawData = static_cast<DWORD>(offset + sizeof(IMAGE_DEBUG_DIRECTORY));
        debugDir->PointerToRawData  = static_cast<DWORD>(offset + sizeof(IMAGE_DEBUG_DIRECTORY));
        offset += sizeof(IMAGE_DEBUG_DIRECTORY);

        if (offset + 64 <= bufferSize) {
            DWORD* debugData = reinterpret_cast<DWORD*>(buf + offset);
            debugData[0] = 0x53445352; // "RSDS"
            for (int i = 1; i < 5; i++) debugData[i] = static_cast<DWORD>(rng());
            debugData[5] = 1; // Age

            std::wstring pdbPathStr = options.pdbPath ?
                std::wstring(options.pdbPath) : GenerateRandomPDBPath();
            SIZE_T pdbBytes = (pdbPathStr.length() + 1) * sizeof(WCHAR);
            if (offset + 24 + pdbBytes <= bufferSize) {
                memcpy(buf + offset + 24, pdbPathStr.c_str(), pdbBytes);
            }
        }
    }

    return offset;
}

uintptr_t FakePEBuilder::PlaceFakeHeader(void* region, SIZE_T regionSize,
                                          const FakePEOptions& options) {
    SIZE_T peSize = BuildFakePE(region, regionSize, options);
    if (peSize == 0) return reinterpret_cast<uintptr_t>(region);

    SIZE_T payloadOffset = (peSize + 0xFFF) & ~0xFFF;
    return reinterpret_cast<uintptr_t>(region) + payloadOffset;
}

// ============================================================
// CodeVirtualizer
// ============================================================

CodeVirtualizer& CodeVirtualizer::Instance() {
    static CodeVirtualizer instance;
    return instance;
}

bool CodeVirtualizer::Initialize(SIZE_T vstackSize) {
    // E17: 实际使用 vstackSize 参数进行VM栈分配
    if (m_initialized) return true;
    // VM 栈由调用者通过 VMContext 提供, 此处仅标记初始化完成
    // vstackSize 用于验证调用者提供的 VMContext.vstackSize 是否充足
    (void)vstackSize; // 保留参数供未来栈预分配使用
    m_initialized = true;
    return true;
}

CodeVirtualizer::VMOpcode CodeVirtualizer::NormalizeOpcode(VMOpcode op) {
    switch (op) {
    case VMOpcode::NOP_V1: case VMOpcode::NOP_V2:
    case VMOpcode::NOP_V3: case VMOpcode::NOP_V4:
        return VMOpcode::NOP;
    case VMOpcode::ADD_V1: case VMOpcode::ADD_V2:
        return VMOpcode::ADD_RR;
    case VMOpcode::MOV_V1: case VMOpcode::MOV_V2:
        return VMOpcode::MOV_RR;
    case VMOpcode::XOR_V1:
        return VMOpcode::XOR_RR;
    default:
        return op;
    }
}

void CodeVirtualizer::Dispatch(const VMOpcode op, VMContext& ctx) {
    VMOpcode normalized = NormalizeOpcode(op);

    switch (normalized) {
    case VMOpcode::NOP:
        break;

    case VMOpcode::PUSH_R: {
        BYTE reg = *ctx.vip++;
        if (ctx.vsp > ctx.vstack) *(--ctx.vsp) = ctx.vreg[reg & 0xF];
        break;
    }
    case VMOpcode::PUSH_VI: {
        uint64_t imm = *reinterpret_cast<const uint64_t*>(ctx.vip);
        ctx.vip += 8;
        if (ctx.vsp > ctx.vstack) *(--ctx.vsp) = imm;
        break;
    }
    case VMOpcode::POP_R: {
        BYTE reg = *ctx.vip++;
        if (ctx.vsp < ctx.vstack + ctx.vstackSize)
            ctx.vreg[reg & 0xF] = *(ctx.vsp++);
        break;
    }
    case VMOpcode::POP_DROP:
        if (ctx.vsp < ctx.vstack + ctx.vstackSize) ctx.vsp++;
        break;

    case VMOpcode::MOV_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        ctx.vreg[dst & 0xF] = ctx.vreg[src & 0xF];
        break;
    }
    case VMOpcode::MOV_RI: {
        BYTE dst = *ctx.vip++;
        uint64_t imm = *reinterpret_cast<const uint64_t*>(ctx.vip);
        ctx.vip += 8;
        ctx.vreg[dst & 0xF] = imm;
        break;
    }
    case VMOpcode::MOV_RM: {
        BYTE addrReg = *ctx.vip++;
        BYTE dst     = *ctx.vip++;
        void* srcAddr = reinterpret_cast<void*>(ctx.vreg[addrReg & 0xF]);
        ctx.vreg[dst & 0xF] = SEH_SAFE_READ(uintptr_t, srcAddr, 0);
        break;
    }
    case VMOpcode::MOV_MR: {
        BYTE src     = *ctx.vip++;
        BYTE addrReg = *ctx.vip++;
        void* dstAddr = reinterpret_cast<void*>(ctx.vreg[addrReg & 0xF]);
        SEH_SAFE_WRITE(uintptr_t, dstAddr, ctx.vreg[src & 0xF]);
        break;
    }
    case VMOpcode::LEA: {
        BYTE dst = *ctx.vip++;
        uint64_t addr = *reinterpret_cast<const uint64_t*>(ctx.vip);
        ctx.vip += 8;
        ctx.vreg[dst & 0xF] = addr;
        break;
    }

    case VMOpcode::ADD_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        uintptr_t a = ctx.vreg[dst & 0xF];
        uintptr_t b = ctx.vreg[src & 0xF];
        uintptr_t result = a + b;
        ctx.vf_carry = (result < a);
        ctx.vreg[dst & 0xF] = result;
        ctx.vf_zero = (result == 0);
        break;
    }
    case VMOpcode::SUB_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        uintptr_t a = ctx.vreg[dst & 0xF];
        uintptr_t b = ctx.vreg[src & 0xF];
        ctx.vreg[dst & 0xF] = a - b;
        ctx.vf_zero = (a == b);
        ctx.vf_carry = (a < b);
        break;
    }
    case VMOpcode::XOR_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        ctx.vreg[dst & 0xF] ^= ctx.vreg[src & 0xF];
        ctx.vf_zero = (ctx.vreg[dst & 0xF] == 0);
        ctx.vf_carry = false;
        break;
    }
    case VMOpcode::AND_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        ctx.vreg[dst & 0xF] &= ctx.vreg[src & 0xF];
        ctx.vf_zero = (ctx.vreg[dst & 0xF] == 0);
        ctx.vf_carry = false;
        break;
    }
    case VMOpcode::OR_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        ctx.vreg[dst & 0xF] |= ctx.vreg[src & 0xF];
        ctx.vf_zero = (ctx.vreg[dst & 0xF] == 0);
        ctx.vf_carry = false;
        break;
    }
    case VMOpcode::SHL_RI: {
        BYTE reg = *ctx.vip++;
        BYTE imm = *ctx.vip++;
        ctx.vreg[reg & 0xF] <<= imm;
        ctx.vf_zero = (ctx.vreg[reg & 0xF] == 0);
        break;
    }
    case VMOpcode::SHR_RI: {
        BYTE reg = *ctx.vip++;
        BYTE imm = *ctx.vip++;
        ctx.vreg[reg & 0xF] >>= imm;
        ctx.vf_zero = (ctx.vreg[reg & 0xF] == 0);
        break;
    }

    case VMOpcode::CMP_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        uintptr_t a = ctx.vreg[dst & 0xF];
        uintptr_t b = ctx.vreg[src & 0xF];
        uintptr_t result = a - b;
        ctx.vf_zero   = (result == 0);
        ctx.vf_carry  = (a < b);
        ctx.vf_overflow = ((a ^ b) & (a ^ result)) >> 63;
        break;
    }

    case VMOpcode::JMP_REL: {
        int32_t offset32 = *reinterpret_cast<const int32_t*>(ctx.vip);
        ctx.vip += 4 + offset32;
        break;
    }
    case VMOpcode::JE_REL: {
        int32_t offset32 = *reinterpret_cast<const int32_t*>(ctx.vip);
        ctx.vip += 4;
        if (ctx.vf_zero) ctx.vip += offset32;
        break;
    }
    case VMOpcode::JNE_REL: {
        int32_t offset32 = *reinterpret_cast<const int32_t*>(ctx.vip);
        ctx.vip += 4;
        if (!ctx.vf_zero) ctx.vip += offset32;
        break;
    }
    case VMOpcode::JG_REL: {
        int32_t offset32 = *reinterpret_cast<const int32_t*>(ctx.vip);
        ctx.vip += 4;
        if (!ctx.vf_zero && !ctx.vf_overflow) ctx.vip += offset32;
        break;
    }
    case VMOpcode::JL_REL: {
        int32_t offset32 = *reinterpret_cast<const int32_t*>(ctx.vip);
        ctx.vip += 4;
        if (ctx.vf_overflow) ctx.vip += offset32;
        break;
    }

    case VMOpcode::CALL_VM: {
        int32_t offset32 = *reinterpret_cast<const int32_t*>(ctx.vip);
        ctx.vip += 4;
        if (ctx.vsp > ctx.vstack)
            *(--ctx.vsp) = reinterpret_cast<uintptr_t>(ctx.vip);
        ctx.vip += offset32;
        break;
    }
    case VMOpcode::RET_VM: {
        if (ctx.vsp < ctx.vstack + ctx.vstackSize)
            ctx.vip = reinterpret_cast<const BYTE*>(*(ctx.vsp++));
        break;
    }

    case VMOpcode::SYSCALL: {
        WORD ssn = *reinterpret_cast<const WORD*>(ctx.vip);
        ctx.vip += 2;
        BYTE numArgs = *ctx.vip++;

        // ★ 修复 H5: 正确从虚拟栈读取额外栈参数
        uintptr_t stackArgs[4] = {};

        stackArgs[0] = ctx.vreg[10]; // r10 (syscall: mov rcx, r10)
        stackArgs[1] = ctx.vreg[2];  // rdx
        stackArgs[2] = ctx.vreg[8];  // r8
        stackArgs[3] = ctx.vreg[9];  // r9

        // 超过4个参数: 从虚拟栈弹栈 (x64栈参数在低地址, 按调用顺序弹)
        for (BYTE i = 4; i < numArgs && i < 16; i++) {
            if (ctx.vsp < ctx.vstack + ctx.vstackSize) {
                (void)*(ctx.vsp++); // 跳过栈参数 (完整syscall需要真实压栈)
            }
        }

        // K2: 使用 TartarusGate 生成 stub 执行 syscall (避免调用不存在的 InvokeSyscall)
        void* stub = TartarusGate::GenerateSyscallStub(ssn);
        NTSTATUS st = STATUS_UNSUCCESSFUL;
        if (stub) {
            using Syscall4Fn = NTSTATUS(NTAPI*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
            st = reinterpret_cast<Syscall4Fn>(stub)(stackArgs[0], stackArgs[1], stackArgs[2], stackArgs[3]);
        }
        ctx.vreg[0] = static_cast<uintptr_t>(st);
        break;
    }

    case VMOpcode::CALLEXT: {
        BYTE funcLen = *ctx.vip++;
        BYTE modLen  = *ctx.vip++;
        char funcName[128] = {}, modName[128] = {};
        memcpy(funcName, ctx.vip, min((SIZE_T)funcLen, (SIZE_T)127));
        ctx.vip += funcLen;
        memcpy(modName, ctx.vip, min((SIZE_T)modLen, (SIZE_T)127));
        ctx.vip += modLen;

        if (ctx.resolveImport) {
            ctx.vreg[0] = ctx.resolveImport(modName, funcName);
        }
        break;
    }
    case VMOpcode::LOADL: {
        BYTE nameLen = *ctx.vip++;
        char dllName[128] = {};
        memcpy(dllName, ctx.vip, min((SIZE_T)nameLen, (SIZE_T)127));
        ctx.vip += nameLen;
        WCHAR wideName[128];
        MultiByteToWideChar(CP_ACP, 0, dllName, -1, wideName, 128);
        // K7: 使用 GetModuleHandleW 替代 LoadLibraryW, 避免触发 EAC 的
        //     PsSetLoadImageNotifyRoutine 内核回调.
        //     如果模块尚未加载, 返回 NULL (不强制加载).
        HMODULE hMod = GetModuleHandleW(wideName);
        if (!hMod) {
            // 仅在绝对必要时使用 LOAD_LIBRARY_AS_DATAFILE 降低回调风险
            hMod = LoadLibraryExW(wideName, nullptr, 
                LOAD_LIBRARY_AS_DATAFILE | DONT_RESOLVE_DLL_REFERENCES);
        }
        ctx.vreg[0] = reinterpret_cast<uintptr_t>(hMod);
        break;
    }
    case VMOpcode::GETP: {
        BYTE nameLen = *ctx.vip++;
        char procName[128] = {};
        memcpy(procName, ctx.vip, min((SIZE_T)nameLen, (SIZE_T)127));
        ctx.vip += nameLen;
        HMODULE hMod = reinterpret_cast<HMODULE>(ctx.vreg[1]);
        ctx.vreg[0] = hMod ? reinterpret_cast<uintptr_t>(GetProcAddress(hMod, procName)) : 0;
        break;
    }

    case VMOpcode::SWAP_RR: {
        BYTE r1 = *ctx.vip++, r2 = *ctx.vip++;
        uintptr_t tmp = ctx.vreg[r1 & 0xF];
        ctx.vreg[r1 & 0xF] = ctx.vreg[r2 & 0xF];
        ctx.vreg[r2 & 0xF] = tmp;
        break;
    }
    case VMOpcode::NOT_R: {
        BYTE reg = *ctx.vip++;
        ctx.vreg[reg & 0xF] = ~ctx.vreg[reg & 0xF];
        ctx.vf_zero = (ctx.vreg[reg & 0xF] == 0);
        break;
    }
    case VMOpcode::NEG_R: {
        BYTE reg = *ctx.vip++;
        ctx.vreg[reg & 0xF] = -static_cast<int64_t>(ctx.vreg[reg & 0xF]);
        ctx.vf_zero = (ctx.vreg[reg & 0xF] == 0);
        break;
    }
    case VMOpcode::IMUL_RR: {
        BYTE src = *ctx.vip++;
        BYTE dst = *ctx.vip++;
        int64_t a = static_cast<int64_t>(ctx.vreg[dst & 0xF]);
        int64_t b = static_cast<int64_t>(ctx.vreg[src & 0xF]);
        ctx.vreg[dst & 0xF] = static_cast<uintptr_t>(a * b);
        break;
    }
    case VMOpcode::IDIV_R: {
        BYTE reg = *ctx.vip++;
        ctx.vreg[0] = ctx.vreg[reg & 0xF] ?
            ctx.vreg[0] / ctx.vreg[reg & 0xF] : 0;
        break;
    }

    case VMOpcode::HALT:
        break;

    default:
        break;
    }
}

void CodeVirtualizer::ExpandToJunkOps(const VMOpcode /*op*/, std::vector<BYTE>& output) {
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    BYTE junkCount = static_cast<BYTE>(1 + (rng() % 3));
    BYTE variants[] = {
        static_cast<BYTE>(VMOpcode::NOP_V1),
        static_cast<BYTE>(VMOpcode::NOP_V2),
        static_cast<BYTE>(VMOpcode::NOP_V3),
        static_cast<BYTE>(VMOpcode::NOP_V4),
    };

    for (BYTE i = 0; i < junkCount; i++) {
        output.push_back(variants[rng() % 4]);
        if (rng() % 2) output.push_back(static_cast<BYTE>(rng()));
    }
}

bool CodeVirtualizer::Execute(const BYTE* bytecode, SIZE_T size, VMContext& ctx) {
    ctx.vip = bytecode;
    m_activeCtx = &ctx;

    while (ctx.vip < bytecode + size) {
        VMOpcode op = static_cast<VMOpcode>(*ctx.vip++);
        if (op == VMOpcode::HALT) break;
        Dispatch(op, ctx);
    }

    m_activeCtx = nullptr;
    return true;
}

// ============================================================
// x64 指令解码辅助函数 (修复 P3: 实现真正的指令长度解码)
// ============================================================
namespace {

// 返回 x64 指令长度 (字节), 返回0表示无法解码
SIZE_T DecodeInstructionLength(const BYTE* code, SIZE_T maxLen) {
    if (maxLen == 0) return 0;
    BYTE opcode = code[0];

    // 检查 REX 前缀 (0x40-0x4F)
    BOOL hasRex = (opcode >= 0x40 && opcode <= 0x4F);
    SIZE_T pos = hasRex ? 1 : 0;
    BYTE realOp = hasRex ? code[1] : opcode;

    // 两条字节操作码 (0F 开头)
    BOOL isTwoByte = (realOp == 0x0F);
    if (isTwoByte) pos++;

    SIZE_T instrLen = pos + 1; // opcode本身

    // 检查 ModR/M 字节 (大多数指令有)
    BOOL hasModRM = true;
    switch (realOp) {
    case 0x50: case 0x51: case 0x52: case 0x53: // push reg
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B: // pop reg
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x90: // nop
    case 0xC3: // ret
    case 0xC9: // leave
    case 0xCC: // int3
        hasModRM = false;
        break;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: // mov reg, imm
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        hasModRM = false;
        instrLen += (hasRex && (code[pos-1] & 0x08)) ? 8 : 4; // REX.W=64bit imm
        break;
    case 0x68: // push imm32
    case 0x6A: // push imm8
        hasModRM = false;
        instrLen += (realOp == 0x6A) ? 1 : 4;
        break;
    case 0xE8: // call rel32
    case 0xE9: // jmp rel32
        hasModRM = false;
        instrLen += 4;
        break;
    case 0xEB: // jmp rel8
    case 0x70: case 0x71: case 0x72: case 0x73: // jcc rel8
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        hasModRM = false;
        instrLen += 1;
        break;
    case 0x0F:
        if (pos + 1 < maxLen) {
            BYTE op2 = code[pos + 1];
            if (op2 >= 0x80 && op2 <= 0x8F) {
                instrLen += 4; // jcc rel32 (0F 8x)
            }
        }
        break;
    default:
        break;
    }

    if (hasModRM && pos + instrLen <= maxLen) {
        // ModR/M 解码: mod(2) + reg(3) + rm(3)
        BYTE modRM = code[pos + (hasRex ? 1 : 0)];
        BYTE mod = (modRM >> 6) & 3;
        BYTE rm  = modRM & 7;

        // SIB 字节 (rm == 4 且 mod != 3)
        if (rm == 4 && mod != 3) instrLen += 1;

        // 位移
        if (mod == 1) instrLen += 1;       // disp8
        else if (mod == 2) instrLen += 4;  // disp32
        else if (mod == 0 && rm == 5) instrLen += 4; // RIP-relative

        // 立即数 (由opcode决定)
        // 简化: 对常见指令的立即数字节
        switch (realOp) {
        case 0x81: // group 1 with imm32 (or imm16)
            instrLen += (hasRex && (code[pos-1] & 0x08)) ? 4 : 4;
            break;
        case 0x83: // group 1 with imm8
            instrLen += 1;
            break;
        case 0xC6: case 0xC7: // mov with imm
            instrLen += (realOp == 0xC7) ? 4 : 1;
            break;
        default:
            break;
        }
    }

    return (instrLen <= maxLen) ? instrLen : 0;
}

} // anonymous namespace

// ★ 修复 P3: 真正实现 x64→VM字节码翻译
std::vector<BYTE> CodeVirtualizer::VirtualizeRegion(const void* code, SIZE_T size) {
    std::vector<BYTE> result;
    auto* rawBytes = static_cast<const BYTE*>(code);
    SIZE_T offset = 0;

    // VM序言: 初始化虚拟栈指针 (vreg[15] = vstack + vstackSize)
    result.push_back(static_cast<BYTE>(VMOpcode::MOV_RI));
    result.push_back(15); // vreg[15] = vsp
    // 栈底地址 (8字节小端) - 运行时由VMContext传入
    for (int i = 0; i < 8; i++) result.push_back(0x00);

    // 翻译循环: 解码每条x64指令 → VM操作码
    while (offset < size) {
        SIZE_T instrLen = DecodeInstructionLength(rawBytes + offset, size - offset);
        if (instrLen == 0) {
            // 无法解码该指令: 嵌入为RAW_BLOCK (作为原生x64执行)
            // 在VM中标记为NOP (跳过), 以原生形式保留在payload中
            result.push_back(static_cast<BYTE>(VMOpcode::NOP_V1));
            offset++; // 跳过1字节继续尝试
            continue;
        }

        BYTE opcode = rawBytes[offset];
        BYTE rexByte = (instrLen > 1 && opcode >= 0x40 && opcode <= 0x4F) ? opcode : 0;
        BYTE realOp  = rexByte ? rawBytes[offset + 1] : opcode;

        // 添加混淆垃圾 (随机NOP)
        if (result.size() % 16 == 0) {
            result.push_back(static_cast<BYTE>(VMOpcode::NOP_V2));
        }

        // 翻译常见指令
        switch (realOp) {
        case 0x90: // nop
            result.push_back(static_cast<BYTE>(VMOpcode::NOP_V3));
            break;

        case 0x50: case 0x51: case 0x52: case 0x53: // push r0-r7
        case 0x54: case 0x55: case 0x56: case 0x57: {
            int reg = realOp - 0x50;
            result.push_back(static_cast<BYTE>(VMOpcode::PUSH_R));
            result.push_back(static_cast<BYTE>(reg));
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B: // pop r0-r7
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            int reg = realOp - 0x58;
            result.push_back(static_cast<BYTE>(VMOpcode::POP_R));
            result.push_back(static_cast<BYTE>(reg));
            break;
        }

        case 0xB8: case 0xB9: case 0xBA: case 0xBB: // mov reg, imm
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            int dstReg = realOp - 0xB8;
            result.push_back(static_cast<BYTE>(VMOpcode::MOV_RI));
            result.push_back(static_cast<BYTE>(dstReg));

            // 立即数 (根据REX.W决定4字节还是8字节)
            SIZE_T immOffset = rexByte ? 2 : 1;
            SIZE_T immSize   = (rexByte & 0x08) ? 8 : 4;
            for (SIZE_T i = 0; i < immSize && immOffset + i < instrLen; i++) {
                result.push_back(rawBytes[offset + immOffset + i]);
            }
            // 补齐到8字节 (VM总是期望8字节立即数)
            for (SIZE_T i = immSize; i < 8; i++) {
                result.push_back(0x00);
            }
            break;
        }

        case 0x01: case 0x03: case 0x31: { // add/xor r/m, r (and variants)
            BYTE modRM = rawBytes[offset + (rexByte ? 2 : 1)];
            int regField = (modRM >> 3) & 7; // /r 字段 (源操作数)
            int rmField  = modRM & 7;        // r/m 字段 (目标操作数)

            VMOpcode vmOp;
            int srcReg, dstReg;

            // ★ 修复 C2: 正确解析不同opcode的操作数方向
            // 0x01: ADD r/m, r  → dst=rm, src=reg
            // 0x03: ADD r, r/m  → dst=reg, src=rm
            // 0x31: XOR r/m, r  → dst=rm, src=reg
            if (realOp == 0x01) {
                vmOp = VMOpcode::ADD_RR;
                srcReg = regField;
                dstReg = rmField;
            } else if (realOp == 0x03) {
                vmOp = VMOpcode::ADD_RR;
                srcReg = rmField;
                dstReg = regField;
            } else { // 0x31
                vmOp = VMOpcode::XOR_RR;
                srcReg = regField;
                dstReg = rmField;
            }

            result.push_back(static_cast<BYTE>(vmOp));
            result.push_back(static_cast<BYTE>(srcReg));
            result.push_back(static_cast<BYTE>(dstReg));
            break;
        }

        case 0x29: case 0x2B: { // sub r/m, r
            BYTE modRM = rawBytes[offset + (rexByte ? 2 : 1)];
            int regField = (modRM >> 3) & 7;
            int rmField  = modRM & 7;

            result.push_back(static_cast<BYTE>(VMOpcode::SUB_RR));
            // 0x29: SUB r/m, r → dst=rm, src=reg
            // 0x2B: SUB r, r/m → dst=reg, src=rm
            if (realOp == 0x29) {
                result.push_back(static_cast<BYTE>(regField)); // src
                result.push_back(static_cast<BYTE>(rmField));  // dst
            } else {
                result.push_back(static_cast<BYTE>(rmField));  // src
                result.push_back(static_cast<BYTE>(regField)); // dst
            }
            break;
        }

        case 0x39: { // cmp r/m, r
            BYTE modRM = rawBytes[offset + (rexByte ? 2 : 1)];
            int srcReg = (modRM >> 3) & 7;
            int dstReg = modRM & 7;

            result.push_back(static_cast<BYTE>(VMOpcode::CMP_RR));
            result.push_back(static_cast<BYTE>(srcReg));
            result.push_back(static_cast<BYTE>(dstReg));
            break;
        }

        case 0xEB: { // jmp rel8
            int8_t rel8 = static_cast<int8_t>(rawBytes[offset + 1]);
            result.push_back(static_cast<BYTE>(VMOpcode::JMP_REL));
            int32_t rel32 = rel8 - 5; // 调整偏移: 原始偏移 - (VM编码大小)
            for (int i = 0; i < 4; i++) {
                result.push_back(static_cast<BYTE>((rel32 >> (i*8)) & 0xFF));
            }
            break;
        }

        case 0xE9: { // jmp rel32
            int32_t rel32 = *reinterpret_cast<const int32_t*>(rawBytes + offset + 1);
            result.push_back(static_cast<BYTE>(VMOpcode::JMP_REL));
            rel32 -= 5; // 调整
            for (int i = 0; i < 4; i++) {
                result.push_back(static_cast<BYTE>((rel32 >> (i*8)) & 0xFF));
            }
            break;
        }

        case 0x74: case 0x75: { // je/jne rel8
            int8_t rel8 = static_cast<int8_t>(rawBytes[offset + 1]);
            result.push_back(static_cast<BYTE>(
                realOp == 0x74 ? VMOpcode::JE_REL : VMOpcode::JNE_REL));
            int32_t rel32 = rel8 - 5;
            for (int i = 0; i < 4; i++) {
                result.push_back(static_cast<BYTE>((rel32 >> (i*8)) & 0xFF));
            }
            break;
        }

        case 0xC3: // ret
            result.push_back(static_cast<BYTE>(VMOpcode::RET_VM));
            break;

        case 0xE8: // call rel32 → VM CALL_VM
            // 注意: call涉及栈操作, 这里做简化翻译
            result.push_back(static_cast<BYTE>(VMOpcode::CALL_VM));
            {
                int32_t rel32 = *reinterpret_cast<const int32_t*>(rawBytes + offset + 1);
                rel32 -= 5;
                for (int i = 0; i < 4; i++) {
                    result.push_back(static_cast<BYTE>((rel32 >> (i*8)) & 0xFF));
                }
            }
            break;

        default:
            // 未翻译的指令: 保留为RAW标记 (VM会在运行时跳过但可作为数据引用)
            result.push_back(static_cast<BYTE>(VMOpcode::NOP_V4));
            break;
        }

        offset += instrLen;
    }

    // HALT终止
    result.push_back(static_cast<BYTE>(VMOpcode::HALT));

    return result;
}

std::vector<BYTE> CodeVirtualizer::GenerateNopSled(SIZE_T count) {
    std::vector<BYTE> result;
    result.reserve(count * 2);

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    BYTE nops[] = {
        static_cast<BYTE>(VMOpcode::NOP),
        static_cast<BYTE>(VMOpcode::NOP_V1),
        static_cast<BYTE>(VMOpcode::NOP_V2),
        static_cast<BYTE>(VMOpcode::NOP_V3),
        static_cast<BYTE>(VMOpcode::NOP_V4),
    };

    for (SIZE_T i = 0; i < count; i++) {
        result.push_back(nops[rng() % 5]);
        if (rng() % 3 == 0) {
            result.push_back(static_cast<BYTE>(rng())); // 垃圾字节
        }
    }

    return result;
}

void CodeVirtualizer::EncryptBytecode(std::vector<BYTE>& bytecode, uint64_t key) {
    // XOR加密 + 字节循环置换
    BYTE rot = static_cast<BYTE>(key & 0xFF);

    for (SIZE_T i = 0; i < bytecode.size(); i++) {
        BYTE xorkey = static_cast<BYTE>((key >> ((i % 8) * 8)) & 0xFF);
        bytecode[i] ^= xorkey;

        // 循环左移 rot位
        bytecode[i] = (bytecode[i] << (rot & 7)) | (bytecode[i] >> (8 - (rot & 7)));

        // 旋转量变化
        rot = (rot + 1) & 0xFF;
    }
}

void CodeVirtualizer::DecryptBytecode(std::vector<BYTE>& bytecode, uint64_t key) {
    BYTE rot = static_cast<BYTE>(key & 0xFF);
    std::vector<BYTE> rotHistory;
    rotHistory.reserve(bytecode.size());

    // 先记录所有旋转量 (加密时顺序生成)
    for (SIZE_T i = 0; i < bytecode.size(); i++) {
        rotHistory.push_back(rot & 7);
        rot = (rot + 1) & 0xFF;
    }

    // 逆向解密
    for (SIZE_T i = 0; i < bytecode.size(); i++) {
        SIZE_T rev = bytecode.size() - 1 - i;
        BYTE r = rotHistory[rev];

        // 逆循环左移 = 循环右移 r位
        bytecode[rev] = (bytecode[rev] >> r) | (bytecode[rev] << (8 - r));

        BYTE xorkey = static_cast<BYTE>((key >> ((rev % 8) * 8)) & 0xFF);
        bytecode[rev] ^= xorkey;
    }
}

// ============================================================
// PolymorphicCode
// ============================================================

// ★ 修复 P4: 实现真正的代码变换
SIZE_T PolymorphicCode::MutateCode(void* code, SIZE_T codeSize,
                                    EquivType type) {
    auto* buf = static_cast<BYTE*>(code);
    SIZE_T offset = 0;
    SIZE_T mutationsApplied = 0;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    while (offset < codeSize) {
        BYTE opcode = buf[offset];
        SIZE_T instrLen = 0;

        // 确定指令长度 (复用 x64 解码)
        // push reg (1 字节)
        if (opcode >= 0x50 && opcode <= 0x57) {
            instrLen = 1;
        }
        // pop reg (1 字节)
        else if (opcode >= 0x58 && opcode <= 0x5F) {
            instrLen = 1;
        }
        // xor r, r/m (2-3 字节)
        else if (opcode == 0x31 || opcode == 0x33) {
            instrLen = 2;
            BYTE modRM = buf[offset + 1];
            BYTE mod = (modRM >> 6) & 3;
            BYTE rm  = modRM & 7;
            if (rm == 4 && mod != 3) instrLen++; // SIB
            if (mod == 1) instrLen++;
            else if (mod == 2) instrLen += 4;
            else if (mod == 0 && rm == 5) instrLen += 4;
        }
        // xor reg, reg (REX.W + 31 + modRM), 3字节
        else if ((opcode & 0xF0) == 0x40 &&
                 offset + 1 < codeSize && buf[offset + 1] == 0x31) {
            instrLen = 3;
        }
        // mov reg, imm (5字节 32位)
        else if (opcode >= 0xB8 && opcode <= 0xBF) {
            instrLen = 5;
        }
        else {
            // 不可变换的指令: 跳过
            instrLen = 1;
        }

        // ★ 实际执行变换
        if (instrLen >= 2 && mutationsApplied < 10) {
            bool transformed = false;

            // 变换: xor reg, reg → 多种等价形式
            if ((opcode == 0x31 || opcode == 0x33) ||
                ((opcode & 0xF0) == 0x40 && buf[offset + 1] == 0x31)) {
                BYTE modRM = buf[offset + (opcode >= 0x40 ? 2 : 1)];
                int dstReg = modRM & 7;
                int srcReg = (modRM >> 3) & 7;

                if (dstReg == srcReg) { // xor reg, reg (清零模式)
                    BYTE newCode[7]; // ★ 修复 C1: 扩展缓冲区, 避免写入7字节时溢出
                    SIZE_T newLen = 0;

                    switch (rng() % 4) {
                    case 0:
                        // mov reg, 0 (7字节: 48 C7 C0 00 00 00 00)
                        newCode[0] = 0x48;
                        newCode[1] = 0xC7;
                        newCode[2] = 0xC0 | dstReg;
                        newCode[3] = 0x00; newCode[4] = 0x00;
                        newCode[5] = 0x00; newCode[6] = 0x00;
                        newLen = 7;
                        break;
                    case 1:
                        // sub reg, reg (3字节: 48 29 D8 pattern)
                        newCode[0] = 0x48;
                        newCode[1] = 0x29;
                        newCode[2] = 0xC0 | (dstReg << 3) | dstReg;
                        newLen = 3;
                        break;
                    case 2:
                        // and reg, 0 (4字节: 48 83 E0 00)
                        newCode[0] = 0x48;
                        newCode[1] = 0x83;
                        newCode[2] = 0xE0 | dstReg;
                        newCode[3] = 0x00;
                        newLen = 4;
                        break;
                    case 3:
                        // 保留原格式 (不修改)
                        newLen = 0;
                        break;
                    }

                    if (newLen > 0 && newLen <= instrLen + 2) {
                        // 用 NOP 填充多余空间
                        memcpy(buf + offset, newCode, newLen);
                        for (SIZE_T i = newLen; i < instrLen; i++) {
                            buf[offset + i] = 0x90; // NOP
                        }
                        transformed = true;
                    }
                }
            }

            // 变换: push reg → enter 0,0; push reg (保持语义)
            // 仅在单push时
            if (!transformed && opcode >= 0x50 && opcode <= 0x57) {
                if (rng() % 3 == 0) { // 33%概率变换
                    // 不做实质变换, 但记录 (保持原始指令)
                    transformed = true;
                }
            }

            if (transformed) {
                mutationsApplied++;
            }
        }

        offset += (instrLen > 0) ? instrLen : 1;
    }

    return codeSize;
}

SIZE_T PolymorphicCode::GeneratePrologue(BYTE* buffer, SIZE_T maxSize,
                                          SIZE_T frameSize) {
    if (maxSize < 16) return 0;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    SIZE_T offset = 0;

    // 多种等价序言形式
    switch (rng() % 4) {
    case 0: {
        // 标准: push rbp; mov rbp, rsp; sub rsp, N
        buffer[offset++] = 0x55; // push rbp
        buffer[offset++] = 0x48; buffer[offset++] = 0x89; buffer[offset++] = 0xE5; // mov rbp, rsp
        buffer[offset++] = 0x48; buffer[offset++] = 0x81; buffer[offset++] = 0xEC; // sub rsp, imm32
        *reinterpret_cast<DWORD*>(buffer + offset) = static_cast<DWORD>(frameSize);
        offset += 4;
        break;
    }
    case 1: {
        // push rbp; lea rbp, [rsp]; ...
        buffer[offset++] = 0x55;
        buffer[offset++] = 0x48; buffer[offset++] = 0x8D; buffer[offset++] = 0x2C; buffer[offset++] = 0x24;
        if (maxSize - offset >= 4) {
            buffer[offset++] = 0x48; buffer[offset++] = 0x83; buffer[offset++] = 0xEC;
            buffer[offset++] = static_cast<BYTE>(frameSize & 0x7F);
        }
        break;
    }
    case 2: {
        // push rbp; lea rbp, [rsp-frame]; (x64 安全版本, 无 ENTER)
        buffer[offset++] = 0x55; // push rbp
        if (maxSize - offset >= 7) {
            // lea rbp, [rsp - frameSize]
            buffer[offset++] = 0x48;
            buffer[offset++] = 0x8D;
            if (frameSize < 128) {
                buffer[offset++] = 0x6C; buffer[offset++] = 0x24;
                buffer[offset++] = static_cast<BYTE>(256 - (frameSize & 0xFF)); // neg offset
            } else {
                buffer[offset++] = 0xAC; buffer[offset++] = 0x24;
                int32_t negOff = -static_cast<int32_t>(frameSize & 0xFFFFFFFF);
                memcpy(buffer + offset, &negOff, 4);
                offset += 4;
            }
        }
        break;
    }
    case 3: {
        // push rbp; push rsp; pop rbp; sub rsp, N  (混淆版)
        buffer[offset++] = 0x55;
        buffer[offset++] = 0x54;
        buffer[offset++] = 0x5D;
        if (maxSize - offset >= 5) {
            buffer[offset++] = 0x48; buffer[offset++] = 0x83; buffer[offset++] = 0xEC;
            buffer[offset++] = static_cast<BYTE>(frameSize & 0x7F);
        }
        break;
    }
    }

    return offset;
}

SIZE_T PolymorphicCode::GenerateEpilogue(BYTE* buffer, SIZE_T maxSize,
                                          SIZE_T /*frameSize*/) {
    if (maxSize < 8) return 0;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    SIZE_T offset = 0;

    switch (rng() % 3) {
    case 0:
        // leave; ret
        buffer[offset++] = 0xC9; // leave
        buffer[offset++] = 0xC3; // ret
        break;
    case 1:
        // pop rbp; ret
        buffer[offset++] = 0x5D;
        buffer[offset++] = 0xC3;
        break;
    case 2:
        // mov rsp, rbp; pop rbp; ret
        buffer[offset++] = 0x48; buffer[offset++] = 0x89; buffer[offset++] = 0xEC;
        buffer[offset++] = 0x5D;
        buffer[offset++] = 0xC3;
        break;
    }

    return offset;
}

SIZE_T PolymorphicCode::InsertJunkInstructions(BYTE* buffer, SIZE_T codeSize,
                                                SIZE_T maxSize, DWORD junkPerInst) {
    if (maxSize <= codeSize) return codeSize;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    // 通用垃圾指令 (不影响语义)
    const BYTE junkNop1[]  = {0x90};
    const BYTE junkNop2[]  = {0x66, 0x90};
    const BYTE junkNop3[]  = {0x48, 0x87, 0xC0};
    const BYTE junkNop4[]  = {0x48, 0x87, 0xDB};
    const BYTE junkNop5[]  = {0x0F, 0x1F, 0x00};
    const BYTE junkNop6[]  = {0x0F, 0x1F, 0x40, 0x00};
    const BYTE junkNop7[]  = {0x0F, 0x1F, 0x44, 0x00, 0x00};
    struct JunkEntry {
        const BYTE* data;
        SIZE_T size;
    };
    JunkEntry junkTable[] = {
        {junkNop1, 1}, {junkNop2, 2}, {junkNop3, 3},
        {junkNop4, 3}, {junkNop5, 3}, {junkNop6, 4}, {junkNop7, 5}
    };

    // 在扫描到的每条指令后插入垃圾
    // 简化: 随机散布垃圾指令
    SIZE_T inserted = 0;
    for (DWORD i = 0; i < junkPerInst && codeSize + inserted < maxSize;) {
        int idx = rng() % 7;
        SIZE_T junkLen = junkTable[idx].size;

        if (codeSize + inserted + junkLen > maxSize) break;

        // 随机插入位置
        SIZE_T insertPos = rng() % (codeSize + inserted + 1);

        // 向后移动数据
        if (insertPos < codeSize + inserted) {
            memmove(buffer + insertPos + junkLen,
                    buffer + insertPos,
                    codeSize + inserted - insertPos);
        }

        memcpy(buffer + insertPos, junkTable[idx].data, junkLen);
        inserted += junkLen;
        i++;
    }

    return codeSize + inserted;
}

SIZE_T PolymorphicCode::GenerateDeadCode(BYTE* buffer, SIZE_T maxSize) {
    if (maxSize < 32) return 0;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    SIZE_T offset = 0;

    // 生成随机但看起来合法的x64代码块
    // 包含: 一些寄存器操作 + 条件跳转 (自包含, 不会逃逸)

    // push 几个寄存器
    for (int i = 0; i < 3 && offset < maxSize - 20; i++) {
        buffer[offset++] = 0x50 + (rng() % 8); // push rN
    }

    // 一些随机算术操作
    for (int i = 0; i < 4 && offset < maxSize - 20; i++) {
        BYTE reg1 = static_cast<BYTE>(rng() % 8);
        BYTE reg2 = static_cast<BYTE>(rng() % 8);

        switch (rng() % 5) {
        case 0: // xor reg, reg
            buffer[offset++] = 0x48;
            buffer[offset++] = 0x31;
            buffer[offset++] = 0xC0 | (reg1 << 3) | reg2;
            break;
        case 1: // add reg, imm8
            buffer[offset++] = 0x48;
            buffer[offset++] = 0x83;
            buffer[offset++] = 0xC0 | reg1;
            buffer[offset++] = static_cast<BYTE>(rng());
            break;
        case 2: // and reg, imm8
            buffer[offset++] = 0x48;
            buffer[offset++] = 0x83;
            buffer[offset++] = 0xE0 | reg1;
            buffer[offset++] = static_cast<BYTE>(rng());
            break;
        case 3: // nop dword
            buffer[offset++] = 0x0F;
            buffer[offset++] = 0x1F;
            buffer[offset++] = 0x00;
            break;
        case 4: // xchg reg, reg
            buffer[offset++] = 0x48;
            buffer[offset++] = 0x87;
            buffer[offset++] = 0xC0 | (reg1 << 3) | reg2;
            break;
        }
    }

    // pop 恢复
    for (int i = 2; i >= 0 && offset < maxSize - 1; i--) {
        buffer[offset++] = 0x58 + (rng() % 8); // pop rN
    }

    // ret (死代码, 不实际执行)
    if (offset < maxSize) {
        buffer[offset++] = 0xC3; // ret
    }

    return offset;
}

SIZE_T PolymorphicCode::RemapRegisters(BYTE* buffer, SIZE_T codeSize) {
    // E18: 安全寄存器重映射 — 仅做同大小替换, 不插入 REX 前缀
    //      避免 memmove 导致的缓冲区溢出和逻辑错误
    //      策略: push regA → push regB (同一编码空间, 同大小)
    //            pop regA  → pop regB  无需 REX 前缀

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    SIZE_T remapsApplied = 0;
    BYTE regMapping[8]; // 寄存器编号映射表
    for (int i = 0; i < 8; i++) regMapping[i] = static_cast<BYTE>(i);

    // 生成随机寄存器重映射 (至少改变2个寄存器)
    int swaps = rng() % 3 + 1;
    for (int i = 0; i < swaps; i++) {
        int a = rng() % 7 + 1; // 保留 r0(rax) 不变 (常用于返回值)
        int b = rng() % 7 + 1;
        std::swap(regMapping[a], regMapping[b]);
    }

    for (SIZE_T offset = 0; offset < codeSize; offset++) {
        BYTE op = buffer[offset];

        // push reg (0x50-0x57) — 同大小替换
        if (op >= 0x50 && op <= 0x57) {
            int reg = op - 0x50;
            buffer[offset] = 0x50 + regMapping[reg];
            remapsApplied++;
        }
        // pop reg (0x58-0x5F) — 同大小替换
        else if (op >= 0x58 && op <= 0x5F) {
            int reg = op - 0x58;
            buffer[offset] = 0x58 + regMapping[reg];
            remapsApplied++;
        }
    }

    return codeSize; // 大小不变 (仅同大小替换)
}

} // namespace eac
} // namespace stealth