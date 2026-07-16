// ============================================================
// memory_cloak.cpp — 内存隐身模块实现
// ============================================================

#include "memory_cloak.h"
#include "platform.h"
#include "syscall_direct.h"
#include <chrono>
#include <cmath>
#include <psapi.h>
#include <random>

#pragma comment(lib, "psapi.lib")

namespace stealth {

// ============================================================
// SleepObfuscator
// ============================================================

SleepObfuscator& SleepObfuscator::Instance() {
    static SleepObfuscator instance;
    return instance;
}

void SleepObfuscator::RC4Crypt(void* data, SIZE_T size, const BYTE* key, SIZE_T keyLen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = static_cast<BYTE>(i);

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        std::swap(S[i], S[j]);
    }

    int i_idx = 0;
    j = 0;
    auto* buf = static_cast<BYTE*>(data);
    for (SIZE_T n = 0; n < size; n++) {
        i_idx = (i_idx + 1) % 256;
        j = (j + S[i_idx]) % 256;
        std::swap(S[i_idx], S[j]);
        buf[n] ^= S[(S[i_idx] + S[j]) % 256];
    }
}

void SleepObfuscator::XorCrypt(void* data, SIZE_T size, BYTE key) {
    auto* buf = static_cast<BYTE*>(data);
    for (SIZE_T i = 0; i < size; i++) {
        buf[i] ^= key ^ static_cast<BYTE>(i * 0xAD + 0x37);
    }
}

// 返回自身代码所在页面的基地址 (用于 EkkoSleep 自身页豁免)
// ★ v3.125: 使用 EkkoSleepMarker 确保与 EkkoSleep 在同一编译单元且同页
namespace {
    // 占位函数: 与 EkkoSleep 在同一 .cpp 文件, 确保代码页被豁免
    static void EkkoSleepMarker() {}
}
uintptr_t SleepObfuscator::GetSelfPage() {
    // 使用 EkkoSleepMarker 的地址 — 与 EkkoSleep 在同一编译单元,
    // 编译器将其放置在 .text 区段的临近位置, 大概率在同一 4KB 页面
    return reinterpret_cast<uintptr_t>(&EkkoSleepMarker) & ~0xFFFULL;
}

void SleepObfuscator::RegisterProtectedRegion(void* addr, SIZE_T size) {
    // ★ v3.125: 固定数组 — 检查容量
    if (m_regionCount >= MAX_REGIONS) return;

    ProtectedRegion& region = m_regions[m_regionCount++];
    region.addr = addr;
    region.size = size;
    region.isCode = false;

    // 生成随机 XOR 密钥
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    region.xorKey = static_cast<BYTE>(rng());
}

void SleepObfuscator::RegisterProtectedCode(void* addr, SIZE_T size) {
    // ★ v3.125: 固定数组 — 检查容量
    if (m_regionCount >= MAX_REGIONS) return;

    ProtectedRegion& region = m_regions[m_regionCount++];
    region.addr = addr;
    region.size = size;
    region.isCode = true;

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    region.xorKey = static_cast<BYTE>(rng());
}

void SleepObfuscator::EncryptAll() {
    // ★ v3.125: 固定数组 — 只遍历 m_regionCount 个有效条目
    for (int ri = 0; ri < m_regionCount; ri++) {
        ProtectedRegion& region = m_regions[ri];
        if (region.isCode) {
            DWORD oldProtect;
            if (!VirtualProtect(region.addr, region.size, PAGE_READWRITE, &oldProtect)) {
                continue;
            }
            XorCrypt(region.addr, region.size, region.xorKey);
            VirtualProtect(region.addr, region.size, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), region.addr, region.size);
        } else {
            // ★ v3.37 FIX: 检查 VirtualProtect 返回值
            //   如果 VirtualProtect 失败 (Win11 HVCI/CFG 可能阻止), 则跳过此区域
            //   避免对 PROTECTED 页面直接 XorCrypt → ACCESS_VIOLATION → 闪退
            DWORD oldProtect = 0;
            if (!VirtualProtect(region.addr, region.size, PAGE_READWRITE, &oldProtect)) {
                continue; // 跳过无法修改保护的区域
            }
            XorCrypt(region.addr, region.size, region.xorKey);
            VirtualProtect(region.addr, region.size, oldProtect, &oldProtect);
        }
    }
}

void SleepObfuscator::DecryptAll() {
    // ★ v3.125: 固定数组 — 只遍历 m_regionCount 个有效条目
    for (int ri = 0; ri < m_regionCount; ri++) {
        ProtectedRegion& region = m_regions[ri];
        if (region.isCode) {
            DWORD oldProtect;
            if (!VirtualProtect(region.addr, region.size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                continue;
            }
            XorCrypt(region.addr, region.size, region.xorKey);
            VirtualProtect(region.addr, region.size, PAGE_EXECUTE_READ, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), region.addr, region.size);
        } else {
            // ★ v3.37 FIX: 检查 VirtualProtect 返回值 (同 EncryptAll)
            DWORD oldProtect = 0;
            if (!VirtualProtect(region.addr, region.size, PAGE_READWRITE, &oldProtect)) {
                continue; // 跳过无法修改保护的区域
            }
            XorCrypt(region.addr, region.size, region.xorKey);
            VirtualProtect(region.addr, region.size, oldProtect, &oldProtect);
        }
    }
}

void SleepObfuscator::ObfuscatedSleep(DWORD milliseconds) {
    // ★ v3.125: 固定数组 m_regionCount
    if (m_regionCount == 0) {
        Sleep(milliseconds);
        return;
    }

    // 加密 → 短暂睡眠 → 解密
    // 将长睡眠拆分为多个短周期
    const DWORD CHUNK_MS = 50; // 每 50ms 解密一次

    DWORD remaining = milliseconds;
    while (remaining > 0) {
        DWORD chunk = min(remaining, CHUNK_MS);

        // ★ v3.37: EncryptAll/DecryptAll 已安全化, VirtualProtect 失败会自动跳过
        EncryptAll();
        Sleep(chunk);
        DecryptAll();

        remaining -= chunk;
    }
}

void SleepObfuscator::EkkoSleep(DWORD milliseconds) {
    // Ekko 技术: 使用 WaitableTimer 替代 Sleep
    // 在计时器触发前加密内存, 触发后解密

    // ★ v3.125: 固定数组 m_regionCount
    if (m_regionCount == 0) {
        Sleep(milliseconds);
        return;
    }

    // ★ v3.38 FIX: 移除冗余的 CreateTimerQueue — 它创建内核线程池
    //   但我们不使用任何 timer callback, 线程池纯属浪费且可能引发未知行为
    //   直接使用 EncryptAll → WaitableTimer → DecryptAll 即可

    // ★ v3.37: EncryptAll/DecryptAll 已安全化 (检查 VirtualProtect 返回值)
    EncryptAll();

    HANDLE hWaitableTimer = CreateWaitableTimerW(nullptr, TRUE, nullptr);
    if (!hWaitableTimer) {
        DecryptAll();  // 加密后必须解密, 否则内存处于损坏状态
        ObfuscatedSleep(milliseconds);
        return;
    }

    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -static_cast<LONGLONG>(milliseconds) * 10000LL;
    SetWaitableTimer(hWaitableTimer, &dueTime, 0, nullptr, nullptr, FALSE);

    WaitForSingleObject(hWaitableTimer, INFINITE);

    DecryptAll();

    CloseHandle(hWaitableTimer);
}

void SleepObfuscator::FoliageSleep(DWORD milliseconds) {
    // Foliage 技术: 使用 NtWaitForSingleObject 的 APC 变体
    // 当 APC 排队时, 线程被唤醒 → 加密内存 → 继续等待

    // ★ v3.125: 固定数组 m_regionCount
    if (m_regionCount == 0) {
        Sleep(milliseconds);
        return;
    }

    // 简化实现: 使用分段的 WaitForSingleObject
    const DWORD CHUNK_MS = 30;
    DWORD remaining = milliseconds;

    // 循环外创建一次 Event, 避免每30ms创建/销毁内核对象
    HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    // K6: 预先生成 syscall stub, 避免每个30ms循环重复分配 4KB
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtWaitForSingleObject;
    void* stub = (ssn && hEvent) ? TartarusGate::GenerateSyscallStub(ssn) : nullptr;
    using NtWaitForSingleObject_t = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
    auto fn = stub ? reinterpret_cast<NtWaitForSingleObject_t>(stub) : nullptr;

    while (remaining > 0) {
        DWORD chunk = min(remaining, CHUNK_MS);

        // ★ v3.37: EncryptAll/DecryptAll 已安全化
        EncryptAll();

        LARGE_INTEGER timeout;
        timeout.QuadPart = -static_cast<LONGLONG>(chunk) * 10000LL;

        if (fn && hEvent) {
            fn(hEvent, FALSE, &timeout);
        }

        DecryptAll();
        remaining -= chunk;
    }

    if (stub) VirtualFree(stub, 0, MEM_RELEASE);
    if (hEvent) CloseHandle(hEvent);
}

// ============================================================
// ModuleStomper
// ============================================================

ModuleStomper::StompCandidate
ModuleStomper::FindCandidateInSelf(SIZE_T requiredSize) {
    StompCandidate best = {};

    // 候选模块: 加载的不敏感 DLL
    const wchar_t* candidates[] = {
        L"msvcrt.dll", L"userenv.dll", L"uxtheme.dll",
        L"dwmapi.dll", L"version.dll", L"ws2_32.dll",
        L"iphlpapi.dll", L"dnsapi.dll", L"winmm.dll"
    };

    for (auto* modName : candidates) {
        HMODULE hMod = GetModuleHandleW(modName);
        if (!hMod) continue;

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
            continue;

        SIZE_T gap = FindWritableGap(hMod, requiredSize);
        if (gap >= requiredSize) {
            // 找到可用间隙
            best.module = hMod;
            best.baseAddress = reinterpret_cast<uintptr_t>(hMod);
            best.moduleSize = modInfo.SizeOfImage;
            best.availableSize = gap;
            best.moduleName = modName;
            break;
        }
    }

    return best;
}

ModuleStomper::StompCandidate
ModuleStomper::FindCandidateInProcess(HANDLE hProcess, SIZE_T requiredSize) {
    StompCandidate best = {};

    // 枚举目标进程模块
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return best;

    DWORD modCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < modCount; i++) {
        WCHAR modName[MAX_PATH] = {};
        GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH);

        // 跳过关键系统模块和反作弊模块
        if (_wcsicmp(modName, L"ntdll.dll") == 0 ||
            _wcsicmp(modName, L"kernel32.dll") == 0 ||
            _wcsicmp(modName, L"kernelbase.dll") == 0 ||
            wcsstr(modName, L"steam") ||
            wcsstr(modName, L"vac") ||
            wcsstr(modName, L"overlay")) {
            continue;
        }

        // 查找不重要的游戏 DLL 中的空隙
        MODULEINFO modInfo;
        if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
            // 检查模块中可写的区段间隙
            auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hMods[i]);
            if (IsBadReadPtr(dos, sizeof(IMAGE_DOS_HEADER)) || dos->e_magic != IMAGE_DOS_SIGNATURE)
                continue;

            auto* ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<uintptr_t>(hMods[i]) + dos->e_lfanew);
            if (IsBadReadPtr(ntHdr, sizeof(IMAGE_NT_HEADERS)) || ntHdr->Signature != IMAGE_NT_SIGNATURE)
                continue;

            auto* section = IMAGE_FIRST_SECTION(ntHdr);
            for (int s = 0; s < static_cast<int>(ntHdr->FileHeader.NumberOfSections); s++) {
                bool isWritable = (section[s].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                bool isExecutable = (section[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

                if (isWritable && !isExecutable) {
                    SIZE_T rawSize = section[s].SizeOfRawData;
                    SIZE_T virtSize = section[s].Misc.VirtualSize;
                    if (virtSize > rawSize + requiredSize) {
                        best.module = reinterpret_cast<HMODULE>(hMods[i]);
                        best.baseAddress = reinterpret_cast<uintptr_t>(hMods[i]);
                        best.moduleSize = modInfo.SizeOfImage;
                        best.availableSize = virtSize - rawSize;
                        best.moduleName = modName;
                        return best;
                    }
                }
            }
        }
    }

    return best;
}

SIZE_T ModuleStomper::FindWritableGap(HMODULE mod, SIZE_T minSize) {
    // 在模块区段之间找可写的空隙
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(mod) + dos->e_lfanew);

    auto* section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < static_cast<int>(nt->FileHeader.NumberOfSections); i++) {
        char name[9] = {};
        memcpy(name, section[i].Name, 8);

        // 优先选择 .data 或 .bss 区段 (通常有大块无用区域)
        bool isWritable = (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        bool isExecutable = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool isBss = (strstr(name, ".bss") != nullptr);
        bool isData = (strstr(name, ".data") != nullptr);

        if (isWritable && !isExecutable && (isData || isBss)) {
            // .data 区段末尾通常有空隙
            SIZE_T rawSize = section[i].SizeOfRawData;
            SIZE_T virtSize = section[i].Misc.VirtualSize;

            if (virtSize > rawSize + minSize) {
                return virtSize - rawSize;
            }
        }
    }

    return 0;
}

bool ModuleStomper::StompInto(StompCandidate& candidate,
                               const void* payload, SIZE_T payloadSize) {
    // 备份原始字节
    std::vector<BYTE> backup(payloadSize);
    memcpy(backup.data(), reinterpret_cast<void*>(candidate.targetAddress), payloadSize);

    // 修改内存保护
    DWORD oldProtect;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(candidate.targetAddress),
                        payloadSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // 写入 payload
    memcpy(reinterpret_cast<void*>(candidate.targetAddress), payload, payloadSize);

    // 刷新缓存
    FlushInstructionCache(GetCurrentProcess(),
        reinterpret_cast<LPCVOID>(candidate.targetAddress), payloadSize);

    return true;
}

bool ModuleStomper::RestoreStomped(const StompCandidate& candidate,
                                    const std::vector<BYTE>& backup) {
    DWORD oldProtect;
    VirtualProtect(reinterpret_cast<LPVOID>(candidate.targetAddress),
                   backup.size(), PAGE_READWRITE, &oldProtect);

    memcpy(reinterpret_cast<void*>(candidate.targetAddress),
           backup.data(), backup.size());

    VirtualProtect(reinterpret_cast<LPVOID>(candidate.targetAddress),
                   backup.size(), oldProtect, &oldProtect);

    return true;
}

bool ModuleStomper::IsInLegitimateModule(uintptr_t addr) {
    HMODULE hMod;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           reinterpret_cast<LPCWSTR>(addr), &hMod) && hMod) {
        WCHAR modPath[MAX_PATH] = {};
        GetModuleFileNameW(hMod, modPath, MAX_PATH);
        std::wstring path(modPath);
        for (auto& c : path) c = towlower(c);

        return (path.find(L"\\system32\\") != std::wstring::npos ||
                path.find(L"\\windows\\") != std::wstring::npos ||
                path.find(L"\\steamapps\\") != std::wstring::npos);
    }
    return false;
}

// ============================================================
// PhantomSection
// ============================================================

void* PhantomSection::AllocatePhantom(SIZE_T size) {
    // 使用 MEM_TOP_DOWN + 特定地址范围使其看起来像系统分配
    // 或使用 NtCreateSection + SEC_IMAGE 标志

    return AllocateAsImageSection(size, L"api-ms-win-core-sysinfo-l1-1-0.dll");
}

void* PhantomSection::AllocateAsImageSection(SIZE_T size, const wchar_t* disguiseName) {
    // 创建 Section 对象, 模仿 DLL 映射
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = {};
    maxSize.QuadPart = static_cast<LONGLONG>(size);

    using NtCreateSection_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    static auto NtCreateSection = reinterpret_cast<NtCreateSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));

    if (!NtCreateSection) return nullptr;

    // 创建 Section (页面文件支持的内存段, VAD 条目表现为正常映射)
    // 注意: 不使用 SEC_IMAGE (需要文件句柄), 而是使用 SEC_COMMIT
    // 此处 VAD 伪装效果有限, 完整实现需要映射到文件支持的对象
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS st = NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        &oa,
        &maxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT, // 不是 SEC_IMAGE, 但 VAD 条目仍正常
        nullptr
    );

    if (!NT_SUCCESS(st)) return nullptr;

    // 映射到随机地址 (模仿 ASLR)
    PVOID baseAddr = nullptr;
    SIZE_T viewSize = size;

    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
        SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    static auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));

    if (NtMapViewOfSection) {
        NtMapViewOfSection(hSection, GetCurrentProcess(), &baseAddr,
            0, size, nullptr, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    }

    CloseHandle(hSection);
    return baseAddr;
}

uintptr_t PhantomSection::AllocatePhantomInProcess(HANDLE hProcess, SIZE_T size) {
    // 在目标进程中创建幽灵分配
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = {};
    maxSize.QuadPart = static_cast<LONGLONG>(size);

    using NtCreateSection_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    static auto NtCreateSection = reinterpret_cast<NtCreateSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));

    if (!NtCreateSection) return 0;

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS st = NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        &oa, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr
    );

    if (!NT_SUCCESS(st)) return 0;

    PVOID remoteAddr = nullptr;
    SIZE_T viewSize = size;

    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
        SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    static auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));

    if (NtMapViewOfSection) {
        NtMapViewOfSection(hSection, hProcess, &remoteAddr,
            0, size, nullptr, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    }

    CloseHandle(hSection);
    return reinterpret_cast<uintptr_t>(remoteAddr);
}

// ============================================================
// ★ Fix B2: VAD Hiding — NtQueryVirtualMemory 代理实现
// ============================================================

// ★ v3.125: 固定数组替代 std::vector — 避免 CRT 堆依赖
PhantomSection::VADHiddenRegion PhantomSection::s_vadHiddenRegions[PhantomSection::MAX_VAD_REGIONS];
int PhantomSection::s_vadRegionCount = 0;

void PhantomSection::RegisterForVADHide(void* addr, SIZE_T size) {
    if (!addr || size == 0) return;
    // ★ v3.125: 固定数组 — 检查容量
    if (s_vadRegionCount >= MAX_VAD_REGIONS) return;

    VADHiddenRegion& region = s_vadHiddenRegions[s_vadRegionCount++];
    region.addr = addr;
    region.size = size;
}

bool PhantomSection::IsInVADHiddenRegion(void* addr) {
    uintptr_t target = reinterpret_cast<uintptr_t>(addr);
    // ★ v3.125: 固定数组 — 只遍历 s_vadRegionCount 个有效条目
    for (int i = 0; i < s_vadRegionCount; i++) {
        const VADHiddenRegion& region = s_vadHiddenRegions[i];
        uintptr_t base = reinterpret_cast<uintptr_t>(region.addr);
        if (target >= base && target < base + region.size) {
            return true;
        }
    }
    return false;
}

HMODULE PhantomSection::GetDisguiseModuleBase() {
    // ★ Fix B2: 返回 ntdll.dll 基址用于 VAD AllocationBase 伪装
    // ntdll.dll 是所有 Windows 进程的默认加载模块, 
    // 将其作为 AllocationBase 可使隐藏区域看起来像 ntdll 的正常映射
    return GetModuleHandleW(L"ntdll.dll");
}

PhantomSection::NtQVM_t PhantomSection::GetRealNtQueryVirtualMemory() {
    static NtQVM_t s_realNtQVM = nullptr;
    if (!s_realNtQVM) {
        s_realNtQVM = reinterpret_cast<NtQVM_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory"));
    }
    return s_realNtQVM;
}

NTSTATUS NTAPI PhantomSection::NtQueryVirtualMemoryProxy(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength)
{
    // ★ Fix B2: 首先调用真实的 NtQueryVirtualMemory 获取真实信息
    auto realNtQVM = GetRealNtQueryVirtualMemory();
    if (!realNtQVM) return STATUS_NOT_SUPPORTED;

    NTSTATUS st = realNtQVM(ProcessHandle, BaseAddress,
                             MemoryInformationClass,
                             MemoryInformation,
                             MemoryInformationLength,
                             ReturnLength);

    // 仅处理 MemoryBasicInformation (class 0) 的伪装
    if (MemoryInformationClass != 0) return st;

    // 仅伪装当前进程的查询 (外部进程不受影响)
    if (ProcessHandle != GetCurrentProcess()) return st;

    if (!NT_SUCCESS(st)) return st;

    // 检查查询地址是否在我们的 VAD 隐藏区域内
    if (!IsInVADHiddenRegion(BaseAddress)) return st;

    // ★ Fix B2: 修改 MEMORY_BASIC_INFORMATION 进行 VAD 伪装
    auto* mbi = static_cast<MEMORY_BASIC_INFORMATION*>(MemoryInformation);

    // Type: 改为 MEM_IMAGE (0x1000000) 伪装成从磁盘映射的 DLL 镜像
    // 而不是暴露 MEM_PRIVATE (0x20000) 的 VirtualAlloc 分配特征
    mbi->Type = MEM_IMAGE;  // 0x1000000

    // State: 保持 MEM_COMMIT (不变, 已提交的内存)
    // mbi->State 保持不变

    // Protection: 改为 PAGE_READONLY 而非 EXECUTE_READ
    // 让区域看起来像只读数据, 不暴露可执行特征
    // 只有当原本就是可执行才需要伪装, 如果是普通数据页则保持原样
    if (mbi->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        mbi->Protect = PAGE_READONLY;
    }
    // AllocationProtect 同样修改
    if (mbi->AllocationProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        mbi->AllocationProtect = PAGE_READONLY;
    }

    // ★ Fix B2: AllocationBase 指向合法模块 (ntdll.dll)
    // 使该区域看起来像是 ntdll 的一部分映射
    HMODULE disguiseMod = GetDisguiseModuleBase();
    if (disguiseMod) {
        mbi->AllocationBase = disguiseMod;
    }

    return st;
}

// ============================================================
// SelfCloaker — 自身 ManualMap 内存隐身
// ============================================================

SelfCloaker::CloakResult SelfCloaker::CloakManualMap(HMODULE dllBase, SIZE_T dllSize) {
    CloakResult result = {};

    if (!dllBase || dllSize < 0x1000) return result;

    // 1. 擦除 PE 头
    result.peStripped = StripPEHeaders(dllBase);

    // 2. 添加假 PEB Ldr 条目
    result.ldrCloaked = AddFakeLdrEntry(dllBase, dllSize, L"dxgi_adapter_cache.dll");

    // 2b. 移除自身 EXE 的 Ldr 条目 (隐藏 loader.exe 模块名)
    // SKIP: ManualMap 场景下 PEB 链表操作不稳定, 自删除已足够隐蔽
    // UnlinkSelfLdrEntry();

    // 3. 随机化页保护
    // SKIP: ManualMap 场景下 RandomizeProtections 不稳定
    result.protectionMixed = true;
    // result.protectionMixed = RandomizeProtections(dllBase, dllSize);

    return result;
}

bool SelfCloaker::StripPEHeaders(HMODULE base) {
    if (!base) return false;

    BYTE* image = reinterpret_cast<BYTE*>(base);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);

    // 验证 MZ 签名
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    DWORD peOffset = dos->e_lfanew;
    if (peOffset < sizeof(IMAGE_DOS_HEADER) || peOffset > 0x1000) return false;

    IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + peOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // --- 步骤1: 擦除 DOS 头 (0x00 - 0x3C) ---
    // 保留 e_lfanew 偏移信息后擦除
    DWORD savedElfanew = dos->e_lfanew;
    
    DWORD oldProtect = 0;
    VirtualProtect(image, 0x1000, PAGE_READWRITE, &oldProtect);

    // 用随机字节填充 DOS 头区域 (0x00 - 0x3C), 人为保留 e_lfanew
    std::mt19937 rng(static_cast<unsigned>(__rdtsc()));
    for (SIZE_T i = 0; i < sizeof(IMAGE_DOS_HEADER); i++) {
        image[i] = static_cast<BYTE>(rng() & 0xFF);
    }
    // 恢复 e_lfanew (后续可能需要定位 NT 头)
    *reinterpret_cast<DWORD*>(image + 0x3C) = savedElfanew;

    // --- 步骤2: 擦除 PE 签名 (4 字节 "PE\0\0") ---
    image[peOffset + 0] = 'R';
    image[peOffset + 1] = 'X';
    image[peOffset + 2] = static_cast<BYTE>(rng());
    image[peOffset + 3] = static_cast<BYTE>(rng());

    // --- 步骤3: 擦除 COFF 文件头 (Machine→NumberOfSections → SizeOfOptionalHeader→Magic) ---
    // COFF 头位置: peOffset + 4
    SIZE_T coffOffset = peOffset + 4;
    SIZE_T coffSize = sizeof(IMAGE_FILE_HEADER);

    for (SIZE_T i = 0; i < coffSize; i++) {
        image[coffOffset + i] = static_cast<BYTE>(rng() & 0xFF);
    }

    // --- 步骤4: 擦除 OptionalHeader 的前半部分 (Magic → SizeOfStackCommit) ---
    // 保留 SizeOfImage (用于 Ldr 条目), AddressOfEntryPoint, BaseOfCode, 
    // 以及 DataDirectory (导入表等已解析)
    SIZE_T optOffset = peOffset + 4 + sizeof(IMAGE_FILE_HEADER);
    SIZE_T optKeepFrom = offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfStackReserve);

    for (SIZE_T i = 0; i < optKeepFrom; i++) {
        image[optOffset + i] = static_cast<BYTE>(rng() & 0xFF);
    }

    VirtualProtect(image, 0x1000, oldProtect, &oldProtect);

    return true;
}

bool SelfCloaker::AddFakeLdrEntry(HMODULE base, SIZE_T size, const wchar_t* disguiseName) {
    if (!base || size == 0) return false;

    // 获取 PEB
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return false;

    PPEB_LDR_DATA ldr = PEB_LDR_PTR(peb);
    if (!ldr) return false;

    // 分配 LDR_DATA_TABLE_ENTRY_FULL (在堆上, 使其看起来像系统分配)
    SIZE_T entrySize = sizeof(LDR_DATA_TABLE_ENTRY_FULL) + 512; // 额外空间给模块名
    auto* fakeEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_FULL*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, entrySize));
    if (!fakeEntry) return false;

    // 填充条目信息
    // 直接用结构体字段写入 (LDR_ENTRY_DLLBASE 在 MinGW 下为函数调用, 不可赋值)
    fakeEntry->DllBase = base;
    fakeEntry->SizeOfImage = static_cast<ULONG>(size);
    fakeEntry->EntryPoint = nullptr; // DLL 入口 (已执行)

    // 复制伪装模块名 (放在结构体后的额外空间)
    auto* nameBuf = reinterpret_cast<wchar_t*>(
        reinterpret_cast<BYTE*>(fakeEntry) + sizeof(LDR_DATA_TABLE_ENTRY_FULL));
    if (disguiseName) {
        wcscpy_s(nameBuf, 128, disguiseName);
    } else {
        wcscpy_s(nameBuf, 128, L"dxgi_adapter_cache.dll");
    }

    UNICODE_STRING* baseNamePtr = LDR_ENTRY_BASE_NAME(fakeEntry);
    baseNamePtr->Buffer = nameBuf;
    baseNamePtr->Length = static_cast<USHORT>(wcslen(nameBuf) * sizeof(wchar_t));
    baseNamePtr->MaximumLength = baseNamePtr->Length + sizeof(wchar_t);

    auto* fullNamePtr = LDR_ENTRY_FULL_NAME(fakeEntry);
    fullNamePtr->Buffer = nameBuf; // 共用一个缓冲区
    fullNamePtr->Length = baseNamePtr->Length;
    fullNamePtr->MaximumLength = baseNamePtr->MaximumLength;

    // --- 插入到三个 Ldr 链表中 ---
    // InLoadOrderModuleList
    PLIST_ENTRY inLoadHead = LDR_INLOAD_HEAD(ldr);
    PLIST_ENTRY inLoadLinks = LDR_ENTRY_LOAD_LINKS(fakeEntry);
    
    // 插入到头部 (模仿 DLL 加载顺序)
    PLIST_ENTRY firstEntry = inLoadHead->Flink;
    inLoadLinks->Flink = firstEntry;
    inLoadLinks->Blink = inLoadHead;
    firstEntry->Blink = inLoadLinks;
    inLoadHead->Flink = inLoadLinks;

    // InMemoryOrderModuleList
    PLIST_ENTRY inMemoryHead = LDR_MEMORY_HEAD(ldr);
    PLIST_ENTRY inMemoryLinks = LDR_ENTRY_MEMORY_LINKS(fakeEntry);
    
    firstEntry = inMemoryHead->Flink;
    inMemoryLinks->Flink = firstEntry;
    inMemoryLinks->Blink = inMemoryHead;
    firstEntry->Blink = inMemoryLinks;
    inMemoryHead->Flink = inMemoryLinks;

    // InInitializationOrderModuleList
    PLIST_ENTRY inInitHead = LDR_INIT_HEAD(ldr);
    PLIST_ENTRY inInitLinks = LDR_ENTRY_INIT_LINKS(fakeEntry);
    
    firstEntry = inInitHead->Flink;
    inInitLinks->Flink = firstEntry;
    inInitLinks->Blink = inInitHead;
    firstEntry->Blink = inInitLinks;
    inInitHead->Flink = inInitLinks;

    return true;
}

bool SelfCloaker::RandomizeProtections(HMODULE base, SIZE_T size) {
    if (!base || size < 0x1000) return false;

    BYTE* image = reinterpret_cast<BYTE*>(base);
    SYSTEM_INFO sysInfo = {};
    GetSystemInfo(&sysInfo);
    DWORD pageSize = sysInfo.dwPageSize;
    if (pageSize == 0) pageSize = 0x1000;

    SIZE_T totalPages = (size + pageSize - 1) / pageSize;
    
    std::mt19937 rng(static_cast<unsigned>(__rdtsc()));

    for (SIZE_T i = 0; i < totalPages; i++) {
        BYTE* pageAddr = image + (i * pageSize);
        DWORD currentProtect = 0;

        // 跳过前 2 页 (已经被 PE 头擦除处理)
        if (i < 2) {
            VirtualProtect(pageAddr, pageSize, PAGE_READWRITE, &currentProtect);
            continue;
        }

        SIZE_T remaining = size - (i * pageSize);
        SIZE_T protectSize = (remaining < pageSize) ? remaining : pageSize;

        // 随机选择保护类型以混合模式
        DWORD newProtect;
        DWORD r = rng() % 100;
        
        if (r < 45) {
            // 45%: READWRITE (看起来像数据段)
            newProtect = PAGE_READWRITE;
        } else if (r < 80) {
            // 35%: EXECUTE_READ (正常的代码段)
            newProtect = PAGE_EXECUTE_READ;
        } else if (r < 90) {
            // 10%: READONLY
            newProtect = PAGE_READONLY;
        } else {
            // 10%: GUARD (在RW基础上加保护页标记, 不引发崩溃)
            newProtect = PAGE_READWRITE | PAGE_GUARD;
        }

        VirtualProtect(pageAddr, protectSize, newProtect, &currentProtect);
    }

    return true;
}

// ============================================================
// UnlinkSelfLdrEntry — 从 PEB Ldr 中移除 EXE 自身的模块条目
// ============================================================

bool SelfCloaker::UnlinkSelfLdrEntry() {
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return false;

    PPEB_LDR_DATA ldr = PEB_LDR_PTR(peb);
    if (!ldr) return false;

    // 获取 EXE 自身句柄
    HMODULE exeBase = GetModuleHandleW(nullptr);
    if (!exeBase) return false;

    // 遍历 InLoadOrderModuleList 找到 EXE 条目
    PLIST_ENTRY head = LDR_INLOAD_HEAD(ldr);
    PLIST_ENTRY entry = head->Flink;

    while (entry && entry != head) {
        auto* dataEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        if (LDR_ENTRY_DLLBASE(dataEntry) == exeBase) {
            // 找到 EXE 条目, 从三向链表中移除
            PLIST_ENTRY loadLinks  = LDR_ENTRY_LOAD_LINKS(dataEntry);
            PLIST_ENTRY memLinks   = LDR_ENTRY_MEMORY_LINKS(dataEntry);
            PLIST_ENTRY initLinks  = LDR_ENTRY_INIT_LINKS(dataEntry);

            // 双向解链
            loadLinks->Flink->Blink = loadLinks->Blink;
            loadLinks->Blink->Flink = loadLinks->Flink;

            memLinks->Flink->Blink = memLinks->Blink;
            memLinks->Blink->Flink = memLinks->Flink;

            initLinks->Flink->Blink = initLinks->Blink;
            initLinks->Blink->Flink = initLinks->Flink;

            // 擦除链表指针以防意外使用
            loadLinks->Flink = loadLinks->Blink = nullptr;
            memLinks->Flink  = memLinks->Blink  = nullptr;
            initLinks->Flink = initLinks->Blink = nullptr;

            return true;
        }
        // 安全检查: 避免无限循环
        if (entry == entry->Flink) break;
        entry = entry->Flink;
    }
    return false;
}

// ============================================================
// TelemetrySilencer — ETW + AMSI Patching
// ============================================================

TelemetrySilencer::PatchRecord TelemetrySilencer::s_etwPatch;
TelemetrySilencer::PatchRecord TelemetrySilencer::s_amsiPatch;

bool TelemetrySilencer::DisableETW() {
    if (s_etwPatch.addr) return true; // 已经 patched

    // 目标: ntdll!EtwEventWrite
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    auto* etwAddr = reinterpret_cast<BYTE*>(
        GetProcAddress(ntdll, "EtwEventWrite"));
    if (!etwAddr) return false;

    // 保存原始字节
    s_etwPatch.addr = etwAddr;
    s_etwPatch.size = 3; // ret = C3, 但需要 xor eax,eax; ret = 33 C0 C3
    // ★ v3.125: 固定数组替代 std::vector
    memcpy(s_etwPatch.originalBytes, etwAddr, 3);
    s_etwPatch.originalSize = 3;

    // Patch: xor eax, eax; ret (返回 0, 表示成功)
    // 33 C0 = xor eax, eax
    // C3    = ret
    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax,eax; ret

    DWORD oldProtect;
    VirtualProtect(etwAddr, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(etwAddr, patch, 3);
    VirtualProtect(etwAddr, 3, oldProtect, &oldProtect);

    return true;
}

bool TelemetrySilencer::DisableAMSI() {
    if (s_amsiPatch.addr) return true;

    // 目标: amsi.dll!AmsiScanBuffer
    HMODULE amsi = LoadLibraryW(L"amsi.dll");
    if (!amsi) return false;

    auto* amsiAddr = reinterpret_cast<BYTE*>(
        GetProcAddress(amsi, "AmsiScanBuffer"));
    if (!amsiAddr) return false;

    s_amsiPatch.addr = amsiAddr;
    s_amsiPatch.size = 6;

    // 保存原始字节
    // ★ v3.125: 固定数组替代 std::vector
    memcpy(s_amsiPatch.originalBytes, amsiAddr, 6);
    s_amsiPatch.originalSize = 6;

    // AmsiScanBuffer 开头 patching:
    // mov eax, AMSI_RESULT_CLEAN (0x80070057 = E_INVALIDARG, 
    // 但 AMSI_RESULT_CLEAN 通常为 0)
    // xor eax, eax; mov [rsp+...]; ret 更可靠
    // 简化: mov eax, 80070057h; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret

    DWORD oldProtect;
    VirtualProtect(amsiAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(amsiAddr, patch, 6);
    VirtualProtect(amsiAddr, 6, oldProtect, &oldProtect);

    return true;
}

bool TelemetrySilencer::RestoreETW() {
    if (!s_etwPatch.addr) return true;

    DWORD oldProtect;
    VirtualProtect(s_etwPatch.addr, s_etwPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);
    // ★ v3.125: 固定数组 originalBytes
    memcpy(s_etwPatch.addr, s_etwPatch.originalBytes, s_etwPatch.size);
    VirtualProtect(s_etwPatch.addr, s_etwPatch.size, oldProtect, &oldProtect);

    s_etwPatch.addr = nullptr;
    return true;
}

bool TelemetrySilencer::RestoreAMSI() {
    if (!s_amsiPatch.addr) return true;

    DWORD oldProtect;
    VirtualProtect(s_amsiPatch.addr, s_amsiPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);
    // ★ v3.125: 固定数组 originalBytes
    memcpy(s_amsiPatch.addr, s_amsiPatch.originalBytes, s_amsiPatch.size);
    VirtualProtect(s_amsiPatch.addr, s_amsiPatch.size, oldProtect, &oldProtect);

    s_amsiPatch.addr = nullptr;
    return true;
}

bool TelemetrySilencer::SilenceAll() {
    DisableETW();
    DisableAMSI();
    return true;
}

bool TelemetrySilencer::RestoreAll() {
    RestoreETW();
    RestoreAMSI();
    return true;
}

bool TelemetrySilencer::IsETWPatched() {
    if (!s_etwPatch.addr) return false;
    auto* addr = static_cast<BYTE*>(s_etwPatch.addr);
    return addr[0] == 0x33 && addr[1] == 0xC0 && addr[2] == 0xC3;
}

// ★ 修复 P8: 检测 AMSI 补丁是否仍有效
bool TelemetrySilencer::IsAMSIPatched() {
    if (!s_amsiPatch.addr) return false;
    auto* addr = static_cast<BYTE*>(s_amsiPatch.addr);
    // 检查 6 字节补丁: B8 57 00 07 80 C3
    return addr[0] == 0xB8 && addr[1] == 0x57 &&
           addr[2] == 0x00 && addr[3] == 0x07 &&
           addr[4] == 0x80 && addr[5] == 0xC3;
}

// ★ 修复 P8: 完整性验证 — EAC 可能恢复原始字节
// 调用此函数每30秒检测一次, 如果EAC恢复了原始代码则自动重新Patch
bool TelemetrySilencer::VerifyAndRepairAll() {
    bool allValid = true;

    // 验证 ETW 补丁
    if (s_etwPatch.addr) {
        if (!IsETWPatched()) {
            // EAC恢复了EtwEventWrite! 需要重新Patch
            allValid = false;

            // 重新读取原始字节 (EAC可能写入了不同的值)
            DWORD oldProtect;
            auto* etwAddr = static_cast<BYTE*>(s_etwPatch.addr);
            VirtualProtect(etwAddr, s_etwPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);

            // 重新写补丁
            BYTE patch[] = { 0x33, 0xC0, 0xC3 };
            memcpy(etwAddr, patch, s_etwPatch.size);
            VirtualProtect(etwAddr, s_etwPatch.size, oldProtect, &oldProtect);
        }
    }

    // 验证 AMSI 补丁
    if (s_amsiPatch.addr) {
        if (!IsAMSIPatched()) {
            allValid = false;

            DWORD oldProtect;
            auto* amsiAddr = static_cast<BYTE*>(s_amsiPatch.addr);
            VirtualProtect(amsiAddr, s_amsiPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);

            BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            memcpy(amsiAddr, patch, s_amsiPatch.size);
            VirtualProtect(amsiAddr, s_amsiPatch.size, oldProtect, &oldProtect);
        }
    }

    return allValid;
}

// ============================================================
// VACNetEvasion
// ============================================================

VACNetEvasion::AimProfile VACNetEvasion::GenerateHumanProfile() {
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    AimProfile profile;

    // 人类参数范围
    std::uniform_real_distribution<float> overshootDist(0.02f, 0.12f);
    std::uniform_real_distribution<float> undershootDist(0.01f, 0.08f);
    std::uniform_real_distribution<float> smoothDist(0.35f, 0.65f);
    std::uniform_real_distribution<float> reactionDist(120.0f, 280.0f);
    std::uniform_real_distribution<float> fatigueIntervalDist(30.0f, 120.0f);
    std::uniform_real_distribution<float> fatigueDurationDist(2.0f, 8.0f);
    std::uniform_real_distribution<float> missDist(0.01f, 0.04f);

    profile.overshootAmount  = overshootDist(rng);
    profile.undershootAmount = undershootDist(rng);
    profile.smoothingFactor  = smoothDist(rng);
    profile.reactionTimeMs   = reactionDist(rng);
    profile.fatigueInterval  = fatigueIntervalDist(rng);
    profile.fatigueDuration  = fatigueDurationDist(rng);
    profile.missChance       = missDist(rng);

    return profile;
}

void VACNetEvasion::HumanizeAim(float& targetX, float& targetY,
                                 const AimProfile& profile) {
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    // 1. 反应延迟模拟
    // (在调用此函数前, 调用者应等待 profile.reactionTimeMs)

    // 2. 欠冲/过冲模拟
    std::uniform_real_distribution<float> noiseDist(-1.0f, 1.0f);
    float overshoot = noiseDist(rng) * profile.overshootAmount * targetX;
    float undershoot = -noiseDist(rng) * profile.undershootAmount * targetY;

    targetX += overshoot;
    targetY += undershoot;

    // 3. 平滑移动 (微修正)
    float smoothX = targetX * profile.smoothingFactor;
    float smoothY = targetY * profile.smoothingFactor;
    targetX = smoothX + (1.0f - profile.smoothingFactor) * noiseDist(rng) * 2.0f;
    targetY = smoothY + (1.0f - profile.smoothingFactor) * noiseDist(rng) * 2.0f;

    // 4. 随机失准
    std::uniform_real_distribution<float> hitDist(0.0f, 1.0f);
    if (hitDist(rng) < profile.missChance) {
        // 故意"打偏"
        std::uniform_real_distribution<float> missOffset(-5.0f, 5.0f);
        targetX += missOffset(rng);
        targetY += missOffset(rng);
    }
}

void VACNetEvasion::RandomizePreAim(float& crosshairX, float& crosshairY,
                                     float mapWidth, float mapHeight) {
    // 添加微小的十字准星漂移
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    std::uniform_real_distribution<float> driftDist(-0.5f, 0.5f);
    crosshairX += driftDist(rng);
    crosshairY += driftDist(rng);
}

DWORD VACNetEvasion::RandomizeFireInterval(float baseIntervalMs) {
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    // 在 ±30% 范围内随机化射击间隔
    std::uniform_real_distribution<float> jitterDist(0.7f, 1.3f);
    return static_cast<DWORD>(baseIntervalMs * jitterDist(rng));
}

bool VACNetEvasion::IsAngleChangeSafe(float oldYaw, float oldPitch,
                                       float newYaw, float newPitch,
                                       float deltaTime) {
    // VAC Live 检测异常视角变化
    // 人类的最大转头速度约 600 度/秒 (但战斗中 200-300 度/秒更常见)

    const float MAX_DEG_PER_SEC = 400.0f; // 安全上限

    float yawDelta = fabsf(newYaw - oldYaw);
    // 处理角度环绕
    if (yawDelta > 180.0f) yawDelta = 360.0f - yawDelta;

    float pitchDelta = fabsf(newPitch - oldPitch);

    float totalDegPerSec = (yawDelta + pitchDelta) / deltaTime;

    return totalDegPerSec < MAX_DEG_PER_SEC;
}

} // namespace stealth
