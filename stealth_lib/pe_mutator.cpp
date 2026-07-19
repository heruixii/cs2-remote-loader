// ============================================================
// pe_mutator.cpp — PE 自修改 + 完整性绕过实现
// ============================================================

#include "pe_mutator.h"
#include "platform.h"
#include "syscall_direct.h"
#include "stealth_process.h"
#include "module_resolver.h"  // ★ BUILD 550: ModNameHash 替代明文模块名比较
#include <psapi.h>
// ★ BUILD 500: 移除 <random> <chrono> — CRT 堆依赖, 用简易 LCG RNG 替代

#pragma comment(lib, "psapi.lib")

namespace stealth {

// ★ BUILD 500: 简易 LCG 随机数生成器 — 替代 std::mt19937 + std::chrono
//   使用 QueryPerformanceCounter 作为种子, 避免 CRT 堆依赖
static uint32_t g_lcgState = 0;
static uint32_t SimpleRand() {
    if (!g_lcgState) {
        LARGE_INTEGER li;
        QueryPerformanceCounter(&li);
        g_lcgState = (uint32_t)(li.QuadPart ^ (li.QuadPart >> 32));
        if (!g_lcgState) g_lcgState = 0xDEADBEEF;
    }
    // LCG: X_{n+1} = (a * X_n + c) mod m (Numerical Recipes)
    g_lcgState = g_lcgState * 1664525 + 1013904223;
    return g_lcgState;
}
// 生成 [min, max] 范围内的随机数
static uint32_t SimpleRandRange(uint32_t min, uint32_t max) {
    if (min >= max) return min;
    uint32_t range = max - min + 1;
    return min + (SimpleRand() % range);
}

// ============================================================
// PeMutator
// ============================================================

HMODULE PeMutator::GetSelfModule() {
    // 从 PEB 获取自身模块基址, 不使用 GetModuleHandle (避免 API 调用)
    HMODULE result = nullptr;

    // 方法1: __readgsqword(0x60) -> PEB -> LDR
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (peb && peb->Ldr) {
        PLIST_ENTRY head = LDR_MEMORY_HEAD(peb->Ldr);
        PLIST_ENTRY entry = head->Flink;
        if (entry != head) {
            auto* dataEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
            result = static_cast<HMODULE>(LDR_ENTRY_DLLBASE(dataEntry));
        }
    }

    // 方法2: 回退 — 从 PEB+0x10 (ImageBaseAddress) 读取
    // ★ BUILD 550: 替代 GetModuleHandleW(nullptr) (规避 PAC 用户态 hook)
    if (!result) {
        PPEB peb2 = reinterpret_cast<PPEB>(__readgsqword(0x60));
        if (peb2) {
            result = *reinterpret_cast<HMODULE*>(reinterpret_cast<BYTE*>(peb2) + 0x10);
        }
    }

    return result;
}

uintptr_t PeMutator::GetSelfBase() {
    return reinterpret_cast<uintptr_t>(GetSelfModule());
}

PIMAGE_DOS_HEADER PeMutator::GetDosHeader() {
    return reinterpret_cast<PIMAGE_DOS_HEADER>(GetSelfBase());
}

PIMAGE_NT_HEADERS PeMutator::GetNtHeaders() {
    auto* dos = GetDosHeader();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    return reinterpret_cast<PIMAGE_NT_HEADERS>(GetSelfBase() + dos->e_lfanew);
}

bool PeMutator::StripRichHeader() {
    // Rich Header 位置: DOS Stub 之后, PE Signature 之前
    // 标记: "Rich" + XOR key
    // 清除策略: 用 0x00 或随机数据覆盖

    auto* dos = GetDosHeader();
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // 验证 e_lfanew 在合理范围内
    if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > 0x1000) {
        return false; // 损坏或异常 PE
    }

    // Rich Header 在偏移 0x80 到 e_lfanew 之间
    uintptr_t dosStubStart = GetSelfBase() + sizeof(IMAGE_DOS_HEADER);
    uintptr_t peSignature = GetSelfBase() + dos->e_lfanew;

    // 搜索 "Rich" 签名
    for (uintptr_t scan = dosStubStart; scan < peSignature - 8; scan++) {
        if (*reinterpret_cast<DWORD*>(scan) == 0x68636952) { // "Rich"
            // 找到 Rich Header, 大小在 Rich 之后 4 字节
            DWORD xorKey = *reinterpret_cast<DWORD*>(scan + 4);
            // 向前找到 DanS 标记来确定准确起始位置
            for (uintptr_t s2 = dosStubStart; s2 < scan - 4; s2++) {
                if (*reinterpret_cast<DWORD*>(s2) == 0x536E6144) { // "DanS"
                    DWORD richStart = static_cast<DWORD>(s2 - GetSelfBase());
                    DWORD richEnd = static_cast<DWORD>(scan + 8 - GetSelfBase());

                    // 修改内存保护以允许写入
                    DWORD oldProtect;
                    VirtualProtect(reinterpret_cast<LPVOID>(s2), richEnd - richStart,
                        PAGE_READWRITE, &oldProtect);

                    // 用随机数据覆盖 Rich Header — ★ BUILD 500: SimpleRand 替代 std::mt19937
                    for (uintptr_t p = s2; p < scan + 8; p++) {
                        *reinterpret_cast<BYTE*>(p) = static_cast<BYTE>(SimpleRand());
                    }

                    VirtualProtect(reinterpret_cast<LPVOID>(s2), richEnd - richStart,
                        oldProtect, &oldProtect);
                    return true;
                }
            }
        }
    }

    return false; // 无 Rich Header 或已清除
}

bool PeMutator::RandomizeTimestamp() {
    auto* nt = GetNtHeaders();
    if (!nt) return false;

    // 生成一个在可信范围内的随机时间戳
    // 使用 2020年-2024年间的时间戳 — ★ BUILD 500: SimpleRandRange 替代 std::mt19937+uniform_int_distribution
    DWORD newTimestamp = SimpleRandRange(1577836800, 1704067200);

    // 修改内存中的 PE 头
    DWORD oldProtect;
    uintptr_t tsAddr = GetSelfBase() + sizeof(IMAGE_DOS_HEADER) +
                       FIELD_OFFSET(IMAGE_NT_HEADERS, FileHeader.TimeDateStamp) -
                       sizeof(IMAGE_NT_HEADERS::OptionalHeader) +
                       sizeof(IMAGE_FILE_HEADER) - sizeof(DWORD);
    // 简化: 直接用 nt 地址计算
    uintptr_t tsPtr = reinterpret_cast<uintptr_t>(&nt->FileHeader.TimeDateStamp);

    VirtualProtect(reinterpret_cast<LPVOID>(tsPtr), sizeof(DWORD),
        PAGE_READWRITE, &oldProtect);

    nt->FileHeader.TimeDateStamp = newTimestamp;

    VirtualProtect(reinterpret_cast<LPVOID>(tsPtr), sizeof(DWORD),
        oldProtect, &oldProtect);

    return true;
}

bool PeMutator::StripDebugInfo() {
    auto* nt = GetNtHeaders();
    if (!nt) return false;

    auto& debugDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    if (debugDir.Size == 0 || debugDir.VirtualAddress == 0) {
        return false; // 无调试信息
    }

    // 清零调试目录
    uintptr_t debugAddr = GetSelfBase() + debugDir.VirtualAddress;
    SIZE_T debugSize = debugDir.Size;

    DWORD oldProtect;
    VirtualProtect(reinterpret_cast<LPVOID>(debugAddr), debugSize,
        PAGE_READWRITE, &oldProtect);

    SecureZeroMemory(reinterpret_cast<PVOID>(debugAddr), debugSize);

    VirtualProtect(reinterpret_cast<LPVOID>(debugAddr), debugSize,
        oldProtect, &oldProtect);

    // 清零数据目录项
    VirtualProtect(&debugDir, sizeof(debugDir), PAGE_READWRITE, &oldProtect);
    debugDir.VirtualAddress = 0;
    debugDir.Size = 0;
    VirtualProtect(&debugDir, sizeof(debugDir), oldProtect, &oldProtect);

    return true;
}

bool PeMutator::ObfuscateImportTable() {
    // ⚠️ 警告: 运行时修改 IAT 导入名称可能导致程序崩溃!
    // 因为 IAT 在加载阶段已解析, 修改名称仅影响磁盘/内存扫描特征。
    //
    // 安全策略: 只修改 OriginalFirstThunk (加载后不再使用的查找表),
    // 不修改 FirstThunk (IAT, 已解析的函数指针表)。
    // 如果 OriginalFirstThunk 不存在, 则完全不操作。
    //
    // 更好的策略: 启用 stealth_config.obfuscateImports = false,
    // 改为在编译后使用 pe_postprocessor.py 修改文件中的导入名称。
    //
    // ★ BUILD 550: 整个函数 #if 0 包裹 — 该函数从未被调用 (dead code),
    //   且 sensitiveApis[] 数组中的 "CreateToolhelp32Snapshot" 等明文 API 名
    //   仍会出现在 .rdata 段, 增加检测特征。改用编译后 pe_postprocessor.py 处理。
#if 0
    auto* nt = GetNtHeaders();
    if (!nt) return false;

    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress || !importDir.Size) return false;

    // 敏感 API (仅用于修改 OriginalFirstThunk 的查找名称)
    static const char* sensitiveApis[] = {
        "WriteProcessMemory", "VirtualProtectEx", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "Module32First", "Module32Next",
        "AdjustTokenPrivileges"
    };

    auto* firstDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR*>(
        GetSelfBase() + importDir.VirtualAddress);

    for (auto* desc = firstDesc; desc->Name; desc++) {
        // 只操作 OriginalFirstThunk (INT), 不操作 FirstThunk (IAT)
        if (!desc->OriginalFirstThunk) continue;

        auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA*>(
            GetSelfBase() + desc->OriginalFirstThunk);

        for (int i = 0; thunk[i].u1.AddressOfData; i++) {
            if (!(thunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                auto* importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME*>(
                    GetSelfBase() + thunk[i].u1.AddressOfData);

                for (auto* sensitive : sensitiveApis) {
                    if (strcmp(importByName->Name, sensitive) == 0) {
                        DWORD oldProtect;
                        VirtualProtect(importByName->Name, strlen(sensitive) + 1,
                            PAGE_READWRITE, &oldProtect);

                        // 只替换为相同长度的模糊名称 (因为名称顺序不影响 IAT)
                        // IAT 已用地址解析, OriginalFirstThunk 不再使用
                        static const char* replacements[] = {
                            "GetSystemTime\x00\x00\x00",
                            "IsDebuggerPresen\x00\x00",
                            "GetTickCount\x00\x00\x00\x00",
                            "InitializeCritX\x00\x00",
                            "SetLastError\x00\x00\x00\x00",
                            "GetConsoleWindow",
                            "LocalFree\x00\x00\x00\x00\x00\x00",
                            "WaitForSingleObX\x00"
                        };
                        const char* replacement = replacements[i % 8];
                        strcpy_s(const_cast<char*>(importByName->Name),
                            strlen(sensitive) + 1, replacement);

                        VirtualProtect(importByName->Name, strlen(sensitive) + 1,
                            oldProtect, &oldProtect);
                    }
                }
            }
        }
    }
#endif
    return true;
}

bool PeMutator::NormalizeSectionNames() {
    auto* nt = GetNtHeaders();
    if (!nt) return false;

    auto* section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {};
        memcpy(name, section[i].Name, 8);

        // 检查非标准区段名
        if (strstr(name, "zzzdbg") ||      // .rdata$zzzdbg
            strstr(name, ".data$") ||       // 任何 $ 后缀数据段
            strchr(name, '$')) {            // 任何含 $ 的区段

            // 重命名为标准名称
            static const char* standardNames[] = {
                ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc"
            };
            const char* newName = standardNames[i % 6];

            DWORD oldProtect;
            VirtualProtect(section[i].Name, 8, PAGE_READWRITE, &oldProtect);
            memset(section[i].Name, 0, 8);
            memcpy(section[i].Name, newName, strlen(newName));
            VirtualProtect(section[i].Name, 8, oldProtect, &oldProtect);
        }
    }

    return true;
}

bool PeMutator::AddJunkOverlay(size_t sizeBytes) {
    // 在 PE 文件末尾添加随机数据
    // 不能直接修改磁盘上的文件 (可能被占用)
    // 但可以在运行时修改内存中的 PE 镜像末尾

    auto* nt = GetNtHeaders();
    if (!nt) return false;

    uintptr_t imageEnd = GetSelfBase() + nt->OptionalHeader.SizeOfImage;

    // 在镜像后分配额外内存并填充随机数据
    // 注意: 这改变了 SizeOfImage
    PVOID junkAddr = reinterpret_cast<PVOID>(imageEnd);
    SIZE_T junkSize = sizeBytes;

    NTSTATUS st = SysAllocateVirtualMemory(
        GetCurrentProcess(),
        &junkAddr,
        0,
        &junkSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(st)) return false;

    // 填充随机数据 — ★ BUILD 500: SimpleRand 替代 std::mt19937
    BYTE* junkBytes = static_cast<BYTE*>(junkAddr);
    for (size_t i = 0; i < junkSize; i++) {
        junkBytes[i] = static_cast<BYTE>(SimpleRand());
    }

    // 更新 SizeOfImage — 先确保 PE 头可写 (ManualMap 下可能是只读)
    {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(GetSelfBase()),
            nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProtect);
        nt->OptionalHeader.SizeOfImage += static_cast<DWORD>(junkSize);
        VirtualProtect(reinterpret_cast<void*>(GetSelfBase()),
            nt->OptionalHeader.SizeOfHeaders, oldProtect, &oldProtect);
    }

    return true;
}

// ============================================================
// IntegrityBypass
// ============================================================

IntegrityBypass::TextSectionBackup IntegrityBypass::s_textBackup;

bool IntegrityBypass::BackupTextSection() {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(PeMutator::GetSelfBase());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        PeMutator::GetSelfBase() + dos->e_lfanew);

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            s_textBackup.baseAddress = PeMutator::GetSelfBase() + section[i].VirtualAddress;
            s_textBackup.size = section[i].Misc.VirtualSize;

            // ★ BUILD 501: VirtualAlloc 替代 std::vector<uint8_t>
            s_textBackup.Free(); // 先释放旧缓冲区
            s_textBackup.originalBytes = (uint8_t*)VirtualAlloc(nullptr, s_textBackup.size, MEM_COMMIT, PAGE_READWRITE);
            if (!s_textBackup.originalBytes) return false;
            memcpy(s_textBackup.originalBytes,
                reinterpret_cast<void*>(s_textBackup.baseAddress),
                s_textBackup.size);

            s_textBackup.patchedBytes = (uint8_t*)VirtualAlloc(nullptr, s_textBackup.size, MEM_COMMIT, PAGE_READWRITE);
            if (!s_textBackup.patchedBytes) {
                VirtualFree(s_textBackup.originalBytes, 0, MEM_RELEASE);
                s_textBackup.originalBytes = nullptr;
                return false;
            }
            memcpy(s_textBackup.patchedBytes, s_textBackup.originalBytes, s_textBackup.size);
            return true;
        }
    }

    return false;
}

bool IntegrityBypass::RestoreTextSection() {
    if (!s_textBackup.isPatched || !s_textBackup.originalBytes)
        return true; // 无需恢复

    DWORD oldProtect;
    VirtualProtect(reinterpret_cast<LPVOID>(s_textBackup.baseAddress),
        s_textBackup.size, PAGE_READWRITE, &oldProtect);

    memcpy(reinterpret_cast<void*>(s_textBackup.baseAddress),
        s_textBackup.originalBytes,
        s_textBackup.size);

    VirtualProtect(reinterpret_cast<LPVOID>(s_textBackup.baseAddress),
        s_textBackup.size, oldProtect, &oldProtect);

    // 刷新指令缓存
    FlushInstructionCache(GetCurrentProcess(),
        reinterpret_cast<LPCVOID>(s_textBackup.baseAddress),
        s_textBackup.size);

    s_textBackup.isPatched = false;
    return true;
}

bool IntegrityBypass::ReapplyTextPatches() {
    if (!s_textBackup.patchedBytes) return true;

    DWORD oldProtect;
    VirtualProtect(reinterpret_cast<LPVOID>(s_textBackup.baseAddress),
        s_textBackup.size, PAGE_READWRITE, &oldProtect);

    memcpy(reinterpret_cast<void*>(s_textBackup.baseAddress),
        s_textBackup.patchedBytes,
        s_textBackup.size);

    VirtualProtect(reinterpret_cast<LPVOID>(s_textBackup.baseAddress),
        s_textBackup.size, oldProtect, &oldProtect);

    s_textBackup.isPatched = true;
    return true;
}

bool IntegrityBypass::ValidateVTablePointer(
    uintptr_t vtablePtr, uintptr_t moduleBase, SIZE_T moduleSize) {

    // 虚表指针应该指向目标模块范围内的地址
    // 如果不在范围内, 说明 VTable hook 已被检测到

    if (vtablePtr >= moduleBase && vtablePtr < moduleBase + moduleSize) {
        return true; // 安全: 在合法模块范围内
    }

    // 检查是否指向已知的系统 DLL
    HMODULE hMod = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(vtablePtr), &mbi, sizeof(mbi))) {
        hMod = static_cast<HMODULE>(mbi.AllocationBase);

        WCHAR modPath[MAX_PATH] = {};
        if (GetModuleFileNameW(hMod, modPath, MAX_PATH)) {
            // ★ BUILD 500: 手动小写转换 + 子串搜索替代 std::wstring
            WCHAR pathLower[MAX_PATH] = {};
            for (int i = 0; i < MAX_PATH && modPath[i]; i++) {
                pathLower[i] = (modPath[i] >= L'A' && modPath[i] <= L'Z') ? modPath[i] + 32 : modPath[i];
            }
            // 合法范围: System32, game bin, steam
            bool inSystem32 = false, inSteam = false, inSteamApps = false;
            for (int i = 0; pathLower[i]; i++) {
                if (pathLower[i] == L'\\' && pathLower[i+1] == L's' && pathLower[i+2] == L'y' &&
                    pathLower[i+3] == L's' && pathLower[i+4] == L't' && pathLower[i+5] == L'e' &&
                    pathLower[i+6] == L'm' && pathLower[i+7] == L'3' && pathLower[i+8] == L'2') inSystem32 = true;
                if (pathLower[i] == L'\\' && pathLower[i+1] == L's' && pathLower[i+2] == L't' &&
                    pathLower[i+3] == L'e' && pathLower[i+4] == L'a' && pathLower[i+5] == L'm') {
                    if (pathLower[i+6] == L'\\' || (pathLower[i+6] == L'a' && pathLower[i+7] == L'p' &&
                        pathLower[i+8] == L'p' && pathLower[i+9] == L's')) inSteam = true;
                }
            }
            if (inSystem32 || inSteam) return true;
        }
    }

    return false; // 不在任何合法模块中 => 检测风险
}

bool IntegrityBypass::ForgeVTable(
    HANDLE hProcess,
    const VTableInfo& original,
    const uintptr_t* newEntries, int entryCount) {

    // 在目标进程现有模块地址范围内伪造虚表
    // 而不是在独立的 RWX 区域创建新虚表
    // 这使 VTable 指针看起来仍然指向合法模块

    // 寻找目标模块附近可写的空洞
    uintptr_t fakeVTableAddr = original.expectedModuleBase - 0x1000;

    SIZE_T allocSize = entryCount * sizeof(uintptr_t);
    PVOID allocAddr = reinterpret_cast<PVOID>(fakeVTableAddr);

    NTSTATUS st = SysAllocateVirtualMemory(
        hProcess,
        &allocAddr,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(st)) {
        // 回退: 在任意有效地址分配
        allocAddr = nullptr;
        st = SysAllocateVirtualMemory(
            hProcess,
            &allocAddr,
            0,
            &allocSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!NT_SUCCESS(st)) return false;
    }

    // 写入伪造的虚表条目
    StealthMemory::Write(hProcess,
        reinterpret_cast<uintptr_t>(allocAddr),
        newEntries,
        allocSize);

    return true;
}

bool IntegrityBypass::IsNetVarValid(uintptr_t value, uintptr_t min, uintptr_t max) {
    return value >= min && value <= max;
}

bool IntegrityBypass::IsVACLoaded(HANDLE hProcess) {
    // ★ BUILD 550: VAC 模块名用编译期 hash 比较 (原明文 L"GameOverlayRenderer.dll" 等)
    //   二进制中不出现明文 Steam/Source 模块名
    constexpr uint32_t vacHashes[] = {
        stealth::ModNameHash(L"GameOverlayRenderer.dll"),
        stealth::ModNameHash(L"steamclient.dll"),
        stealth::ModNameHash(L"tier0.dll"),
        stealth::ModNameHash(L"serverbrowser.dll"),
    };

    HMODULE hMods[1024] = {};
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return false;

    DWORD modCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < modCount; i++) {
        WCHAR modName[MAX_PATH] = {};
        if (GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH)) {
            uint32_t modHash = stealth::ModNameHashRT(modName);
            for (auto h : vacHashes) {
                if (modHash == h) {
                    return true;
                }
            }
        }
    }

    return false;
}

uintptr_t IntegrityBypass::GetVACModuleBase(HANDLE hProcess) {
    // ★ BUILD 550: hash 比较 (原明文 _wcsicmp(L"GameOverlayRenderer.dll") 等)
    constexpr uint32_t overlayHash = stealth::ModNameHash(L"GameOverlayRenderer.dll");
    constexpr uint32_t steamclientHash = stealth::ModNameHash(L"steamclient.dll");

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            WCHAR modName[MAX_PATH] = {};
            GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH);
            uint32_t modHash = stealth::ModNameHashRT(modName);

            if (modHash == overlayHash || modHash == steamclientHash) {
                return reinterpret_cast<uintptr_t>(hMods[i]);
            }
        }
    }

    return 0;
}

bool IntegrityBypass::IsVACScanning() {
    // 启发式检测 VAC 扫描:
    // 1. 频繁的内存读取 (NtReadVirtualMemory 调用)
    // 2. 特定线程特征

    // 简化: 基于时间的概率检测
    // 实际实现需要 hook NtReadVirtualMemory 或监控线程创建

    static DWORD lastCheck = 0;
    DWORD now = GetTickCount();

    // VAC 通常每 30-120 秒扫描一次
    // 在预期扫描窗口内返回 true
    bool inScanWindow = (now - lastCheck > 25000);

    if (inScanWindow) {
        lastCheck = now;
        return true;
    }

    return false;
}

bool IntegrityBypass::InstallVACSafetyHook() {
    // v3.26: 此函数仅做 .text 段备份, 不安装定时器/线程.
    //   备份目标是 payload 自身的 .text 段 (ManualMap 区域),
    //   但 payload .text 无实际补丁 (patchedBytes==originalBytes),
    //   因此 RestoreTextSection+ReapplyTextPatches 实际是空操作.
    //
    //   VAC 扫描的是 cs2.exe/engine.dll/ntdll.dll 而非 payload 自身,
    //   真正的 VAC 保护由以下机制提供:
    //   - StealthSleep: RestoreAll (清除 ETW/AMSI patch) → EkkoSleep
    //     (加密 payload 内存) → SilenceAll (恢复 patch)
    //   - VerifyAndRepairAll (每5s): ETW/AMSI 自愈
    //   - StackSpoof: 所有 syscall 调用栈指向 ntdll gadget
    //
    //   保留此函数仅为 API 兼容性, enableVACSafety 默认已改为 false.
    static bool initialized = false;
    if (!initialized) {
        BackupTextSection();
        initialized = true;
    }

    // 简化实现: 在每个游戏帧更新时调用
    // 使用者需要在主循环中调用以下逻辑:
    //   if (IntegrityBypass::IsVACScanning()) {
    //       IntegrityBypass::RestoreTextSection();
    //       Sleep(100); // 等待扫描完成
    //       IntegrityBypass::ReapplyTextPatches();
    //   }

    return initialized;
}

} // namespace stealth
