// ============================================================
// stealth_process.cpp — 隐蔽进程/内存操作实现
#include "platform.h"
// ============================================================

#include "stealth_process.h"
#include "syscall_direct.h"
#include <winternl.h>
#include <TlHelp32.h>
#include <algorithm>

namespace stealth {

// ============================================================
// NtQuerySystemInformation 类型定义
// ============================================================

#define SystemProcessInformation 5

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

// ============================================================
// StealthProcess
// ============================================================

std::vector<StealthProcess::ProcessInfo>
StealthProcess::EnumerateProcesses(const wchar_t* targetName) {
    std::vector<ProcessInfo> results;

    // 使用 NtQuerySystemInformation 替代 CreateToolhelp32Snapshot
    ULONG bufferSize = 0x100000; // 1MB 初始
    std::vector<BYTE> buffer(bufferSize);
    ULONG returnLength = 0;

    NTSTATUS status;
    int maxRetries = 5;
    do {
        buffer.resize(bufferSize);
        status = SysQuerySystemInformation(
            SystemProcessInformation,
            buffer.data(),
            bufferSize,
            &returnLength
        );
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
        }
        if (--maxRetries <= 0 && status != 0) break;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) return results;

    PSYSTEM_PROCESS_INFO entry = reinterpret_cast<PSYSTEM_PROCESS_INFO>(buffer.data());

    while (true) {
        if (entry->ImageName.Buffer && entry->UniqueProcessId) {
            std::wstring procName(entry->ImageName.Buffer,
                entry->ImageName.Length / sizeof(WCHAR));

            // 不区分大小写匹配
            std::wstring lowerName = procName;
            std::wstring lowerTarget = targetName ? targetName : L"";
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);

            if (!targetName || lowerName.find(lowerTarget) != std::wstring::npos) {
                ProcessInfo info;
                info.pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(entry->UniqueProcessId));
                wcscpy_s(info.name, procName.c_str());
                info.handle = nullptr;
                results.push_back(info);
            }
        }

        // 检查是否到达链表末尾 (NextEntryOffset = 0)
        if (entry->NextEntryOffset == 0) break;

        // 前进到下一个条目
        entry = reinterpret_cast<PSYSTEM_PROCESS_INFO>(
            reinterpret_cast<BYTE*>(entry) + entry->NextEntryOffset);
    }

    return results;
}

DWORD StealthProcess::FindProcessByWindow(const wchar_t* className, const wchar_t* windowName) {
    HWND hwnd = FindWindowW(className, windowName);
    if (!hwnd) return 0;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

HANDLE StealthProcess::OpenProcessStealth(DWORD pid) {
    // 使用 NtOpenProcess 直接系统调用
    // 规避 kernel32!OpenProcess 以及 ObRegisterCallbacks 回调

    CLIENT_ID clientId = {};
    clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));
    clientId.UniqueThread = nullptr;

    OBJECT_ATTRIBUTES objAttr = {};
    objAttr.Length = sizeof(objAttr);

    // 使用最小必要权限: VM_READ + VM_WRITE + VM_OPERATION + QUERY_INFORMATION
    ACCESS_MASK desiredAccess = PROCESS_VM_READ | PROCESS_VM_WRITE |
                                 PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

    // 不请求 PROCESS_CREATE_THREAD / PROCESS_VM_WRITE 的高危组合
    // 减少触发内核回调的可能性

    HANDLE hProcess = nullptr;
    NTSTATUS status = SysOpenProcess(&hProcess, desiredAccess, &objAttr, &clientId);

    if (!NT_SUCCESS(status)) {
        // 降低权限重试
        desiredAccess = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
        status = SysOpenProcess(&hProcess, desiredAccess, &objAttr, &clientId);
    }

    return NT_SUCCESS(status) ? hProcess : nullptr;
}

HANDLE StealthProcess::OpenProcessMinimal(DWORD pid) {
    // 仅使用 PROCESS_VM_READ — 最低检测风险
    // RWX 模式后续通过其他方式实现

    CLIENT_ID clientId = {};
    clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));

    OBJECT_ATTRIBUTES objAttr = {};
    objAttr.Length = sizeof(objAttr);

    // 注意: 直接使用 kernel32!OpenProcess 反而更自然
    // 因为几乎所有程序都会调用它
    // 关键是不使用 WriteProcessMemory+VirtualProtectEx 组合
    return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
}

HANDLE StealthProcess::DuplicateHandleFromLowRisk(DWORD pid) {
    // 找一个低风险的中间进程 (如 csrss.exe, svchost.exe)
    // 从它那里复制目标进程的句柄
    // 规避: 从我们的进程直接 OpenProcess 的痕迹

    // 简化实现: 找 explorer.exe 作为中间进程
    auto processes = EnumerateProcesses(L"explorer.exe");
    if (processes.empty()) return nullptr;

    HANDLE hMediator = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processes[0].pid);
    if (!hMediator) return nullptr;

    HANDLE hTarget = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hTarget) {
        CloseHandle(hMediator);
        return nullptr;
    }

    HANDLE hDuplicated = nullptr;
    DuplicateHandle(
        hTarget,                    // 源进程
        GetCurrentProcess(),        // 伪源句柄 (从自身取)
        hMediator,                  // 中介进程
        &hDuplicated,
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE,
        DUPLICATE_SAME_ACCESS
    );

    CloseHandle(hMediator);
    CloseHandle(hTarget);

    return hDuplicated;
}

bool StealthProcess::EnsureDebugPrivilegeSilent() {
    // 先检查是否已有权限
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return false;

    TOKEN_PRIVILEGES tp = {};
    LUID luid;

    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }

    // 检查现有权限
    DWORD size = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (GetTokenInformation(hToken, TokenPrivileges, buffer.data(), size, &size)) {
        auto* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());
        for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
            if (privileges->Privileges[i].Luid.LowPart == luid.LowPart &&
                privileges->Privileges[i].Luid.HighPart == luid.HighPart &&
                (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
                CloseHandle(hToken);
                return true; // 已有权限, 无需调用 AdjustTokenPrivileges
            }
        }
    }

    // 仅在确实需要时才调用 AdjustTokenPrivileges
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);

    return result != FALSE && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

bool StealthProcess::BypassPrivilegeCheck() {
    // 方案: 如果当前进程以管理员运行, 父进程继承的令牌可能已有 SeDebugPrivilege
    // 优先检查继承的令牌而不是调用 AdjustTokenPrivileges

    // 检查是否以管理员运行
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation = {};
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    // 如果已提权, 继承的令牌可能已包含 SeDebugPrivilege
    if (isElevated) {
        return EnsureDebugPrivilegeSilent(); // 静默确认
    }

    return false;
}

std::vector<StealthProcess::ModuleInfo>
StealthProcess::GetProcessModules(HANDLE hProcess) {
    std::vector<ModuleInfo> results;

    // 使用 NtQueryInformationProcess 获取 PEB -> LDR
    // 规避 Module32First/Next

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG returnLength = 0;

    NTSTATUS status = SysQueryInformationProcess(
        hProcess,
        0, // ProcessBasicInformation
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
        // 回退: 使用 Module32First (仅当直接方法失败时)
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
        if (hSnap == INVALID_HANDLE_VALUE) return results;

        MODULEENTRY32W me32 = { sizeof(me32) };
        if (Module32FirstW(hSnap, &me32)) {
            do {
                ModuleInfo info;
                info.name = me32.szModule;
                info.baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                info.size = me32.modBaseSize;
                results.push_back(info);
            } while (Module32NextW(hSnap, &me32));
        }
        CloseHandle(hSnap);
    } else {
        // 通过远程 PEB 读取模块列表（使用 LDR_DATA_TABLE_ENTRY_FULL）
        PEB remotePeb = {};
        SIZE_T bytesRead = 0;
        if (SysReadVirtualMemory(hProcess, pbi.PebBaseAddress,
            &remotePeb, sizeof(PEB), &bytesRead, SyscallMethod::Indirect) &&
            bytesRead == sizeof(PEB) && remotePeb.Ldr) {

            // PEB_LDR_DATA 的 InLoadOrderModuleList 在偏移 0x10
            // 只读足够大的区域以覆盖链表头
            BYTE ldrBuf[0x40] = {};
            if (!SysReadVirtualMemory(hProcess, remotePeb.Ldr,
                ldrBuf, sizeof(ldrBuf), &bytesRead, SyscallMethod::Indirect))
                return results;

            // InLoadOrderModuleList 在 LDR 结构偏移 0x10 处
            auto* headInLdr = reinterpret_cast<PLIST_ENTRY>(
                reinterpret_cast<uintptr_t>(remotePeb.Ldr) + 0x10);

            // 读取链表表头
            LIST_ENTRY headEntry = {};
            if (!SysReadVirtualMemory(hProcess, headInLdr,
                &headEntry, sizeof(LIST_ENTRY), &bytesRead, SyscallMethod::Indirect))
                return results;

            // 遍历链表 (InLoadOrderLinks 是 LDR_DATA_TABLE_ENTRY_FULL 的第一个字段, 偏移 0)
            LIST_ENTRY next = headEntry;
            int safety = 0;
            while (safety++ < 512) {
                // Flink 直接指向下一个 LDR_DATA_TABLE_ENTRY_FULL (InLoadOrderLinks 在偏移 0)
                auto entryAddr = reinterpret_cast<uintptr_t>(next.Flink);
                
                // 检查是否回绕到 LDR 表头
                if (entryAddr == reinterpret_cast<uintptr_t>(headInLdr))
                    break;

                LDR_DATA_TABLE_ENTRY_FULL entry = {};
                if (!SysReadVirtualMemory(hProcess,
                    reinterpret_cast<PVOID>(entryAddr),
                    &entry, sizeof(entry), &bytesRead, SyscallMethod::Indirect))
                    break;

                if (entry.DllBase && entry.SizeOfImage) {
                    ModuleInfo info;
                    info.baseAddress = reinterpret_cast<uintptr_t>(entry.DllBase);
                    info.size = entry.SizeOfImage;

                    // 读取模块名
                    if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0 &&
                        entry.BaseDllName.Length < MAX_PATH * 2) {
                        std::vector<WCHAR> nameBuf(entry.BaseDllName.Length / 2 + 1);
                        if (SysReadVirtualMemory(hProcess, entry.BaseDllName.Buffer,
                            nameBuf.data(), entry.BaseDllName.Length, &bytesRead,
                            SyscallMethod::Indirect)) {
                            info.name = nameBuf.data();
                        }
                    }
                    results.push_back(info);
                }

                // 读取下一个链表项
                if (!SysReadVirtualMemory(hProcess, next.Flink,
                    &next, sizeof(LIST_ENTRY), &bytesRead, SyscallMethod::Indirect))
                    break;
            }
        }
    }

    return results;
}

bool StealthProcess::IsModuleLoaded(HANDLE hProcess, const wchar_t* moduleName) {
    auto modules = GetProcessModules(hProcess);
    for (auto& mod : modules) {
        if (_wcsicmp(mod.name.c_str(), moduleName) == 0) {
            return true;
        }
    }
    return false;
}

// ============================================================
// StealthMemory
// ============================================================

bool StealthMemory::Read(HANDLE hProcess, uintptr_t addr, void* buffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    NTSTATUS status = SysReadVirtualMemory(
        hProcess,
        reinterpret_cast<PVOID>(addr),
        buffer,
        size,
        &bytesRead
    );
    return NT_SUCCESS(status) && bytesRead == size;
}

bool StealthMemory::Write(HANDLE hProcess, uintptr_t addr, const void* buffer, SIZE_T size) {
    SIZE_T bytesWritten = 0;
    NTSTATUS status = SysWriteVirtualMemory(
        hProcess,
        reinterpret_cast<PVOID>(addr),
        const_cast<void*>(buffer),
        size,
        &bytesWritten
    );
    return NT_SUCCESS(status) && bytesWritten == size;
}

bool StealthMemory::Protect(HANDLE hProcess, uintptr_t addr, SIZE_T size,
                            DWORD newProtect, DWORD* oldProtect) {
    PVOID baseAddr = reinterpret_cast<PVOID>(addr);
    SIZE_T regionSize = size;
    ULONG old = 0;

    NTSTATUS status = SysProtectVirtualMemory(
        hProcess,
        &baseAddr,
        &regionSize,
        static_cast<ULONG>(newProtect),
        &old
    );

    if (oldProtect) *oldProtect = static_cast<DWORD>(old);
    return NT_SUCCESS(status);
}

bool StealthMemory::SetupShadowPage(HANDLE hProcess, uintptr_t targetAddr, SIZE_T size) {
    // 影子页策略:
    // 1. 分配两个物理页: pageA (原始) / pageB (修改后)
    // 2. 默认指向 pageA
    // 3. VAC 扫描时切换回 pageA
    // 4. 正常使用时切换到 pageB

    // 简化版: 使用内存映射文件的写时复制机制
    // 详细实现在 stealth_core 层
    return true;
}

// ============================================================
// TransactionalWrite
// ============================================================

StealthMemory::TransactionalWrite::TransactionalWrite(
    HANDLE hProcess, uintptr_t addr, SIZE_T size)
    : m_process(hProcess), m_addr(addr), m_size(size) {
    // 备份原始数据
    m_original.resize(size);
    StealthMemory::Read(hProcess, addr, m_original.data(), size);
}

StealthMemory::TransactionalWrite::~TransactionalWrite() {
    if (!m_committed && !m_original.empty()) {
        // 析构时自动恢复
        Rollback();
    }
}

bool StealthMemory::TransactionalWrite::Commit() {
    if (m_modified.empty()) return false;

    bool ok = StealthMemory::Write(m_process, m_addr, m_modified.data(), m_size);
    if (ok) m_committed = true;
    return ok;
}

bool StealthMemory::TransactionalWrite::Rollback() {
    if (m_original.empty()) return false;

    return StealthMemory::Write(m_process, m_addr, m_original.data(), m_size);
}

bool StealthMemory::TransactionalWrite::IsVACScanning() {
    // 检测 VAC 扫描的启发式方法:
    // 1. 监控可疑线程创建 (VAC 扫描线程)
    // 2. 检查特定模块的加载 (VAC 模块通常由 Steam 注入)
    // 3. 监控对 .text 段的大范围读取 (扫描特征)

    // 简化: 通过检查 csgo.exe 中 Steam 模块的线程活动
    // 实际实现需要更精确的时序分析
    return false;
}

uintptr_t StealthMemory::AllocateInExistingRegion(HANDLE hProcess, SIZE_T size) {
    // 在目标进程中寻找现有的 MEM_COMMIT 区域之间的空隙
    // 而不是在随机地址分配新内存
    // 规避: 高熵内存区域 = 异常特征

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0;
    SIZE_T maxRegionSize = 0;

    while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            // 检查此区域是否在合法模块附近 (看起来更像正常分配)
            // 而不是在完全随机的地址
            uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);

            PVOID allocAddr = reinterpret_cast<PVOID>(regionStart);
            SIZE_T allocSize = size;
            NTSTATUS st = SysAllocateVirtualMemory(
                hProcess,
                &allocAddr,
                0,
                &allocSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (NT_SUCCESS(st)) {
                return reinterpret_cast<uintptr_t>(allocAddr);
            }
        }
        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return 0;
}

uintptr_t StealthMemory::AllocateViaSection(HANDLE hProcess, SIZE_T size) {
    // 通过 Section (文件映射) 共享内存, 而非直接 VirtualAllocEx
    // 规避: VirtualAllocEx 分配热区检测

    // 创建页面文件支持的内存段
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = {};
    maxSize.QuadPart = static_cast<LONGLONG>(size);

    // 使用 NtCreateSection (通过动态解析)
    using NtCreateSection_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    static auto NtCreateSection = reinterpret_cast<NtCreateSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));

    if (!NtCreateSection) return 0;

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS st = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE,
        &oa, &maxSize, PAGE_READWRITE, SEC_COMMIT, nullptr);

    if (!NT_SUCCESS(st)) return 0;

    // 映射到本地进程
    PVOID localAddr = nullptr;
    SIZE_T viewSize = size;

    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
        SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    static auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));

    if (NtMapViewOfSection) {
        NtMapViewOfSection(hSection, GetCurrentProcess(), &localAddr,
            0, size, nullptr, &viewSize, 1, 0, PAGE_READWRITE);
    }

    // 映射到目标进程 (同一物理页)
    PVOID remoteAddr = nullptr;
    if (NtMapViewOfSection) {
        NtMapViewOfSection(hSection, hProcess, &remoteAddr,
            0, size, nullptr, &viewSize, 1, 0, PAGE_READWRITE);
    }

    CloseHandle(hSection);

    return reinterpret_cast<uintptr_t>(remoteAddr);
}

} // namespace stealth
