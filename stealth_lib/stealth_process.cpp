// ============================================================
// stealth_process.cpp — 隐蔽进程/内存操作实现
#include "platform.h"
// ============================================================

#include "stealth_process.h"
#include "syscall_direct.h"
#include "byovd_kernel.h"  // ★ BUILD 549: KernelMemoryAccessor for ShadowPageManager
#include <winternl.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstdarg>

namespace stealth {

// 本地诊断日志 — 写 %TEMP%\sd.log (与 payload.cpp 的 DiagLog 同一文件)
// ★ BUILD 549: 文件名脱敏 (原 stealth_diag.log, 含 "stealth" 特征)
static void ProcDiag(const char* fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len < 0) return;
    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"sd.log");  // ★ BUILD 549: 文件名脱敏 (与 payload.cpp 一致)
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);
        CloseHandle(h);
    }
}

// 手动转小写辅助函数 (避免 CRT 依赖)
static void MakeLowerW(wchar_t* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (str[i] >= L'A' && str[i] <= L'Z') {
            str[i] = str[i] + (L'a' - L'A');
        }
    }
}

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

int StealthProcess::EnumerateProcesses(const wchar_t* targetName, ProcessInfo* outBuf, int maxResults) {
    int count = 0;

    ProcDiag("EnumerateProcesses: target='%ls'\n", targetName ? targetName : L"(null)");

    // 准备小写目标名 (用于不区分大小写匹配)
    WCHAR lowerTarget[MAX_PATH] = {};
    if (targetName) {
        wcscpy_s(lowerTarget, targetName);
        MakeLowerW(lowerTarget, wcslen(lowerTarget));
    }

    // ============================================================
    // 方法1: NtQuerySystemInformation syscall (绕过 EAC 用户态 Hook)
    // ============================================================
    ULONG bufferSize = 0x100000; // 1MB 初始
    BYTE* buffer = nullptr;
    ULONG returnLength = 0;

    NTSTATUS status;
    int maxRetries = 5;
    do {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = (BYTE*)VirtualAlloc(nullptr, bufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buffer) break;
        status = SysQuerySystemInformation(
            SystemProcessInformation,
            buffer,
            bufferSize,
            &returnLength
        );
        ProcDiag("  NtQSI: bufSize=%u status=0x%08X retLen=%u\n",
            bufferSize, (unsigned)status, returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
        }
        if (--maxRetries <= 0 && status != 0) break;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (buffer && NT_SUCCESS(status)) {
        PSYSTEM_PROCESS_INFO entry = reinterpret_cast<PSYSTEM_PROCESS_INFO>(buffer);
        int totalProcesses = 0;
        int matchedProcesses = 0;

        while (true) {
            if (entry->ImageName.Buffer && entry->UniqueProcessId) {
                // 提取进程名到 wchar_t 数组
                WCHAR procName[MAX_PATH] = {};
                SIZE_T nameLen = entry->ImageName.Length / sizeof(WCHAR);
                if (nameLen >= MAX_PATH) nameLen = MAX_PATH - 1;
                if (nameLen > 0) {
                    memcpy(procName, entry->ImageName.Buffer, nameLen * sizeof(WCHAR));
                }

                // 手动转小写比较
                WCHAR lowerName[MAX_PATH] = {};
                wcscpy_s(lowerName, procName);
                MakeLowerW(lowerName, wcslen(lowerName));

                totalProcesses++;
                // 记录前10个进程名和所有匹配的进程
                if (totalProcesses <= 10 || (targetName && wcsstr(lowerName, lowerTarget))) {
                    ProcDiag("  PROC[%d]: PID=%u name='%ls'\n",
                        totalProcesses,
                        static_cast<DWORD>(reinterpret_cast<uintptr_t>(entry->UniqueProcessId)),
                        procName);
                }

                if (!targetName || wcsstr(lowerName, lowerTarget)) {
                    if (count < maxResults) {
                        ProcessInfo& info = outBuf[count];
                        info.pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(entry->UniqueProcessId));
                        wcscpy_s(info.name, procName);
                        info.handle = nullptr;
                        count++;
                    }
                    matchedProcesses++;
                }
            }

            if (entry->NextEntryOffset == 0) break;
            entry = reinterpret_cast<PSYSTEM_PROCESS_INFO>(
                reinterpret_cast<BYTE*>(entry) + entry->NextEntryOffset);
        }

        ProcDiag("EnumerateProcesses(NtQSI): total=%d matched=%d\n",
            totalProcesses, matchedProcesses);
        VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = nullptr;
        if (count > 0) return count;
        ProcDiag("EnumerateProcesses(NtQSI): no match, trying fallback...\n");
    } else {
        if (buffer) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            buffer = nullptr;
        }
        ProcDiag("EnumerateProcesses(NtQSI): FAILED status=0x%08X, trying fallback...\n",
            (unsigned)status);
    }

    // ============================================================
    // 方法2: 已废弃 — CreateToolhelp32Snapshot 会被 PAC 用户态 hook 检测
    // ★ BUILD 550: 移除 Toolhelp32 回退路径, NtQuerySystemInformation 失败时直接返回
    //   原回退调用 CreateToolhelp32Snapshot/Process32FirstW/Process32NextW,
    //   这些 API 在导入表中暴露特征, 且 PAC 用户态 hook 可拦截。
    //   NtQuerySystemInformation (syscall) 已足够可靠, 无需回退。
    // ============================================================
    ProcDiag("EnumerateProcesses: NtQSI failed, no fallback (BUILD 550)\n");
    return count;
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
    ProcessInfo processes[16];
    int procCount = EnumerateProcesses(L"explorer.exe", processes, 16);
    if (procCount == 0) return nullptr;

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
    if (size == 0) {
        CloseHandle(hToken);
        return false;
    }

    BYTE* buffer = (BYTE*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hToken);
        return false;
    }

    bool alreadyHavePrivilege = false;
    if (GetTokenInformation(hToken, TokenPrivileges, buffer, size, &size)) {
        auto* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer);
        for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
            if (privileges->Privileges[i].Luid.LowPart == luid.LowPart &&
                privileges->Privileges[i].Luid.HighPart == luid.HighPart &&
                (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
                alreadyHavePrivilege = true;
                break;
            }
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);

    if (alreadyHavePrivilege) {
        CloseHandle(hToken);
        return true; // 已有权限, 无需调用 AdjustTokenPrivileges
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

int StealthProcess::GetProcessModules(HANDLE hProcess, ModuleInfo* outBuf, int maxResults) {
    int count = 0;

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
        // ★ BUILD 550: 移除 CreateToolhelp32Snapshot/Module32FirstW 回退
        //   原回退调用 Toolhelp32 APIs 在导入表中暴露特征, 且 PAC 用户态 hook 可拦截。
        //   NtQueryInformationProcess 失败时直接返回 0 (调用方已有 fallback 逻辑)。
        ProcDiag("GetProcessModules: NtQueryInformationProcess failed, no fallback (BUILD 550)\n");
        return 0;
    } else {
        PEB remotePeb = {};
        SIZE_T bytesRead = 0;
        if (NT_SUCCESS(SysReadVirtualMemory(hProcess, pbi.PebBaseAddress,
            &remotePeb, sizeof(PEB), &bytesRead, SyscallMethod::Indirect)) &&
            bytesRead == sizeof(PEB) && remotePeb.Ldr) {

            BYTE ldrBuf[0x40] = {};
            if (!NT_SUCCESS(SysReadVirtualMemory(hProcess, remotePeb.Ldr,
                ldrBuf, sizeof(ldrBuf), &bytesRead, SyscallMethod::Indirect)))
                return count;

            auto* headInLdr = reinterpret_cast<PLIST_ENTRY>(
                reinterpret_cast<uintptr_t>(remotePeb.Ldr) + 0x10);

            LIST_ENTRY headEntry = {};
            if (!NT_SUCCESS(SysReadVirtualMemory(hProcess, headInLdr,
                &headEntry, sizeof(LIST_ENTRY), &bytesRead, SyscallMethod::Indirect)))
                return count;

            LIST_ENTRY next = headEntry;
            int safety = 0;
            while (safety++ < 512) {
                auto entryAddr = reinterpret_cast<uintptr_t>(next.Flink);
                
                if (entryAddr == reinterpret_cast<uintptr_t>(headInLdr))
                    break;

                LDR_DATA_TABLE_ENTRY_FULL entry = {};
                if (!NT_SUCCESS(SysReadVirtualMemory(hProcess,
                    reinterpret_cast<PVOID>(entryAddr),
                    &entry, sizeof(entry), &bytesRead, SyscallMethod::Indirect)))
                    break;

                if (entry.DllBase && entry.SizeOfImage) {
                    if (count >= maxResults) break;
                    ModuleInfo& info = outBuf[count];
                    info.baseAddress = reinterpret_cast<uintptr_t>(entry.DllBase);
                    info.size = entry.SizeOfImage;
                    info.name[0] = L'\0';

                    if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0 &&
                        entry.BaseDllName.Length < MAX_PATH * 2) {
                        WCHAR nameBuf[260] = {};
                        USHORT readLen = entry.BaseDllName.Length;
                        if (readLen > (USHORT)(sizeof(nameBuf) - sizeof(WCHAR)))
                            readLen = (USHORT)(sizeof(nameBuf) - sizeof(WCHAR));
                        if (NT_SUCCESS(SysReadVirtualMemory(hProcess, entry.BaseDllName.Buffer,
                            nameBuf, readLen, &bytesRead,
                            SyscallMethod::Indirect))) {
                            wcscpy_s(info.name, nameBuf);
                        }
                    }
                    count++;
                }

                if (!NT_SUCCESS(SysReadVirtualMemory(hProcess, next.Flink,
                    &next, sizeof(LIST_ENTRY), &bytesRead, SyscallMethod::Indirect)))
                    break;
            }
        }
    }

    return count;
}

bool StealthProcess::IsModuleLoaded(HANDLE hProcess, const wchar_t* moduleName) {
    ModuleInfo modules[256];
    int modCount = GetProcessModules(hProcess, modules, 256);
    for (int i = 0; i < modCount; i++) {
        if (_wcsicmp(modules[i].name, moduleName) == 0) {
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
    // 备份原始数据 (固定数组, 最多 4096 字节)
    if (size > 0 && size <= sizeof(m_original)) {
        StealthMemory::Read(hProcess, addr, m_original, size);
    }
}

StealthMemory::TransactionalWrite::~TransactionalWrite() {
    if (!m_committed && m_size > 0) {
        // 析构时自动恢复
        Rollback();
    }
}

bool StealthMemory::TransactionalWrite::Commit() {
    if (m_size == 0) return false;

    bool ok = StealthMemory::Write(m_process, m_addr, m_modified, m_size);
    if (ok) m_committed = true;
    return ok;
}

bool StealthMemory::TransactionalWrite::Rollback() {
    if (m_size == 0) return false;

    return StealthMemory::Write(m_process, m_addr, m_original, m_size);
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

// ============================================================
// ★ BUILD 549: ShadowPageManager 实现
//   通过 PTE manipulation 实现 CS2 client.dll .text 段影子页
//   详细原理参见 byovd_kernel.cpp 的 PTE Manipulation API
// ============================================================

ShadowPageManager& ShadowPageManager::Instance() {
    static ShadowPageManager inst;
    return inst;
}

bool ShadowPageManager::Install(HANDLE hCs2, uintptr_t patchAddr) {
    if (m_installed) return true;
    if (!patchAddr) return false;

    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        ProcDiag("B549:SP:01 kma not active\n");
        return false;
    }

    m_hCs2 = hCs2;
    m_patchAddr = patchAddr;

    // 步骤 1: 验证 PTE 自映射可用
    if (!kma.VerifyPteSelfMap()) {
        ProcDiag("B549:SP:02 selfmap FAIL\n");
        return false;
    }

    // 步骤 2: 读取补丁地址的原始 PTE
    uint64_t origPte = 0;
    if (!kma.ReadPte(patchAddr, &origPte)) {
        ProcDiag("B549:SP:03 ReadPte FAIL addr=0x%llX\n",
                 (unsigned long long)patchAddr);
        return false;
    }
    if (!(origPte & 1)) {  // PTE_PRESENT
        ProcDiag("B549:SP:04 PTE not present addr=0x%llX pte=0x%llX\n",
                 (unsigned long long)patchAddr, (unsigned long long)origPte);
        return false;
    }
    m_origPteValue = origPte;
    ProcDiag("B549:SP:05 origPte=0x%llX addr=0x%llX\n",
             (unsigned long long)origPte, (unsigned long long)patchAddr);

    // 步骤 3: 分配 pageB (用户态 VirtualAlloc + VirtualLock)
    uint64_t pageBPhys = kma.AllocContiguousPhysical(4096);
    if (!pageBPhys) {
        ProcDiag("B549:SP:06 AllocContiguousPhysical FAIL\n");
        return false;
    }
    m_pageBPhys = pageBPhys;
    m_pageBVA = kma.MapPhysicalToKernelVA(pageBPhys, 4096);
    if (!m_pageBVA) {
        ProcDiag("B549:SP:07 MapPhysicalToKernelVA FAIL\n");
        kma.FreeContiguousPhysical(pageBPhys);
        m_pageBPhys = 0;
        return false;
    }

    // 步骤 4: 复制 pageA 内容到 pageB
    //   pageA 是 client.dll 原页, 通过 ReadProcessMemory 读取 (CS2 进程内可直接 memcpy)
    //   pageB 是用户态 VA, 直接 memcpy 写入
    uintptr_t pageAStart = patchAddr & ~0xFFFULL;  // 页对齐
    memcpy((void*)m_pageBVA, (void*)pageAStart, 4096);

    // 步骤 5: 在 pageB 内写入补丁字节 (offset = patchAddr & 0xFFF)
    //   补丁: 32 c0 → 90 90 (NOP NOP)
    size_t offset = patchAddr & 0xFFF;
    ((uint8_t*)m_pageBVA)[offset]     = 0x90;
    ((uint8_t*)m_pageBVA)[offset + 1] = 0x90;

    ProcDiag("B549:SP:08 pageB filled, offset=%zu\n", offset);

    // 步骤 6: 构造补丁 PTE (复制原 PTE, 修改 PFN 指向 pageB)
    //   PTE 字段: bit 12-51 = PFN
    //   保留: P, RW, U/S, A, D, G, NX 等其他位
    constexpr uint64_t PTE_PFN_MASK = 0x000FFFFFFFFFF000ULL;
    uint64_t pageBPfn = pageBPhys >> 12;
    m_patchPteValue = (origPte & ~PTE_PFN_MASK) | (pageBPfn << 12);

    // 步骤 7: 切换 PTE 到 pageB
    if (!kma.WritePte(patchAddr, m_patchPteValue)) {
        ProcDiag("B549:SP:09 WritePte FAIL\n");
        kma.FreeContiguousPhysical(pageBPhys);
        m_pageBPhys = 0;
        m_pageBVA = 0;
        return false;
    }

    // 步骤 8: 等待 TLB 刷新 (用户态页 G=0, context switch 自动刷新)
    Sleep(50);

    // 步骤 9: 验证切换成功
    //   ★ BUILD 549 关键验证: 读取 patchAddr 应读到 90 90 (pageB 内容)
    //   因为 payload.dll 在 CS2 进程内, patchAddr 是 CS2 进程的 VA
    //   修改 PTE 后, CS2 进程访问 patchAddr 应该读到 pageB 的 90 90
    //   (TLB 已通过 Sleep(50) + context switch 刷新)
    uint8_t verifyPatch[2] = {0};
    memcpy(verifyPatch, (void*)patchAddr, 2);
    uint8_t verifyPageB[2] = {0};
    memcpy(verifyPageB, (void*)(m_pageBVA + offset), 2);
    if (verifyPatch[0] != 0x90 || verifyPatch[1] != 0x90 ||
        verifyPageB[0] != 0x90 || verifyPageB[1] != 0x90) {
        ProcDiag("B549:SP:10 verify FAIL patch=%02X%02X pageB=%02X%02X\n",
                 verifyPatch[0], verifyPatch[1], verifyPageB[0], verifyPageB[1]);
        kma.WritePte(patchAddr, m_origPteValue);  // 恢复原 PTE
        Sleep(50);
        kma.FreeContiguousPhysical(pageBPhys);
        m_pageBPhys = 0;
        m_pageBVA = 0;
        return false;
    }

    m_installed = true;
    ProcDiag("B549:SP:11 OK addr=0x%llX pageBPhys=0x%llX\n",
             (unsigned long long)patchAddr, (unsigned long long)pageBPhys);
    return true;
}

void ShadowPageManager::RevealOriginal() {
    if (!m_installed) return;
    auto& kma = KernelMemoryAccessor::Instance();
    // 切到 pageA (恢复原 PTE)
    kma.WritePte(m_patchAddr, m_origPteValue);
    // ★ 不在此处 Sleep, 由调用方控制时序 (MaintainCs2Patch 中 Sleep(50))
}

void ShadowPageManager::ReapplyPatch() {
    if (!m_installed) return;
    auto& kma = KernelMemoryAccessor::Instance();
    // 切到 pageB (补丁 PTE)
    kma.WritePte(m_patchAddr, m_patchPteValue);
    // ★ 不在此处 Sleep, 由调用方控制时序
}

void ShadowPageManager::Uninstall() {
    if (!m_installed) return;
    auto& kma = KernelMemoryAccessor::Instance();

    // 恢复原 PTE
    kma.WritePte(m_patchAddr, m_origPteValue);
    Sleep(50);  // 等 TLB 刷新, 确保 CS2 不再访问 pageB

    // 释放 pageB
    if (m_pageBPhys) {
        kma.FreeContiguousPhysical(m_pageBPhys);
    }

    m_installed = false;
    m_patchAddr = 0;
    m_origPteValue = 0;
    m_patchPteValue = 0;
    m_pageBPhys = 0;
    m_pageBVA = 0;
    ProcDiag("B549:SP:12 uninstalled\n");
}

} // namespace stealth
