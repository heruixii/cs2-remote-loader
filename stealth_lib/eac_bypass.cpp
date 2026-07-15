// ============================================================
// eac_bypass.cpp — Easy Anti-Cheat 专用规避实现
// ============================================================

#include "eac_bypass.h"
#include "platform.h"
#include "syscall_direct.h"
#include "stealth_process.h"
#include "memory_cloak.h"
#include <winternl.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <random>
#include <chrono>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace stealth {
namespace eac {

// ============================================================
// HandleBypass — 6 策略句柄获取
// ============================================================

bool HandleBypass::HasSufficientAccess(ACCESS_MASK access) {
    const ACCESS_MASK required = PROCESS_VM_READ | PROCESS_VM_WRITE |
                                  PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    return (access & required) == required;
}

std::vector<HandleBypass::ExistingHandle> HandleBypass::EnumerateHandles(DWORD targetPid) {
    std::vector<ExistingHandle> results;

    // v3.64: 使用 SystemExtendedHandleInformation (0x40) — 结构体定义稳定
    // 相比 SystemHandleInformation (0x10), 不会随 Windows 版本变化
    ULONG bufferSize = 0x400000;
    std::vector<BYTE> buffer(bufferSize);
    ULONG retLen = 0;

    NTSTATUS st = SysQuerySystemInformation(0x40, buffer.data(), bufferSize, &retLen);
    if (st == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize = retLen + 0x10000;
        buffer.resize(bufferSize);
        st = SysQuerySystemInformation(0x40, buffer.data(), bufferSize, &retLen);
    }

    if (!NT_SUCCESS(st)) return results;

    // SystemExtendedHandleInformation 结构:
    //   typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    //       ULONG_PTR NumberOfHandles;
    //       ULONG_PTR Reserved;
    //       SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];  // 40 bytes each
    //   }
    struct HandleEntryEx {
        PVOID    Object;                // offset 0
        ULONG_PTR UniqueProcessId;     // offset 8
        ULONG_PTR HandleValue;         // offset 16
        ULONG    GrantedAccess;        // offset 24
        USHORT   CreatorBackTraceIndex;// offset 28
        USHORT   ObjectTypeIndex;      // offset 30
        ULONG    HandleAttributes;     // offset 32
        ULONG    Reserved;             // offset 36
        // total: 40 bytes
    };
    struct HandleInfoEx {
        ULONG_PTR NumberOfHandles;     // offset 0
        ULONG_PTR Reserved;            // offset 8
        HandleEntryEx Handles[1];      // offset 16
    };

    auto* info = reinterpret_cast<HandleInfoEx*>(buffer.data());

    // 边界检查
    size_t headerSize = 16; // NumberOfHandles(8) + Reserved(8)
    ULONG_PTR maxHandles = (bufferSize > headerSize) ? ((bufferSize - headerSize) / sizeof(HandleEntryEx)) : 0;
    ULONG_PTR actualCount = info->NumberOfHandles;
    if (actualCount > maxHandles) actualCount = maxHandles;

    DWORD myPid = GetCurrentProcessId();

    for (ULONG_PTR i = 0; i < actualCount; i++) {
        auto& handle = info->Handles[i];
        DWORD ownerId = (DWORD)handle.UniqueProcessId;
        if (ownerId == myPid) continue;

        if (ownerId == targetPid || ownerId == 4) {
            ExistingHandle eh;
            eh.handleValue    = (HANDLE)handle.HandleValue;
            eh.ownerPid       = ownerId;
            eh.targetPid      = targetPid;
            eh.grantedAccess  = handle.GrantedAccess;
            eh.objectTypeIndex = (UCHAR)handle.ObjectTypeIndex;
            results.push_back(eh);
        }
    }

    // 按权限从高到低排序
    std::sort(results.begin(), results.end(), [](const ExistingHandle& a, const ExistingHandle& b) {
        return a.grantedAccess > b.grantedAccess;
    });

    return results;
}

HANDLE HandleBypass::ViaThreadHandleEscalation(DWORD pid) {
    // 1. 枚举目标进程中的线程
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return nullptr;

    THREADENTRY32 te32 = { sizeof(te32) };
    DWORD tid = 0;

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                tid = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnap, &te32));
    }
    CloseHandle(hSnap);

    if (!tid) return nullptr;

    // 2. 打开线程句柄 (EAC 对线程句柄的监控较松)
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                                 FALSE, tid);
    if (!hThread) return nullptr;

    // 3. 从线程句柄获取进程句柄
    //    通过 NtQueryInformationThread → THREAD_BASIC_INFORMATION → ClientId
    THREAD_BASIC_INFORMATION tbi = {};
    using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIT = reinterpret_cast<NtQueryInformationThread_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));

    HANDLE hProcess = nullptr;
    if (NtQIT) {
        ULONG retLen;
        NtQIT(hThread, 0, &tbi, sizeof(tbi), &retLen);

        // 4. 用线程的 ClientId 直接 NtOpenProcess (绕过 ObRegisterCallbacks 的进程名检查)
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        CLIENT_ID cid = { tbi.ClientId.UniqueProcess, nullptr };
        SysOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid, SyscallMethod::Indirect);
    }

    CloseHandle(hThread);
    return hProcess;
}

HANDLE HandleBypass::ViaExistingHandle(DWORD pid) {
    auto handles = EnumerateHandles(pid);

    // ★ 修复 P6: NtDuplicateObject typedef (用于绕过 EAC 的 DuplicateHandle Hook)
    using NtDuplicateObject_t = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, HANDLE, PHANDLE,
        ACCESS_MASK, ULONG, ULONG);
    static auto NtDupObj = reinterpret_cast<NtDuplicateObject_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject"));

    for (auto& h : handles) {
        if (!HasSufficientAccess(h.grantedAccess)) continue;

        // ★ 使用 SysOpenProcess 而非 OpenProcess (绕过 ObRegisterCallbacks)
        HANDLE hOwner = nullptr;
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        CLIENT_ID cid = { (HANDLE)(uintptr_t)h.ownerPid, nullptr };
        NTSTATUS st = SysOpenProcess(&hOwner, PROCESS_DUP_HANDLE,
                                      &oa, &cid, SyscallMethod::Indirect);
        if (!NT_SUCCESS(st) || !hOwner) continue;

        // ★ 使用 NtDuplicateObject 而非 DuplicateHandle (绕过 Win32 API Hook)
        HANDLE hDup = nullptr;
        NTSTATUS dupSt = NtDupObj ? NtDupObj(
            hOwner,            // 源进程句柄
            h.handleValue,     // 源句柄
            GetCurrentProcess(),// 目标进程句柄
            &hDup,             // 目标句柄
            0,                 // 保持原权限
            0,                 // 属性
            DUPLICATE_SAME_ACCESS
        ) : STATUS_UNSUCCESSFUL;

        SysClose(hOwner, SyscallMethod::Indirect);

        if (NT_SUCCESS(dupSt) && hDup) {
            // 验证句柄有效性 (通过 NtQueryObject 而非 GetProcessId)
            struct { ULONG GrantedAccess; ULONG HandleCount; ULONG PointerCount; ULONG Reserved[10]; }
                objInfo = {};
            ULONG retLen = 0;

            using NtQueryObject_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            static auto NtQO = reinterpret_cast<NtQueryObject_t>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));

            if (NtQO && NT_SUCCESS(NtQO(hDup, 0, &objInfo, sizeof(objInfo), &retLen))) {
                // 如果句柄权限足够, 直接使用
                if (HasSufficientAccess(objInfo.GrantedAccess)) {
                    return hDup;
                }
            }
            SysClose(hDup, SyscallMethod::Indirect);
        }
    }

    return nullptr;
}

HANDLE HandleBypass::ViaTrustedPivot(DWORD pid) {
    // 找到 SYSTEM 权限的受信进程 (services.exe 或 csrss.exe)
    const wchar_t* trustedProcesses[] = {
        L"services.exe", L"lsass.exe", L"svchost.exe"
    };

    for (auto* procName : trustedProcesses) {
        DWORD trustedPid = StealthProcess::FindProcessByWindow(nullptr, nullptr);
        // 简化: 通过进程名枚举
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) continue;

        PROCESSENTRY32W pe32 = { sizeof(pe32) };
        DWORD foundPid = 0;
        if (Process32FirstW(hSnap, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, procName) == 0) {
                    foundPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe32));
        }
        CloseHandle(hSnap);

        if (!foundPid) continue;

        // 打开受信进程的令牌并模拟
        HANDLE hToken = nullptr;
        // ★ Fix A1: 使用 SysOpenProcess 而非 OpenProcess (绕过 EAC 的 Win32 API Hook)
        HANDLE hTrusted = nullptr;
        OBJECT_ATTRIBUTES oaTrust = { sizeof(oaTrust) };
        CLIENT_ID cidTrust = { (HANDLE)(uintptr_t)foundPid, nullptr };
        SysOpenProcess(&hTrusted, PROCESS_QUERY_INFORMATION,
                       &oaTrust, &cidTrust, SyscallMethod::Indirect);
        if (!hTrusted) continue;

        if (OpenProcessToken(hTrusted, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {
            HANDLE hDupToken = nullptr;
            if (DuplicateToken(hToken, SecurityImpersonation, &hDupToken)) {
                if (ImpersonateLoggedOnUser(hDupToken)) {
                    // 现在以 SYSTEM 身份打开目标进程
                    CLIENT_ID cidGame = { (HANDLE)(ULONG_PTR)pid, nullptr };
                    OBJECT_ATTRIBUTES oaGame = { sizeof(oaGame) };
                    HANDLE hGame = nullptr;
                    SysOpenProcess(&hGame, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                        &oaGame, &cidGame, SyscallMethod::Indirect);

                    RevertToSelf();
                    CloseHandle(hDupToken);
                    CloseHandle(hToken);
                    CloseHandle(hTrusted);

                    if (hGame) return hGame;
                }
                CloseHandle(hDupToken);
            }
            CloseHandle(hToken);
        }
        CloseHandle(hTrusted);
    }

    return nullptr;
}

HANDLE HandleBypass::ViaSectionMapping(DWORD pid) {
    // 创建 Section 并通过映射访问游戏内存
    // 绕过传统句柄 OpenProcess→RPM/WPM 路径

    // ★ Fix A2: 使用 SysOpenProcess 而非 OpenProcess (绕过 EAC 的 Win32 API Hook)
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES oaSec = { sizeof(oaSec) };
    CLIENT_ID cidSec = { (HANDLE)(uintptr_t)pid, nullptr };

    SysOpenProcess(&hProcess, PROCESS_DUP_HANDLE,
                   &oaSec, &cidSec, SyscallMethod::Indirect);
    if (!hProcess) {
        // 用最小权限打开
        SysOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                       &oaSec, &cidSec, SyscallMethod::Indirect);
    }
    if (!hProcess) return nullptr;

    // 创建 Section 对象
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = {};
    maxSize.QuadPart = 0x1000000; // 16MB

    using NtCreateSection_t = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    static auto NtCreateSection = reinterpret_cast<NtCreateSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));

    if (NtCreateSection) {
        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE,
            &oa, &maxSize, PAGE_READWRITE, SEC_COMMIT, nullptr);
    }

    // E1: ViaSectionMapping 返回有效的进程句柄 (含 PROCESS_DUP_HANDLE)
    //     Section 映射到远程进程需要进程句柄完成映射,
    //     但返回有 DUP_HANDLE 权限的进程句柄可用于句柄复制策略
    if (hSection) CloseHandle(hSection);
    return hProcess; // 返回有 DUP_HANDLE 权限的句柄
}

HANDLE HandleBypass::ViaMinimalUpgrade(DWORD pid) {
    // 渐进式权限升级:
    // 1. 最小权限打开 (PROCESS_QUERY_LIMITED_INFORMATION)
    // 2. 通过 NtDuplicateObject 复制句柄到自身并提升权限
    // 3. 或使用 NtQueryInformationProcess 获取更多信息后重新打开

    HANDLE hMinimal = nullptr;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = { (HANDLE)(uintptr_t)pid, nullptr };

    // 使用 PROCESS_QUERY_LIMITED_INFORMATION (不触发 EAC 的高危权限检测)
    NTSTATUS st = SysOpenProcess(&hMinimal, PROCESS_QUERY_LIMITED_INFORMATION,
                                  &oa, &cid, SyscallMethod::Indirect);

    if (!NT_SUCCESS(st) || !hMinimal) return nullptr;

    // 验证进程存在
    DWORD exitCode = 0;
    if (GetExitCodeProcess(hMinimal, &exitCode) && exitCode != STILL_ACTIVE) {
        CloseHandle(hMinimal);
        return nullptr;
    }

    // E3: 使用 NtDuplicateObject 而非 DuplicateHandle (绕过EAC的Win32 API Hook)
    HANDLE hUpgraded = nullptr;
    using NtDuplicateObject_t = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
    static auto NtDupObjUpgrade = reinterpret_cast<NtDuplicateObject_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject"));

    if (NtDupObjUpgrade) {
        NtDupObjUpgrade(
            GetCurrentProcess(), hMinimal,
            GetCurrentProcess(), &hUpgraded,
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            0, DUPLICATE_SAME_ACCESS);
    }

    // ★ 修复 P2: 验证升级后的句柄权限
    // 定义所需的最小权限掩码用于验证
    const ACCESS_MASK requiredAccess =
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

    if (hUpgraded) {
        // 通过 NtQueryObject 获取句柄实际授予的权限
        // PUBLIC_OBJECT_BASIC_INFORMATION + ObjectBasicInformation (0)
        struct { ULONG GrantedAccess; ULONG HandleCount; ULONG PointerCount; ULONG Reserved[10]; }
            objInfo = {};
        ULONG retLen = 0;

        using NtQueryObject_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        static auto NtQO = reinterpret_cast<NtQueryObject_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));

        if (NtQO && NT_SUCCESS(NtQO(hUpgraded, 0, &objInfo, sizeof(objInfo), &retLen)) &&
            HasSufficientAccess(objInfo.GrantedAccess)) {
            CloseHandle(hMinimal);
            return hUpgraded;
        }
        CloseHandle(hUpgraded);
    }

    // 回退: 保持最小权限句柄 (至少可以读 PEB/LDR)
    return hMinimal;
}

HANDLE HandleBypass::OpenProcessEAC(DWORD pid) {
    // 按成功率从高到低尝试 6 种策略
    HANDLE hProcess = nullptr;

    // 策略2: 窃取已有句柄 (最隐蔽, 不触发 ObRegisterCallbacks)
    hProcess = ViaExistingHandle(pid);
    // ViaExistingHandle 内部已验证句柄权限, 无需再用 HasSufficientAccess(0) 检查
    if (hProcess) return hProcess;

    // 策略3: 受信中转
    hProcess = ViaTrustedPivot(pid);
    if (hProcess) return hProcess;

    // 策略1: 线程权限升级
    hProcess = ViaThreadHandleEscalation(pid);
    if (hProcess) return hProcess;

    // 策略6: 渐进升级
    hProcess = ViaMinimalUpgrade(pid);
    if (hProcess) return hProcess;

    // 策略4: Section 映射 (作为最后手段)
    hProcess = ViaSectionMapping(pid);

    return hProcess;
}

// ============================================================
// EACScanPredictor
// ============================================================

// ★ Fix B3: 静态被修改内存区域列表定义
std::vector<EACScanPredictor::ModifiedRegion> EACScanPredictor::s_modifiedRegions;

EACScanPredictor& EACScanPredictor::Instance() {
    static EACScanPredictor instance;
    return instance;
}

bool EACScanPredictor::StartMonitoring(DWORD gamePid) {
    m_gamePid = gamePid;
    m_timing = {};
    m_consecutivePulses = 0;
    m_scanIntervals.clear();
    m_emaInterval = 0;
    m_eacDriverBase = 0;
    m_eacDriverSize = 0;
    m_gameTextBase = 0;
    m_gameTextSize = 0;

    // 获取 System 进程 (PID 4) 的基础 CPU 时间
    // 用于后续检测 EAC 驱动线程的内核时间增量
    FILETIME createTime, exitTime, kernelTime, userTime;

    // ★ 修复 H4+H2: 使用 SysOpenProcess 而非 OpenProcess (绕过 EAC 监控)
    HANDLE hSystem = nullptr;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = { (HANDLE)4, nullptr };
    SysOpenProcess(&hSystem, PROCESS_QUERY_LIMITED_INFORMATION,
                   &oa, &cid, SyscallMethod::Indirect);
    if (hSystem) {
        GetProcessTimes(hSystem, &createTime, &exitTime, &kernelTime, &userTime);
        m_lastKernelTime = ((ULONG64)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
        m_lastUserTime   = ((ULONG64)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;

        // ★ Fix B1: 尝试定位 EAC 驱动在 System 进程中的映射范围
        // 枚举 System 进程模块, 查找 EasyAntiCheat.sys
        HMODULE hModsSys[1024];
        DWORD cbSysNeeded;
        if (EnumProcessModules(hSystem, hModsSys, sizeof(hModsSys), &cbSysNeeded)) {
            DWORD modCount = cbSysNeeded / sizeof(HMODULE);
            for (DWORD i = 0; i < modCount; i++) {
                WCHAR modNameSys[MAX_PATH] = {};
                if (GetModuleBaseNameW(hSystem, hModsSys[i], modNameSys, MAX_PATH)) {
                    if (wcsstr(modNameSys, L"EasyAntiCheat") ||
                        wcsstr(modNameSys, L"EasyAntiCheat.sys") ||
                        _wcsicmp(modNameSys, L"EasyAntiCheat.sys") == 0) {
                        MODULEINFO modInfoSys;
                        if (GetModuleInformation(hSystem, hModsSys[i], &modInfoSys, sizeof(modInfoSys))) {
                            m_eacDriverBase = reinterpret_cast<uintptr_t>(modInfoSys.lpBaseOfDll);
                            m_eacDriverSize = modInfoSys.SizeOfImage;
                        }
                        break;
                    }
                }
            }
        }
        SysClose(hSystem, SyscallMethod::Indirect);
    }

    // ★ Fix B3: 定位游戏进程的 .text 段地址范围
    // 通过打开游戏进程句柄并枚举模块来获取 .text 段
    HANDLE hGame = nullptr;
    OBJECT_ATTRIBUTES oaGame = { sizeof(oaGame) };
    CLIENT_ID cidGame = { (HANDLE)(uintptr_t)gamePid, nullptr };
    NTSTATUS stGame = SysOpenProcess(&hGame, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      &oaGame, &cidGame, SyscallMethod::Indirect);
    if (NT_SUCCESS(stGame) && hGame) {
        // 获取游戏主模块 (.exe) 的基址
        HMODULE hGameMods[256];
        DWORD cbNeeded;
        if (EnumProcessModules(hGame, hGameMods, sizeof(hGameMods), &cbNeeded)) {
            if (cbNeeded > 0) {
                HMODULE hGameExe = hGameMods[0]; // 第一个模块是主exe
                MODULEINFO modInfo;
                if (GetModuleInformation(hGame, hGameExe, &modInfo, sizeof(modInfo))) {
                    // 解析 .text 段
                    BYTE headerBuf[0x1000] = {};
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(hGame, modInfo.lpBaseOfDll, headerBuf, sizeof(headerBuf), &bytesRead)) {
                        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(headerBuf);
                        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                            auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                                reinterpret_cast<uintptr_t>(headerBuf) + dos->e_lfanew);
                            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                auto* section = IMAGE_FIRST_SECTION(nt);
                                for (int s = 0; s < nt->FileHeader.NumberOfSections; s++) {
                                    char secName[9] = {};
                                    memcpy(secName, section[s].Name, 8);
                                    if (strstr(secName, ".text") || 
                                        (section[s].Characteristics & IMAGE_SCN_CNT_CODE)) {
                                        m_gameTextBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll) 
                                                         + section[s].VirtualAddress;
                                        m_gameTextSize = section[s].Misc.VirtualSize;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        SysClose(hGame, SyscallMethod::Indirect);
    }

    m_monitoring = true;
    return true;
}

// ★ 修复 H4: 停止监控, 释放 DetectScanPulse 中缓存的 System 句柄
void EACScanPredictor::StopMonitoring() {
    // DetectScanPulse 中缓存了一个 static HANDLE, 无法从外部直接访问
    // 通过重新调用 DetectScanPulse 后内部机制来标记需要关闭
    // 实际清理: 将监控状态标记为 false, 下次调用 DetectScanPulse 时会检测到并关闭
    m_monitoring = false;
    m_gamePid = 0;
}

// ★ Fix B1: 枚举游戏进程中所有线程, 检查是否有线程起始地址落入EAC驱动模块范围
int EACScanPredictor::EnumerateEACWorkerThreads() {
    if (!m_gamePid) return 0;

    // 如果没有 EAC 驱动基址信息, 跳过线程检查
    // (仍然返回基于内核时间的检测)
    if (m_eacDriverBase == 0 || m_eacDriverSize == 0) return 0;

    // 枚举游戏进程中的线程
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIT = reinterpret_cast<NtQueryInformationThread_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));

    // ThreadQuerySetWin32StartAddress = 9
    const ULONG ThreadQuerySetWin32StartAddress = 9;

    int eacWorkerCount = 0;
    THREADENTRY32 te32 = { sizeof(te32) };

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID != m_gamePid) continue;

            // 打开线程句柄以查询其起始地址
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (!hThread) continue;

            // 查询线程起始地址 (Win32StartAddress)
            PVOID startAddr = nullptr;
            if (NtQIT) {
                ULONG retLen = 0;
                NTSTATUS st = NtQIT(hThread, ThreadQuerySetWin32StartAddress,
                                     &startAddr, sizeof(startAddr), &retLen);
                if (NT_SUCCESS(st) && startAddr) {
                    uintptr_t addr = reinterpret_cast<uintptr_t>(startAddr);
                    // 检查起始地址是否在 EAC 驱动模块范围内
                    if (addr >= m_eacDriverBase &&
                        addr < m_eacDriverBase + m_eacDriverSize) {
                        eacWorkerCount++;
                    }
                }
            }
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te32));
    }

    CloseHandle(hSnap);
    return eacWorkerCount;
}

bool EACScanPredictor::DetectScanPulse() {
    // ★ 修复 P6: 缓存 PID 4 句柄, 避免每帧重复 OpenProcess (EAC监控此操作)
    static HANDLE hSystemCached = nullptr;
    static DWORD lastReopenTime = 0;

    // ★ 修复 H4: 如果监控已停止, 关闭缓存句柄
    if (!m_monitoring) {
        if (hSystemCached) {
            SysClose(hSystemCached, SyscallMethod::Indirect);
            hSystemCached = nullptr;
        }
        lastReopenTime = 0;
        return false;
    }

    DWORD now = GetTickCount();
    // 每60秒刷新一次句柄 (防止句柄过期)
    if (!hSystemCached || (now - lastReopenTime > 60000)) {
        // E7: 使用 SysClose 代替 CloseHandle (保持与 SysOpenProcess 一致)
        if (hSystemCached) SysClose(hSystemCached, SyscallMethod::Indirect);

        OBJECT_ATTRIBUTES oa = { sizeof(oa) };
        CLIENT_ID cid = { (HANDLE)4, nullptr };
        SysOpenProcess(&hSystemCached, PROCESS_QUERY_LIMITED_INFORMATION,
                       &oa, &cid, SyscallMethod::Indirect);
        lastReopenTime = now;
    }

    if (!hSystemCached) return false;

    FILETIME createTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(hSystemCached, &createTime, &exitTime, &kernelTime, &userTime)) {
        return false;
    }

    ULONG64 currentKernel = ((ULONG64)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime;
    ULONG64 currentUser   = ((ULONG64)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime;

    // 内核时间增量 (100ns 单位)
    ULONG64 kernelDelta = currentKernel - m_lastKernelTime;
    m_lastKernelTime = currentKernel;
    m_lastUserTime   = currentUser;

    // EAC 扫描脉冲: 内核时间显著增加 (>50ms in 100ns units = 500000)
    const ULONG64 SCAN_THRESHOLD = 500000; // 50ms 内核CPU时间

    bool kernelPulse = kernelDelta > SCAN_THRESHOLD;

    // ★ Fix B1: 线程起始地址检测作为辅助信号
    // 检查游戏进程中是否有线程的起始地址落入 EAC 驱动模块范围
    // 这表明 EAC 驱动正在执行内存扫描 (通过注入到游戏进程的线程)
    int eacThreads = EnumerateEACWorkerThreads();

    // 组合检测: 内核脉冲 OR 检测到 EAC 工作线程
    // 任一条件满足即认为可能在扫描中
    return kernelPulse || (eacThreads > 0);
}

bool EACScanPredictor::IsScanning() {
    if (!m_monitoring) return false;

    bool pulseDetected = DetectScanPulse();

    // ★ Fix B1: 降低误报率 — 需要连续2次采样都在阈值之上才确认扫描
    if (pulseDetected) {
        m_consecutivePulses++;
    } else {
        m_consecutivePulses = 0;
        return false;
    }

    // 需要至少连续2次检测到脉冲才算真正的扫描
    const int MIN_CONSECUTIVE_FOR_SCAN = 2;
    if (m_consecutivePulses < MIN_CONSECUTIVE_FOR_SCAN) {
        return false; // 可能是误报, 等待下次确认
    }

    // 确认扫描中, 更新计时信息
    m_timing.lastScanAt = GetTickCount();

    // 记录扫描间隔
    if (m_timing.lastScanAt > 0 && m_timing.nextScanEstimate > 0) {
        DWORD interval = m_timing.lastScanAt - m_timing.nextScanEstimate;
        if (interval > 1000 && interval < 60000) { // 过滤异常值
            m_scanIntervals.push_back(interval);
            // 保持最近 10 次扫描间隔
            if (m_scanIntervals.size() > 10) {
                m_scanIntervals.erase(m_scanIntervals.begin());
            }

            // ★ Fix B1: 使用指数移动平均计算扫描间隔
            if (m_scanIntervals.size() >= 2) {
                // 首次: 用简单算术平均初始化 EMA
                if (m_emaInterval < 1.0f) {
                    DWORD sum = 0;
                    for (auto iv : m_scanIntervals) sum += iv;
                    m_emaInterval = static_cast<float>(sum) / static_cast<float>(m_scanIntervals.size());
                } else {
                    // EMA 更新: ema = alpha * current + (1-alpha) * ema
                    m_emaInterval = EMA_ALPHA * static_cast<float>(interval) +
                                    (1.0f - EMA_ALPHA) * m_emaInterval;
                }
                m_timing.scanIntervalMs = static_cast<DWORD>(m_emaInterval);
                m_timing.nextScanEstimate = m_timing.lastScanAt + m_timing.scanIntervalMs;
            } else {
                m_timing.scanIntervalMs = interval;
                m_timing.nextScanEstimate = m_timing.lastScanAt + interval;
            }
        }
    }

    m_timing.cycleCount++;
    return true;
}

DWORD EACScanPredictor::GetSafeWindowMs() {
    if (!m_monitoring || m_timing.nextScanEstimate == 0) return 0;

    DWORD now = GetTickCount();
    if (now >= m_timing.nextScanEstimate) return 100; // 已经过预期时间, 给 100ms

    DWORD remaining = m_timing.nextScanEstimate - now - 500; // 预留 500ms 安全边距
    return remaining > 500 ? remaining : 0;
}

bool EACScanPredictor::ExecuteInSafeWindow(
    std::function<void()> operation, DWORD timeoutMs) {

    if (!m_monitoring) {
        operation();
        return true;
    }

    DWORD startTime = GetTickCount();
    DWORD elapsed = 0;

    while (elapsed < timeoutMs) {
        // 检查是否在扫描中
        if (IsScanning()) {
            // 扫描中, 等待扫描结束
            Sleep(100);
            elapsed = GetTickCount() - startTime;
            continue;
        }

        // 不在扫描中, 检查剩余安全时间
        DWORD safeWindow = GetSafeWindowMs();
        if (safeWindow < 200) {
            // 安全窗口不足, 等待直到更加安全
            Sleep(100);
            elapsed = GetTickCount() - startTime;
            continue;
        }

        // 在安全窗口内执行操作
        operation();
        return true;
    }

    // 超时, 降级执行 (可能触发检测)
    operation();
    return false;
}

// ★ Fix B1: 使用指数移动平均预测下次扫描间隔
DWORD EACScanPredictor::PredictNextScanInterval() {
    if (m_emaInterval < 1.0f) {
        // EMA 尚未初始化, 使用简单平均作为后备
        if (m_scanIntervals.size() >= 2) {
            DWORD sum = 0;
            for (auto iv : m_scanIntervals) sum += iv;
            return sum / static_cast<DWORD>(m_scanIntervals.size());
        }
        return 0; // 数据不足
    }
    return static_cast<DWORD>(m_emaInterval);
}

// ★ Fix B3: 获取游戏 .text 段地址范围
bool EACScanPredictor::GetGameTextRange(uintptr_t& outBase, SIZE_T& outSize) const {
    if (m_gameTextBase == 0 || m_gameTextSize == 0) return false;
    outBase = m_gameTextBase;
    outSize = m_gameTextSize;
    return true;
}

// ★ Fix B3: 安全内存读取 — 仅在预测扫描窗口外执行读取
bool EACScanPredictor::SafeReadMemory(void* dst, const void* src, SIZE_T size) {
    auto& predictor = Instance();
    if (!predictor.m_monitoring) {
        // 未监控, 直接读取
        memcpy(dst, src, size);
        return true;
    }

    const DWORD TIMEOUT_MS = 10000; // 最长等待10秒
    DWORD startTime = GetTickCount();

    while (true) {
        // 检查是否在扫描窗口内
        if (predictor.IsScanning()) {
            // 扫描中, 等待
            DWORD elapsed = GetTickCount() - startTime;
            if (elapsed > TIMEOUT_MS) return false; // 超时
            Sleep(50);
            continue;
        }

        // 检查剩余安全窗口
        DWORD safeWindow = predictor.GetSafeWindowMs();
        if (safeWindow < 100 && predictor.m_timing.nextScanEstimate > 0) {
            // 安全窗口不足, 等待到下次安全期
            DWORD elapsed = GetTickCount() - startTime;
            if (elapsed > TIMEOUT_MS) return false;
            Sleep(50);
            continue;
        }

        // ★ Fix B3: 当前时间在预测扫描窗口外, 安全执行读取
        memcpy(dst, src, size);
        return true;
    }
}

// ★ Fix B3: 标记已修改的内存区域
void EACScanPredictor::MarkMemoryModified(void* addr, SIZE_T size) {
    if (!addr || size == 0) return;

    ModifiedRegion region;
    region.addr = addr;
    region.size = size;
    region.originalBytes.resize(size);

    // 读取当前保护
    MEMORY_BASIC_INFORMATION mbi = {};
    VirtualQuery(addr, &mbi, sizeof(mbi));
    region.originalProtect = mbi.Protect;

    // 备份原始字节
    memcpy(region.originalBytes.data(), addr, size);

    s_modifiedRegions.push_back(region);
}

// ★ Fix B3: 在预测的EAC扫描窗口前恢复所有被标记的修改
void EACScanPredictor::RestoreAllModified() {
    for (auto& region : s_modifiedRegions) {
        DWORD oldProtect;
        // 设置为可写以恢复原始字节
        VirtualProtect(region.addr, region.size, PAGE_READWRITE, &oldProtect);
        memcpy(region.addr, region.originalBytes.data(), region.size);
        // 恢复原始保护
        VirtualProtect(region.addr, region.size, region.originalProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), region.addr, region.size);
    }
}

// ★ Fix B3: 在预测的EAC扫描窗口后重新应用所有被标记的修改
void EACScanPredictor::ReapplyAllModified() {
    // 注意: 此处的"重新应用"指的是用户实际想要写入的数据,
    // 但当前备份的是修改前的原始数据, 所以需要调用者在修改后通过
    // MarkMemoryModified 重新登记修改后的内容.
    // 这个接口主要用于框架集成: 在扫描窗口后, 外部模块可重新写入修改内容.
    // 简化实现: 清空记录 (因为用户需要重新标记)
    // 实际使用中, 外部在每个扫描周期前后负责加密/解密
    // 这里仅提供清理接口, 配合 SleepObfuscator 的 EncryptAll/DecryptAll
    s_modifiedRegions.clear();
}

// ============================================================
// PEHeaderStripper
// ============================================================

bool PEHeaderStripper::StripLoadedHeaders(uintptr_t imageBase) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // ★ 先读取 e_lfanew (在擦除MZ之前) —— 修复 P1
    LONG e_lfanew = dos->e_lfanew;
    if (e_lfanew < 0x40 || e_lfanew > 0x2000) return false; // 合法性校验

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD oldProtect;

    // 1. 擦除 PE 签名 (e_lfanew 处的 "PE\0\0") —— 先擦远处
    uintptr_t peSigAddr = imageBase + e_lfanew;
    VirtualProtect(reinterpret_cast<LPVOID>(peSigAddr), 4, PAGE_READWRITE, &oldProtect);
    *reinterpret_cast<DWORD*>(peSigAddr) = 0x00000000;
    VirtualProtect(reinterpret_cast<LPVOID>(peSigAddr), 4, oldProtect, &oldProtect);

    // 2. 擦除 e_lfanew (offset 0x3C)
    VirtualProtect(reinterpret_cast<LPVOID>(imageBase + 0x3C), 4, PAGE_READWRITE, &oldProtect);
    *reinterpret_cast<DWORD*>(imageBase + 0x3C) = 0;
    VirtualProtect(reinterpret_cast<LPVOID>(imageBase + 0x3C), 4, oldProtect, &oldProtect);

    // 3. 最后擦除 MZ 魔数 (最后一个 DWORD, 防止扫描器通过MZ定位)
    VirtualProtect(reinterpret_cast<LPVOID>(imageBase), 4, PAGE_READWRITE, &oldProtect);
    *reinterpret_cast<DWORD*>(imageBase) = 0x00000000;
    VirtualProtect(reinterpret_cast<LPVOID>(imageBase), 4, oldProtect, &oldProtect);

    return true;
}

bool PEHeaderStripper::ReplaceFF25Stubs(uintptr_t imageBase) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress || !importDir.Size) return false;

    // 遍历 import thunk, 替换 FF 25 为 mov rax, addr; jmp rax
    auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        imageBase + importDir.VirtualAddress);

    for (int i = 0; desc[i].Name; i++) {
        uintptr_t iatAddr = imageBase + desc[i].FirstThunk;

        // E2: 实际扫描 .text 段替换 FF 25 模式
        //     定位 .text 区段进行 FF 25 扫描
        auto* section = IMAGE_FIRST_SECTION(nt);
        for (int s = 0; s < nt->FileHeader.NumberOfSections; s++) {
            if (!(section[s].Characteristics & IMAGE_SCN_CNT_CODE)) continue;

            BYTE* scanStart = reinterpret_cast<BYTE*>(imageBase + section[s].VirtualAddress);
            SIZE_T scanSize = section[s].Misc.VirtualSize;
            if (scanSize < 6) continue;

            for (SIZE_T off = 0; off < scanSize - 6; off++) {
                // 检测 FF 25 [rip+disp32] 模式
                if (scanStart[off] == 0xFF && scanStart[off + 1] == 0x25) {
                    // 计算 FF 25 目标地址 = rip(off+6) + disp32
                    int32_t* disp32 = reinterpret_cast<int32_t*>(scanStart + off + 2);
                    uintptr_t targetAddr = reinterpret_cast<uintptr_t>(scanStart + off + 6) + *disp32;

                    // 检查目标是否在 IAT 范围内
                    if (targetAddr >= iatAddr &&
                        targetAddr < iatAddr + 0x1000) {
                        // ★ Fix C: 随机语义NOP替换 (替代固定6×0x90防EAC签名匹配)
                        static const BYTE semanticNopPatterns[][6] = {
                            {0x48,0x87,0xC0,0x48,0x87,0xC0},
                            {0x48,0x87,0xC9,0x48,0x87,0xC9},
                            {0x48,0x87,0xD2,0x48,0x87,0xD2},
                            {0x4D,0x87,0xC0,0x4D,0x87,0xC0},
                            {0x90,0x48,0x87,0xC0,0x90,0x90},
                            {0x48,0x85,0xC0,0x90,0x90,0x90},
                            {0x48,0x8D,0x00,0x90,0x90,0x90},
                            {0x90,0x90,0x48,0x87,0xC0,0x90},
                        };
                        static const int npCount = sizeof(semanticNopPatterns)/sizeof(semanticNopPatterns[0]);
                        std::mt19937 rngFF(static_cast<unsigned>(
                            __rdtsc() ^ (uintptr_t)(scanStart + off)));
                        int idx = rngFF() % npCount;

                        DWORD oldProtRE;
                        VirtualProtect(scanStart + off, 6, PAGE_READWRITE, &oldProtRE);
                        memcpy(scanStart + off, semanticNopPatterns[idx], 6);
                        VirtualProtect(scanStart + off, 6, oldProtRE, &oldProtRE);
                    }
                }
            }
        }
    }

    return true;
}

bool PEHeaderStripper::ClearDosStub(uintptr_t imageBase) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // DOS stub 从 offset 0x40 到 e_lfanew
    SIZE_T stubSize = dos->e_lfanew - 0x40;
    if (stubSize > 0x1000) return false; // 异常

    auto* stubAddr = reinterpret_cast<BYTE*>(imageBase + 0x40);

    DWORD oldProtect;
    if (VirtualProtect(stubAddr, stubSize, PAGE_READWRITE, &oldProtect)) {
        // 填充随机数据 (覆盖 Rich Header 和版权字符串)
        std::mt19937 rng(static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        for (SIZE_T i = 0; i < stubSize; i++) {
            stubAddr[i] = static_cast<BYTE>(rng());
        }
        VirtualProtect(stubAddr, stubSize, oldProtect, &oldProtect);
    }

    return true;
}

bool PEHeaderStripper::ScrubSectionNames(uintptr_t imageBase) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dos->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(nt);

    DWORD oldProtect;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        // 将区段名替换为随机 8 字节 (保留 null 终止)
        // EAC 扫描已知外挂的区段名特征
        VirtualProtect(section[i].Name, 8, PAGE_READWRITE, &oldProtect);
        std::mt19937 rng(static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        for (int j = 0; j < 7; j++) {
            section[i].Name[j] = static_cast<char>('A' + (rng() % 26));
        }
        section[i].Name[7] = 0;
        VirtualProtect(section[i].Name, 8, oldProtect, &oldProtect);
    }

    return true;
}

bool PEHeaderStripper::RandomizeSectionFlags(uintptr_t imageBase) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dos->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(nt);

    // EAC 扫描 IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE 组合 (RWX 页)
    // 这是外挂的典型特征

    DWORD oldProtect;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        VirtualProtect(&section[i].Characteristics, 4, PAGE_READWRITE, &oldProtect);

        // 随机翻转低优先级标志 (保持功能)
        if (std::rand() % 2) {
            section[i].Characteristics ^= IMAGE_SCN_MEM_DISCARDABLE;
        }
        if (std::rand() % 2) {
            section[i].Characteristics ^= IMAGE_SCN_MEM_NOT_CACHED;
        }

        VirtualProtect(&section[i].Characteristics, 4, oldProtect, &oldProtect);
    }

    return true;
}

// ============================================================
// DeepStackSpoofer
// ============================================================

DeepStackSpoofer& DeepStackSpoofer::Instance() {
    static DeepStackSpoofer instance;
    return instance;
}

std::vector<uintptr_t> DeepStackSpoofer::ScanModuleFunctions(HMODULE hModule, int maxFunctions) {
    std::vector<uintptr_t> functions;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return functions;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(hModule) + dos->e_lfanew);

    auto exceptionRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    auto exceptionSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (!exceptionRva || !exceptionSize) return functions;

    auto* runtimeFuncs = reinterpret_cast<PRUNTIME_FUNCTION>(
        reinterpret_cast<uintptr_t>(hModule) + exceptionRva);
    DWORD count = exceptionSize / sizeof(RUNTIME_FUNCTION);

    // 随机采样函数
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<DWORD> dist(0, count > 0 ? count - 1 : 0);

    for (int i = 0; i < maxFunctions && i < (int)count; i++) {
        DWORD idx = dist(rng);
        uintptr_t funcAddr = reinterpret_cast<uintptr_t>(hModule) +
                             runtimeFuncs[idx].BeginAddress;

        if (HasValidUnwindInfo(funcAddr)) {
            functions.push_back(funcAddr);
        }
    }

    return functions;
}

bool DeepStackSpoofer::HasValidUnwindInfo(uintptr_t addr) {
    // 检查地址是否在模块的 .pdata RUNTIME_FUNCTION 覆盖范围内
    HMODULE hMod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           reinterpret_cast<LPCWSTR>(addr), &hMod) && hMod) {
        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hMod);
        auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uintptr_t>(hMod) + dos->e_lfanew);

        auto exceptRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        if (!exceptRva) return false;

        auto* funcs = reinterpret_cast<PRUNTIME_FUNCTION>(
            reinterpret_cast<uintptr_t>(hMod) + exceptRva);
        DWORD funcCount = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
                          / sizeof(RUNTIME_FUNCTION);

        DWORD rva = static_cast<DWORD>(addr - reinterpret_cast<uintptr_t>(hMod));

        for (DWORD i = 0; i < funcCount; i++) {
            if (rva >= funcs[i].BeginAddress && rva < funcs[i].EndAddress) {
                return true;
            }
        }
    }

    return false;
}

bool DeepStackSpoofer::GenerateFrameChain() {
    // 扫描多个系统 DLL 中的合法函数作为伪造帧
    const wchar_t* modules[] = {
        L"kernel32.dll", L"ntdll.dll", L"kernelbase.dll",
        L"user32.dll", L"gdi32.dll", L"advapi32.dll",
        L"ole32.dll", L"shell32.dll", L"combase.dll",
        L"msvcrt.dll", L"ws2_32.dll", L"bcrypt.dll",
        L"crypt32.dll", L"winmm.dll", L"dwmapi.dll",
        L"uxtheme.dll", L"version.dll", L"setupapi.dll",
        L"rpcrt4.dll", L"sechost.dll", L"shlwapi.dll",
        L"imm32.dll", L"msctf.dll", L"clbcatq.dll",
        L"propsys.dll", L"devobj.dll", L"wintrust.dll",
        L"msasn1.dll", L"cfgmgr32.dll", L"wldp.dll",
        L"ucrtbase.dll", L"ntmarta.dll" // 32个模块
    };

    m_chain.clear();
    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    for (const auto* modName : modules) {
        // ★ 修复 H2: 仅使用已加载的模块, 不使用 LoadLibraryW (触发EAC加载回调)
        HMODULE hMod = GetModuleHandleW(modName);
        if (!hMod) continue; // 模块未加载, 跳过 (EAC会检测LoadLibrary调用)

        auto funcs = ScanModuleFunctions(hMod, 3);
        if (!funcs.empty()) {
            StackFrame frame;
            frame.returnAddress = funcs[rng() % funcs.size()];
            frame.framePointer  = 0; // 运行时不使用帧指针
            frame.frameSize     = 0x28 + (rng() % 0x80); // 32-160 字节栈帧
            frame.moduleName    = nullptr; // 调试用, 忽略

            m_chain.push_back(frame);
        }

        if (m_chain.size() >= 32) break;
    }

    // 补充帧到恰好 32 帧
    while (m_chain.size() < 32) {
        // 复用 ntdll/kernel32 中的函数
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto funcs = ScanModuleFunctions(ntdll, 10);
        if (!funcs.empty()) {
            StackFrame frame;
            frame.returnAddress = funcs[rng() % funcs.size()];
            frame.framePointer  = 0;
            frame.frameSize     = 0x28 + (rng() % 0x80);
            frame.moduleName    = nullptr;
            m_chain.push_back(frame);
        } else break;
    }

    m_initialized = m_chain.size() >= 24;
    return m_initialized;
}

uintptr_t DeepStackSpoofer::ApplyToStack(void* originalStack, SIZE_T stackSize) {
    // 将伪造的 32 帧调用链写入栈
    // Rsp 向下增长: 栈顶(低地址) ← ... ← 栈底(高地址)
    // 伪造链: 第1帧(最内层) → 第32帧(最外层)

    if (m_chain.size() < 32) return reinterpret_cast<uintptr_t>(originalStack);

    auto* stack = static_cast<uintptr_t*>(originalStack);
    SIZE_T wordCount = stackSize / sizeof(uintptr_t);
    SIZE_T frameCount = min(m_chain.size(), wordCount / 2);

    for (SIZE_T i = 0; i < frameCount; i++) {
        stack[i * 2]     = m_chain[i].returnAddress; // 返回地址
        stack[i * 2 + 1] = m_chain[i].framePointer;  // 帧指针
    }

    return reinterpret_cast<uintptr_t>(stack);
}

std::vector<DeepStackSpoofer::StackFrame>
DeepStackSpoofer::GetShortChain(int frameCount) {
    if (m_chain.empty()) return {};

    std::vector<StackFrame> result;
    frameCount = min(frameCount, (int)m_chain.size());

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<size_t> dist(0, m_chain.size() - 1);

    for (int i = 0; i < frameCount; i++) {
        result.push_back(m_chain[dist(rng)]);
    }

    return result;
}

// ============================================================
// ProcessDisguise
// ============================================================

bool ProcessDisguise::DisguiseProcessName(const wchar_t* fakeName) {
    // 修改 PEB 中的 ImagePathName
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return false;

    auto* params = peb->ProcessParameters;
    if (!params) return false;

    // 修改 ImagePathName (UNICODE_STRING)
    SIZE_T nameLen = wcslen(fakeName) * sizeof(WCHAR);
    SIZE_T maxLen = params->ImagePathName.MaximumLength;

    if (nameLen > maxLen) return false;

    DWORD oldProtect;
    if (!VirtualProtect(params->ImagePathName.Buffer, maxLen, PAGE_READWRITE, &oldProtect)) {
        return false;
    }

    wcscpy_s(params->ImagePathName.Buffer, maxLen / sizeof(WCHAR), fakeName);
    params->ImagePathName.Length = static_cast<USHORT>(nameLen);

    VirtualProtect(params->ImagePathName.Buffer, maxLen, oldProtect, &oldProtect);

    return true;
}

bool ProcessDisguise::DisguiseOverlayWindow(HWND hwnd) {
    if (!hwnd) return false;

    // 移除可疑的扩展样式
    LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);

    // 随机翻转标志, 避开固定样式组合
    exStyle &= ~WS_EX_LAYERED;    // 移除分层窗口
    exStyle &= ~WS_EX_TRANSPARENT; // 移除透明
    // 保留 WS_EX_TOPMOST (许多合法窗口也使用)

    SetWindowLongPtrW(hwnd, GWL_EXSTYLE, exStyle);

    // 强制刷新窗口属性
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    return true;
}

bool ProcessDisguise::DisguiseParentProcess(DWORD fakeParentPid) {
    // 修改 PEB 中的 InheritedFromUniqueProcessId
    // EAC 会检查父进程是否合法 (应为 explorer.exe 或等效信任进程)
    
    if (fakeParentPid == 0) {
        // 默认: 伪装为 explorer.exe 的 PID
        // 查找 explorer.exe 进程
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32 = { sizeof(pe32) };
        if (Process32FirstW(hSnap, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
                    fakeParentPid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    
    if (fakeParentPid == 0) return false;
    
    // 获取 PEB 地址
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS st = SysQueryInformationProcess(
        GetCurrentProcess(), 0, &pbi, sizeof(pbi), &retLen);
    
    if (NT_SUCCESS(st) && pbi.PebBaseAddress) {
        auto* pebPtr = reinterpret_cast<BYTE*>(pbi.PebBaseAddress);
        DWORD oldProtect = 0;
        VirtualProtect(pebPtr + 0xB0, sizeof(HANDLE), PAGE_READWRITE, &oldProtect);
        // InheritedFromUniqueProcessId 在 PEB+0xB0 (Win10+)
        *reinterpret_cast<HANDLE*>(pebPtr + 0xB0) = ULongToHandle(fakeParentPid);
        VirtualProtect(pebPtr + 0xB0, sizeof(HANDLE), oldProtect, &oldProtect);
        return true;
    }
    
    return false;
}

bool ProcessDisguise::StripDigitalSignature() {
    // 检查并清除可能暴露的数字签名信息
    // - PEB 中的 IsImageSigned / ImageSignatureLevel 字段 (Win8+)
    // - kernelbase 中缓存的签名验证结果
    
    // 获取 PEB
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS st = SysQueryInformationProcess(
        GetCurrentProcess(), 0, &pbi, sizeof(pbi), &retLen);
    
    if (!NT_SUCCESS(st) || !pbi.PebBaseAddress)
        return false;
    
    auto* pebPtr = reinterpret_cast<BYTE*>(pbi.PebBaseAddress);
    // Win8+ PEB 签名相关字段:
    // - PEB+0xBC: ImageSignatureLevel (BYTE)  — 0x06=Windows 签名, 0x08=Microsoft 签名
    // - PEB+0xBD: ImageSignatureType  (BYTE)  — 0x00=None, 0x01=Catalog, 0x02=Embedded
    // 清零这些字段伪装为未签名
    DWORD oldProtect = 0;
    if (VirtualProtect(pebPtr + 0xBC, 2, PAGE_READWRITE, &oldProtect)) {
        pebPtr[0xBC] = 0; // ImageSignatureLevel = 0 (未签名)
        pebPtr[0xBD] = 0; // ImageSignatureType = 0 (无签名)
        VirtualProtect(pebPtr + 0xBC, 2, oldProtect, &oldProtect);
    }
    
    return true;
}

bool ProcessDisguise::DisguiseAsSystemProcess() {
    // 常见系统进程名
    const wchar_t* names[] = {
        L"C:\\Windows\\System32\\svchost.exe",
        L"C:\\Windows\\System32\\dllhost.exe",
        L"C:\\Windows\\System32\\rundll32.exe",
        L"C:\\Windows\\System32\\conhost.exe",
        L"C:\\Windows\\System32\\taskhostw.exe"
    };

    std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    const wchar_t* name = names[rng() % 5];

    return DisguiseProcessName(name);
}

// ============================================================
// CommunicationEvasion
// ============================================================

bool CommunicationEvasion::IsEACServiceRunning() {
    return GetEACServicePid() != 0;
}

DWORD CommunicationEvasion::GetEACServicePid() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    DWORD pid = 0;

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"EasyAntiCheat_EOS.exe") == 0 ||
                _wcsicmp(pe32.szExeFile, L"EasyAntiCheat.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return pid;
}

bool CommunicationEvasion::IsReporting() {
    // 检查 EAC 服务是否有活跃的网络连接上报数据
    // 通过检测 EAC 进程网络活动判断
    
    DWORD eacPid = GetEACServicePid();
    if (eacPid == 0) return false; // EAC 未运行, 不在上报
    
    // 简单启发式: 检查 EAC 进程是否有大量网络活动
    // 使用 GetProcessTimes 检查 IO 活动
    CLIENT_ID cidEac = { (HANDLE)(ULONG_PTR)eacPid, nullptr };
    OBJECT_ATTRIBUTES oaEac = { sizeof(oaEac) };
    HANDLE hEac = nullptr;
    SysOpenProcess(&hEac, PROCESS_QUERY_LIMITED_INFORMATION, &oaEac, &cidEac, SyscallMethod::Indirect);
    if (!hEac) return false;
    
    FILETIME create, exit, kernel, user;
    if (GetProcessTimes(hEac, &create, &exit, &kernel, &user)) {
        static ULONG64 lastKernel = 0;
        static DWORD lastCheck = 0;
        DWORD now = GetTickCount();
        
        ULONG64 currentKernel = ((ULONG64)kernel.dwHighDateTime << 32) | kernel.dwLowDateTime;
        
        if (lastKernel != 0 && lastCheck != 0 && now > lastCheck) {
            // EAC 进程在内核态有活跃活动 (包括网络IO)
            ULONG64 delta = currentKernel - lastKernel;
            // 如果内核时间增长超过阈值, 认为在活跃通信
            if (delta > 0) {
                CloseHandle(hEac);
                return true;
            }
        }
        
        lastKernel = currentKernel;
        lastCheck = now;
    }
    
    CloseHandle(hEac);
    return false;
}

bool CommunicationEvasion::HookReportingFilter() {
    // 注入到 EasyAntiCheat_EOS.exe 进程 Hook 网络发送
    // 此类注入需配合手动映射器实现, 运行时可选择性启用
    // 注意: 直接注入 EAC 进程风险极高 (反调试/反注入)
    return false; // 需显式注入能力, 默认不启用
}

} // namespace eac
} // namespace stealth
