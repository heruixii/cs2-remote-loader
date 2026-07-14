#pragma once
// ============================================================
// eac_bypass.h — Easy Anti-Cheat 专用规避模块 (2026版)
//
// EAC 架构: 内核驱动(EasyAntiCheat.sys) + 用户态服务(EasyAntiCheat_EOS.exe) + 游戏注入DLL(EasyAntiCheat.dll)
//
// 核心检测机制 (来自 EAC 逆向分析, SigPwny 2026):
//   1. ObRegisterCallbacks — 句柄打开拦截, 剔除 PROCESS_VM_READ/WRITE/CREATE_THREAD
//   2. 内存完整性 — 驱动复制到 NonPagedPool, 每 10-40s 全量比较游戏内存
//   3. PE 头扫描 — 搜索 MZ/PE 签名 + FF 25 import stub 模式
//   4. RtlVirtualUnwind — 检查 32 帧调用栈, 标记不在合法模块内的返回地址
//   5. SSDT 完整性 — 验证系统服务调度表未被 Hook
//   6. 驱动池扫描 — 关键内核驱动自检
//
// 本模块技术 (纯用户态):
//   A. 多路径句柄获取 — 6种策略绕过 Handle Stripping
//   B. EAC 扫描周期预测 — 基于驱动线程CPU时间的行为分析
//   C. PE 头剥离 — Manual Map后擦除 MZ/PE + FF 25 替换
//   D. 深度调用栈伪造 — 32帧完整合法链构造
//   E. EAC 进程伪装 — 外部渲染器伪装为系统进程
//   F. EAC 通信规避 — 网络特征混淆
// ============================================================

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace stealth {
namespace eac {

// ============================================================
// 1. Handle Stripping 深度规避 — 6 种句柄获取策略
//
// EAC 在 ObRegisterCallbacks 的 PreOperation 中:
//   1. 检查调用者进程 (是否为已知外挂进程)
//   2. 剔除 PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
//   3. 检查调用者线程栈 (IsCallerSuspicious)
//
// 6 种策略按隐蔽性从高到低排序:
// ============================================================

class HandleBypass {
public:
    enum class Strategy {
        ThreadHandleEscalation,   // 策略1: 线程句柄→进程句柄权限升级
        ExistingHandleSteal,      // 策略2: 窃取系统中已有的高权限句柄
        TrustedProcessPivot,      // 策略3: 受信进程(explorer/csrss)中转复制
        SectionObjectAccess,      // 策略4: Section 对象映射绕过句柄
        DirectKernelRead,         // 策略5: 物理内存直接读取(需驱动)
        MinimalAccessRetry        // 策略6: 最小权限渐进式升级
    };

    // ---- 策略1: 线程句柄权限升级 ----
    // 原理: EAC 对线程句柄的监控弱于进程句柄
    // 步骤: OpenThread → NtDuplicateObject (复制到进程句柄) → 获得完整权限
    static HANDLE ViaThreadHandleEscalation(DWORD pid);

    // ---- 策略2: 窃取已有高权限句柄 ----
    // 原理: 枚举 SystemHandleInformation, 找到系统中已有目标进程的高权限句柄,
    //       通过 DuplicateHandle 复制到当前进程
    // 优势: 不触发 ObRegisterCallbacks (句柄已存在, 非新建)
    static HANDLE ViaExistingHandle(DWORD pid);

    // ---- 策略3: 受信进程中转 ----
    // 原理: csrss.exe 或 services.exe 有 SeDebugPrivilege,
    //       通过 OpenProcessToken → DuplicateTokenEx → ImpersonateLoggedOnUser
    //       获得 SYSTEM 权限的句柄访问
    static HANDLE ViaTrustedPivot(DWORD pid);

    // ---- 策略4: Section 对象映射 ----
    // 原理: 创建 Section 对象并映射到游戏进程,
    //       通过 section 读写绕过进程句柄权限检查
    static HANDLE ViaSectionMapping(DWORD pid);

    // ---- 策略6: 最小权限渐进升级 ----
    // 原理: 先用 PROCESS_QUERY_LIMITED_INFORMATION 打开(不触发EAC),
    //       再用 NtDuplicateObject 逐步升级权限
    static HANDLE ViaMinimalUpgrade(DWORD pid);

    // ---- 自动选择最佳策略 ----
    static HANDLE OpenProcessEAC(DWORD pid);

private:
    HandleBypass() = default;

    // 通过 NtQuerySystemInformation(SystemHandleInformation) 查找句柄
    struct ExistingHandle {
        HANDLE handleValue;
        DWORD  ownerPid;
        DWORD  targetPid;
        ACCESS_MASK grantedAccess;
        WORD   objectTypeIndex;
    };
    static std::vector<ExistingHandle> EnumerateHandles(DWORD targetPid);

    // 检查句柄是否有足够权限
    static bool HasSufficientAccess(ACCESS_MASK access);
};

// ============================================================
// 2. EAC 扫描周期预测
//
// EAC 驱动(EasyAntiCheat.sys) 的核心检测循环:
//   - 在 DriverEntry 中分配 NonPagedPool 缓冲区
//   - 复制 .text 段到池内存作为"黄金副本"
//   - 创建系统线程, 每 10-40 秒全量比较游戏进程内存
//   - 检测到差异 → 标记为可疑 → 上报 EAC 云
//
// 预测原理:
//   - EAC 驱动线程有规律性的 CPU 时间峰值
//   - 通过 NtQuerySystemInformation(SystemProcessInformation)
//     监控 System 进程(内核线程宿主)的 CPU 时间增量
//   - 检测到扫描脉冲后, 在脉冲间执行内存操作
// ============================================================

class EACScanPredictor {
public:
    struct ScanTiming {
        DWORD scanIntervalMs;     // 扫描间隔 (10000-40000ms)
        DWORD scanDurationMs;     // 扫描持续时间 (50-200ms)
        DWORD nextScanEstimate;   // 下次扫描预计时间 (GetTickCount)
        DWORD lastScanAt;         // 上次扫描实际时间
        int   cycleCount;         // 已检测的扫描周期数
    };

    static EACScanPredictor& Instance();

    // 开始监控 EAC 驱动活动 (需要游戏进程已运行)
    bool StartMonitoring(DWORD gamePid);

    // ★ 修复 H4: 停止监控并释放缓存的 System 进程句柄
    void StopMonitoring();

    // 检测当前是否在 EAC 扫描窗口中
    bool IsScanning();

    // 获取下一个安全操作窗口的时间
    // 返回距离下次扫描的毫秒数 (0 = 不确定, 请等待)
    DWORD GetSafeWindowMs();

    // 在安全窗口内执行操作
    // 自动等待直到扫描结束, 在安全窗口执行回调, 返回是否成功
    bool ExecuteInSafeWindow(std::function<void()> operation, DWORD timeoutMs = 5000);

    const ScanTiming& GetTiming() const { return m_timing; }

private:
    EACScanPredictor() = default;

    // 通过 System 进程的内核时间检测扫描脉冲
    bool DetectScanPulse();

    ScanTiming m_timing = {};
    DWORD m_gamePid = 0;
    bool m_monitoring = false;
    ULONG64 m_lastKernelTime = 0;
    ULONG64 m_lastUserTime = 0;
    DWORD m_consecutivePulses = 0;
    std::vector<DWORD> m_scanIntervals; // 记录扫描间隔用于预测
};

// ============================================================
// 3. PE 头/FF 25 Stub 擦除
//
// EAC 扫描游戏进程内存中的:
//   - MZ 魔数 (4D 5A) + PE 签名 (50 45 00 00)
//   - FF 25 模式 (jmp [IAT]) — 编译器生成的导入表 thunk
//   - Rich Header 编译器指纹
//   - PDB 路径字符串
//
// 规避: Manual Map 后擦除所有 PE 痕迹, 替换 FF 25 为等价指令
// ============================================================

class PEHeaderStripper {
public:
    // 擦除已加载的 PE 头 (MZ/PE/Rich Header/e_lfanew)
    // 在 Manual Map 完成后调用, 使内存扫描找不到 PE 证据
    static bool StripLoadedHeaders(uintptr_t imageBase);

    // 替换 FF 25 import thunk 为等价的间接调用
    // FF 25 XX XX XX XX → 48 B8 [addr]; FF E0 (mov rax, addr; jmp rax)
    static bool ReplaceFF25Stubs(uintptr_t imageBase);

    // 清除 DOS stub (MZ 和 Rich Header 之间的内容)
    static bool ClearDosStub(uintptr_t imageBase);

    // 清除区段名 (.text/.data 等)
    static bool ScrubSectionNames(uintptr_t imageBase);

    // 随机化区段特征位 (IMAGE_SCN_MEM_*)
    static bool RandomizeSectionFlags(uintptr_t imageBase);

private:
    PEHeaderStripper() = default;
};

// ============================================================
// 4. 深度调用栈伪造 — 32 帧完整合法链
//
// EAC 通过 RtlVirtualUnwind 回溯调用栈 32 帧:
//   1. 暂停目标线程
//   2. 遍历 RUNTIME_FUNCTION 条目
//   3. 验证每个返回地址是否在合法模块内
//   4. 验证 unwind 操作码序列是否合理
//
// 规避: 构造 32 帧完整调用链, 每帧指向不同合法模块中的函数
// ============================================================

class DeepStackSpoofer {
public:
    struct StackFrame {
        uintptr_t returnAddress;   // 伪造的返回地址 (合法模块内)
        uintptr_t framePointer;    // 伪造的帧指针
        SIZE_T    frameSize;       // 帧大小
        const char* moduleName;    // 来源模块名 (调试用)
    };

    static DeepStackSpoofer& Instance();

    // 预生成 32 帧调用链 (扫描 kernel32/ntdll/user32/gdi32 等模块)
    bool GenerateFrameChain();

    // 获取伪造的调用链 (32帧)
    const std::vector<StackFrame>& GetChain() const { return m_chain; }

    // 将伪造调用链写入栈 (在 syscall 前调用)
    // 返回需要修正的 RSP 值
    uintptr_t ApplyToStack(void* originalStack, SIZE_T stackSize);

    // 获取一个随机合法帧 (短链, 3-5帧)
    std::vector<StackFrame> GetShortChain(int frameCount);

private:
    DeepStackSpoofer() = default;

    // 在指定模块中扫描合法函数地址
    std::vector<uintptr_t> ScanModuleFunctions(HMODULE hModule, int maxFunctions);

    // 验证地址是否在模块的 .pdata 中有合法 RUNTIME_FUNCTION 条目
    bool HasValidUnwindInfo(uintptr_t addr);

    std::vector<StackFrame> m_chain;
    bool m_initialized = false;
};

// ============================================================
// 5. EAC 进程伪装 — 外部渲染器伪装
//
// EAC 检测外部 overlay 窗口:
//   - WS_EX_LAYERED + WS_EX_TRANSPARENT + WS_EX_TOPMOST 组合
//   - 窗口类名包含 "overlay"/"cheat"/"hack"
//   - 进程名不在白名单中
//
// 规避:
//   - 窗口伪装 (随机 WS_EX_* 组合)
//   - 进程名伪装 (SetProcessImageName 或父进程继承)
//   - 数字签名伪装
// ============================================================

class ProcessDisguise {
public:
    // 伪装进程名 (通过修改 PEB 中的 ImagePathName)
    static bool DisguiseProcessName(const wchar_t* fakeName);

    // 伪装窗口属性
    // 修改窗口的扩展样式, 使其看起来像普通窗口
    static bool DisguiseOverlayWindow(HWND hwnd);

    // 伪装父进程 (修改 PEB 中的 InheritedFromUniqueProcessId)
    static bool DisguiseParentProcess(DWORD fakeParentPid);

    // 清除数字签名痕迹
    // (EAC 检查进程是否有合法签名)
    static bool StripDigitalSignature();

    // 将当前进程伪装为常见的 Windows 系统进程名
    static bool DisguiseAsSystemProcess();

private:
    ProcessDisguise() = default;
};

// ============================================================
// 6. EAC 通信规避
//
// EAC 用户态服务 (EasyAntiCheat_EOS.exe) 向 EAC 云服务器:
//   1. 发送检测报告
//   2. 接收新的扫描签名
//   3. 发送遥测数据
//
// 规避:
//   - 不阻止通信 (会触发心跳超时检测)
//   - 过滤上报数据内容
//   - 延迟/混淆敏感信息
// ============================================================

class CommunicationEvasion {
public:
    // 检查 EAC 服务是否在运行
    static bool IsEACServiceRunning();

    // 获取 EAC 服务的 PID
    static DWORD GetEACServicePid();

    // 检查 EAC 是否正在上报 (通过监控网络活动)
    static bool IsReporting();

    // (高级) 通过 API hook 过滤上报数据中的敏感信息
    // 需要注入到 EasyAntiCheat_EOS.exe 进程
    static bool HookReportingFilter();

private:
    CommunicationEvasion() = default;
};

} // namespace eac
} // namespace stealth
