#pragma once
// ============================================================
// stealth_process.h — 隐蔽进程操作
// 规避: 行为检测(句柄打开/内存写入/进程枚举/权限提升监控)
// ============================================================

#include <Windows.h>
#include <cstdint>

namespace stealth {

// ============================================================
// 隐蔽进程句柄管理
// 规避: OpenProcess 句柄打开监控
//       AdjustTokenPrivileges 权限提升监控
// ============================================================

class StealthProcess {
public:
    // ---- 进程发现 (替代 CreateToolhelp32Snapshot) ----
    // 使用 NtQuerySystemInformation 遍历进程
    // 规避: CreateToolhelp32Snapshot + Process32First/Next 组合特征
    struct ProcessInfo {
        DWORD   pid;
        WCHAR   name[MAX_PATH];
        HANDLE  handle; // 延迟获取
    };

    // 通过 SystemProcessInformation 枚举进程
    // 规避: 不走 CreateToolhelp32Snapshot 路径
    // 返回匹配的进程数, 0 表示未找到
    static int EnumerateProcesses(const wchar_t* targetName, ProcessInfo* outBuf, int maxResults);

    // 通过窗口名发现进程 (替代方案, 更隐蔽)
    // FindWindow + GetWindowThreadProcessId 调用量少
    static DWORD FindProcessByWindow(const wchar_t* className, const wchar_t* windowName);

    // ---- 句柄打开 (替代 OpenProcess) ----
    // 使用 NtOpenProcess 直接系统调用打开目标进程
    // 规避: OpenProcess 的 ObRegisterCallbacks 注册的句柄操作回调
    //       以及内核中的进程保护回调
    static HANDLE OpenProcessStealth(DWORD pid);

    // 使用弱权限打开句柄 (减少检测告警)
    // VM_READ 通常不会被标记为可疑
    static HANDLE OpenProcessMinimal(DWORD pid);

    // 句柄伪装: 从其他低风险进程复制句柄
    static HANDLE DuplicateHandleFromLowRisk(DWORD pid);

    // ---- 权限处理 ----
    // 检查是否已有 SeDebugPrivilege, 如无则静默获取
    // 规避: AdjustTokenPrivileges 频繁调用引起的告警
    //       优先尝试通过父进程继承或令牌复制
    static bool EnsureDebugPrivilegeSilent();

    // 使用带外方式提升权限 (不使用 AdjustTokenPrivileges)
    // 例如: 通过 WMI / COM 启动的子进程自动继承
    static bool BypassPrivilegeCheck();

    // ---- 模块信息 (替代 Module32First/Next) ----
    struct ModuleInfo {
        WCHAR      name[MAX_PATH];
        uintptr_t  baseAddress;
        SIZE_T     size;
    };

    // 通过 NtQueryInformationProcess 获取进程模块列表
    // 规避: Module32First/Next 的监控
    // 返回获取的模块数, 0 表示未找到
    static int GetProcessModules(HANDLE hProcess, ModuleInfo* outBuf, int maxResults);

    // 检查特定模块是否在目标进程中
    static bool IsModuleLoaded(HANDLE hProcess, const wchar_t* moduleName);

private:
    StealthProcess() = default;
};

// ============================================================
// 隐蔽内存操作
// 规避: WriteProcessMemory 内存写入监控
//       .text 段完整性校验
// ============================================================

class StealthMemory {
public:
    // ---- 安全内存读取 (替代 ReadProcessMemory) ----
    // 使用 NtReadVirtualMemory 直接系统调用
    static bool Read(HANDLE hProcess, uintptr_t addr, void* buffer, SIZE_T size);

    template<typename T>
    static T Read(HANDLE hProcess, uintptr_t addr) {
        T value{};
        Read(hProcess, addr, &value, sizeof(T));
        return value;
    }

    // ---- 安全内存写入 (替代 WriteProcessMemory) ----
    // 使用 NtWriteVirtualMemory 直接系统调用
    // 额外: 写入前先读取并备份原始值, 用于后续恢复
    static bool Write(HANDLE hProcess, uintptr_t addr, const void* buffer, SIZE_T size);

    template<typename T>
    static bool Write(HANDLE hProcess, uintptr_t addr, const T& value) {
        return Write(hProcess, addr, &value, sizeof(T));
    }

    // ---- 内存保护修改 (替代 VirtualProtectEx) ----
    static bool Protect(HANDLE hProcess, uintptr_t addr, SIZE_T size,
                        DWORD newProtect, DWORD* oldProtect);

    // ---- VAC 模块绕过 ----
    // VAC 会扫描目标进程内存中的修改
    // 对策: 在 VAC 扫描周期内暂时恢复原始值

    // 创建"影子页": 将修改写入另一个地址, 利用页表技巧
    // 简化版: 使用 VEH (Vectored Exception Handler) 捕获对特定页的访问
    static bool SetupShadowPage(HANDLE hProcess, uintptr_t targetAddr, SIZE_T size);

    // 在 VAC 扫描时快速恢复原始值
    class TransactionalWrite {
    public:
        TransactionalWrite(HANDLE hProcess, uintptr_t addr, SIZE_T size);
        ~TransactionalWrite();

        bool Commit();                     // 确认写入
        bool Rollback();                   // 恢复原始值
        bool IsVACScanning();              // 检测 VAC 是否正在扫描

    private:
        HANDLE    m_process;
        uintptr_t m_addr;
        SIZE_T    m_size;
        uint8_t   m_original[4096];
        uint8_t   m_modified[4096];
        bool      m_committed = false;
    };

    // ---- 内存分配策略 ----
    // 实际的跨进程注入使用 PhantomSection::AllocatePhantomInProcess
    // (memory_cloak.cpp), 通过 Section 映射 + TxF 实现痕迹清除
    // 不直接使用本类的分配接口

private:
    StealthMemory() = default;
};

// ============================================================
// ★ BUILD 549: ShadowPageManager — 影子页管理器
//   通过 PTE manipulation 实现 CS2 client.dll .text 段影子页
//
//   工作原理:
//   - pageA = client.dll 原页 (PAC 扫描看到原始字节 32 c0)
//   - pageB = VirtualAlloc 锁定页 (复制原内容 + 改 90 90)
//   - 修改 client.dll 补丁页 PTE.PFN 指向 pageB → CS2 执行补丁代码
//   - 周期性切回 pageA 50ms → PAC 扫描命中原始字节
//
//   关键依赖:
//   - KernelMemoryAccessor::VerifyPteSelfMap (PML4 自引用索引检测)
//   - KernelMemoryAccessor::ReadPte/WritePte (PTE 读写)
//   - KernelMemoryAccessor::AllocContiguousPhysical (pageB 分配)
//
//   失败回退:
//   - Install 失败 → ApplyCs2Patch 回退到 VirtualProtect 路径
//   - 周期性切换由 payload.cpp 主循环驱动 (MaintainCs2Patch)
// ============================================================
class ShadowPageManager {
public:
    static ShadowPageManager& Instance();

    // 安装影子页 (在 ApplyCs2Patch 中, 找到补丁地址后调用)
    //   hCs2: CS2 进程句柄 (当前未直接使用, 保留接口)
    //   patchAddr: 补丁虚拟地址 (client.dll 内, 必须页对齐到 4KB)
    //   返回: true=影子页安装成功, false=回退到 VirtualProtect 路径
    bool Install(HANDLE hCs2, uintptr_t patchAddr);

    // 切换到原始页 (pageA) — PAC 扫描窗口
    //   调用后 Sleep(50) 等待 TLB 刷新 (用户态页 G=0, context switch 自动刷新)
    void RevealOriginal();

    // 切换到补丁页 (pageB) — CS2 执行补丁代码
    //   调用后 Sleep(50) 等待 TLB 刷新
    void ReapplyPatch();

    // 卸载影子页 (恢复原 PTE, 释放 pageB)
    //   CS2 退出或 loader2 退出前必须调用
    void Uninstall();

    bool IsInstalled() const { return m_installed; }

private:
    ShadowPageManager() = default;

    bool      m_installed = false;
    uintptr_t m_patchAddr = 0;       // 补丁虚拟地址 (CS2 进程内)
    uint64_t  m_origPteValue = 0;    // 原 PTE 值 (指向 pageA, client.dll 原页)
    uint64_t  m_patchPteValue = 0;   // 补丁 PTE 值 (指向 pageB, 锁定页)
    uint64_t  m_pageBPhys = 0;       // pageB 物理地址
    uint64_t  m_pageBVA = 0;         // pageB 用户态虚拟地址 (用于读写内容和释放)
    HANDLE    m_hCs2 = nullptr;
};

} // namespace stealth