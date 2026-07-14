#pragma once
// ============================================================
// stealth_process.h — 隐蔽进程操作
// 规避: 行为检测(句柄打开/内存写入/进程枚举/权限提升监控)
// ============================================================

#include <Windows.h>
#include <vector>
#include <string>
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
    static std::vector<ProcessInfo> EnumerateProcesses(const wchar_t* targetName);

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
        std::wstring name;
        uintptr_t    baseAddress;
        SIZE_T       size;
    };

    // 通过 NtQueryInformationProcess 获取进程模块列表
    // 规避: Module32First/Next 的监控
    static std::vector<ModuleInfo> GetProcessModules(HANDLE hProcess);

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
        HANDLE   m_process;
        uintptr_t m_addr;
        SIZE_T   m_size;
        std::vector<uint8_t> m_original;
        std::vector<uint8_t> m_modified;
        bool     m_committed = false;
    };

    // ---- 内存分配策略 ----
    // 规避: VirtualAllocEx 分配的 RWX 内存 (高熵区域 = 可疑特征)

    // 在已存在的合法内存区域中分配 (如目标进程的堆)
    static uintptr_t AllocateInExistingRegion(HANDLE hProcess, SIZE_T size);

    // 释放 AllocateInExistingRegion 分配的内存
    // v3.25: 补充 Free 接口防止内存泄漏
    static bool FreeInExistingRegion(HANDLE hProcess, uintptr_t addr, SIZE_T size);

    // 使用文件映射共享内存 (更难追踪)
    static uintptr_t AllocateViaSection(HANDLE hProcess, SIZE_T size);

    // 取消映射 AllocateViaSection 的远程视图
    // v3.25: 补充 Unmap 接口释放 Section 映射
    static bool UnmapSectionView(HANDLE hProcess, uintptr_t addr);

private:
    StealthMemory() = default;
};

} // namespace stealth
