#pragma once
// ============================================================
// byovd_kernel.h — BYOVD 内核级 EAC 防御模块
//
// 原理: 加载合法签名但有漏洞的内核驱动 (RTCore64.sys / gdrv.sys)
//       通过 IOCTL 获取内核内存任意读写能力 (Ring-0)
//       然后从内核层直接摘除 EAC 注册的 ObRegisterCallbacks
//       和 EPROCESS DKOM 隐藏进程
//
// 参考:
//   - ARES 2024: "Kernel Anti-Cheat Architecture" 
//   - "Fast and Furious" paper (RAID 2023)
//   - Lazarus FudModule BYOVD technique
//   - EDRSandBlast / kdmapper 开源实现
// ============================================================

#include <Windows.h>
#include <cstdint>
#include <string>
#include <functional>
#include <vector>
#include <memory>

namespace stealth {

// 前向声明 (实现在 byovd_kernel.cpp)
class PageTableWalker;

// ============================================================
// 内核偏移量 (Windows 10/11 22H2, 通过符号动态解析以兼容更多版本)
// 回退硬编码偏移供无符号环境使用
// ============================================================
struct KernelOffsets {
    // EPROCESS
    uint32_t ActiveProcessLinks;    // LIST_ENTRY offset in EPROCESS
    uint32_t UniqueProcessId;       // PID
    uint32_t ImageFileName;         // 进程名 [15 chars]

    // ntoskrnl 导出/符号
    uint64_t PsLoadedModuleList;    // 内核模块链表头 (nt!PsLoadedModuleList)
    uint64_t ObpCallbackArray;      // ObRegisterCallbacks 回调数组

    // PsSetCreateProcessNotifyRoutine 数组
    uint64_t PspCreateProcessNotifyRoutine;
    uint32_t PspCreateProcessNotifyRoutineCount;
    uint32_t PspCreateProcessNotifyRoutineSize;

    // PsSetLoadImageNotifyRoutine 数组
    uint64_t PspLoadImageNotifyRoutine;
    uint32_t PspLoadImageNotifyRoutineCount;
    uint32_t PspLoadImageNotifyRoutineSize;

    // PsSetCreateThreadNotifyRoutine 数组
    uint64_t PspCreateThreadNotifyRoutine;
    uint32_t PspCreateThreadNotifyRoutineCount;
    uint32_t PspCreateThreadNotifyRoutineSize;
};

// ============================================================
// BYOVD 驱动信息
// ============================================================
struct BYOVDDriverInfo {
    std::wstring serviceName;    // 注册表服务名
    std::wstring displayName;    // 显示名称
    std::wstring devicePath;     // 设备路径 (如 \\.\RTCore64)
    std::wstring driverPath;     // .sys 文件磁盘路径
    uint32_t    ioctlCode;       // 内核R/W用IOCTL
    bool        needsMemoryMap;  // 是否需要先映射物理内存
};

namespace BYOVDDrivers {
    // RTCore64.sys — MSI Afterburner (最常用)
    // 暴露: 任意物理/虚拟内存 R/W via IOCTL 0xC3502580 / 0xC3502588
    extern const BYOVDDriverInfo RTCore64;

    // gdrv.sys — Gigabyte (备选)
    // 暴露: 13 IOCTL, 包括内核 memcpy
    extern const BYOVDDriverInfo Gdrv;
}

// ============================================================
// 内核内存访问器 (通过漏洞驱动 IOCTL)
// ============================================================
class KernelMemoryAccessor {
public:
    static KernelMemoryAccessor& Instance();

    // 初始化: 加载漏洞驱动并建立 IOCTL 通道
    bool Initialize(const BYOVDDriverInfo& driver);

    // 清理: 卸载驱动
    void Shutdown();

    bool IsActive() const { return m_active; }

    // === 物理内存映射/读写原语 (通过 RTCore64 IOCTL) ===

    // 映射物理地址范围到用户态虚拟地址
    bool MapPhysical(uint64_t physAddr, uint32_t size, uint8_t** outVirtAddr);

    // 读取物理地址
    bool ReadPhysical(uint64_t physAddr, void* outBuf, size_t size);

    // 写入物理地址
    bool WritePhysical(uint64_t physAddr, const void* inBuf, size_t size);

    // === 内核内存读写原语 ===

    // 读取内核虚拟地址 (va: 内核空间地址)
    bool ReadKernelVA(uint64_t va, void* outBuf, size_t size);

    // 写入内核虚拟地址
    bool WriteKernelVA(uint64_t va, const void* inBuf, size_t size);

    // 模板化便捷方法
    template<typename T>
    T Read(uint64_t va) {
        T value{};
        ReadKernelVA(va, &value, sizeof(T));
        return value;
    }

    template<typename T>
    bool Write(uint64_t va, const T& value) {
        return WriteKernelVA(va, &value, sizeof(T));
    }

    // === 内核地址解析 ===

    // 获取 ntoskrnl.exe 基址
    uint64_t GetNtoskrnlBase();

    // 获取指定内核模块基址 (通过 PsLoadedModuleList 遍历)
    uint64_t GetKernelModuleBase(const std::string& moduleName);

    // 从内核模块基址 + 导出名解析函数地址
    uint64_t ResolveExport(uint64_t moduleBase, const char* funcName);

    // === 硬件断点 / 安全检测 ===

    // 检查 HVCI (Hypervisor Code Integrity) 是否启用
    // HVCI 启用时漏洞驱动可能被阻止加载
    static bool IsHVCIEnabled();

    // 检查内核地址是否有效 (避免访问无效内存导致BSOD)
    bool IsKernelAddressValid(uint64_t va);

    // 主动卸载已加载的 BYOVD 驱动
    void EjectLoadedDrivers();

private:
    KernelMemoryAccessor() = default;

    bool LoadDriver(const std::wstring& serviceName, const std::wstring& driverPath);
    bool UnloadDriver(const std::wstring& serviceName);
    bool EnablePrivilege(const wchar_t* privilegeName);

    HANDLE     m_hDevice    = INVALID_HANDLE_VALUE;
    bool       m_active     = false;
    uint64_t   m_ntosBase   = 0;
    BYOVDDriverInfo m_driverInfo;
    std::unique_ptr<PageTableWalker> m_pageTableWalker;
};

// ============================================================
// EAC 内核回调摘除器
// 
// EAC 注册 4 类内核回调:
//   1. ObRegisterCallbacks — 句柄访问监控 (最关键)
//   2. PsSetCreateProcessNotifyRoutine — 进程创建通知
//   3. PsSetLoadImageNotifyRoutine — 模块加载通知  
//   4. PsSetCreateThreadNotifyRoutine — 线程创建通知
//
// 本类使用 KernelMemoryAccessor 的内核R/W能力:
//   - 遍历各回调数组
//   - 找到 EAC 驱动注册的回调
//   - 将回调函数指针 NULL 化 → EAC 内核组件"失明"
// ============================================================
class EACCallbackDisabler {
public:
    static EACCallbackDisabler& Instance();

    // 尝试摘除所有 EAC 内核回调
    // 返回摘除成功的回调总数
    int DisableAll(const std::string& eacDriverName = "EasyAntiCheat");

    // 单独摘除 ObRegisterCallbacks
    int DisableObCallbacks(const std::string& eacDriverName);

    // 单独摘除进程通知回调
    int DisableProcessNotifyCallbacks(const std::string& eacDriverName);

    // 单独摘除模块加载通知回调
    int DisableImageNotifyCallbacks(const std::string& eacDriverName);

private:
    EACCallbackDisabler() = default;

    // 辅助: 判断函数地址是否在指定内核模块范围内
    bool IsAddressInModule(uint64_t addr, uint64_t moduleBase, uint32_t moduleSize);

    // Sigscan 定位 ObpCallbackArrayHead
    uint64_t FindObpCallbackArrayHead(KernelMemoryAccessor& kma);
};

// ============================================================
// DKOM 进程隐藏器
//
// 将我们的进程从 EPROCESS.ActiveProcessLinks 双向链表中摘除
// 效果: EAC 通过 NtQuerySystemInformation 枚举无法找到我们
//       进程继续正常执行 (调度器不依赖 ActiveProcessLinks)
// ============================================================
class DKOMProcessHider {
public:
    static DKOMProcessHider& Instance();

    // 隐藏当前进程
    // 副作用: Task Manager / Process Explorer 看不到我们
    bool HideProcess();

    // 取消隐藏 (重新插入 ActiveProcessLinks)
    bool UnhideProcess();

    // 获取当前 EPROCESS 地址 (调试用)
    uint64_t GetCurrentEPROCESS() const { return m_eprocess; }

private:
    DKOMProcessHider() = default;

    uint64_t m_eprocess     = 0;
    uint64_t m_flinkBackup  = 0;
    uint64_t m_blinkBackup  = 0;
    bool     m_hidden       = false;
};

// ============================================================
// 一体化内核防御管理器
// 串联: BYOVD加载 → 回调摘除 → DKOM进程隐藏
// ============================================================
class KernelDefense {
public:
    // 顺序执行所有内核防御
    // 返回各项防御的成功标志
    struct Result {
        bool driverLoaded  = false;
        int  obCallbacksRemoved = 0;
        int  processCallbacksRemoved = 0;
        int  imageCallbacksRemoved = 0;
        int  threadCallbacksRemoved = 0;
        bool processHidden = false;
    };

    static Result EnableAll();
    static void DisableAll();
};

} // namespace stealth
