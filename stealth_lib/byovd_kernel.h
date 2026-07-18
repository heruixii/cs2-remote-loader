#pragma once
// ============================================================
// byovd_kernel.h — BYOVD 内核级反作弊防御模块
//
// 原理: 加载合法签名但有漏洞的内核驱动 (RTCore64.sys / gdrv.sys)
//       通过 IOCTL 获取内核内存任意读写能力 (Ring-0)
//       然后从内核层直接摘除 PAC 注册的 ObRegisterCallbacks
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
// ★ BUILD 496: 移除 <string> <functional> <vector> <memory> — CRT 堆未初始化

namespace stealth {

// ============================================================
// v3.69: 受保护用户态内存区域 — 防止 RTCore64 IOCTL
//        物理内存映射覆盖 DLL 代码页导致 STATUS_PRIVILEGED_INSTRUCTION
//
//        注意: 所有访问均在单线程 (CheatMainLoop) 中完成,
//        无需同步原语。
// ============================================================
struct ProtectedUserRegion {
    uintptr_t base;
    SIZE_T    size;
};
// ★ v3.117: 固定数组, 避免 std::vector CRT 堆依赖
static constexpr size_t MAX_PROTECTED_REGIONS = 32;
extern ProtectedUserRegion g_protectedUserRegions[MAX_PROTECTED_REGIONS];
extern int g_protectedRegionCount;

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
    wchar_t    serviceName[128];  // ★ BUILD 496: 固定数组替代 std::wstring
    wchar_t    displayName[128];
    wchar_t    devicePath[128];   // 设备路径 (如 \\.\RTCore64)
    wchar_t    driverPath[260];   // .sys 文件磁盘路径
    uint32_t   ioctlCode;        // 内核R/W用IOCTL
    bool       needsMemoryMap;   // 是否需要先映射物理内存
};

namespace BYOVDDrivers {
    // RTCore64.sys — MSI Afterburner (嵌入驱动)
    // 暴露: 任意物理/虚拟内存 R/W via IOCTL 0x80002048/0x4C
    // 注意: Win11 2026 可能因证书吊销阻止加载
    extern const BYOVDDriverInfo RTCore64;

    // ★ BUILD 489: PDFWKRNL.sys — AMD PDF Worker (替代驱动)
    // 暴露: 内核VA memcpy R/W via IOCTL 0x80002014 (METHOD_BUFFERED)
    // 优势: 2026年未被 Microsoft 漏洞驱动阻止列表拦截
    extern const BYOVDDriverInfo PDFWKRNL;

    // 获取所有可用驱动候选列表 (已排优先级)
    const BYOVDDriverInfo* GetAllCandidates();
    int GetCandidateCount();
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

    // v3.49: 获取服务名和驱动路径 (用于一用即卸清理)
    const wchar_t* GetServiceName() const { return m_actualServiceName; }
    const wchar_t* GetDriverPath() const { return m_driverInfo.driverPath; }

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

    // === ★ BUILD 549: PTE Manipulation API (Shadow Page) ===
    //   通过 PTE 自映射 (PML4 自引用索引 0x1ED, PTE_BASE=0xFFFFF68000000000)
    //   实现影子页切换 — CS2 执行补丁字节 (pageB), PAC 扫描看到原始字节 (pageA)
    //
    //   PTE 虚拟地址计算公式: PTE_BASE + ((va >> 12) << 3)
    //   PTE 结构: bit 0=P, 1=RW, 2=U/S, 5=A, 6=D, 7=PS, 8=G, 12-51=PFN, 63=NX

    // 读取任意 VA 的 PTE (8 bytes)
    //   成功返回 PTE 虚拟地址, 失败返回 0
    uint64_t ReadPte(uint64_t va, uint64_t* outPteValue);

    // 写入 PTE (修改 PFN 实现页切换)
    //   成功返回 true, 失败返回 false
    bool WritePte(uint64_t va, uint64_t newPteValue);

    // 验证 PTE 自映射可用性 (检测 PML4 自引用索引)
    //   原理: 读取 CR3 → PML4 物理基址, 检查 PML4E[0x1ED] 的 PFN 是否等于 PML4 基址 (自引用特征)
    //   失败尝试备选索引: 0x1E8, 0x1F0, 0x1F8
    //   成功后缓存有效索引到 m_pml4SelfRefIndex
    bool VerifyPteSelfMap();

    // 内核分配连续物理页 (用于 pageB)
    //   实现方式: 通过 PTE 自映射读取一个空闲 PfnDatabase 条目, 标记为 Active
    //   简化实现: 调用 NtAllocateContiguousMemory (需通过内核 R/W 修改系统进程页表)
    //   返回物理地址, 0 表示失败
    //   ★ 当前实现采用最简方案: 复用一个已分配但未使用的物理页 (从非分页池分配后获取其物理地址)
    uint64_t AllocContiguousPhysical(size_t size);

    // 内核释放连续物理页
    bool FreeContiguousPhysical(uint64_t physAddr);

    // 物理地址 → 内核虚拟地址映射 (用于读写页内容)
    //   实现方式: 通过 PTE 自映射查找/创建一个映射该物理地址的内核 PTE
    //   简化实现: 利用 MmMapIoSpace 内核导出 (通过内核 R/W 调用)
    //   ★ 当前实现采用 PTE 自映射方案: 修改一个系统 PTE 指向目标物理页
    uint64_t MapPhysicalToKernelVA(uint64_t physAddr, size_t size);

    // 获取当前 PML4 自引用索引 (VerifyPteSelfMap 成功后有效)
    uint32_t GetPml4SelfRefIndex() const { return m_pml4SelfRefIndex; }

    // === 内核地址解析 ===

    // 获取 ntoskrnl.exe 基址
    uint64_t GetNtoskrnlBase();

    // 获取指定内核模块基址 (通过 PsLoadedModuleList 遍历)
    // ★ BUILD 496: 仅保留 const char* 重载, 移除 std::string 版本
    uint64_t GetKernelModuleBase(const char* moduleName);

    // 从内核模块基址 + 导出名解析函数地址
    uint64_t ResolveExport(uint64_t moduleBase, const char* funcName);

    // === 硬件断点 / 安全检测 ===

    // 检查 HVCI (Hypervisor Code Integrity) 是否启用
    // HVCI 启用时漏洞驱动可能被阻止加载
    static bool IsHVCIEnabled();

    // 检查内核地址是否有效 (避免访问无效内存导致BSOD)
    bool IsKernelAddressValid(uint64_t va);

    // ★ v3.69: 注册需要保护的 DLL 代码区域 (防止 IOCTL 映射覆盖)
    static void RegisterCodeRegion(void* base, SIZE_T size);
    // 检查给定 VA 范围是否与受保护区域重叠
    static bool IsOverlappingProtectedRegion(uintptr_t va, SIZE_T size);

private:
    KernelMemoryAccessor() = default;

    bool LoadDriver(const wchar_t* serviceName, const wchar_t* driverPath);
    bool UnloadDriver(const wchar_t* serviceName);
    bool EnablePrivilege(const wchar_t* privilegeName);

    HANDLE     m_hDevice    = INVALID_HANDLE_VALUE;
    bool       m_active     = false;
    uint64_t   m_ntosBase   = 0;
    BYOVDDriverInfo m_driverInfo;
    // ★ BUILD 496: 固定数组替代 std::wstring
    wchar_t    m_actualServiceName[128] = {};  // v3.60: 实际使用的服务名 (可能含随机后缀)
    // ★ BUILD 496: 移除 std::unique_ptr<PageTableWalker> — CRT 堆依赖
    // PageTableWalker 已不再使用 (v3.84: IOCTL 扫描 PML4)

    // ★ BUILD 549: PTE 自映射状态
    //   0 = 未验证, 非 0 = 已验证的 PML4 自引用索引 (Win10 1709+ 通常为 0x1ED)
    uint32_t   m_pml4SelfRefIndex = 0;
    // ★ BUILD 549: pageB 内核虚拟地址缓存 (复用映射, 避免重复 PTE 操作)
    uint64_t   m_shadowPageBKernelVA = 0;
    uint64_t   m_shadowPageBPhys     = 0;

    // ★ v3.84: ReadCR3 需要通过 IOCTL 扫描 PML4, 需要访问 device handle
    friend uint64_t ReadCR3();
};

// ============================================================
// 内核回调摘除器
// 
// PAC 注册多类内核回调:
//   1. ObRegisterCallbacks — 句柄访问监控 (最关键)
//   2. PsSetCreateProcessNotifyRoutine — 进程创建通知
//   3. PsSetLoadImageNotifyRoutine — 模块加载通知
//   4. PsSetCreateThreadNotifyRoutine — 线程创建通知 (可选)
//
// 本类使用 KernelMemoryAccessor 的内核R/W能力:
//   - 遍历各回调数组
//   - 找到反作弊驱动注册的回调
//   - 将回调函数指针 NULL 化 → 反作弊内核组件"失明"
// ============================================================
class EACCallbackDisabler {
public:
    static EACCallbackDisabler& Instance();

    // 尝试摘除所有内核回调
    // 返回摘除成功的回调总数
    // ★ BUILD 497: 签名统一为 const char* — 避免 std::string CRT 堆依赖
    int DisableAll(const char* acDriverName = "EasyAntiCheat");

    // ★ v3.110: 恢复所有已保存的回调 (临时移除后恢复)
    int RestoreAll();

    // 单独摘除 ObRegisterCallbacks
    // ★ BUILD 497: 签名统一为 const char* — 避免 std::string CRT 堆依赖
    int DisableObCallbacks(const char* eacDriverName = "EasyAntiCheat");

    // 单独摘除进程通知回调
    int DisableProcessNotifyCallbacks(const char* eacDriverName = "EasyAntiCheat");

    // 单独摘除模块加载通知回调
    int DisableImageNotifyCallbacks(const char* eacDriverName = "EasyAntiCheat");

    // ★ v3.110: 检查是否已摘除回调 (用于判断是否需要恢复)
    bool HasRemovedCallbacks() const { return m_obCallbacksSaved || m_processCallbacksSaved || m_imageCallbacksSaved; }

    // ★ BUILD 528: E+G — 重新移除 PAC ObCallbacks (内部处理名称解析)
    //   供 payload.cpp 主循环周期性调用, 对抗 PAC 重新注册回调.
    //   内部调用 GetPacTargetName() + WStringToString() + DisableObCallbacks().
    //   返回本次重新移除的回调数 (0 表示无需移除或移除失败).
    int ReDisablePacCallbacks();

private:
    EACCallbackDisabler() = default;

    // 辅助: 判断函数地址是否在指定内核模块范围内
    bool IsAddressInModule(uint64_t addr, uint64_t moduleBase, uint32_t moduleSize);

    // Sigscan 定位 ObpCallbackArrayHead
    uint64_t FindObpCallbackArrayHead(KernelMemoryAccessor& kma);

    // ★ v3.119: 固定数组, 避免 std::vector CRT 堆依赖
    static constexpr size_t MAX_SAVED_OB_CALLBACKS = 64;
    static constexpr size_t MAX_SAVED_ARRAY_CALLBACKS = 64;

    struct SavedObEntry {
        uint64_t address; // 回调条目地址
        uint64_t preOp;   // 原始 PreOperation
        uint64_t postOp;  // 原始 PostOperation
    };
    SavedObEntry m_savedObCallbacks[MAX_SAVED_OB_CALLBACKS];
    int m_savedObCallbackCount = 0;

    struct SavedArrayEntry {
        uint64_t address; // 回调数组条目地址
        uint64_t originalValue; // 原始值 (含 EX_FAST_REF)
    };
    SavedArrayEntry m_savedProcessCallbacks[MAX_SAVED_ARRAY_CALLBACKS];
    int m_savedProcessCallbackCount = 0;
    SavedArrayEntry m_savedImageCallbacks[MAX_SAVED_ARRAY_CALLBACKS];
    int m_savedImageCallbackCount = 0;

    bool m_obCallbacksSaved = false;
    bool m_processCallbacksSaved = false;
    bool m_imageCallbacksSaved = false;
};

// ============================================================
// DKOM 进程隐藏器
//
// 将我们的进程从 EPROCESS.ActiveProcessLinks 双向链表中摘除
// 效果: 反作弊通过 NtQuerySystemInformation 枚举无法找到我们
//       进程继续正常执行 (调度器不依赖 ActiveProcessLinks)
//
// ★ BUILD 544: 多 PID 支持 — 同时隐藏 loader2.exe (当前进程) + basic.exe (子进程)
//   固定数组 m_hiddenList[4] 替代单一状态字段, 避免 std::vector CRT 堆依赖
// ============================================================
class DKOMProcessHider {
public:
    static DKOMProcessHider& Instance();

    // === 向后兼容 API (转发到多 PID 实现) ===
    // 隐藏当前进程 — 转发到 HideProcessByPid(GetCurrentProcessId())
    // 副作用: Task Manager / Process Explorer 看不到我们
    bool HideProcess();

    // 取消隐藏当前进程 — 转发到 UnhideProcessByPid(GetCurrentProcessId())
    bool UnhideProcess();

    // === BUILD 544: 多 PID API ===
    // 隐藏指定 PID 的进程 (用于 basic.exe)
    // ★ 对非当前进程启用自循环加固 (basic.exe 被 TerminateProcess 时
    //   PspExitProcess → RemoveEntryList 检查 current->Blink->Flink==&current 通过)
    bool HideProcessByPid(DWORD pid);

    // 取消隐藏指定 PID 的进程
    bool UnhideProcessByPid(DWORD pid);

    // 取消隐藏所有已隐藏进程 — 进程退出前必须调用 (防 0x139 蓝屏)
    void UnhideAll();

    // 获取当前进程 (loader2.exe) 的 EPROCESS — 向后兼容
    uint64_t GetCurrentEPROCESS() const;

private:
    DKOMProcessHider() = default;

    // 隐藏条目 (固定数组, 不使用 std::vector — manual-mapped DLL CRT 堆未初始化)
    struct HiddenEntry {
        uint64_t eprocess;      // 0 = 空槽
        uint64_t flinkBackup;   // 原 next (用于 Unhide 时检查链表完整性)
        uint64_t blinkBackup;   // 原 prev
        DWORD    pid;
        bool     hidden;
    };

    static constexpr size_t MAX_HIDDEN = 4;  // loader2 + basic + 2 余量
    HiddenEntry m_hiddenList[MAX_HIDDEN] = {};

    // 动态 EPROCESS 偏移 (运行时扫描缓存, 全部 PID 共享)
    // ★ BUILD 537: Win11 24H2 (Build 26100) 偏移与 23H2 完全不同 — 必须运行时扫描
    uint32_t m_pidOffset   = 0;   // UniqueProcessId 偏移 (Win10/11 23H2 = 0x440, Win11 24H2 = 0x1D0)
    uint32_t m_linksOffset = 0;   // ActiveProcessLinks 偏移 (Win10/11 23H2 = 0x448, Win11 24H2 = 0x1D8)

    // === 辅助方法 (private) ===
    // 解析 EPROCESS 偏移 (扫描 System EPROCESS PID=4, 0x100-0x800 范围)
    bool EnsureOffsetsResolved(KernelMemoryAccessor& kma, uint64_t ntBase);
    // 通过 PID 查找 EPROCESS (从 PsInitialSystemProcess 遍历 ActiveProcessLinks)
    uint64_t FindEPROCESSByPid(KernelMemoryAccessor& kma, DWORD pid);
    // 在 m_hiddenList 中查找已存在的条目, 没有则分配空槽
    HiddenEntry* FindOrAllocSlot(DWORD pid);
    // 执行 DKOM 断链 (先 next.Blink 后 prev.Flink — 失败安全)
    bool PerformUnlink(KernelMemoryAccessor& kma, HiddenEntry* entry, DWORD pid, uint64_t eproc);
    // 自循环加固 (写 current.Flink=&current, current.Blink=&current)
    // 防止非当前进程被外部 TerminateProcess 时 RemoveEntryList 检查失败 → 0x139
    bool SelfLoopHarden(KernelMemoryAccessor& kma, HiddenEntry* entry);
};

// ============================================================
// 一体化内核防御管理器
// 串联: BYOVD加载 → 回调摘除 → DKOM进程隐藏
// ============================================================
class KernelDefense {
public:
    // ★ BUILD 503: PAC 三态结果 — 区分"未安装"与"已中立化"
    enum class PacStatus {
        NotInstalled = 0,  // PAC 驱动未加载, 无需/无法中立化
        Neutralized  = 1,  // PAC 已成功中立化
        Failed       = 2,  // 中立化尝试失败, PAC 仍活跃
    };

    // 顺序执行所有内核防御
    // 返回各项防御的成功标志
    struct Result {
        bool driverLoaded  = false;
        int  obCallbacksRemoved = 0;
        int  processCallbacksRemoved = 0;
        int  imageCallbacksRemoved = 0;
        int  threadCallbacksRemoved = 0;
        bool processHidden = false;
        PacStatus pacStatus = PacStatus::NotInstalled;  // ★ BUILD 503: PAC 三态
    };

    static Result EnableAll();
    static void DisableAll();

    // ★ v3.126j: PAC minifilter 禁用 (停止服务 + 卸载过滤器 + 删除驱动文件)
    // ★ BUILD 503: 返回 PacStatus 三态 — NotInstalled/Neutralized/Failed
    static PacStatus DisablePac();
    // ★ v3.126j: PAC 周期性守卫 — 检查 PAC 是否被重新安装/启动并重新禁用
    static void GuardPac();

    // ★ v3.110: 临时恢复反作弊回调
    static void RestoreAllCallbacks();

    // ★ v3.110: 重新摘除反作弊回调 (恢复后重新摘除)
    static void ReapplyAllCallbacks();
};

// ============================================================
// v3.34: VAD 节点伪装器
//
// 通过 BYOVD 内核 R/W 修改 cs2.exe 的 VAD 树,
// 将注入区域的 MEM_PRIVATE 标记改为 MEM_MAPPED,
// 使其看起来像正常模块映射, 绕过反作弊 VAD 扫描
// ============================================================
class VADConcealer {
public:
    // 伪装指定进程中的内存区域
    // pid: 目标进程 PID (cs2.exe)
    // regionBase: 注入区域的基址
    // regionSize: 注入区域大小
    static bool ConcealRegion(DWORD pid, uintptr_t regionBase, SIZE_T regionSize);

    // 批量伪装 (对 cleanedBases 中的所有区域)
    static int ConcealAllRegions(DWORD pid, const uintptr_t* bases, int count);
};

// ============================================================
// ★ v3.126m: Kernel Trace Cleaner — 清理内核中残留的检测痕迹
//
// Windows 内核在驱动加载/卸载时会在多个结构中留下痕迹:
//   1. MmUnloadedDrivers[50] — 最近 50 个卸载驱动的记录 (含路径/名称)
//   2. PiDDBCacheTable (AVL树) — 驱动加载缓存 (含时间戳/校验和)
//   3. ci.dll g_KernelHashBucketList — Code Integrity 哈希桶
//
// 现代反作弊 (EAC/BattlEye/Vanguard) 在游戏启动时扫描上述结构
// PAC 是否扫描未公开, 但清除是深层防御的必要措施
//
// 通过 BYOVD 内核 R/W 直接操作这些结构, 无需额外驱动加载
// ============================================================
class KernelTraceCleaner {
public:
    // 清理全部 3 张表中的 RTCore64.sys 痕迹
    static bool CleanAllTraces();

private:
    // 子步骤: 扫描 MmUnloadedDrivers 数组并清除
    static bool ClearMmUnloadedDrivers(uint64_t ntosBase);
    // 子步骤: 扫描 PiDDBCacheTable AVL 树并删除条目
    static bool ClearPiDDBCacheTable(uint64_t ntosBase);
    // 子步骤: 扫描 ci.dll KernelHashBucketList 并删除哈希条目
    static bool ClearCiHashBucket(uint64_t ciBase);
};

// ============================================================
// ★ v3.126n: Minifilter Neutralizer — 中和 MessageTransfer minifilter
//
// 替换 FilterUnload 方案:
//   不卸载 minifilter (避免 PAC 平台检测到 minifilter 缺失)
//   而是用 BYOVD 内核 R/W 替换其操作回调为无害 stub
//   使 minifilter 在结构上"存在"但功能上完全失效
//
// 原理:
//   1. 定位 fltmgr.sys 中 FltGlobals → FrameList → FilterList
//   2. 遍历找到 MessageTransfer 的 FLT_FILTER 结构
//   3. 读取 FLT_FILTER.Operations → FLT_OPERATION_REGISTRATION 数组
//   4. 将每个 PreOp/PostOp 回调替换为返回
//      FLT_PREOP_SUCCESS_NO_CALLBACK(=0) 的 stub
//   5. minifilter 仍在 FilterFindFirst 列表中, 但文件操作不受拦截
// ============================================================
class MinifilterNeutralizer {
public:
    // 中和 MessageTransfer minifilter (不卸载)
    // 返回 true = 成功中和, false = 失败 (可回退到 FilterUnload)
    static bool NeutralizeMessageTransfer();

    // ★ v3.126n: 检查 MessageTransfer 回调是否仍为无害 stub
    //   用于 GuardPac 周期性验证 — 防止 PAC 平台修复回调
    static bool IsMessageTransferNeutralized();

    // ★ BUILD 475: 管道验证 — 枚举所有已加载 minifilter 证明 FLT 管道可用
    //   即使 MessageTransfer.sys 未加载, 也能确定: 一旦加载, 中和就能生效
    //   返回 true = 管道完整可用 (FltGlobals->FrameList->FilterList->回调替换)
    static bool VerifyFltPipeline();

private:
    // 通过 sigscan 在 fltmgr.sys 中定位 FltGlobals
    static uint64_t FindFltGlobals(uint64_t fltmgrBase);
    // 在 FilterList 中查找 Name=="MessageTransfer" 的 FLT_FILTER
    static uint64_t FindFilterByName(uint64_t fltmgrBase, uint64_t fltGlobals, const wchar_t* name);
    // 替换 FLT_FILTER.Operations 数组中所有回调为无害 stub
    static bool NeutralizeCallbacks(uint64_t filterAddr);
};

} // namespace stealth
