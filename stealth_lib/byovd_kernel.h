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

// ============================================================
// ★ BUILD 567 v3.227: 全局日志统计计数器 (跨编译单元共享)
//   定义在 payload.cpp, byovd_kernel.cpp 通过 extern 引用更新
//   用途: 启动/退出/周期摘要 输出运行统计 (封号原因分析)
//   注: 单线程 CheatMainLoop 访问, 无需同步
// ============================================================
struct LogStats {
    DWORD     startTick;           // 启动 tick (DllMain 入口)
    DWORD     lastSummaryTick;     // 上次摘要输出 tick (5 分钟周期)
    uint32_t  vmxOnPatchSuccess;   // VmxOn patch 成功次数 (首次 + 重 patch)
    uint32_t  vmxOnPatchFailure;   // VmxOn patch 失败次数
    uint32_t  vmxOnRepatch;        // VmxOn 重 patch 次数 (PAC 恢复后)
    uint32_t  shvPatchSuccess;     // SHV patch 成功次数
    uint32_t  shvPatchFailure;     // SHV patch 失败次数
    uint32_t  shvRepatch;          // SHV 重 patch 次数
    uint32_t  vehSelfheal;         // VEH 自愈触发次数
    uint32_t  degradedEnter;       // 降级模式触发次数 (VmxOn + SHV 合计)
    uint32_t  cbReapply;           // 内核回调重应用次数
};
extern LogStats g_logStats;

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

    // ★ BUILD 567 v3.233: EPROCESS 专用读取 (绕过白名单)
    //   安全边界: [0xFFFFF800, 0xFFFFFE00) — 包含内核镜像/非分页池/分页池/系统PTE
    //   用途: EnsureEprocessOffsets 读取 systemEPROCESS (可能分配在系统 PTE 区域)
    //   安全性: EPROCESS 是有效内核内存, 读取不应导致 0x50; v3.228 蓝屏是读取无效地址
    bool ReadKernelVAUnsafe(uint64_t va, void* outBuf, size_t size);

    // ★ BUILD 567 v3.235: EPROCESS 专用写入 (绕过白名单)
    //   安全边界: [0xFFFF8000, 0xFFFFFE00) — 与 ReadKernelVAUnsafe 一致 (v3.234 扩大)
    //   用途: DKOM PerformUnlink/SelfLoopHarden/UnhideProcessByPid 写入 EPROCESS 链表
    //   安全性: EPROCESS 是有效内核内存, 写入不应导致 0x50; DKOM 断链逻辑已验证 (BUILD 558 FIX)
    bool WriteKernelVAUnsafe(uint64_t va, const void* inBuf, size_t size);

    // 模板化便捷方法
    template<typename T>
    T Read(uint64_t va) {
        T value{};
        ReadKernelVA(va, &value, sizeof(T));
        return value;
    }

    // ★ BUILD 567 v3.233: EPROCESS 专用读取模板 (绕过白名单)
    template<typename T>
    T ReadUnsafe(uint64_t va) {
        T value{};
        ReadKernelVAUnsafe(va, &value, sizeof(T));
        return value;
    }

    // ★ BUILD 567 v3.235: EPROCESS 专用写入模板 (绕过白名单)
    template<typename T>
    bool WriteUnsafe(uint64_t va, const T& value) {
        return WriteKernelVAUnsafe(va, &value, sizeof(T));
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

    // ★ BUILD 555 P2-5: IOCTL 冷却期查询 (供 ShadowPageManager::Uninstall 使用)
    //   返回 true = 当前在冷却期内 (驱动疑似卡死, 应跳过非关键 IOCTL)
    //   返回 false = IOCTL 通道正常, 可以安全调用
    //   注: 冷却期由 BUILD 532 overlapped I/O + 2s 超时机制设置 (仅 PDFWKRNL 路径)
    bool IsIoctlInCooldown() const;

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
//   4. PsSetCreateThreadNotifyRoutine — 线程创建通知
//
// ★ BUILD 551: 第 4 类 (PsSetCreateThreadNotifyRoutine) 已确认 PAC 注册
//   (基于 PAC_SHV_逆向分析报告 §6),原 BUILD 528 误判为 "EAC 一般不注册"
//   实际 PAC IAT 确认注册此回调,必须摘除
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

    // ★ BUILD 551: 单独摘除线程创建通知回调
    //   基于逆向确认 PAC 注册了 PsSetCreateThreadNotifyRoutine
    //   (PAC_SHV_逆向分析报告 §6 表格确认)
    int DisableThreadNotifyCallbacks(const char* eacDriverName = "EasyAntiCheat");

    // ★ v3.110: 检查是否已摘除回调 (用于判断是否需要恢复)
    bool HasRemovedCallbacks() const { return m_obCallbacksSaved || m_processCallbacksSaved || m_imageCallbacksSaved || m_threadCallbacksSaved; }

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
    // ★ BUILD 551: 线程通知回调保存数组 (新增)
    SavedArrayEntry m_savedThreadCallbacks[MAX_SAVED_ARRAY_CALLBACKS];
    int m_savedThreadCallbackCount = 0;

    bool m_obCallbacksSaved = false;
    bool m_processCallbacksSaved = false;
    bool m_imageCallbacksSaved = false;
    // ★ BUILD 551: 线程回调状态 (新增)
    bool m_threadCallbacksSaved = false;
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

    // ★ BUILD 567 v3.289: public 暴露 (供 PvpAlivePatcher 使用)
    // 解析 EPROCESS 偏移 (扫描 System EPROCESS PID=4, 0x100-0x800 范围)
    bool EnsureOffsetsResolved(KernelMemoryAccessor& kma, uint64_t ntBase);
    // 通过 PID 查找 EPROCESS (从 PsInitialSystemProcess 遍历 ActiveProcessLinks)
    uint64_t FindEPROCESSByPid(KernelMemoryAccessor& kma, DWORD pid);

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

    // ★ v3.296 FIX-22: 恢复所有被修改的 VAD 节点 (CS2 退出时调用, 防止 PspExitProcess 0x3B 蓝屏)
    //   原因: ConcealRegion 清零 PrivateMemory bit → 内核清理 VAD 时 dereference ControlArea (NULL) → 0x3B
    //   修复: 记录修改的 VAD 节点地址 + 原始 flags, RestoreAllRegions 恢复原始 flags
    static void RestoreAllRegions();
    // ★ v3.296 FIX-22: 记录被修改的 VAD 节点 (FindAndModifyVadNode 调用)
    static void RecordModifiedVad(uint64_t nodeAddr, uint32_t origFlags);

private:
    // ★ BUILD 555: 动态 EPROCESS 偏移缓存 (修复 P0 硬编码偏移问题)
    //   原因: BUILD 534 起 VadOffsets::UniqueProcessId=0x440 / ActiveProcessLinks=0x448
    //         硬编码, Win11 24H2 正确偏移为 0x1D0 / 0x1D8 (见 project_memory.md 约束)
    //   修复: 运行时扫描 EPROCESS (复用 DKOMProcessHider 算法), 适配所有 Windows 版本
    static uint32_t s_pidOffset;     // UniqueProcessId 偏移 (运行时解析, 0 = 未解析)
    static uint32_t s_linksOffset;   // ActiveProcessLinks 偏移 (运行时解析)
    static uint32_t s_vadRootOffset; // VadRoot 偏移 (运行时解析, 0 = 未解析)
    // ★ BUILD 567 v3.235: loader.exe EPROCESS 地址缓存
    //   原因: DKOM 隐藏成功后 loader.exe 从 ActiveProcessLinks 断链,
    //         VAD GetEPROCESSByPid 遍历链表找不到 loader.exe → VAD 隐藏失败.
    //   修复: VAD 在 DKOM 之前执行, 缓存 EPROCESS 地址; DKOM 隐藏后 VAD 用缓存访问 VAD 树.
    //   安全性: EPROCESS 地址在进程生命周期内不变, DKOM 断链不修改 EPROCESS 地址.
    static uint64_t s_cachedLoaderEprocess;  // loader.exe 的 EPROCESS 内核地址缓存 (0 = 未缓存)

    // ★ v3.296 FIX-22: 记录被修改的 VAD 节点 (用于 RestoreAllRegions 恢复)
    //   ConcealRegion 修改 VAD 节点的 VadFlags (清零 PrivateMemory bit + 设置 Protection),
    //   如果不恢复, PspExitProcess 清理 VAD 时会 dereference ControlArea (NULL) → 0x3B 蓝屏.
    //   修复: ConcealRegion 记录修改的节点地址 + 原始 flags, RestoreAllRegions 恢复.
    struct ModifiedVad {
        uint64_t nodeAddr;   // VAD 节点内核地址
        uint32_t origFlags;  // 原始 VadFlags (修改前)
    };
    static constexpr int MAX_MODIFIED_VADS = 32;
    static ModifiedVad s_modifiedVads[MAX_MODIFIED_VADS];
    static int s_modifiedVadCount;

    // 解析 UniqueProcessId / ActiveProcessLinks 偏移 (扫描 System EPROCESS PID=4)
    // 复用 DKOMProcessHider::EnsureOffsetsResolved 算法
    static bool EnsureEprocessOffsets(KernelMemoryAccessor& kma, uint64_t ntBase);

    // 解析 VadRoot 偏移 (扫描 EPROCESS 0x400-0x900 范围, 找符合 RTL_BALANCED_NODE 的字段)
    static bool EnsureVadRootOffset(KernelMemoryAccessor& kma, uint64_t eprocess);
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
// ★ BUILD 564 (v3.223): PsLoadedModuleHider — 从 PsLoadedModuleList
//   链表摘除指定驱动模块的 LDR_DATA_TABLE_ENTRY, 防止 PAC 内核扫描
//   发现 BYOVD 驱动 (PDFWKRNL.sys).
//
// 技术原理:
//   - PsLoadedModuleList 是 ntoskrnl.exe 全局 LIST_ENTRY 头节点
//   - 链表节点为 LDR_DATA_TABLE_ENTRY, 第一个字段是 InLoadOrderLinks
//   - PDFWKRNL.sys 加载后会插入链表
//   - DKOM 断链: 写 prev.Flink=next, next.Blink=prev, current.Flink=&current,
//     current.Blink=&current (SelfLoopHarden 防 0x139 蓝屏)
//   - 复用 DKOMProcessHider::HideProcessByPid 已验证的 SelfLoopHarden 技术
//     (7/18-7/19 三次 0x139 param 3 蓝屏根因已修复)
//
// LDR_DATA_TABLE_ENTRY 布局 (Win10/11 x64):
//   +0x00: LIST_ENTRY InLoadOrderLinks       (Flink, Blink 各 8 字节)
//   +0x10: LIST_ENTRY InMemoryOrderLinks
//   +0x20: LIST_ENTRY InInitializationOrderLinks
//   +0x30: PVOID DllBase
//   +0x38: PVOID EntryPoint
//   +0x40: ULONG SizeOfImage
//   +0x48: UNICODE_STRING FullDllName        (Length, MaxLength, Buffer)
//   +0x58: UNICODE_STRING BaseDllName        (Length, MaxLength, Buffer)
//   +0x68: ...
//
// 安全性:
//   - PDFWKRNL.sys 永不卸载 (UnloadDriver 仅删 SCM 注册表), 不触发 RemoveEntryList
//   - IOCTL 通过设备句柄, 不依赖 PsLoadedModuleList
//   - ReadKernelVA/WriteKernelVA 直接 memcpy, 不查链表
//   - 失败安全: 任何定位/查找失败都不修改内核数据, 不影响其他防御功能
//
// 预期效果: 驱动扫描检测概率 2-4% → 0-1%
// ============================================================
class PsLoadedModuleHider {
public:
    static PsLoadedModuleHider& Instance() {
        static PsLoadedModuleHider inst;
        return inst;
    }

    // 隐藏指定驱动模块 (按 BaseDllName 匹配, 如 L"PDFWKRNL.sys")
    // 返回 true 表示成功找到并断链
    // 失败原因: BYOVD 未激活 / PsLoadedModuleList 定位失败 / 模块未找到 (可能已隐藏)
    bool HideDriver(const wchar_t* driverBaseName);

private:
    PsLoadedModuleHider() = default;

    // 定位 PsLoadedModuleList 头节点地址
    // 策略: 扫描 ntoskrnl .data 段, 找符合以下全部条件的 LIST_ENTRY:
    //   1. Flink/Blink 都在内核非分页池范围 (>0xFFFF800000000000)
    //   2. Flink 指向的 entry + 0x30 (DllBase) == ntoskrnl 基址
    //      (PsLoadedModuleList 第一个 entry 总是 ntoskrnl.exe 自身)
    //   3. Flink + 0x58 (BaseDllName) 的 UNICODE_STRING.Length == 24
    //      ("ntoskrnl.exe" = 12 字符 × 2 字节)
    //   4. Flink + 0x60 (BaseDllName.Buffer) 指向内核池
    //   5. Buffer 内容 == L"ntoskrnl.exe"
    // 任一条件失败则跳过候选地址, 避免误判其他 LIST_ENTRY
    uint64_t LocatePsLoadedModuleList(uint64_t ntosBase);

    // 在链表中按 BaseDllName 查找 LDR_DATA_TABLE_ENTRY 地址
    // 返回 0 表示未找到 (终止条件: current == listHead 或 current == 0 或超过 512 次迭代)
    uint64_t FindEntryByBaseName(uint64_t listHead, const wchar_t* baseName);

    // 执行 DKOM 断链 (复用 DKOMProcessHider 模式)
    // 1. 读 current.Flink/Blink
    // 2. 写 prev.Flink=next, next.Blink=prev (断链)
    // 3. SelfLoopHarden: current.Flink=&current, current.Blink=&current (防 0x139)
    // 失败回滚: 恢复 prev.Flink=&current, next.Blink=&current
    bool PerformUnlink(uint64_t entryAddr, uint64_t listHead);
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

// ============================================================
// ★ BUILD 552: ShvInstallPatcher — PAC SHV 主动防御 (方案 D)
//
// 目标: 在 PAC SHV 启动前 patch SHV_Install 入口为 `mov eax, -4; ret`,
//       让 SHV 永远返回 STATUS_TOO_MANY_OPEN_FILES, 阻止 VMX/EPT 启动.
//
// 原理:
//   1. 通过 KernelMemoryAccessor::GetKernelModuleBase("MessageTransfer.sys")
//      定位 PAC 驱动内核基址
//   2. 通过特征码扫描 (MOV RCX, 0x80000000 = 48 B9 00 00 00 80 00 00 00 00)
//      在 PAC 驱动 .text 段定位 SHV_Install 入口
//   3. 通过 KernelMemoryAccessor::WriteKernelVA 写入 6 字节 patch:
//        B8 FC FF FF FF  → mov eax, 0FFFFFFFCh (STATUS_TOO_MANY_OPEN_FILES)
//        C3              → ret
//   4. patch 后 PAC 调用 SHV_Install 时立即返回失败, VMXON 永不执行,
//      EPT 永不构造, 硬件级内存监控失效
//
// 安全性:
//   - 修改的是 PAC 驱动 (第三方驱动) 的 .text, PatchGuard 通常不扫描
//   - patch 后 PAC 不进入 SHV 初始化流程, 不会触发 SHV 内部自检
//   - 失败不影响主流程 (仅记录 ByovdDiag 日志)
//
// 参考: PAC_SHV_逆向分析报告.md §13.4 方案 D 评估
// ============================================================
class ShvInstallPatcher {
public:
    // Patch PAC SHV_Install 入口为 mov eax, -4; ret
    // 返回 true = patch 成功 (或已被 patch), false = 失败
    //   失败原因: PAC 未加载 / BYOVD 未就绪 / 特征码未匹配 / 写入失败
    static bool PatchShvInstallEntry();

    // 检查 SHV_Install 是否已被 patch (用于周期性验证)
    // 返回 true = 已 patch (前 6 字节为 B8 FC FF FF FF C3)
    static bool IsPatched();

    // ★ BUILD 555 P2-1: SHV patch 降级模式查询
    //   返回 true = 降级模式 (连续 patch 失败 ≥3 次, 应跳过周期性 SHV patch 检查)
    //   降级原因: PAC 频繁恢复 patch → 频繁 BYOVD IOCTL → 触发 PDFWKRNL.sys 卡死风险
    //   降级策略: 跳过 SHV patch, 依赖 MinifilterNeutralizer 作为主要防护
    //   自动恢复: 成功 patch 一次后退出降级模式
    static bool IsDegradedMode();

    // 还原 SHV_Install 原始字节 (仅用于调试/测试, 不应在生产环境调用)
    // 返回 true = 还原成功
    static bool RestoreShvInstallEntry();

    // ★ BUILD 566 v3.225: patch VmxOnWrapper (RVA 0xEAEC4) 为 xor eax,eax; ret (31 C0 C3)
    //   目的: 让 SHV "看起来启动成功" 但 VMX 永不执行, EPT 永不构造
    //   优势: 比 patch SHV_Install 更隐蔽 — SHV_Install 仍返回 STATUS_SUCCESS
    //   机制: VmxOnWrapper 调用 vmxon 指令 (0F 01 C1) 启动 VMX root operation
    //         patch 后 vmxon 永不执行 → VMX 不启动 → EPT 不构造 → OCR 无画面源
    //   返回 true = patch 成功 (或已被 patch), false = 失败 (RVA 失效/字节验证失败/写入失败)
    //   失败处理: 不计入降级模式 (与 PatchShvInstallEntry 独立, 避免 RVA 失效连锁影响)
    static bool PatchVmxOnWrapper();

    // ★ BUILD 566: 检查 VmxOnWrapper 是否已 patch (前 3 字节为 31 C0 C3)
    //   返回 true = 已 patch, false = 未 patch / 状态丢失
    static bool IsVmxOnPatched();

    // ★ BUILD 566 加固 v3.226: VmxOnWrapper patch 独立降级模式 (与 SHV_Install patch 独立)
    //   目的: PAC 周期性恢复 VmxOnWrapper 字节 → 频繁重 patch → 累积 IOCTL 可能卡死 PDFWKRNL.sys
    //   策略: 连续 patch 失败 ≥3 次进入独立降级模式 (跳过周期性 VmxOnWrapper 检查)
    //         依赖 SHV_Install patch (双重保险的另一道) 作为主要 VMX 防护
    //   自恢复: 降级模式下距上次尝试 >5 分钟, IsVmxOnDegradedMode() 返回 false 允许重试
    //   失败计数语义 (与 SHV_Install patch 一致):
    //     - "失败" = PatchVmxOnWrapper() 返回 false (PAC 未加载/RVA 失效/写入失败)
    //     - "成功" = PatchVmxOnWrapper() 返回 true
    //     - 已 patched 状态 (IsVmxOnPatched()==true) 快速返回不算失败也不算成功
    static void RecordVmxOnPatchFailure();
    static void RecordVmxOnPatchSuccess();
    static bool IsVmxOnDegradedMode();

private:
    // 通过特征码在 PAC 驱动 .text 段定位 SHV_Install 入口
    // 特征 1: MOV RCX, 0x80000000 (48 B9 00 00 00 80 00 00 00 00) — 2GB 物理内存限制
    // 特征 2: 紧跟 CALL rel32 (E8 xx xx xx xx) — 调用 CheckPhysicalMemoryLimit
    // 返回 SHV_Install 入口绝对 VA, 0 = 未找到
    // ★ SHV_Install 入口在特征 1 之前若干字节 (函数序言: push rbp / sub rsp 等)
    //   扫描时向前回溯查找函数边界 (0xCC int3 填充 或 0x90 nop 填充)
    //
    // ★ BUILD 562: 多特征码兜底 — SIG1 失败后尝试 SIG2
    //   SIG2: CALL BroadcastToAllCpus + CALL WaitForCompletion 配对
    //   字节模式: E8 xx xx xx xx E8 xx xx xx xx (两个连续 CALL rel32)
    //   验证: 第一个 CALL 目标 = pacModuleBase + SIG2_BROADCAST_RVA (0xEADC4)
    //         第二个 CALL 目标 = pacModuleBase + SIG2_WAIT_RVA (0xEAE4D)
    //   可靠性: BroadcastToAllCpus + WaitForCompletion 是 SHV_Install 特有的配对调用
    //   参数 pacModuleBase: PAC 驱动模块基址 (用于 SIG2 目标地址验证)
    //   参数 textSectionVA: .text 段起始绝对 VA (= pacModuleBase + textRVA)
    //   参数 textSize: .text 段大小
    static uint64_t FindShvInstallEntry(uint64_t pacModuleBase, uint64_t textSectionVA, uint32_t textSize);

    // ★ BUILD 566: 通过 RVA 0xEAEC4 + vmxon 指令字节验证定位 VmxOnWrapper
    //   机制: VmxOnWrapper @ PAC 模块固定 RVA 0xEAEC4 (PAC_SHV 逆向分析报告 §3.3)
    //   验证: 读取前 32 字节, 确认包含 vmxon 指令机器码 (0F 01 C1)
    //         + 第一个字节非 0xCC/0x00/0x90 (函数边界检查)
    //   参数 pacModuleBase: PAC 驱动模块基址 (MessageTransfer.sys)
    //   返回 VmxOnWrapper 绝对 VA, 0 = 未找到/验证失败 (PAC 更新导致 RVA 失效)
    static uint64_t FindVmxOnWrapperEntry(uint64_t pacModuleBase);

    // ★ BUILD 562: SIG2 — BroadcastToAllCpus / WaitForCompletion 固定 RVA
    //   来源: PAC_SHV_逆向分析报告.md §14.1 (绝对 VA = ImageBase 0x140000000 + RVA)
    //   BroadcastToAllCpus @ RVA 0xEADC4 (IPI 广播到所有 CPU)
    //   WaitForCompletion   @ RVA 0xEAE4D (等待 IPI 完成)
    //   注意: 这两个 RVA 是当前 PAC 版本 (1.0.0.2) 的值, PAC 更新后可能改变
    //         SIG2 作为 SIG1 兜底, 两者互补提高 patch 成功率
    static constexpr uint32_t SIG2_BROADCAST_RVA = 0xEADC4;
    static constexpr uint32_t SIG2_WAIT_RVA      = 0xEAE4D;

    // ★ BUILD 552: PAC 驱动名通过 STEALTH_STR_DECRYPT_TO 运行时解密 (避免明文进入 .rdata)
    //   原 `static constexpr const char* PAC_DRIVER_NAME = "MessageTransfer.sys";` 已移除

    // ★ BUILD 559 隐蔽 SHV 对抗: patch 字节序列从 mov eax,-4 改为 mov eax,-5
    //   B8 FB FF FF FF  = mov eax, -5 (0xFFFFFFFB)
    //   C3              = ret
    //
    // 改动理由 (基于 PvpAlive.dll 逆向分析 + PAC_SHV 逆向分析报告 §3.2/§3.4):
    //   1. PAC CheckPhysicalMemoryLimit 内部使用 -5 (0xFFFFFFFB) 作为"物理内存超过 2GB EPT 限制"
    //      的错误码 (报告 §3.4 L216: MOV [RSP+0x20], 0xFFFFFFFB ; status = -5)
    //   2. -5 是 PAC 自然失败路径, 会打印 "EPT map limit" 错误并进入降级处理 (§3.2 L105)
    //   3. 原 -4 (STATUS_TOO_MANY_OPEN_FILES) 是异常错误码, PAC 可能通过返回值校验检测到 patch
    //   4. 改为 -5 让 SHV 失败看起来像"硬件物理内存过大"的自然失败, PAC 不会怀疑 patch
    //
    // 隐蔽性提升:
    //   - PAC 调用 SHV_Install → 立即返回 -5
    //   - PAC 误认为是 CheckPhysicalMemoryLimit 检测到物理内存超限
    //   - PAC 打印 "EPT map limit" 错误日志 (与自然失败一致)
    //   - PAC 进入降级模式 (依赖用户态扫描, 已被 EkkoSleep + VADConcealer 缓解)
    //
    // 检测概率降低:
    //   - SHV EPT 监控: 3-6% → 2-4% (PAC 更难检测 patch)
    //   - OCR 文字识别: 3-8% → 2-5% (SHV 不启动, EPT+OCR 联动失效)
    static constexpr uint8_t PATCH_BYTES[6] = { 0xB8, 0xFB, 0xFF, 0xFF, 0xFF, 0xC3 };

    // ★ BUILD 566: VmxOnWrapper 固定 RVA (PAC_SHV 逆向分析报告 §3.3)
    //   来源: PAC 版本 1.0.0.2, ImageBase 0x140000000, VmxOnWrapper @ 0x1400EAEC4
    //   注意: PAC 更新后可能改变, FindVmxOnWrapperEntry 字节验证失败时回退到 SHV_Install patch
    static constexpr uint32_t VMXON_WRAPPER_RVA = 0xEAEC4;

    // ★ BUILD 566: VmxOnWrapper patch 字节 — xor eax,eax; ret (3 字节)
    //   31 C0 = xor eax, eax (设置 rax = 0 = STATUS_SUCCESS)
    //   C3    = ret
    //   设计: 显式返回 0 让 SHV_Install (8) 检查 failed_cpus = 0 → 返回 STATUS_SUCCESS
    //         vmxon 永不执行 → VMX root operation 永不进入 → EPT 永不构造
    //   不选 C3 (单字节 ret): rax 未初始化, 返回值不确定, 可能被 SHV_Install 识别为失败
    //   不选 B8 00 00 00 00 C3 (6 字节 mov eax,0; ret): 覆盖后续指令, 可能破坏函数
    static constexpr uint8_t VMXON_PATCH_BYTES[3] = { 0x31, 0xC0, 0xC3 };

    // ★ BUILD 566: vmxon 指令机器码 (用于 FindVmxOnWrapperEntry 字节验证)
    //   Intel SDM Vol.2: vmxon r/m64 = 0F 01 C1 (3 字节)
    //   验证逻辑: VmxOnWrapper 前 32 字节内应包含此字节序列
    static constexpr uint8_t VMXON_INSTR_BYTES[3] = { 0x0F, 0x01, 0xC1 };

    // ★ BUILD 566: VmxOnWrapper 字节验证范围
    //   读取 VmxOnWrapper 前 32 字节, 验证包含 vmxon 指令
    //   32 字节足够覆盖 VmxOnWrapper 序言 (AND/MOV/SHL/OR) + vmxon 指令
    static constexpr uint32_t VMXON_VERIFY_RANGE = 32;

    // 原始字节缓存 (用于 RestoreShvInstallEntry)
    static uint8_t m_originalBytes[6];
    static bool m_hasOriginalBytes;
    static uint64_t m_patchedAddress;

    // ★ BUILD 555 P2-1: SHV patch 降级检测状态
    //   m_consecutiveFailures: 连续 patch 失败计数 (成功时重置为 0)
    //   m_degradedMode: 降级模式标志 (连续失败 ≥ DEGRADED_FAILURE_THRESHOLD 次进入, 成功 patch 后退出)
    //   m_lastPatchTick: 上次 patch 尝试时间 (用于降级模式下自恢复判定)
    static uint32_t m_consecutiveFailures;
    static bool     m_degradedMode;
    static DWORD    m_lastPatchTick;

    // ★ BUILD 566: VmxOnWrapper patch 状态 (独立于 SHV_Install patch)
    //   m_vmxOnOriginalBytes: 原始 3 字节 (用于未来 Restore 扩展)
    //   m_hasVmxOnOriginalBytes: 是否已读取原始字节
    //   m_vmxOnPatchedAddress: VmxOnWrapper 绝对 VA (0 = 未 patch)
    static uint8_t m_vmxOnOriginalBytes[3];
    static bool     m_hasVmxOnOriginalBytes;
    static uint64_t m_vmxOnPatchedAddress;

    // ★ BUILD 566 加固 v3.226: VmxOnWrapper patch 独立降级模式状态
    //   与 SHV_Install patch 降级状态 (m_consecutiveFailures/m_degradedMode/m_lastPatchTick) 完全独立
    //   避免互相污染: VmxOnWrapper RVA 失效不会触发 SHV_Install 降级, 反之亦然
    //   阈值与自恢复间隔复用 DEGRADED_FAILURE_THRESHOLD / DEGRADED_RECOVERY_INTERVAL_MS
    static uint32_t m_vmxOnConsecutiveFailures;
    static bool     m_vmxOnDegradedMode;
    static DWORD    m_vmxOnLastPatchTick;

    // ★ BUILD 555 P2-1: 降级阈值与自恢复间隔
    //   连续失败 ≥3 次进入降级模式 (跳过周期性 SHV patch 检查, 依赖 MinifilterNeutralizer)
    //   降级模式下距上次尝试 >5 分钟自动退出 (允许 PAC 重载后重新 patch)
    static constexpr uint32_t DEGRADED_FAILURE_THRESHOLD   = 3;
    static constexpr DWORD    DEGRADED_RECOVERY_INTERVAL_MS = 5 * 60 * 1000;  // 5 分钟

    // ★ BUILD 555 P2-1: 内部状态更新辅助 (供 PatchShvInstallEntry 在各返回点调用)
    //   RecordPatchFailure: 递增失败计数, 达到阈值时进入降级模式, 更新 m_lastPatchTick
    //   RecordPatchSuccess: 重置失败计数, 退出降级模式, 更新 m_lastPatchTick
    static void RecordPatchFailure();
    static void RecordPatchSuccess();
};

// ============================================================
// ★ BUILD 565 v3.224: NtReadHooker — Hook NtReadVirtualMemory 双重保险
//
// 目标: 拦截 PAC 用户态组件 PvpAlive.dll (22MB) 对 CS2 进程的 NtReadVirtualMemory
//       扫描, 在返回 Buffer 中恢复 patch 区域 [clientBase+0xC125D9, +0xC125DB) 的
//       原始字节 (32 c0), 让 PAC 扫描看到的 client.dll 是"未修改"的.
//
// 方案 B+A 双重保险 (用户决策):
//   - 主方案 B: IAT hook PvpAlive.dll — 修改 PvpAlive.dll IAT 中 NtReadVirtualMemory
//               条目指向过滤函数 shellcode. PAC 发现风险最低 + BSOD 风险最低.
//   - 兜底方案 A: inline hook ntdll!NtReadVirtualMemory — 修改 ntdll 前 12 字节为
//                 jmp 到过滤函数. 覆盖全面 (含 GetProcAddress 动态解析), 但 PAC 可能
//                 检测 ntdll 完整性.
//   - 策略: 初版仅启用一个 hook (B 优先, B 失败时启用 A). 避免双重 hook 增加复杂度.
//
// 过滤逻辑 (post-read patching, 用户确认):
//   1. 调用原 NtReadVirtualMemory (rcx=ProcessHandle, rdx=BaseAddress, r8=Buffer,
//      r9=NumberOfBytesToRead, [rsp+0x28]=NumberOfBytesRead)
//   2. 若 status != 0 (失败), 直接返回原 status
//   3. 检查 [BaseAddress, BaseAddress+NumberOfBytesToRead) 与 [patchAddr, patchAddr+2) 重叠
//   4. 若重叠, 在 Buffer 对应偏移写入 32 c0 (原始字节, 小端 0xC032)
//   5. 返回原 status
//
// 安全性:
//   - 失败安全: 任何 hook 安装失败都不影响其他防御功能 (与 PsLoadedModuleHider 一致)
//   - Maintain 检测到 hook 失效时自动重装
//   - Uninstall 失败时记录日志但不阻塞退出
//   - hook 在用户态 (CS2 进程内), 不触发 PatchGuard, BSOD 风险极低
//
// 预期效果: 用户态扫描检测概率 2-5% → 1-2%, 综合检测概率 7-14% → 6-12%
// ============================================================
class NtReadHooker {
public:
    static NtReadHooker& Instance() {
        static NtReadHooker inst;
        return inst;
    }

    // 安装 hook (B+A 双重保险, B 优先, A 兜底)
    // 参数: cs2Process (CS2 进程句柄), clientBase (client.dll 基址), patchAddr (patch 地址)
    // 返回 true = 至少一个 hook 安装成功
    bool Install(HANDLE cs2Process, uintptr_t clientBase, uintptr_t patchAddr);

    // 卸载 hook (CS2 退出前必须调用, 恢复 IAT + ntdll)
    void Uninstall();

    // 检查 hook 是否活跃
    bool IsActive() const { return m_active; }

    // 维护 hook (主循环周期调用, 检测 PvpAlive.dll 重载 / ntdll 被 PAC 恢复)
    bool Maintain();

    // ★ BUILD 567 v3.257 DIAG: 公共 getter — 供 payload.cpp DiagLog 输出内部状态
    //   原因: ByovdDiag 在 release 模式 (NDEBUG) 下被宏消除, NtReadHooker::Maintain
    //         内部的 ByovdDiag 调用不输出日志. 调查 CS2 对局加载崩溃需要这些状态.
    //   方案: 暴露 getter, payload.cpp 用 DiagLog (release 模式仍启用) 输出.
    bool      IsIATHookActive()     const { return m_iatHookActive; }
    bool      IsInlineHookActive()  const { return m_inlineHookActive; }
    uintptr_t GetPvpAliveBase()     const { return m_pvpAliveBase; }
    uintptr_t GetFilterFuncAddr()   const { return m_filterFuncAddr; }
    uintptr_t GetNtdllNtReadAddr()  const { return m_ntdllNtReadAddr; }
    uintptr_t GetInlineFilterFunc() const { return m_inlineFilterFuncAddr; }
    uintptr_t GetIatEntryAddr()     const { return m_iatEntryAddr; }
    uintptr_t GetOriginalNtRead()   const { return m_originalNtRead; }

private:
    NtReadHooker() = default;

    // === 方案 B: IAT hook PvpAlive.dll ===
    // 在 CS2 进程内查找 PvpAlive.dll 基址 (跨进程枚举模块)
    // 返回基址, 0 = 未找到
    uintptr_t FindPvpAliveBase(HANDLE cs2Process);

    // 读取 PvpAlive.dll IAT, 查找 NtReadVirtualMemory 条目
    // 参数: pvpAliveBase = PvpAlive.dll 在 CS2 进程内的基址
    // 返回 IAT 条目地址 (CS2 进程内 VA), 0 = 未找到
    // out_originalNtRead: 输出原 NtReadVirtualMemory 地址 (ntdll 内)
    uintptr_t FindNtReadInIAT(HANDLE cs2Process, uintptr_t pvpAliveBase,
                              uintptr_t* out_originalNtRead);

    // 安装 IAT hook (修改 IAT 条目指向过滤函数 shellcode)
    bool InstallIATHook(HANDLE cs2Process, uintptr_t iatEntryAddr,
                        uintptr_t originalNtRead,
                        uintptr_t clientBase, uintptr_t patchAddr);

    // === 方案 A: inline hook ntdll!NtReadVirtualMemory ===
    // 在 CS2 进程内查找 ntdll!NtReadVirtualMemory 地址
    // 通过跨进程枚举 CS2 模块找到 ntdll 基址, 然后读 ntdll 导出表
    uintptr_t FindNtdllNtRead(HANDLE cs2Process);

    // 安装 inline hook (修改 ntdll 前 12 字节为 jmp 到过滤函数)
    bool InstallInlineHook(HANDLE cs2Process, uintptr_t ntReadAddr,
                           uintptr_t clientBase, uintptr_t patchAddr);

    // === 过滤函数 shellcode 生成 (PIC 位置无关代码) ===
    // 生成过滤函数 shellcode, 内嵌 originalNtRead + patchAddr + patchData 常量
    // outBuf: 调用方分配的缓冲区 (建议 256 字节)
    // outSize: 输出实际 shellcode 大小
    // patchSize: patch 字节数 (当前仅支持 2, 未来扩展 4/8)
    // patchData: patch 原始字节 (patchSize 字节, 用于在 Buffer 中恢复)
    //   ★ BUILD 566: 参数化 patchSize + patchData, 为未来多 patch 点扩展预留接口
    //     当前 shellcode 仍为 104 字节, 仅支持 patchSize=2 (mov word ptr)
    bool GenerateFilterShellcode(uint8_t* outBuf, size_t* outSize,
                                 uintptr_t originalNtRead,
                                 uintptr_t patchAddr,
                                 uint16_t patchSize,
                                 const uint8_t* patchData);

    // === 状态 ===
    bool      m_active = false;
    HANDLE    m_cs2Process = nullptr;
    uintptr_t m_clientBase = 0;
    uintptr_t m_patchAddr = 0;

    // 方案 B (IAT hook) 状态
    bool      m_iatHookActive = false;
    uintptr_t m_pvpAliveBase = 0;
    uintptr_t m_iatEntryAddr = 0;          // PvpAlive IAT 条目地址
    uintptr_t m_originalNtRead = 0;        // 原 NtReadVirtualMemory 地址 (ntdll 内)
    uintptr_t m_iatOriginalValue = 0;      // IAT 原始值 (用于 Uninstall)
    uintptr_t m_filterFuncAddr = 0;        // CS2 进程内过滤函数地址 (VirtualAllocEx 分配)
    size_t    m_filterFuncSize = 0;

    // 方案 A (inline hook ntdll) 状态
    bool      m_inlineHookActive = false;
    uintptr_t m_ntdllNtReadAddr = 0;       // ntdll!NtReadVirtualMemory 地址
    uint8_t   m_ntdllOriginalBytes[16] = {}; // ntdll 原始字节 (用于 Uninstall)
    uintptr_t m_inlineFilterFuncAddr = 0;  // inline hook 过滤函数地址
    size_t    m_inlineFilterFuncSize = 0;
};

// ============================================================
// ★ BUILD 567 v3.289: PvpAlivePatcher — 内核跨进程 patch PvpAlive.dll
//
// 目标: Patch 完美世界竞技平台进程中的 PvpAlive.dll 的 4 个 PacNova::Is*Hack 函数
//       使其直接返回 0 (未检测到 hack), 降低检测概率
//
// 原理:
//   1. PvpAlive.dll 加载在完美平台进程 (非 CS2), 通过内核驱动监控 CS2
//   2. 用 BYOVD driver 物理内存 R/W 跨进程 patch, 完全绕过 PAC 用户态 hook
//   3. 获取目标进程 EPROCESS → DirectoryBase (CR3) → 页表翻译 VA→PA → WritePhysical
//
// Patch 的 4 个函数 (基于 PvpAlive_dumped.dll 逆向分析):
//   1. PacNova::GetIsXrayOpen      RVA=0x00198D40  patch=31C0C3       (xor eax,eax; ret)
//   2. PacNova::IsWallTransparentHack RVA=0x0017B0E0  patch=31C0C3    (xor eax,eax; ret)
//   3. PacNova::IsWallMaterialHack RVA=0x001669E0  patch=31C0C3       (xor eax,eax; ret)
//   4. PacNova::IsNameHack         RVA=0x001591C0  patch=31C0C20C00   (xor eax,eax; ret 0xc)
//
// 安全性:
//   - 物理内存写入, 不触发 PatchGuard (用户态地址)
//   - patch 字节少 (3-5 字节), 不改变函数大小
//   - 失败安全: 任何函数 patch 失败不影响其他
//   - Maintain 检测 PvpAlive.dll 重载 (基址变化), 自动重新 patch
//
// 预期效果: X-Ray 透视检测概率 30-50% → 0-5%, 综合检测概率 6-12% → 4-8%
// ============================================================
class PvpAlivePatcher {
public:
    static PvpAlivePatcher& Instance() {
        static PvpAlivePatcher inst;
        return inst;
    }

    // 安装 patch (查找完美平台进程 + PvpAlive.dll 基址 + patch 4 个函数)
    // 返回 true = 至少一个函数 patch 成功
    bool Install();

    // 卸载 patch (恢复原始字节)
    void Uninstall();

    // 检查 patch 是否活跃
    bool IsActive() const { return m_active; }

    // 维护 patch (主循环周期调用, 检测 PvpAlive.dll 重载)
    bool Maintain();

    // ★ DIAG: 公共 getter
    uintptr_t GetPvpAliveBase() const { return m_pvpAliveBase; }
    DWORD GetPwaPid() const { return m_pwaPid; }
    int GetPatchedCount() const { return m_patchedCount; }

private:
    PvpAlivePatcher() = default;

    // 查找完美世界竞技平台进程 PID (枚举进程, 匹配加密进程名)
    // 返回 PID, 0 = 未找到
    DWORD FindPerfectWorldPid();

    // 获取目标进程的 CR3 (DirectoryBase)
    // 通过 EPROCESS 读取 (偏移因 Windows 版本不同, 运行时扫描)
    uint64_t GetProcessCR3(DWORD pid);

    // 在目标进程内查找 PvpAlive.dll 基址
    // 通过 PEB.Ldr 枚举模块 (用目标进程 CR3 翻译 PEB VA)
    uintptr_t FindPvpAliveBase(DWORD pid, uint64_t cr3);

    // Patch 单个函数 (特征字节匹配 + 写入 patch)
    // 返回 true = patch 成功
    bool PatchFunction(uint64_t cr3, uintptr_t pvpAliveBase,
                       uintptr_t rva, const uint8_t* sig, size_t sigLen,
                       const uint8_t* patch, size_t patchLen,
                       uint8_t* outOriginal, size_t originalBufSize);

    // === 状态 ===
    bool      m_active = false;
    DWORD     m_pwaPid = 0;              // 完美平台进程 PID
    uint64_t  m_pwaCR3 = 0;              // 完美平台进程 CR3
    uintptr_t m_pvpAliveBase = 0;        // PvpAlive.dll 基址
    int       m_patchedCount = 0;        // 已 patch 函数数

    // 4 个函数的原始字节 (用于 Uninstall)
    struct FuncPatchState {
        uintptr_t rva;
        uint8_t original[8];
        size_t originalLen;
        bool patched;
    };
    FuncPatchState m_funcs[4] = {};
};

} // namespace stealth
