#pragma once
// ============================================================
// eac_vm_evasion.h — EAC VM保护/内核反调试/回调链规避模块 (2026版)
//
// 来源: EAC驱动逆向分析(yougame.biz 2026.05) + RawCheats EAC 2026
//       + arXiv 2408.00500(Instr.Callback) + lxkast.github.io(NMI)
//
// 六大技术:
//   1. VM Gate Bypass — 绕过EAC自定义VM中的INT1/INT3/RDTSC门控
//   2. NMI Callback Spoofing — 用户态等效HalPreprocessNmi回调链欺骗
//   3. Instrumentation Callback Bypass — 绕过加载镜像/进程/线程回调
//   4. Fake PE Builder — 构造合法PE头欺骗EAC内存扫描
//   5. Code Virtualizer — 自定义字节码VM解释执行关键代码
//   6. Polymorphic Code — 运行时多态代码生成击败签名扫描
// ============================================================

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace stealth {
namespace eac {

// ============================================================
// 1. VM Gate Bypass — EAC自定义VM门控绕过
//
// EAC驱动在 .sec7 区段运行自定义虚拟机 (1025个handler地址, 54 QWORD上下文)
// 门控机制:
//   - INT 1 (Single-Step): 设置TF标志, 捕获STATUS_SINGLE_STEP检测调试器
//                         触发 STATUS_DRIVER_UNABLE_TO_LOAD 使驱动加载失败
//   - INT 3 (Breakpoint):  启动时+监控循环随机触发, 检测代码完整性
//   - RDTSC 时序检测:      随机周期数的操作间延迟测量, 检测Hook/VT-x开销
//
// 绕过: VEH拦截→静默处理→RDTSC值归一化
// ============================================================

class VMGateBypass {
public:
    struct VMDetectionResult {
        bool int1Trapped;       // 是否拦截了INT1单步陷阱
        bool int3Trapped;       // 是否拦截了INT3断点陷阱
        bool rdtscNormalized;   // 是否对RDTSC进行了归一化
        DWORD int1Count;        // 累计INT1捕获次数
        DWORD int3Count;        // 累计INT3捕获次数
        DWORD lastInterceptMs;  // 上次拦截时间
    };

    static VMGateBypass& Instance();

    // ---- 安装VEH拦截EAC的INT 1/INT 3陷阱 ----
    // 返回: 是否成功安装
    bool InstallExceptionProxy();

    // ---- 卸载VEH ----
    void UninstallExceptionProxy();

    // ---- RDTSC归一化 ----
    // EAC测量RDTSC差值检测调试器开销 (>10000 cycles视为异常)
    // 返回归一化后的TSC值 (基于最后一次RDTSC调用+随机增量)
    static ULONG64 NormalizeRDTSC();

    // ---- 获取RDTSC增量 (用于内部调用间时间伪装) ----
    static ULONG64 GetNormalizedDelta();

    // ---- 检测EAC VM是否活跃 ----
    // 扫描进程内存中的 .sec7 区段或VM handler特征
    bool IsVMGuardActive();

    // ---- 状态查询 ----
    const VMDetectionResult& GetStats() const { return m_stats; }
    bool IsInstalled() const { return m_installed; }

private:
    VMGateBypass() = default;

    // VEH异常处理器
    static LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS info);

    // 处理INT 1 (STATUS_SINGLE_STEP): 清除TF标志并继续
    static LONG HandleSingleStep(PCONTEXT ctx);

    // 处理INT 3 (STATUS_BREAKPOINT): 跳过断点指令并继续
    static LONG HandleBreakpoint(PCONTEXT ctx);

    // RDTSC状态
    static ULONG64 s_lastTsc;
    static ULONG64 s_tscOffset;
    static ULONG64 s_tscDrift;

    VMDetectionResult m_stats = {};
    bool m_installed = false;
    PVOID m_vehHandle = nullptr;
};

// ============================================================
// 2. NMI Callback Spoofing — 用户态等效NMI回调链欺骗
//
// EAC内核驱动: Hook HalPreprocessNmi, 在NMI回调链中添加检测回调
// 用户态等效: 
//   - 枚举VEH回调链, 识别EAC注册的处理器
//   - 在回调链末尾添加清理/恢复回调
//   - 伪造处理器状态使EAC回调失效
//
// NMI回调链结构: HalpNmiCallbackListHead (LIST_ENTRY)
// 每个条目: HalpNmiCallback → 包含回调函数指针+上下文
// 用户态模拟: VectoredExceptionHandler链 + KiUserExceptionDispatcher
// ============================================================

class NMICallbackSpoofer {
public:
    struct VEHChainEntry {
        PVOID  handler;          // 回调函数指针
        PVOID  moduleBase;       // 所在模块基址
        SIZE_T moduleSize;       // 模块大小
        bool   isSystem;         // 是否系统模块
        bool   isEACSuspected;   // 是否疑似EAC注册
    };

    static NMICallbackSpoofer& Instance();

    // ---- 枚举VEH回调链 ----
    // 遍历当前进程的VectoredExceptionHandler链表
    // 通过TEB→ExceptionList 或 NtQueryInformationProcess 获取
    std::vector<VEHChainEntry> EnumerateVEHChain();

    // ---- 在VEH链末尾注册清理回调 ----
    // 该回调在EAC的VEH之后执行, 可恢复被EAC修改的状态
    bool RegisterCleanupCallback();

    // ---- 卸载清理回调 (修复 P5) ----
    void UnregisterCleanupCallback();

    // ---- 尝试移除EAC注册的VEH处理器 ----
    // 通过RtlRemoveVectoredExceptionHandler移除疑似EAC的处理器
    // 注意: 激进操作, 可能被EAC检测
    bool EvictEACSuspectedHandlers();

    // ---- 伪造处理器上下文 ----
    // 将CONTEXT中的寄存器状态恢复为"合法"的user-mode值
    static void ForgeProcessorState(PCONTEXT ctx);

    // ---- 状态 ----
    bool IsRegistered() const { return m_cleanupRegistered; }

private:
    NMICallbackSpoofer() = default;

    // 内部清理回调
    static LONG CALLBACK CleanupVEH(PEXCEPTION_POINTERS info);

    bool m_cleanupRegistered = false;
    PVOID m_cleanupHandle = nullptr;
};

// ============================================================
// 3. Instrumentation Callback Bypass
//
// EAC注册的内核回调 (无法直接移除, 但可规避触发):
//   - PsSetLoadImageNotifyRoutine → 监控DLL加载 → 用Manual Map规避
//   - PsSetCreateProcessNotifyRoutine → 监控进程创建
//   - PsSetCreateThreadNotifyRoutine → 监控线程创建 → HideFromDebugger
//   - CmRegisterCallback → 注册表操作监控
//
// 用户态规避:
//   - PEB Ldr链表脱链 (隐藏Manual Map的模块)
//   - VAD节点伪装 (隐藏可疑内存区域)
//   - 线程创建隐匿 (THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER + NtCreateThreadEx)
// ============================================================

class InstrumentationCallbackBypass {
public:
    static InstrumentationCallbackBypass& Instance();

    // ---- PEB Ldr链表脱链 ----
    // 从 InLoadOrderModuleList/InMemoryOrderModuleList/InInitOrderModuleList
    // 中移除指定模块, 使EAC用户态DLL的Ldr枚举无法发现
    bool UnlinkModuleFromLdr(HMODULE hModule);
    bool UnlinkModuleFromLdr(const wchar_t* moduleName);

    // ---- 隐藏自身模块 ----
    bool UnlinkSelfFromPEB();

    // ---- VAD节点伪装 ----
    // 修改 VAD (Virtual Address Descriptor) 节点类型标记
    // 使分配的内存区域在 NtQueryVirtualMemory 中显示为 MEM_IMAGE 而非 MEM_PRIVATE
    // 注意: VAD在内核地址空间, 用户态只能通过NtQueryVirtualMemory影响返回结果
    bool DisguiseMemoryAsImage(void* address, SIZE_T size);

    // ---- 创建EAC隐匿线程 ----
    // 使用NtCreateThreadEx + THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
    // 不在EAC的线程通知回调中暴露
    static HANDLE CreateEACStealthThread(
        LPTHREAD_START_ROUTINE start, PVOID param,
        DWORD creationFlags = 0);

    // ---- 内存区域碎片化 ----
    // 将大块连续分配拆分为多个小分配,
    // 规避EAC对大块 MEM_PRIVATE 内存的扫描
    struct FragmentedAlloc {
        std::vector<void*> pages;
        SIZE_T totalSize;
        SIZE_T pageSize;
    };
    static FragmentedAlloc FragmentedAllocate(SIZE_T totalSize);

    // ---- 释放碎片化分配 ----
    static void FragmentedFree(FragmentedAlloc& alloc);

    // ---- 状态 ----
    bool IsInitialized() const { return m_initialized; }

private:
    InstrumentationCallbackBypass() = default;
    bool m_initialized = false;
};

// ============================================================
// 4. Fake PE Builder — 构造假PE头欺骗EAC内存扫描
//
// EAC每10-40秒扫描游戏进程内存:
//   1. 搜索 MZ(4D5A) + PE(50450000) 签名
//   2. 检查PE结构合法性 (区段数/入口点/大小)
//   3. 验证导入表DLL是否合法
//   4. 检查区段权限组合 (RWX = 可疑)
//
// 规避: 在注入的内存区域放置伪造的合法PE头
// ============================================================

class FakePEBuilder {
public:
    struct FakePEOptions {
        // 基础设置
        bool randomizeTimestamp = true;     // 随机化PE时间戳
        bool randomizeEntryPoint = true;    // 随机化入口点RVA
        bool randomizeImageSize = true;     // 随机化映像大小

        // 目录表
        bool includeExports = true;         // 伪造导出表
        bool includeImports = true;         // 伪造导入表 (常用DLL)
        bool includeRelocations = false;    // 伪造重定位表
        bool includeDebugInfo = true;       // 伪造调试目录 (PDB路径)
        bool includeTLS = false;            // 伪造TLS目录
        bool includeResources = true;       // 伪造资源目录 (含版本信息)

        // Rich Header
        bool includeRichHeader = true;      // 伪造MSVC Rich Header签名

        // 区段
        int sectionCount = 3;               // 伪造的区段数 (.text/.data/.rsrc)

        // PDB路径 (随机化)
        const wchar_t* pdbPath = nullptr;   // nullptr = 自动生成随机路径

        // 伪装类型
        enum class ImpersonateType {
            SystemDll,      // 伪装为系统DLL (ntdll/kernel32/user32)
            GameEngine,     // 伪装为游戏引擎模块 (Unity/Unreal)
            Driver,         // 伪装为驱动 (.sys)
            RandomCommon,   // 随机常用模块
        };
        ImpersonateType impersonateAs = ImpersonateType::SystemDll;
    };

    static const FakePEOptions DefaultOptions;

    // ---- 构建完整假PE头 ----
    // buffer: 输出缓冲区
    // bufferSize: 缓冲区大小
    // 返回: 构造的PE头大小
    static SIZE_T BuildFakePE(void* buffer, SIZE_T bufferSize,
                              const FakePEOptions& options = DefaultOptions);

    // ---- 在内存区域放置假PE头 ----
    // 在region起始位置放置假PE, 返回实际payload起始地址
    static uintptr_t PlaceFakeHeader(void* region, SIZE_T regionSize,
                                     const FakePEOptions& options = DefaultOptions);

    // ---- 仅构建Rich Header ----
    static SIZE_T BuildRichHeader(BYTE* buffer, SIZE_T maxSize);

    // ---- 构建伪造的导入描述符 ----
    static SIZE_T BuildFakeImportTable(BYTE* buffer, SIZE_T maxSize);

    // ---- 构建伪造的区段表 ----
    static SIZE_T BuildFakeSectionHeaders(BYTE* buffer, int sectionCount,
                                          SIZE_T imageSize);

private:
    FakePEBuilder() = default;

    // 常用合法DLL列表
    static const wchar_t* s_commonDlls[];

    // 随机生成合法模块名
    static std::wstring GenerateRandomPDBPath();

    // 生成合法子系统的区段名
    static const char* GetFakeSectionName(int index);
};

// ============================================================
// 5. Code Virtualizer — 自定义字节码VM
//
// 将关键代码段转化为自定义字节码, 由嵌入式VM解释执行
// 使静态分析/签名扫描完全失效
//
// VM架构:
//   - 16个虚拟寄存器 (vreg[16])
//   - 虚拟栈 (独立于本机栈)
//   - 虚拟标志位 (Zero/Carry/Overflow)
//   - 26+条虚拟指令 (含混淆变体)
// ============================================================

class CodeVirtualizer {
public:
    // VM执行上下文
    struct VMContext {
        uintptr_t vreg[16];         // 虚拟寄存器 r0-r15
        uintptr_t* vstack;          // 虚拟栈底
        SIZE_T vstackSize;          // 虚拟栈大小 (word数)
        uintptr_t* vsp;             // 虚拟栈指针
        const BYTE* vip;            // 虚拟指令指针
        bool vf_zero;               // 零标志
        bool vf_carry;              // 进位标志
        bool vf_overflow;           // 溢出标志

        // 外部调用接口
        std::function<uintptr_t(const char*, const char*)> resolveImport;
        // syscall代理
        std::function<NTSTATUS(DWORD, PVOID)> syscallProxy;
    };

    // 虚拟操作码 (包含混淆变体)
    enum class VMOpcode : BYTE {
        // 基础操作
        NOP      = 0x00,
        PUSH_R   = 0x01,    // 压栈寄存器
        POP_R    = 0x02,    // 弹栈到寄存器
        MOV_RR   = 0x03,    // 寄存器到寄存器
        MOV_RI   = 0x04,    // 立即数到寄存器
        MOV_RM   = 0x05,    // 内存到寄存器
        MOV_MR   = 0x06,    // 寄存器到内存
        LEA      = 0x07,    // 加载有效地址

        // 算术
        ADD_RR   = 0x08,
        SUB_RR   = 0x09,
        XOR_RR   = 0x0A,
        AND_RR   = 0x0B,
        OR_RR    = 0x0C,
        SHL_RI   = 0x0D,
        SHR_RI   = 0x0E,
        IMUL_RR  = 0x0F,
        IDIV_R   = 0x10,    // r0=rdx:rax / rN

        // 比较/跳转
        CMP_RR   = 0x11,
        JMP_REL  = 0x12,    // 相对跳转
        JE_REL   = 0x13,    // 等于跳转
        JNE_REL  = 0x14,
        JG_REL   = 0x15,    // 大于(signed)跳转
        JL_REL   = 0x16,

        // 调用
        CALL_VM  = 0x17,    // VM内调用
        RET_VM   = 0x18,    // VM内返回
        SYSCALL  = 0x19,    // 间接系统调用
        CALLEXT  = 0x1A,    // 调用外部函数 (通过resolveImport)
        LOADL    = 0x1B,    // 加载库
        GETP     = 0x1C,    // 获取函数地址

        // 混淆变体 (行为与基础操作相同但编码不同)
        NOP_V1   = 0x20,
        NOP_V2   = 0x21,
        NOP_V3   = 0x22,
        NOP_V4   = 0x23,
        ADD_V1   = 0x24,
        ADD_V2   = 0x25,
        MOV_V1   = 0x26,
        MOV_V2   = 0x27,
        XOR_V1   = 0x28,
        PUSH_VI  = 0x29,    // 立即数压栈 (混淆用的特殊形式)
        POP_DROP = 0x2A,    // 弹栈丢弃
        SWAP_RR  = 0x2B,    // 交换寄存器
        NOT_R    = 0x2C,    // 按位取反
        NEG_R    = 0x2D,    // 取负

        HALT     = 0xFF,
    };

    static CodeVirtualizer& Instance();

    // ---- 初始化VM ----
    bool Initialize(SIZE_T vstackSize = 0x4000);

    // ---- 执行字节码 ----
    // bytecode: 字节码数据
    // size: 字节码大小
    // ctx: 执行上下文 (需要预先设置vreg/vstack等)
    // 返回: 是否正常HALT
    bool Execute(const BYTE* bytecode, SIZE_T size, VMContext& ctx);

    // ---- 虚拟化代码区域 ----
    // 将x64机器码转换为VM字节码 (基础翻译器)
    static std::vector<BYTE> VirtualizeRegion(const void* code, SIZE_T size);

    // ---- 生成随机NOP序列 ----
    static std::vector<BYTE> GenerateNopSled(SIZE_T count);

    // ---- 加密字节码 ----
    // XOR+字节置换, 运行时解密
    static void EncryptBytecode(std::vector<BYTE>& bytecode, uint64_t key);

    // ---- 解密字节码 (内联解密, 原地修改) ----
    static void DecryptBytecode(std::vector<BYTE>& bytecode, uint64_t key);

private:
    CodeVirtualizer() = default;

    // VM指令分发
    void Dispatch(const VMOpcode op, VMContext& ctx);

    // 混淆变体展开 (将混淆opcode映射到基础opcode)
    static VMOpcode NormalizeOpcode(VMOpcode op);

    // 随机扩展操作 (一条指令→多条等效指令)
    static void ExpandToJunkOps(const VMOpcode op, std::vector<BYTE>& output);

    VMContext* m_activeCtx = nullptr;
    bool m_initialized = false;
};

// ============================================================
// 6. Polymorphic Code — 运行时多态代码生成
//
// 击败基于字节模式的特征扫描 (EAC的PE扫描+代码段校验)
// 每次执行时生成语义等价但编码不同的代码
// ============================================================

class PolymorphicCode {
public:
    // 等价变换类型
    enum class EquivType {
        Random,          // 随机选择等价形式
        Shortest,        // 最短编码
        MostObfuscated,  // 最混淆形式
    };

    // ---- 多态代码生成 ----
    // 将输入代码变换为语义等价的变体
    // 返回新代码大小 (可能>原大小)
    static SIZE_T MutateCode(void* code, SIZE_T codeSize,
                             EquivType type = EquivType::Random);

    // ---- 生成多态函数序言 ----
    // push rbp; mov rbp, rsp; sub rsp, X 的等价变体
    static SIZE_T GeneratePrologue(BYTE* buffer, SIZE_T maxSize, SIZE_T frameSize);

    // ---- 生成多态函数尾声 ----
    // add rsp, X; pop rbp; ret 的等价变体
    static SIZE_T GenerateEpilogue(BYTE* buffer, SIZE_T maxSize, SIZE_T frameSize);

    // ---- 在代码中插入垃圾指令 ----
    // 在不改变语义的前提下插入随机无操作指令
    static SIZE_T InsertJunkInstructions(BYTE* buffer, SIZE_T codeSize,
                                          SIZE_T maxSize, DWORD junkPerInst);

    // ---- 生成死代码块 ----
    // 生成完全随机但语法正确的x64代码 (永不执行)
    static SIZE_T GenerateDeadCode(BYTE* buffer, SIZE_T maxSize);

    // ---- 寄存器重命名 ----
    // 将代码中的所有寄存器引用替换为等效寄存器
    // (仅在不冲突时, 如: rax→r8, rcx→r9等)
    static SIZE_T RemapRegisters(BYTE* buffer, SIZE_T codeSize);

private:
    PolymorphicCode() = default;

    // 单条指令的等价变换表
    struct Equivalent {
        BYTE pattern[8];       // 指令模式 (可变长)
        SIZE_T patternSize;
        std::vector<std::vector<BYTE>> alternatives; // 等价编码列表
    };

    static const Equivalent* FindEquivalent(const BYTE* instr, SIZE_T maxLen);

    // 常用等价变换
    static void PushRegEquiv(int reg, std::vector<BYTE>& out);
    static void PopRegEquiv(int reg, std::vector<BYTE>& out);
    static void MoveImmEquiv(int reg, uint64_t val, std::vector<BYTE>& out);
    static void XorRegRegEquiv(int reg1, int reg2, std::vector<BYTE>& out);
};

} // namespace eac
} // namespace stealth
