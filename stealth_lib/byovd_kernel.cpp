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
#include <algorithm>
#include <fstream>
#include <random>
#include <ctime>
#include <cstdarg>
#include <Psapi.h>
#include <shlobj.h>
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

// ★ v3.104: 存储探测到的 IOCTL 码 (读/写分开)
static uint32_t g_probedReadIoctl  = 0;
static uint32_t g_probedWriteIoctl = 0;

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

// v3.57: 仅 RTCore64 — 其他驱动无嵌入文件, 从候选列表移除
static const BYOVDDriverInfo* g_driverCandidates[] = {
    &BYOVDDrivers::RTCore64,
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
// 优先级:
//   0. 给定路径直接存在 (MutateAndRandomizeDriver 已写入 %TEMP%)
//   1. System32\drivers\<name> (系统已安装)
//   2. %TEMP%\<name> (从嵌入字节提取)
// ============================================================
static std::wstring EnsureDriverFile(const std::wstring& driverName) {
    // ★ v3.126q: 确保随机种子在此函数首次调用前已初始化
    //   EnsureDriverFile 在 Initialize 中被 srand 之前调用, 需独立初始化
    static bool srandSeeded = false;
    if (!srandSeeded) { srand(GetTickCount() ^ __rdtsc()); srandSeeded = true; }

    // ★ v3.97: 0. 先检查给定路径是否直接存在 (MutateAndRandomizeDriver 已写入 TEMP)
    if (GetFileAttributesW(driverName.c_str()) != INVALID_FILE_ATTRIBUTES) {
        ByovdDiag("BYOVD:EnsureDriverFile: file exists at given path '%ls'\n", driverName.c_str());
        return driverName;
    }

    wchar_t sysPath[MAX_PATH];

    // 1. 检查 System32\drivers
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\drivers\\");
    wcscat_s(sysPath, driverName.c_str());

    if (GetFileAttributesW(sysPath) != INVALID_FILE_ATTRIBUTES) {
        return std::wstring(sysPath); // 系统已安装
    }

    // 2. 从嵌入字节提取到 %TEMP%
    {
        const uint8_t* embedData = nullptr;
        size_t embedSize = 0;

        // 匹配驱动文件名 (支持纯文件名和完整路径)
        const wchar_t* baseName = driverName.c_str();
        const wchar_t* lastSlash = wcsrchr(baseName, L'\\');
        if (lastSlash) baseName = lastSlash + 1;

        if (wcscmp(baseName, L"RTCore64.sys") == 0) {
            embedData = stealth::embedded::RTCore64_data;
            embedSize = stealth::embedded::RTCore64_size;
            ByovdDiag("BYOVD:EnsureDriverFile: matched RTCore64, embed=0x%p size=%zu\n", embedData, embedSize);
        } else {
            ByovdDiag("BYOVD:EnsureDriverFile: driverName '%ls' != RTCore64.sys\n", driverName.c_str());
        }

        if (embedData && embedSize > 0) {
            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);

            // ★ v3.110: 使用完全随机文件名, 不再使用 "RTCore64_XXXX.sys" 模式
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
                    ByovdDiag("BYOVD:EnsureDriverFile: constructing wstring from '%ls'...\n", tryPath);
                    std::wstring result(tryPath);
                    ByovdDiag("BYOVD:EnsureDriverFile: wstring constructed OK (len=%zu)\n", result.length());
                    return result;
                }
                ByovdDiag("BYOVD:EnsureDriverFile: CreateFileW FAILED for %ls (err=%u, retry=%d)\n", tryPath, GetLastError(), retry);
            }
        } else {
            ByovdDiag("BYOVD:EnsureDriverFile: embedData=0x%p or embedSize=%zu — skipping\n", embedData, embedSize);
        }
    }

    return L"";
}

// ★ v3.75: 强制停止并删除所有残留 RTCore64 服务
//   解决 STATUS_OBJECT_NAME_COLLISION (0xC0000035):
//   之前异常的进程退出导致 \Driver\RTCore64 内核对象未清理,
//   导致再次加载时 NtLoadDriver 返回重名冲突
//   通过 SCM ControlService(SERVICE_CONTROL_STOP) 触发 DriverUnload,
//   然后 NtUnloadDriver + DeleteService 彻底清理
static void ForceRemoveRTCore64Services() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr,
        SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD bytesNeeded = 0, serviceCount = 0, resumeHandle = 0;
    // 第一次调用获取所需缓冲区大小
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded,
        &serviceCount, &resumeHandle, nullptr);
    if (bytesNeeded == 0) { CloseServiceHandle(hSCM); return; }

    // ★ v3.120: VirtualAlloc 替代 std::vector — 避免 CRT 堆依赖
    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, bytesNeeded + 0x100, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseServiceHandle(hSCM); return; }
    auto* services = (ENUM_SERVICE_STATUS_PROCESSW*)buf;
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_STATE_ALL, buf, (DWORD)(bytesNeeded + 0x100), &bytesNeeded,
        &serviceCount, &resumeHandle, nullptr)) {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseServiceHandle(hSCM);
        return;
    }

    for (DWORD i = 0; i < serviceCount; i++) {
        bool isOurSvc = (wcsstr(services[i].lpServiceName, L"RTCore64") == services[i].lpServiceName)
                     || (wcsstr(services[i].lpServiceName, L"SysMon") == services[i].lpServiceName);
        if (!isOurSvc)
            continue;

        ByovdDiag("BYOVD:ForceRemove: found stale service '%ls' (state=%u)\n",
            services[i].lpServiceName, services[i].ServiceStatusProcess.dwCurrentState);

        SC_HANDLE hSvc = OpenServiceW(hSCM, services[i].lpServiceName,
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (!hSvc) continue;

        // 发送 STOP 控制码 → 触发驱动的 DriverUnload 例程
        SERVICE_STATUS svcStatus;
        if (ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus)) {
            // 等待驱动完全卸载 (最多等 3 秒)
            for (int wait = 0; wait < 30; wait++) {
                if (!QueryServiceStatus(hSvc, &svcStatus)) break;
                if (svcStatus.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(100);
            }
        }

        // 删除服务
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);

        // ★ 兜底: 用 NtUnloadDriver 再试一次 (确保内核对象释放)
        std::wstring regPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        regPath += services[i].lpServiceName;
        UNICODE_STRING us;
        us.Buffer = regPath.data();
        us.Length = (USHORT)(regPath.size() * sizeof(wchar_t));
        us.MaximumLength = us.Length + sizeof(wchar_t);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            using NtUnloadDriver_t = NTSTATUS(NTAPI*)(PUNICODE_STRING);
            auto pNtUnloadDriver = (NtUnloadDriver_t)GetProcAddress(ntdll, "NtUnloadDriver");
            if (pNtUnloadDriver) pNtUnloadDriver(&us);
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    CloseServiceHandle(hSCM);
}

bool KernelMemoryAccessor::LoadDriver(const std::wstring& serviceName, 
                                       const std::wstring& driverPath) {
    // ★ v3.92: 必须先启用特权再清理 — ForceRemoveRTCore64Services 内部也调用 NtUnloadDriver
    EnablePrivilege(L"SeLoadDriverPrivilege");

    // ★ v3.75: 加载前强制清理所有残留 RTCore64 服务/驱动
    ForceRemoveRTCore64Services();

    // 注册表: 创建服务条目
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
    HKEY hKey;

    // v3.61: 先尝试卸载旧驱动 (需要 registry key 还未删除)
    UnloadDriver(serviceName);

    // v3.55: 删旧服务再重建 — 防止残留键导致 STATUS_OBJECT_NAME_INVALID
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    
    // ★ v3.97: DeleteService 只标记删除, 键可能仍存在 (ERROR_ALREADY_EXISTS=183)
    //   先尝试创建, 若已存在则打开现有键
    LONG regResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(),
                        0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, nullptr, &hKey, nullptr);
    if (regResult != ERROR_SUCCESS) {
        if (regResult == ERROR_ALREADY_EXISTS) {
            // 键已存在 (DeleteService 标记删除但未清理), 尝试打开
            regResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(),
                                      0, KEY_ALL_ACCESS, &hKey);
        }
        if (regResult != ERROR_SUCCESS) {
            ByovdDiag("BYOVD:LoadDriver: RegCreateKeyEx/RegOpenKeyEx FAILED (err=%u)\n", regResult);
            return false;
        }
        ByovdDiag("BYOVD:LoadDriver: opened existing key (was marked for deletion)\n");
    }

    DWORD type = 1; // SERVICE_KERNEL_DRIVER
    DWORD start = 3; // SERVICE_DEMAND_START
    DWORD errorControl = 1; // SERVICE_ERROR_NORMAL

    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&type, sizeof(type));
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&start, sizeof(start));
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&errorControl, sizeof(errorControl));

    // 使用驱动文件名(同目录)或系统路径
    wchar_t fullPath[MAX_PATH];
    if (driverPath.find(L'\\') == std::wstring::npos) {
        // 仅文件名 → 补充完整路径
        GetSystemDirectoryW(fullPath, MAX_PATH);
        wcscat_s(fullPath, L"\\drivers\\");
        wcscat_s(fullPath, driverPath.c_str());
    } else {
        wcscpy_s(fullPath, driverPath.c_str());
    }

    // v3.48: 内核需要 NT 路径格式 — 自动加 \??\ 前缀
    wchar_t ntPath[MAX_PATH * 2];
    if (fullPath[0] != L'\\' && fullPath[1] != L'\\') {
        swprintf_s(ntPath, L"\\??\\%ls", fullPath);
    } else {
        wcscpy_s(ntPath, fullPath);
    }

    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
                   (BYTE*)ntPath, (DWORD)((wcslen(ntPath) + 1) * sizeof(wchar_t)));
    ByovdDiag("BYOVD:LoadDriver: ImagePath=%ls\n", ntPath);
    RegCloseKey(hKey);

    // 调用 NtLoadDriver (走 syscall 更安全, 但这里用直接调用)
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    using NtLoadDriver_t = NTSTATUS(NTAPI*)(PUNICODE_STRING);
    auto pNtLoadDriver = (NtLoadDriver_t)GetProcAddress(ntdll, "NtLoadDriver");
    if (!pNtLoadDriver) return false;

    std::wstring regPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
    UNICODE_STRING us;
    us.Buffer = regPath.data();
    us.Length = (USHORT)(regPath.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);

    NTSTATUS status = pNtLoadDriver(&us);
    ByovdDiag("BYOVD:LoadDriver: NtLoadDriver → 0x%08X\n", status);
    // STATUS_IMAGE_ALREADY_LOADED (0xC000010E) 也是成功
    return NT_SUCCESS(status) || status == 0xC000010E;
}

bool KernelMemoryAccessor::UnloadDriver(const std::wstring& serviceName) {
    // ★ v3.87: NtUnloadDriver 需要 SeLoadDriverPrivilege, 否则静默失败
    //         之前缺少此特权导致驱动无法卸载 → zombie \Device\RTCore64 残留
    EnablePrivilege(L"SeLoadDriverPrivilege");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    using NtUnloadDriver_t = NTSTATUS(NTAPI*)(PUNICODE_STRING);
    auto pNtUnloadDriver = (NtUnloadDriver_t)GetProcAddress(ntdll, "NtUnloadDriver");
    if (!pNtUnloadDriver) return false;

    std::wstring regPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
    UNICODE_STRING us;
    us.Buffer = regPath.data();
    us.Length = (USHORT)(regPath.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);

    NTSTATUS st = pNtUnloadDriver(&us);
    ByovdDiag("BYOVD:UnloadDriver: %ls → 0x%08X\n", serviceName.c_str(), (uint32_t)st);
    return NT_SUCCESS(st);
}

bool KernelMemoryAccessor::EnablePrivilege(const wchar_t* privilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueW(nullptr, privilegeName, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
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
// 内核虚拟地址读写 (通过 PhysicalReadViaIOCTL / PhysicalWriteViaIOCTL)
// ★ v3.124: 实际测试证实 0x80002048 直接读写内核VA (非物理地址),
//   BUILD 407 (v3.109) 已验证此方案正常工作。
//   VirtualReadViaIOCTL (0x80002000) 在此RTCore64版本不支持 (err=87)。
// ============================================================

bool KernelMemoryAccessor::ReadKernelVA(uint64_t va, void* outBuf, size_t size) {
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false;

    // ★ v3.124: 使用 PhysicalReadViaIOCTL (0x80002048) — 此RTCore64版本直接将地址作为内核VA处理
    //   VirtualReadViaIOCTL (0x80002000) 在此RTCore64版本不支持 (err=87)
    return PhysicalReadViaIOCTL(m_hDevice, g_probedReadIoctl, va, outBuf, size);
}

bool KernelMemoryAccessor::WriteKernelVA(uint64_t va, const void* inBuf, size_t size) {
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false;

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

// ★ v3.116: std::string 重载 — 委托给 const char* 版本 (避免 CRT 堆分配)
uint64_t KernelMemoryAccessor::GetKernelModuleBase(const std::string& moduleName) {
    return GetKernelModuleBase(moduleName.c_str());
}

// ============================================================
// 初始化 / 清理
// ============================================================

bool KernelMemoryAccessor::Initialize(const BYOVDDriverInfo& driver) {
    ByovdDiag("BYOVD:Init: ENTER (driverPath='%ls' svcName='%ls')\n",
        driver.driverPath.c_str(), driver.serviceName.c_str());
    m_driverInfo = driver;
    ByovdDiag("BYOVD:Init: m_driverInfo copied OK\n");

    // 1. 检测 HVCI
    if (IsHVCIEnabled()) {
        ByovdDiag("BYOVD:Init: HVCI ENABLED (will likely block driver load)\n");
    }
    ByovdDiag("BYOVD:Init: HVCI check done\n");

    // 2. 确保驱动文件存在 (System32\drivers → 嵌入提取到 %TEMP%)
    ByovdDiag("BYOVD:Init: calling EnsureDriverFile('%ls')...\n", driver.driverPath.c_str());
    std::wstring resolvedPath = EnsureDriverFile(driver.driverPath);
    ByovdDiag("BYOVD:Init: EnsureDriverFile returned, string length=%zu\n", resolvedPath.length());
    ByovdDiag("BYOVD:Init: EnsureDriverFile returned '%ls'\n", resolvedPath.c_str());
    const std::wstring& actualPath = resolvedPath.empty() ? driver.driverPath : resolvedPath;

    // ★ v3.110: 彻底随机化服务名 — 使用完全随机的12字符名称
    //   不再使用 "RTCore64Svc_XXXX" 模式 (含 "RTCore64" 是强特征)
    //   使用类似 "UxUpdateSvc" 的合法服务名风格
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
    std::wstring actualServiceName(svcName);
    m_actualServiceName = actualServiceName;  // store for cleanup

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
                // 匹配 RTCore64Svc/SysMon (旧格式, 直接匹配)
                bool isStaleSvc = (wcsstr(subKeyName, L"RTCore64Svc") == subKeyName)
                               || (wcsstr(subKeyName, L"SysMon") == subKeyName);
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
                    std::wstring svcName(subKeyName);
                    // 跳过当前要加载的服务名
                    if (svcName == actualServiceName) { idx++; continue; }
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
                    ByovdDiag("BYOVD:Init: found stale service '%ls', unloading...\n", subKeyName);
                    // ★ 先卸载 (需要 registry key 存在)
                    bool unloaded = UnloadDriver(svcName);
                    ByovdDiag("BYOVD:Init: unload %ls → %d\n", subKeyName, (int)unloaded);
                    // 卸载后删除注册表残留
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
        m_driverInfo.devicePath.c_str());

    m_hDevice = CreateFileW(m_driverInfo.devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (m_hDevice != INVALID_HANDLE_VALUE) {
        // ★ v3.114: 已有设备, 直接用默认 IOCTL 码测试内核读取
        //   不再调用 ProbeIoctlCode — 硬编码地址探测会导致蓝屏
        ByovdDiag("BYOVD:Init: existing device opened, testing with default IOCTL 0x%08X...\n",
            m_driverInfo.ioctlCode);
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
        //   NtMakeTemporaryObject 对文件句柄无效 (需要设备对象句柄),
        //   NtOpenDirectoryObject 枚举 \Device 目录在 manual-mapped DLL 中会崩溃.
        //   唯一清理方式: 重启系统.
        ByovdDiag("BYOVD:Init: ZOMBIE DEVICE DETECTED — reboot required to clear\n");
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
        m_active = false;
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
    ByovdDiag("BYOVD:Init: loading %ls (path=%ls)\n", actualServiceName.c_str(), actualPath.c_str());
    bool loadOk = LoadDriver(actualServiceName, actualPath);
    ByovdDiag("BYOVD:Init: LoadDriver → %d\n", (int)loadOk);

    if (!loadOk) {
        // ★ v3.95: NtLoadDriver 失败 — 可能是僵尸设备名冲突
        //   尝试用 DefineDosDeviceW 重建符号链接后打开设备
        //   从 devicePath (如 \\.\RT64_A1B2) 提取 DOS 名和 NT 设备名
        std::wstring devPath = m_driverInfo.devicePath;
        std::wstring dosName, ntDevName;
        if (devPath.size() > 4 && devPath.substr(0, 4) == L"\\\\.\\") {
            dosName = devPath.substr(4);                // e.g. "RT64_A1B2"
            ntDevName = L"\\Device\\" + dosName;        // e.g. "\\Device\\RT64_A1B2"
        } else {
            dosName = L"RTCore64";
            ntDevName = L"\\Device\\RTCore64";
        }

        ByovdDiag("BYOVD:Init: LoadDriver FAILED, trying symlink fix: '%ls' → '%ls'\n",
            dosName.c_str(), ntDevName.c_str());

        if (DefineDosDeviceW(DDD_RAW_TARGET_PATH, dosName.c_str(), ntDevName.c_str())) {
            ByovdDiag("BYOVD:Init: DefineDosDeviceW OK, trying to open...\n");
            m_hDevice = CreateFileW(m_driverInfo.devicePath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (m_hDevice != INVALID_HANDLE_VALUE) {
                // ★ v3.114: 直接用默认 IOCTL 码测试, 不再调用 ProbeIoctlCode
                ByovdDiag("BYOVD:Init: zombie device opened after symlink fix, testing IOCTL 0x%08X...\n",
                    m_driverInfo.ioctlCode);
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
    m_hDevice = CreateFileW(m_driverInfo.devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        ByovdDiag("BYOVD:Init: CreateFileW FAILED for %ls (err=%u)\n",
            m_driverInfo.devicePath.c_str(), GetLastError());
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

    // ★ v3.123: 直接使用 IOCTL 0x80002048/0x4C 读写内核VA
    //   BUILD 407 (v3.109) 已验证此方案正常工作。
    //   不再尝试 IOCTL 0x80002000 (虚拟内存IOCTL) — 此RTCore64版本不支持。
    //   不再降级到物理IOCTL + PageTableWalker — 此前导致BSOD。
    ByovdDiag("BYOVD:Init: STEP_B1 probing IOCTL 0x80002048 (verified working in BUILD 407)...\n");
    {
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

    // ★ v3.110: 驱动加载成功, 立即删除临时文件抹除磁盘痕迹
    if (!actualPath.empty()) {
        ByovdDiag("BYOVD:Init: STEP_C deleting temp file '%ls'...\n", actualPath.c_str());
        if (DeleteFileW(actualPath.c_str())) {
            ByovdDiag("BYOVD:Init: STEP_C deleted OK\n");
        } else {
            // ★ v3.126o: 修复 — 检查删除失败 (AV 锁定 / 权限不足)
            DWORD err = GetLastError();
            ByovdDiag("BYOVD:Init: STEP_C delete FAILED err=%d, retrying with MOVEFILE_DELAY_UNTIL_REBOOT\n", (int)err);
            MoveFileExW(actualPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }

    m_active = true;
    ByovdDiag("BYOVD:Init: STEP_D m_active=true, verifying IOCTL...\n");

    // ★ v3.124: 验证 IOCTL R/W 可用 — 使用 PhysicalReadViaIOCTL (0x80002048)
    //   之前使用了 VirtualReadViaIOCTL (0x80002000) 做验证, 但此RTCore64版本不支持,
    //   导致验证失败后卸载驱动, 虽已成功打开物理IOCTL却功亏一篑。
    {
        uint8_t testBuf[8] = {};
        bool ok = PhysicalReadViaIOCTL(m_hDevice, g_probedReadIoctl, m_ntosBase, testBuf, 8);
        uint32_t readVal = *(uint32_t*)testBuf;
        ByovdDiag("BYOVD:Init: STEP_E PhysicalReadViaIOCTL(ntos+0x0)=%d val=0x%08X\n",
                  (int)ok, readVal);
        if (!ok || readVal == 0 || readVal == 0xFFFFFFFF) {
            ByovdDiag("BYOVD:Init: Physical IOCTL verify FAILED (val=0x%08X)\n", readVal);
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
    // ★ v3.96: 先发送 SERVICE_CONTROL_STOP 触发 DriverUnload → IoDeleteDevice,
    //   再 NtUnloadDriver 彻底卸载。仅 NtUnloadDriver 可能不会触发 Unload 例程,
    //   导致 \Device\RTCore64 设备对象残留 (僵尸设备)。
    EnablePrivilege(L"SeLoadDriverPrivilege");
    m_active = false;
    m_pageTableWalker.reset();
    g_physMappingCount = 0; // ★ v3.118: 固定数组, 无需 clear()

    if (!m_actualServiceName.empty()) {
        // ★ v3.96: SCM STOP → 触发驱动 Unload 例程 → IoDeleteDevice
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr,
            SC_MANAGER_CONNECT);
        if (hSCM) {
            SC_HANDLE hSvc = OpenServiceW(hSCM, m_actualServiceName.c_str(),
                SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (hSvc) {
                SERVICE_STATUS svcStatus;
                if (ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus)) {
                    ByovdDiag("BYOVD:Shutdown: SERVICE_CONTROL_STOP sent, waiting...\n");
                    for (int wait = 0; wait < 30; wait++) {
                        if (!QueryServiceStatus(hSvc, &svcStatus)) break;
                        if (svcStatus.dwCurrentState == SERVICE_STOPPED) break;
                        Sleep(100);
                    }
                    ByovdDiag("BYOVD:Shutdown: service state=%u\n", svcStatus.dwCurrentState);
                } else {
                    ByovdDiag("BYOVD:Shutdown: ControlService FAILED (err=%u)\n", GetLastError());
                }
                CloseServiceHandle(hSvc);
            } else {
                ByovdDiag("BYOVD:Shutdown: OpenService FAILED (err=%u)\n", GetLastError());
            }
            CloseServiceHandle(hSCM);
        }
        // NtUnloadDriver 作为兜底
        UnloadDriver(m_actualServiceName);
    }
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
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
                    if (target > ntBase + 0x100000 && target < ntBase + 0x400000) {
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

int EACCallbackDisabler::DisableObCallbacks(const std::string& eacDriverName) {
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
    uint64_t eacBase = kma.GetKernelModuleBase(eacDriverName + ".sys");
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
                    if (_stricmp(ansiName, (eacDriverName + ".sys").c_str()) == 0) {

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
            i, eacDriverName.c_str());
    }
    return removed;
}

int EACCallbackDisabler::DisableProcessNotifyCallbacks(const std::string& eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    uint64_t eacBase = kma.GetKernelModuleBase(eacDriverName + ".sys");
    if (!eacBase) {
        // BUILD 456: 自体验证
        ByovdDiag("VERIFY:ProcessNotify: '%s.sys' not loaded — skip scan (would scan if driver loaded)\n",
            eacDriverName.c_str());
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

int EACCallbackDisabler::DisableImageNotifyCallbacks(const std::string& eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    uint64_t eacBase = kma.GetKernelModuleBase(eacDriverName + ".sys");
    if (!eacBase) {
        // BUILD 456: 自体验证
        ByovdDiag("VERIFY:ImageNotify: '%s.sys' not loaded — skip scan (would scan if driver loaded)\n",
            eacDriverName.c_str());
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

int EACCallbackDisabler::DisableAll(const std::string& eacDriverName) {
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

            // 断链: Blink→Flink = 我们的Flink, Flink→Blink = 我们的Blink
            // 即: 前一个节点的 Flink 指向后一个节点
            //     后一个节点的 Blink 指向前一个节点
            // 这样跳过了当前节点
            kma.Write(blinkVA, flink);        // prev.Flink = next
            kma.Write(flinkVA + 8, blink);    // next.Blink = prev

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
    //   改为使用原始未修改驱动 + 原始设备名 \\.\RTCore64,
    //   通过 SCM 清理 + DefineDosDeviceW 修复僵尸设备来避免冲突。
    //
    //   仅随机化服务名 (注册表唯一性), 驱动内容保持原样。

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
    if (original.driverPath == L"RTCore64.sys") {
        embedData = stealth::embedded::RTCore64_data;
        embedSize = stealth::embedded::RTCore64_size;
    }
    ByovdDiag("BYOVD:Mutate: embedData=0x%p embedSize=%zu\n", embedData, embedSize);

    if (!embedData || embedSize == 0 || embedSize > 100 * 1024 * 1024) {
        ByovdDiag("BYOVD:Mutate: no embedded data, falling back to file system\n");
        // 回退到文件系统
        std::wstring srcPath;
        {
            wchar_t sysDir[MAX_PATH];
            GetSystemDirectoryW(sysDir, MAX_PATH);
            wcscat_s(sysDir, L"\\drivers\\");
            wcscat_s(sysDir, original.driverPath.c_str());
            if (GetFileAttributesW(sysDir) == INVALID_FILE_ATTRIBUTES) {
                srcPath = original.driverPath;
            } else {
                srcPath = sysDir;
            }
        }
        HANDLE hSrc = CreateFileW(srcPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
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
        // 直接写入原始嵌入数据 (不做任何修改)
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

    if (GetFileAttributesW(tempPath) == INVALID_FILE_ATTRIBUTES) return original;

    // 构建驱动信息: 使用原始设备名 \\.\RTCore64 (驱动内部硬编码),
    //   仅服务名随机化以避免注册表冲突
    BYOVDDriverInfo mutated;
    mutated.devicePath = original.devicePath;     // ★ 保持原始 \\.\RTCore64
    mutated.ioctlCode = original.ioctlCode;
    mutated.needsMemoryMap = original.needsMemoryMap;
    mutated.driverPath = tempPath;

    wchar_t svcName[64] = {};
    wsprintfW(svcName, L"SysMon%s", randomHex);
    mutated.serviceName = svcName;
    wchar_t dspName[64] = {};
    wsprintfW(dspName, L"System Monitor %s", randomHex);
    mutated.displayName = dspName;

    ByovdDiag("BYOVD:Mutate: device=%ls svc=%ls path=%ls\n",
        mutated.devicePath.c_str(), mutated.serviceName.c_str(), mutated.driverPath.c_str());

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
static std::wstring ReadKernelUnicodeString(uint64_t poolAddr, uint16_t lenBytes) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!poolAddr || !lenBytes) return L"";

    uint16_t chars = lenBytes / 2;
    if (chars > 256) chars = 256; // 安全限制

    std::vector<wchar_t> buf(chars);
    if (kma.ReadKernelVA(poolAddr, buf.data(), chars * 2)) {
        return std::wstring(buf.data(), chars);
    }
    return L"";
}

// === 目标驱动名列表 — 需要从痕迹表中清除 ===
static const wchar_t* g_traceTargetNames[] = {
    L"RTCore64.sys",
    L"RTCore64",
    nullptr
};

static bool IsTraceTarget(const std::wstring& name) {
    // ★ v3.126m-review: 修复 — 精确匹配 (wcsstr 包含匹配已足够, 但不误伤)
    //   只匹配全名中包含 RTCore64.sys 或 RTCore64 的条目
    for (int i = 0; g_traceTargetNames[i]; i++) {
        if (name.find(g_traceTargetNames[i]) != std::wstring::npos)
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

        std::wstring name = ReadKernelUnicodeString(nameBuf, nameLen);
        if (name.empty()) continue;

        if (IsTraceTarget(name)) {
            ByovdDiag("TRACE:MmUnloadedDrivers: [%d] found '%ls' → clearing\n", idx, name.c_str());
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
        std::wstring name = ReadKernelUnicodeString(entry.DriverNameBuffer, entry.DriverNameLength);
        if (IsTraceTarget(name)) {
            ByovdDiag("TRACE:PiDDBCache: found '%ls' (stamp=0x%llX) at depth=%d\n",
                name.c_str(), (unsigned long long)entry.TimeDateStamp, depth);
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
    std::vector<uint8_t> chunk(0x10000);
    for (uint64_t addr = scanStart; addr < scanEnd; addr += 0x10000) {
        if (!kma.ReadKernelVA(addr, chunk.data(), chunk.size()))
            continue;

        for (size_t off = 0; off < chunk.size() - 0x78; off += 8) {
            KernRTL_AVL_TABLE* table = (KernRTL_AVL_TABLE*)(chunk.data() + off);
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
            if (!kma.ReadKernelVA(addr, chunk.data(), 0x1000))
                continue;
            for (size_t off = 0; off < 0x1000 - 0x100; off += 8) {
                // 查找可能的 AVL 表: 扫描表头 0x78 字节后的区域
                // PiDDBLock + 0x80 处常有 0 的 ERESOURCE 和 AVL 表
                KernRTL_AVL_TABLE* table = (KernRTL_AVL_TABLE*)(chunk.data() + off);
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
        return false;
    }

    // 读取 AVL 表的根节点并开始遍历
    KernRTL_AVL_TABLE table = {};
    if (!kma.ReadKernelVA(foundTable, &table, sizeof(table)))
        return false;

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

                std::wstring name = ReadKernelUnicodeString(strPtr, strLen);
                if (IsTraceTarget(name)) {
                    ByovdDiag("TRACE:CiHashBucket: found '%ls' at ci+0x%zX → clearing\n",
                        name.c_str(), (size_t)(addr + off - 8 - ciBase));
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
static uint64_t FindPacFilterInKernel(uint64_t fltmgrBase, uint64_t fltGlobals, std::wstring& outName);
static bool IsPacPattern(const wchar_t* name);
static std::wstring GetPacTargetName();
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

    std::vector<uint8_t> chunk(0x10000);
    for (uint64_t addr = scanStart; addr < scanEnd; addr += 0x10000) {
        if (!kma.ReadKernelVA(addr, chunk.data(), chunk.size()))
            continue;
        for (size_t off = 0; off < chunk.size() - 3; off++) {
            if (chunk[off] == stub[0] && chunk[off+1] == stub[1] && chunk[off+2] == stub[2]) {
                uint64_t stubAddr = addr + off;
                ByovdDiag("FLT:NTRL: found ret0 stub at fltmgr+0x%llX\n",
                    (unsigned long long)(stubAddr - fltmgrBase));
                return stubAddr;
            }
        }
    }
    ByovdDiag("FLT:NTRL: ret0 stub not found in fltmgr\n");
    return 0;
}

// BUILD 458: 辅助函数 — 从 fltmgr 函数体中 sigscan 查找 FltGlobals
// 模式: LEA/MOV RXX, [RIP + xx xx xx xx] → 目标在 fltmgr .data 段
// 分块读取 4096 字节 (部分 Windows 版本函数体超大, FltRegisterFilter 可达 2KB+)
static uint64_t ScanFuncForFltGlobals(uint64_t fltmgrBase, uint64_t targetFunc) {
    auto& kma = KernelMemoryAccessor::Instance();
    uint8_t buf[512] = {};

    for (int chunk = 0; chunk < 8; chunk++) {
        if (!kma.ReadKernelVA(targetFunc + chunk * 512, buf, sizeof(buf)))
            break;

        for (int i = 0; i < 500; i++) {
            // LEA/MOV RXX, [RIP+rel32]: 48/4C/4D prefix
            if ((buf[i] == 0x48 || buf[i] == 0x4C || buf[i] == 0x4D) &&
                (buf[i+1] == 0x8D || buf[i+1] == 0x8B) &&
                (buf[i+2] & 0xC7) == 0x05) {
                int32_t rel32 = *(int32_t*)(buf + i + 3);
                uint64_t candidate = targetFunc + chunk * 512 + i + 7 + rel32;
                if (candidate > fltmgrBase + 0x100000 && candidate < fltmgrBase + 0x400000) {
                    return candidate;
                }
            }
        }
    }
    return 0;
}

// BUILD 455/457: 多函数 fallback 查找 FltGlobals + MOV 变体
// 先 LEA 后 MOV 扫描 RIP-relative 指令 → fltmgr .data 段
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
            ByovdDiag("FLT:NTRL: FltGlobals at 0x%llX (via %s)\n",
                (unsigned long long)candidate, exportName);
            return candidate;
        }
        ByovdDiag("FLT:NTRL: %s found but no .data LEA/MOV ref\n", exportName);
    }
    ByovdDiag("FLT:NTRL: FltGlobals not found via any export\n");
    return 0;
}

// 在 FilterList 中查找指定名称的 FLT_FILTER
uint64_t MinifilterNeutralizer::FindFilterByName(uint64_t fltmgrBase, uint64_t fltGlobals, const wchar_t* name) {
    auto& kma = KernelMemoryAccessor::Instance();
    ByovdDiag("FLT:NTRL: finding filter '%ls'\n", name);

    // FltGlobals → FrameList (FltGlobals + 0x000 → LIST_ENTRY / FLTP_FRAME*)
    uint64_t frameList = 0;
    if (!kma.ReadKernelVA(fltGlobals, &frameList, sizeof(frameList))) {
        ByovdDiag("FLT:NTRL: cannot read FrameList from FltGlobals\n");
        return 0;
    }
    if (!frameList || frameList < fltmgrBase || frameList > fltmgrBase + 0x500000) {
        ByovdDiag("FLT:NTRL: FrameList invalid 0x%llX\n", (unsigned long long)frameList);
        return 0;
    }

    // FLTP_FRAME.FilterList 通常在 +0x140 偏移
    //  尝试几个已知偏移进行匹配
    uint64_t filterOffsets[] = { 0x140, 0x148, 0x150, 0x138 };
    uint64_t filterListHead = 0;

    for (uint64_t off : filterOffsets) {
        uint64_t addr = frameList + off;
        uint64_t flink = 0, blink = 0;
        if (kma.ReadKernelVA(addr, &flink, sizeof(flink)) &&
            kma.ReadKernelVA(addr + 8, &blink, sizeof(blink))) {
            // FilterList 非空: Flink → 第一个 FLT_FILTER.ActiveLink
            //   Flink 应该 != Blink (非空链表), 且 Flink 应在内核池中
            if (flink != addr && flink > 0xFFFF800000000000ULL && blink > 0xFFFF800000000000ULL) {
                filterListHead = addr;
                ByovdDiag("FLT:NTRL: FilterList head at frame+0x%llX\n", off);
                break;
            }
        }
    }

    if (!filterListHead) {
        ByovdDiag("FLT:NTRL: FilterList not found in FLTP_FRAME\n");
        return 0;
    }

    // 遍历 FilterList 链表
    // FLT_FILTER.ActiveLink 在 FLT_FILTER + 0x008
    // Name.UNICODE_STRING 的偏移需要运行时检测 (尝试几个常见偏移)
    uint64_t nameOffsets[] = { 0x188, 0x198, 0x1A8, 0x178 }; // Win10/11 变体

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

                    std::wstring filterName = ReadKernelUnicodeString(nameBuf, nameLen);
                    if (_wcsicmp(filterName.c_str(), name) == 0) {
                        ByovdDiag("FLT:NTRL: found '%ls' at 0x%llX (nameOff=0x%llX)\n",
                            filterName.c_str(), (unsigned long long)filterBase, nameOff);
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
    std::wstring pacName = GetPacTargetName();
    uint64_t filterAddr = FindFilterByName(fltmgrBase, fltGlobals, pacName.c_str());
    if (!filterAddr) {
        // ★ v3.126p: 精确匹配失败 → 尝试内核模糊扫描
        std::wstring kernName;
        filterAddr = FindPacFilterInKernel(fltmgrBase, fltGlobals, kernName);
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

bool MinifilterNeutralizer::IsMessageTransferNeutralized() {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return true; // BYOVD 未激活时不报错

    // 检查 fltmgr FilterFindFirst 列表中的 minifilter 是否仍然是 stub
    // 简化为: 检查 fltmgr 内是否有非 stub 的 MessageTransfer 回调
    uint64_t fltmgrBase = kma.GetKernelModuleBase("fltmgr.sys");
    if (!fltmgrBase) return true;

    uint64_t fltGlobals = FindFltGlobals(fltmgrBase);
    if (!fltGlobals) return true; // 找不到 Globals 不报错

    uint64_t filterAddr = FindFilterByName(fltmgrBase, fltGlobals, GetPacTargetName().c_str());
    if (!filterAddr) {
        // ★ v3.126p: 精确匹配失败 → 模糊扫描
        std::wstring kernName;
        filterAddr = FindPacFilterInKernel(fltmgrBase, fltGlobals, kernName);
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
static std::wstring g_cachedPacName;
static DWORD     g_lastPacNameCheck = 0;

static std::wstring GetPacTargetName() {
    DWORD now = GetTickCount();
    if (!g_cachedPacName.empty() && now - g_lastPacNameCheck < 30000)
        return g_cachedPacName;
    g_lastPacNameCheck = now;

    // 枚举所有 minifilter, 找 PAC 匹配
    std::wstring found;
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
                if (IsPacPattern(fn)) { found = fn; break; }
                hr = pFN(hF,buf,sizeof(buf),&br);
            }
            if (hF) pFC(hF);
        }
        FreeLibrary(hFltLib);
    }
    if (found.empty()) found = L"MessageTransfer"; // 回退默认
    g_cachedPacName = found;
    return found;
}

static void RefreshPacName() { g_cachedPacName.clear(); g_lastPacNameCheck=0; GetPacTargetName(); }

// ★ v3.126p: wstring → string 辅助转换
static std::string WStringToString(const std::wstring& ws) {
    if (ws.empty()) return "";
    int len = WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

// ★ v3.126p: 内核层模糊扫描 PAC minifilter (用于 Neutralize 失败后的回退)
static uint64_t FindPacFilterInKernel(uint64_t fltmgrBase, uint64_t fltGlobals, std::wstring& outName) {
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
                    std::wstring filterName = ReadKernelUnicodeString(nameBuf, nameLen);
                    if (IsPacPattern(filterName.c_str())) {
                        outName = filterName;
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
        if (_wcsicmp(filterName, GetPacTargetName().c_str()) == 0) {
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

    std::wstring pacName = GetPacTargetName();
    SC_HANDLE svc = OpenServiceW(scm, pacName.c_str(),
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE | SERVICE_START);
    if (!svc) {
        ByovdDiag("PAC: SCM service '%ls' not found (may already be removed)\n", pacName.c_str());
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

    std::wstring pacName = GetPacTargetName();
    HRESULT hr = pFilterUnload(pacName.c_str());
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
                    wsprintfW(drvFile, L"%s\\%s.sys", pluginDir, GetPacTargetName().c_str());
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
    wsprintfW(sys32Drv, L"C:\\Windows\\System32\\drivers\\%s.sys", GetPacTargetName().c_str());
    if (!DeleteFileW(sys32Drv)) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            ByovdDiag("PAC:DeleteDrvFiles: cannot delete system32 driver, err=%d, scheduling reboot\n", (int)err);
            MoveFileExW(sys32Drv, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    } else {
        wchar_t sys32Bak[MAX_PATH] = {};
        wsprintfW(sys32Bak, L"C:\\Windows\\System32\\drivers\\%s.sys.bak", GetPacTargetName().c_str());
        DeleteFileW(sys32Bak);
    }
}

bool KernelDefense::DisablePac() {
    ByovdDiag("PAC:DisablePac: starting...\n");

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

    // 检查 1: SCM 服务状态
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, GetPacTargetName().c_str(), SERVICE_QUERY_STATUS);
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
        wcsncpy_s(drvName, cand->driverPath.c_str(), 63);
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
    std::string pacNameA = WStringToString(GetPacTargetName());
    int pacOb = cbDisabler.DisableObCallbacks(pacNameA);
    int pacProc = cbDisabler.DisableProcessNotifyCallbacks(pacNameA);
    int pacImg = cbDisabler.DisableImageNotifyCallbacks(pacNameA);
    if (pacOb || pacProc || pacImg) {
        ByovdDiag("BYOVD: callbacks removed (PAC/%s) — ob=%d proc=%d img=%d\n",
            pacNameA.c_str(), pacOb, pacProc, pacImg);
        result.obCallbacksRemoved += pacOb;
        result.processCallbacksRemoved += pacProc;
        result.imageCallbacksRemoved += pacImg;
    }

    // ★ v3.126j: PAC minifilter 禁用 (这比 ObRegisterCallbacks 摘除更重要)
    //   因为 PAC 主要通过 minifilter 扫盘 + 文件操作拦截检测作弊
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
        std::wstring svcName = kma.GetServiceName();
        std::wstring drvPath = kma.GetDriverPath();

        // ★ v3.126m: 卸载前最后清理一次 PiDDBCacheTable (驱动名已随机化,
        //   MmUnloadedDrivers 无需清理, 但 PiDDBCacheTable 按校验和索引)
        KernelTraceCleaner::CleanAllTraces();

        kma.Shutdown();

        // 删除注册表服务键
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + svcName;
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath.c_str());

        // 删除 TEMP 中的驱动文件
        if (!drvPath.empty()) {
            DeleteFileW(drvPath.c_str());
        }

        ByovdDiag("BYOVD: %ls unloaded & cleaned.\n", svcName.c_str());
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

    // ★ v3.126p: PAC — 动态名称（唯一目标）
    total += cbDisabler.DisableAll(WStringToString(GetPacTargetName()));

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
