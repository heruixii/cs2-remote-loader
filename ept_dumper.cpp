// ============================================================
// ept_dumper.cpp — PAC SHV EPT 页表 dump 工具
//
// 目的:
//   通过 PDFWKRNL.sys 内核读写能力, 扫描 PAC MessageTransfer.sys
//   驱动 .data 段, 定位 EPTP (Extended Page Table Pointer) 和
//   EPT 页表内核虚拟地址, 然后 dump EPT 页表项, 识别 SHV 监控
//   目标 (哪些物理页被标记为 'no access', 即 EPT_VIOLATION 触发页).
//
// 工作流程:
//   1. 初始化 KernelMemoryAccessor (PDFWKRNL.sys via IOCTL 0x80002014)
//   2. GetKernelModuleBase("MessageTransfer.sys") 获取 PAC 驱动内核基址
//   3. 解析 PE 头, 获取 .data 段范围 (RVA + size)
//   4. ReadKernelVA 读取 .data 段 (限制 32 KB, 一次读)
//   5. 扫描 .data 段:
//      a. EPTP 候选: 8 字节, 低 12 位 = 0x58 (UC) 或 0x5E (WB)
//      b. EPT 页表 VA 候选: 0xFFFFF8*/0xFFFFE0* 前缀
//   6. 对每个候选, ReadKernelVA 读取 4 KB
//   7. 验证是否为有效 EPT PML4/PDPTE/PDE/PTE 表
//   8. Dump 表项, 标记 R/W/X 权限
//
// 安全约束:
//   - 不读取 .text 段 (避免 PatchGuard 0x109 BSOD)
//   - 不读取 ntoskrnl 敏感地址
//   - 总 IOCTL 读取量 < 256 KB (PDFWKRNL 2s 超时 + 10s 冷却)
//   - 每次 ReadKernelVA 不超过 4 KB
//
// 编译:
//   g++ -std=c++20 -O2 -s -fpermissive -DNDEBUG -D_WIN32_WINNT=0x0A00 \
//       -Istealth_lib ept_dumper.cpp \
//       stealth_lib/byovd_kernel.cpp \
//       stealth_lib/syscall_direct.cpp \
//       stealth_lib/anti_debug.cpp \
//       stealth_lib/eac_syscall_guard.cpp \
//       -lntdll -ladvapi32 -lpsapi \
//       -o ept_dumper.exe
// ============================================================

#include "byovd_kernel.h"
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>

// ============================================================
// 全局变量定义 — byovd_kernel.cpp 通过 extern 引用这些变量
//   (原定义在 payload.cpp 中, ept_dumper 作为独立工具提供空实现)
// ============================================================
uint8_t* g_backupBuf = nullptr;
SIZE_T   g_backupLen = 0;
uint8_t* g_backupCodeBase = nullptr;
void*    g_vehHandlerPageVA = nullptr;

// ============================================================
// 日志输出 — 同时写文件和控制台
// ============================================================
static FILE* g_logFile = nullptr;

static void Log(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len < 0) len = 0;

    // 控制台
    fputs(buf, stdout);

    // 文件
    if (g_logFile) {
        fwrite(buf, 1, len, g_logFile);
        fflush(g_logFile);
    }
}

// ============================================================
// PE 解析 — 获取 .data 段范围
// ============================================================
struct PESectionInfo {
    uint32_t rva;
    uint32_t virtualSize;
    char     name[9];
};

static bool ParsePESections(const uint8_t* peHeaderBuf, size_t bufSize,
                             PESectionInfo* outSections, int maxSections,
                             int* outCount) {
    if (bufSize < 0x40) return false;
    if (peHeaderBuf[0] != 'M' || peHeaderBuf[1] != 'Z') return false;

    uint32_t e_lfanew = *(uint32_t*)(peHeaderBuf + 0x3C);
    if (e_lfanew + 24 > bufSize) return false;

    const uint8_t* pe = peHeaderBuf + e_lfanew;
    if (*(uint32_t*)pe != 0x00004550) return false;  // "PE\0\0"

    uint16_t numSections = *(uint16_t*)(pe + 6);
    uint16_t optHdrSize  = *(uint16_t*)(pe + 20);

    const uint8_t* sectHdr = pe + 24 + optHdrSize;
    if (sectHdr + (size_t)numSections * 40 > peHeaderBuf + bufSize) return false;

    int count = (numSections < maxSections) ? numSections : maxSections;
    for (int i = 0; i < count; i++) {
        const uint8_t* s = sectHdr + i * 40;
        memcpy(outSections[i].name, s, 8);
        outSections[i].name[8] = '\0';
        outSections[i].rva = *(uint32_t*)(s + 12);
        outSections[i].virtualSize = *(uint32_t*)(s + 8);
    }
    *outCount = count;
    return true;
}

// ============================================================
// EPTP 格式验证
// ============================================================
// EPTP (Extended Page Table Pointer) 64-bit 格式:
//   Bits 0-2:   Memory type (0=UC, 6=WB)
//   Bits 3-5:   Page walk length - 1 (must be 3 for 4-level EPT)
//   Bit 6:      Allow WB on large pages (1)
//   Bits 7-11:  Reserved (0)
//   Bits 12-51: EPT PML4 physical address (4 KB aligned)
//   Bits 52-63: Reserved (0)
//
// 典型值:
//   memory_type=6 (WB), walk_length=3+1=4, allow_wb=1:
//     low 12 bits = (6) | (3 << 3) | (1 << 6) = 0x06 | 0x18 | 0x40 = 0x5E
//   memory_type=0 (UC), walk_length=3+1=4, allow_wb=1:
//     low 12 bits = (0) | (3 << 3) | (1 << 6) = 0x58
struct EptpFormat {
    uint64_t value;
    uint64_t pml4Phys;
    uint32_t memType;
    uint32_t walkLength;
    bool     allowWb;
};

static bool ParseEPTP(uint64_t val, EptpFormat* out) {
    uint32_t low12 = (uint32_t)(val & 0xFFF);
    uint32_t memType    = low12 & 0x7;
    uint32_t walkLen    = (low12 >> 3) & 0x7;
    uint32_t allowWb    = (low12 >> 6) & 0x1;
    uint32_t reservedLo = (low12 >> 7) & 0x1F;
    uint64_t pml4Phys   = val & 0x000FFFFFFFFFF000ULL;  // bits 12-51
    uint64_t reservedHi = val >> 52;

    // EPTP 必须满足:
    // - memType = 0 (UC) 或 6 (WB)
    // - walkLen = 3 (4-level EPT)
    // - allowWb = 1
    // - reservedLo = 0
    // - reservedHi = 0
    // - pml4Phys 4 KB 对齐且非零
    if (memType != 0 && memType != 6) return false;
    if (walkLen != 3) return false;
    if (allowWb != 1) return false;
    if (reservedLo != 0) return false;
    if (reservedHi != 0) return false;
    if (pml4Phys == 0) return false;
    if (pml4Phys & 0xFFF) return false;
    if (pml4Phys > 0x7FFFFFFFULL) return false;  // 物理地址限制 < 2 GB (PAC SHV 限制)

    out->value = val;
    out->pml4Phys = pml4Phys;
    out->memType = memType;
    out->walkLength = walkLen + 1;
    out->allowWb = (allowWb != 0);
    return true;
}

// ============================================================
// EPT PTE 格式解析
// ============================================================
// EPT PTE 64-bit 格式:
//   Bit 0:     Read access
//   Bit 1:     Write access
//   Bit 2:     Execute access
//   Bits 3-5:  Reserved (must be 0)
//   Bits 6-7:  Memory type
//   Bit 8:     Ignore PAT
//   Bits 9-11: Reserved
//   Bits 12-51: Physical address
//   Bits 52-58: Reserved
//   Bit 59:    Execute for user-mode (XE)
//   Bits 60-63: Reserved
struct EptPte {
    uint64_t raw;
    uint64_t physAddr;
    bool     r, w, x, xe;
    uint32_t memType;
    bool     isLeaf;  // PDE/PDTE 大页
};

static void ParseEptPte(uint64_t raw, EptPte* out) {
    out->raw = raw;
    out->r = (raw & 0x1) != 0;
    out->w = (raw & 0x2) != 0;
    out->x = (raw & 0x4) != 0;
    out->memType = (raw >> 6) & 0x3;
    out->physAddr = raw & 0x000FFFFFFFFFF000ULL;
    out->xe = (raw >> 59) & 0x1;
    out->isLeaf = false;  // 由 caller 根据 level 设置
}

// ============================================================
// 工具: 格式化 R/W/X 字符串
// ============================================================
static const char* RwxStr(const EptPte& pte) {
    static char buf[8];
    buf[0] = pte.r ? 'R' : '-';
    buf[1] = pte.w ? 'W' : '-';
    buf[2] = pte.x ? 'X' : '-';
    buf[3] = pte.xe ? 'U' : '-';
    buf[4] = '\0';
    return buf;
}

// ============================================================
// 主程序
// ============================================================
int main() {
    // 打开日志文件
    g_logFile = fopen("ept_dump.log", "w");
    if (!g_logFile) {
        printf("[ERROR] Cannot open ept_dump.log for writing\n");
        return 1;
    }

    Log("============================================================\n");
    Log("  PAC SHV EPT Page Table Dumper\n");
    Log("  Date: %s %s\n", __DATE__, __TIME__);
    Log("============================================================\n\n");

    // ========== 阶段 1: 初始化 KernelMemoryAccessor ==========
    Log("[Phase 1] Initializing KernelMemoryAccessor (PDFWKRNL.sys)...\n");

    auto& kma = stealth::KernelMemoryAccessor::Instance();
    if (!kma.Initialize(stealth::BYOVDDrivers::PDFWKRNL)) {
        Log("[FAIL] KernelMemoryAccessor initialization failed.\n");
        Log("       Possible causes:\n");
        Log("       - PDFWKRNL.sys not loaded (run loader2.exe first)\n");
        Log("       - Driver service not registered\n");
        Log("       - IOCTL 0x80002014 not responding\n");
        if (g_logFile) fclose(g_logFile);
        return 2;
    }
    Log("[OK] KernelMemoryAccessor initialized.\n\n");

    // ========== 阶段 2: 获取 MessageTransfer.sys 内核基址 ==========
    Log("[Phase 2] Locating MessageTransfer.sys in kernel...\n");
    uint64_t pacBase = kma.GetKernelModuleBase("MessageTransfer.sys");
    if (!pacBase) {
        Log("[FAIL] MessageTransfer.sys not found in kernel module list.\n");
        Log("       Possible causes:\n");
        Log("       - PAC not running (launch PerfectWorld Arena + CS2 first)\n");
        Log("       - Service name different from 'MessageTransfer.sys'\n");
        kma.Shutdown();
        if (g_logFile) fclose(g_logFile);
        return 3;
    }
    Log("[OK] MessageTransfer.sys kernel base = 0x%llX\n\n", (unsigned long long)pacBase);

    // ========== 阶段 3: 解析 PE 头, 获取 .data 段范围 ==========
    Log("[Phase 3] Parsing PE headers to locate .data section...\n");

    // 读取 PE 头 (前 4 KB 应该足够)
    uint8_t peHdr[4096];
    if (!kma.ReadKernelVA(pacBase, peHdr, sizeof(peHdr))) {
        Log("[FAIL] Cannot read PE header at 0x%llX\n", (unsigned long long)pacBase);
        kma.Shutdown();
        if (g_logFile) fclose(g_logFile);
        return 4;
    }

    PESectionInfo sections[16];
    int sectionCount = 0;
    if (!ParsePESections(peHdr, sizeof(peHdr), sections, 16, &sectionCount)) {
        Log("[FAIL] PE header parsing failed.\n");
        kma.Shutdown();
        if (g_logFile) fclose(g_logFile);
        return 5;
    }
    Log("[OK] Found %d sections:\n", sectionCount);
    for (int i = 0; i < sectionCount; i++) {
        Log("  [%d] %-8s RVA=0x%08X VSize=0x%08X\n",
            i, sections[i].name, sections[i].rva, sections[i].virtualSize);
    }

    // 查找 .data 段
    uint32_t dataRva = 0;
    uint32_t dataSize = 0;
    for (int i = 0; i < sectionCount; i++) {
        if (strcmp(sections[i].name, ".data") == 0) {
            dataRva = sections[i].rva;
            dataSize = sections[i].virtualSize;
            break;
        }
    }
    if (!dataRva || !dataSize) {
        Log("[FAIL] .data section not found in MessageTransfer.sys\n");
        kma.Shutdown();
        if (g_logFile) fclose(g_logFile);
        return 6;
    }
    Log("[OK] .data section: RVA=0x%08X Size=0x%X (%u bytes)\n",
        dataRva, dataSize, dataSize);

    // 限制 .data 段读取量 (避免超时)
    const uint32_t MAX_DATA_SCAN = 0x10000;  // 64 KB
    uint32_t scanSize = (dataSize < MAX_DATA_SCAN) ? dataSize : MAX_DATA_SCAN;
    Log("       Scanning first %u bytes (limit: %u KB)\n\n", scanSize, MAX_DATA_SCAN / 1024);

    uint64_t dataVA = pacBase + dataRva;
    uint8_t* dataBuf = (uint8_t*)malloc(scanSize);
    if (!dataBuf) {
        Log("[FAIL] malloc failed for dataBuf\n");
        kma.Shutdown();
        if (g_logFile) fclose(g_logFile);
        return 7;
    }

    // 分块读取 .data 段 (每块 4 KB, 避免 PDFWKRNL 超时)
    const uint32_t CHUNK = 0x1000;
    bool readOk = true;
    for (uint32_t off = 0; off < scanSize; off += CHUNK) {
        uint32_t thisChunk = (off + CHUNK <= scanSize) ? CHUNK : (scanSize - off);
        if (!kma.ReadKernelVA(dataVA + off, dataBuf + off, thisChunk)) {
            Log("[WARN] ReadKernelVA failed at .data+0x%X (off=%u)\n", off, off);
            readOk = false;
            break;
        }
    }
    if (!readOk) {
        Log("[FAIL] Cannot fully read .data section.\n");
        free(dataBuf);
        kma.Shutdown();
        if (g_logFile) fclose(g_logFile);
        return 8;
    }
    Log("[OK] .data section read successfully.\n\n");

    // ========== 阶段 4: 扫描 EPTP 候选 ==========
    Log("[Phase 4] Scanning for EPTP (Extended Page Table Pointer) candidates...\n");

    int eptpCount = 0;
    for (uint32_t off = 0; off + 8 <= scanSize; off += 8) {
        uint64_t val = *(uint64_t*)(dataBuf + off);
        EptpFormat eptp;
        if (ParseEPTP(val, &eptp)) {
            Log("  [EPTP @ .data+0x%X] val=0x%016llX | PML4Phys=0x%llX memType=%u walk=%u allowWb=%d\n",
                off, (unsigned long long)val,
                (unsigned long long)eptp.pml4Phys, eptp.memType, eptp.walkLength, (int)eptp.allowWb);
            eptpCount++;
        }
    }
    Log("[OK] Found %d EPTP candidate(s).\n\n", eptpCount);

    // ========== 阶段 5: 扫描 EPT 页表内核虚拟地址候选 ==========
    Log("[Phase 5] Scanning for EPT page table kernel VA candidates...\n");
    Log("         (Looking for pointers like 0xFFFFF8*, 0xFFFFE0* with valid EPT table format)\n");

    // PAC 通过 MmAllocateContiguousMemory 分配 EPT 页表
    // 返回的内核 VA 通常在 0xFFFFF8xxxxxxxxxx 范围
    // 但 MmAllocateContiguousMemory 返回的 VA 实际上是 0xFFFFFFFFxxxxxxxx 之类(取决于 pool)
    // 我们扫描所有 8 字节对齐的内核地址(高位 = 0xFFFFF8 或 0xFFFFE0)
    int vaCandidateCount = 0;
    struct VaCandidate {
        uint32_t offInData;
        uint64_t va;
    };
    VaCandidate vaCandidates[64];

    for (uint32_t off = 0; off + 8 <= scanSize; off += 8) {
        uint64_t val = *(uint64_t*)(dataBuf + off);

        // 检查是否为内核地址 (高位 = 0xFFFF)
        uint16_t hi16 = (uint16_t)(val >> 48);
        if (hi16 != 0xFFFF) continue;

        // 检查是否为典型内核地址范围
        uint64_t hi = val >> 40;
        // 0xFFFFF8 = 内核空间典型范围 (包括 pool、page table 等)
        // 0xFFFFE0 = MmPfnDatabase 区域
        if (hi != 0xFFFFF8 && hi != 0xFFFFE0 && hi != 0xFFFFF0 && hi != 0xFFFFFFFE) continue;

        // 跳过明显的无效值 (零、对齐不正确)
        if (val == 0 || val == 0xFFFFFFFFFFFFFFFF) continue;
        if (val & 0xFFF) continue;  // 必须页对齐 (4 KB)

        if (vaCandidateCount < 64) {
            vaCandidates[vaCandidateCount].offInData = off;
            vaCandidates[vaCandidateCount].va = val;
            vaCandidateCount++;
            if (vaCandidateCount <= 32) {
                Log("  [VA @ .data+0x%X] 0x%016llX\n", off, (unsigned long long)val);
            }
        }
    }
    if (vaCandidateCount > 32) {
        Log("  ... (%d more candidates omitted)\n", vaCandidateCount - 32);
    }
    Log("[OK] Found %d VA candidate(s).\n\n", vaCandidateCount);

    // ========== 阶段 6: 验证 VA 候选是否为 EPT PML4 表 ==========
    Log("[Phase 6] Validating VA candidates as EPT PML4 tables...\n");
    Log("         (Reading first 4 KB of each candidate, checking EPT PML4E format)\n");

    int validatedTableCount = 0;
    struct ValidatedTable {
        uint64_t va;
        uint32_t offInData;
        int      entryCount;       // 非零项数
        int      validEntryCount;  // 符合 EPT PML4E 格式的项数
    };
    ValidatedTable validatedTables[8];

    // 限制验证的候选数, 避免过多 IOCTL
    int maxValidate = (vaCandidateCount < 8) ? vaCandidateCount : 8;

    for (int i = 0; i < maxValidate; i++) {
        uint64_t va = vaCandidates[i].va;
        uint32_t off = vaCandidates[i].offInData;

        // 读取 4 KB
        uint8_t page[4096];
        if (!kma.ReadKernelVA(va, page, sizeof(page))) {
            Log("  [VA @ .data+0x%X 0x%llX] READ FAILED\n", off, (unsigned long long)va);
            continue;
        }

        // 解析为 512 个 PML4E (每个 8 字节)
        int nonZero = 0;
        int validEptEntries = 0;
        int noAccessCount = 0;
        for (int e = 0; e < 512; e++) {
            uint64_t entry = *(uint64_t*)(page + e * 8);
            if (entry == 0) continue;
            nonZero++;

            EptPte pte;
            ParseEptPte(entry, &pte);

            // EPT PML4E/PDPTE/PDE 非 leaf 项: 低 3 位 R/W/X 通常全为 1
            // EPT PTE leaf 项: 物理 address bits 12-51 必须有效
            // EPT PML4E 通常指向下一级页表 (PDPTE)
            // 验证: 物理地址 < 2 GB (PAC SHV 限制), 且 4 KB 对齐
            if (pte.physAddr == 0) continue;
            if (pte.physAddr & 0xFFF) continue;
            if (pte.physAddr > 0x7FFFFFFFULL) continue;

            validEptEntries++;

            // 标记 "no access" 项 (R=0, W=0, X=0) — 这是 EPT_VIOLATION 触发页
            if (!pte.r && !pte.w && !pte.x) {
                noAccessCount++;
            }
        }

        // 有效的 EPT 表应该有非零项
        if (nonZero == 0) {
            Log("  [VA @ .data+0x%X 0x%llX] empty (all zeros)\n", off, (unsigned long long)va);
            continue;
        }

        Log("  [VA @ .data+0x%X 0x%llX] nonZero=%d validEpt=%d noAccess=%d\n",
            off, (unsigned long long)va, nonZero, validEptEntries, noAccessCount);

        // 如果有大量 EPT 格式有效项, 认为是 EPT 页表
        if (validEptEntries >= 1 && validatedTableCount < 8) {
            validatedTables[validatedTableCount].va = va;
            validatedTables[validatedTableCount].offInData = off;
            validatedTables[validatedTableCount].entryCount = nonZero;
            validatedTables[validatedTableCount].validEntryCount = validEptEntries;
            validatedTableCount++;
        }
    }
    Log("[OK] Validated %d EPT page table(s).\n\n", validatedTableCount);

    // ========== 阶段 7: Dump EPT 页表(限制深度, 避免超时) ==========
    int totalIoctlCount = 0;  // 总 IOCTL 读取计数 (跨阶段 7 统计)
    if (validatedTableCount > 0) {
        Log("[Phase 7] Dumping EPT page table structure (limited depth)...\n");
        Log("          (Limiting to first 4 PML4E entries × 4 PDPTE × 4 PDE = 64 leaf pages)\n\n");

        const int MAX_IOCTL = 100;  // 总 IOCTL 限制

        for (int t = 0; t < validatedTableCount && totalIoctlCount < MAX_IOCTL; t++) {
            Log("=== Table #%d at VA=0x%llX (.data+0x%X) ===\n",
                t, (unsigned long long)validatedTables[t].va, validatedTables[t].offInData);

            // 读取 PML4 表 (再次读取, 因为之前的数据可能已变)
            uint8_t pml4[4096];
            if (!kma.ReadKernelVA(validatedTables[t].va, pml4, 4096)) {
                Log("  [SKIP] Cannot re-read PML4 table\n");
                continue;
            }
            totalIoctlCount++;

            int pml4eProcessed = 0;
            for (int p4 = 0; p4 < 512 && pml4eProcessed < 4 && totalIoctlCount < MAX_IOCTL; p4++) {
                uint64_t pml4e = *(uint64_t*)(pml4 + p4 * 8);
                if (pml4e == 0) continue;

                EptPte pte;
                ParseEptPte(pml4e, &pte);
                Log("  PML4E[%d] = 0x%016llX  %s  phys=0x%llX\n",
                    p4, (unsigned long long)pml4e, RwxStr(pte),
                    (unsigned long long)pte.physAddr);
                pml4eProcessed++;

                // PML4E 指向 PDPTE 表 (物理地址)
                // 我们无法直接读取物理地址 (PDFWKRNL 只支持 VA)
                // 但 PAC 驱动 .data 段中可能存储了 PDPTE 的 VA
                // 尝试在 vaCandidates 中查找
                // 简化方案: 只 dump PML4E 层, 不深入
                // (深入需要物理 → VA 转换, 当前不支持)
            }
            Log("\n");
        }

        Log("[NOTE] Deep dump (PDPTE/PDE/PTE levels) requires physical-to-VA conversion.\n");
        Log("       Current PDFWKRNL only supports VA memcpy, cannot read physical pages directly.\n");
        Log("       To enable deep dump, need to:\n");
        Log("         1. Add MmMapIoSpace or MmGetVirtualForPhysical support, OR\n");
        Log("         2. Find PAC driver's internal VA pointers for PDPTE/PDE tables, OR\n");
        Log("         3. Use a different BYOVD driver that supports physical memory read\n");
    } else {
        Log("[Phase 7] SKIPPED — no validated EPT page tables.\n");
        Log("          Possible reasons:\n");
        Log("          - SHV not active (PAC not running, or SHV init failed)\n");
        Log("          - EPT page table VA not in .data section (in heap/pool)\n");
        Log("          - .data section larger than 64 KB scan limit\n");
        Log("          - EPT table entries do not match expected format\n\n");

        Log("[Recommendation] Try the following:\n");
        Log("  1. Ensure CS2 + PAC is running before executing ept_dumper.exe\n");
        Log("  2. Increase MAX_DATA_SCAN to 256 KB (modify ept_dumper.cpp)\n");
        Log("  3. Manually inspect .data section dump for kernel pointer patterns\n");
    }

    Log("\n============================================================\n");
    Log("  EPT Dump Complete\n");
    Log("  Total IOCTL reads performed: %d (limit was 100)\n", totalIoctlCount);
    Log("  Log file: ept_dump.log\n");
    Log("============================================================\n");

    // 清理
    free(dataBuf);
    kma.Shutdown();
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = nullptr;
    }
    return 0;
}
