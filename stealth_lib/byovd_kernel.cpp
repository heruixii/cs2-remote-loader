// ============================================================
// byovd_kernel.cpp — BYOVD 内核级 EAC 防御完整实现
//
// 技术栈:
//   1. RTCore64.sys BYOVD 加载 (合法签名漏洞驱动)
//   2. CR3 页表遍历: VA→PA 转换 (PML4→PDPT→PD→PT)
//   3. 物理内存 R/W: IOCTL 0xC3502580 映射任意物理地址
//   4. Sigscan ObRegisterCallbacks → 定位 ObpCallbackArrayHead
//   5. 遍历回调数组 → NULL EAC 的所有注册回调
//   6. DKOM EPROCESS 断链 (可选, 触发 PatchGuard)
//
// 参考: Lazarus FudModule, kdmapper, EDRSandBlast, CheekyBlinder
// ============================================================

#include "byovd_kernel.h"
#include <winreg.h>
#include <winternl.h>   // PUNICODE_STRING, UNICODE_STRING, NT_SUCCESS, NtQuerySystemInformation
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#ifdef _MSC_VER
#include <intrin.h>     // __readcr3() for MSVC
#endif

// BYOVD 驱动嵌入支持: 将 RTCore64.sys 编译进 payload
//   1. python scripts/embed_driver.py RTCore64.sys
//   2. 复制生成的 rtcore64_embed.h 到 stealth_lib/
//   3. 编译时加 -DBYOVD_EMBED_RTCORE64
#ifdef BYOVD_EMBED_RTCORE64
#include "rtcore64_embed.h"
#endif

#pragma comment(lib, "advapi32.lib")

namespace stealth {

// ============================================================
// CR3 读取 (兼容 MSVC 和 MinGW/g++)
// MSVC x64: 不支持内联汇编, 使用 __readcr3() intrinsic
// MinGW/g++: 支持内联汇编, 也可用 __builtin_ia32_readcr3()
// ============================================================
static uint64_t ReadCR3() {
#ifdef _MSC_VER
    return __readcr3();
#else
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
#endif
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
    0xC3502580,   // 物理内存映射 IOCTL
    true
};

const BYOVDDriverInfo BYOVDDrivers::Gdrv = {
    L"gdrv",
    L"Gigabyte Kernel Driver",
    L"\\\\.\\gdrv",
    L"gdrv.sys",
    0xC3502808,   // 内核内存拷贝 IOCTL
    false
};

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
//   1. System32\drivers\<name> (系统已安装)
//   2. %TEMP%\<name> (从嵌入字节提取)
// ============================================================
static std::wstring EnsureDriverFile(const std::wstring& driverName) {
    wchar_t sysPath[MAX_PATH];

    // 1. 检查 System32\drivers
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\drivers\\");
    wcscat_s(sysPath, driverName.c_str());

    if (GetFileAttributesW(sysPath) != INVALID_FILE_ATTRIBUTES) {
        return std::wstring(sysPath); // 系统已安装
    }

    // 2. 从嵌入字节提取到 %TEMP%
#ifdef BYOVD_EMBED_RTCORE64
    const uint8_t* embedData = nullptr;
    size_t embedSize = 0;

    // 匹配驱动文件名
    if (driverName == L"RTCore64.sys") {
        embedData = stealth::embedded::RTCore64_data;
        embedSize = stealth::embedded::RTCore64_size;
    }
    // 可扩展: gdrv.sys 等

    if (embedData && embedSize > 0) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        wcscat_s(tempPath, driverName.c_str());

        // 写入嵌入字节到临时文件
        std::ofstream out(tempPath, std::ios::binary);
        if (out.is_open()) {
            out.write(reinterpret_cast<const char*>(embedData), embedSize);
            out.close();

            if (GetFileAttributesW(tempPath) != INVALID_FILE_ATTRIBUTES) {
                return std::wstring(tempPath);
            }
        }
    }
#endif

    // 3. 回退: 返回空 → 尝试以纯文件名加载 (LoadDriver 会补全 System32 路径)
    return L"";
}

bool KernelMemoryAccessor::LoadDriver(const std::wstring& serviceName, 
                                       const std::wstring& driverPath) {
    EnablePrivilege(L"SeLoadDriverPrivilege");

    // 注册表: 创建服务条目
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
    HKEY hKey;

    // 如果服务已存在, 尝试先使用
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                      KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        // 服务已存在, 尝试直接加载
    } else {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(),
                            0, nullptr, REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
            return false;
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

        RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
                       (BYTE*)fullPath, (DWORD)((wcslen(fullPath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }

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
    // STATUS_IMAGE_ALREADY_LOADED (0xC000010E) 也是成功
    return NT_SUCCESS(status) || status == 0xC000010E;
}

bool KernelMemoryAccessor::UnloadDriver(const std::wstring& serviceName) {
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

    return NT_SUCCESS(pNtUnloadDriver(&us));
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

    // IOCTL 请求: 物理地址映射
    struct {
        uint64_t physAddr;
        uint32_t size;
        uint32_t flags;     // 0 = 读, 1 = 写
    } request;

    request.physAddr = alignedAddr;
    request.size     = alignedSize;
    request.flags    = 0;

    DWORD bytesReturned = 0;
    uint8_t* mappedAddr = nullptr;

    BOOL ok = DeviceIoControl(m_hDevice, m_driverInfo.ioctlCode,
                              &request, sizeof(request),
                              &mappedAddr, sizeof(mappedAddr),
                              &bytesReturned, nullptr);

    if (!ok || !mappedAddr) {
        // 备选: 某些版本 RTCore64 使用不同的 IOCTL 格式
        // 尝试 standard RTCore64 物理读: 先 map, 再读
        DWORD ioctlRead = 0xC3502580;
        DWORD ioctlWrite = 0xC3502588;

        // RTCore64: 使用 struct { HANDLE hPhysicalMemory; ... }
        // 重新尝试不同格式 (部分驱动版本差异)
        return false;
    }

    // 缓存映射
    PhysMemMapping mapping;
    mapping.physAddr = alignedAddr;
    mapping.size     = alignedSize;
    mapping.virtAddr = mappedAddr;
    g_physMappings.push_back(mapping);

    // LRU 淘汰
    if (g_physMappings.size() > MAX_PHYS_MAPPINGS) {
        // 不释放映射 (内核驱动管理), 只从列表中移除
        g_physMappings.erase(g_physMappings.begin());
    }

    *outVirtAddr = mappedAddr + (physAddr - alignedAddr);
    return true;
}

bool KernelMemoryAccessor::ReadPhysical(uint64_t physAddr, void* outBuf, size_t size) {
    // 小读取: 直接映射并拷贝
    uint8_t* virtAddr = nullptr;
    if (!MapPhysical(physAddr, (uint32_t)size, &virtAddr)) {
        return false;
    }
    memcpy(outBuf, virtAddr, size);
    return true;
}

bool KernelMemoryAccessor::WritePhysical(uint64_t physAddr, const void* inBuf, size_t size) {
    // 物理内存写入: 需要 MAP_WRITE 标志
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;

    uint64_t alignedAddr = physAddr & ~0xFFFULL;
    uint32_t alignedSize = ((physAddr + size - alignedAddr + 0xFFF) & ~0xFFF);

    // RTCore64 写入: IOCTL 0xC3502588 (unmap 后重新 map with write)
    // 或使用不同的 IOCTL
    struct {
        uint64_t physAddr;
        uint32_t size;
        uint32_t flags;     // 1 = 可写
    } request;

    request.physAddr = alignedAddr;
    request.size     = alignedSize;
    request.flags    = 1;

    uint8_t* mappedAddr = nullptr;
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(m_hDevice, m_driverInfo.ioctlCode + 8,  // +8 = write variant
                              &request, sizeof(request),
                              &mappedAddr, sizeof(mappedAddr),
                              &bytesReturned, nullptr);

    if (!ok || !mappedAddr) return false;

    memcpy(mappedAddr + (physAddr - alignedAddr), inBuf, size);
    return true;
}

// ============================================================
// 内核虚拟地址读写 (通过 VA→PA 转换 + 物理内存 R/W)
// ============================================================

bool KernelMemoryAccessor::ReadKernelVA(uint64_t va, void* outBuf, size_t size) {
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false; // 非法内核地址

    // 懒初始化 CR3 和页表遍历器
    if (!m_pageTableWalker) {
        uint64_t cr3 = ReadCR3();
        m_pageTableWalker.reset(new PageTableWalker(cr3, *this));
    }

    // 处理跨页读取
    uint8_t* dst = (uint8_t*)outBuf;
    size_t remaining = size;
    uint64_t currentVA = va;

    while (remaining > 0) {
        uint64_t pageEnd = (currentVA & ~0xFFFULL) + 0x1000;
        size_t chunkSize = std::min(remaining, (size_t)(pageEnd - currentVA));

        uint64_t physAddr = m_pageTableWalker->VaToPa(currentVA);
        if (!physAddr) return false;

        if (!ReadPhysical(physAddr, dst, chunkSize)) {
            return false;
        }

        dst += chunkSize;
        currentVA += chunkSize;
        remaining -= chunkSize;
    }

    return true;
}

bool KernelMemoryAccessor::WriteKernelVA(uint64_t va, const void* inBuf, size_t size) {
    if (!m_active) return false;
    if (va < 0xFFFF800000000000ULL) return false;

    if (!m_pageTableWalker) {
        uint64_t cr3 = ReadCR3();
        m_pageTableWalker.reset(new PageTableWalker(cr3, *this));
    }

    const uint8_t* src = (const uint8_t*)inBuf;
    size_t remaining = size;
    uint64_t currentVA = va;

    while (remaining > 0) {
        uint64_t pageEnd = (currentVA & ~0xFFFULL) + 0x1000;
        size_t chunkSize = std::min(remaining, (size_t)(pageEnd - currentVA));

        uint64_t physAddr = m_pageTableWalker->VaToPa(currentVA);
        if (!physAddr) return false;

        if (!WritePhysical(physAddr, src, chunkSize)) {
            return false;
        }

        src += chunkSize;
        currentVA += chunkSize;
        remaining -= chunkSize;
    }

    return true;
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
    // 通过 NtQuerySystemInformation(SystemModuleInformation, class=11)
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    using NtQuery_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto pNtQuery = (NtQuery_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQuery) return 0;

    // 查询所需缓冲区大小
    ULONG bufSize = 0;
    pNtQuery(11, nullptr, 0, &bufSize);
    if (bufSize == 0) return 0;

    std::vector<uint8_t> buffer(bufSize + 0x1000);
    if (pNtQuery(11, buffer.data(), bufSize, &bufSize) != 0) return 0;

    // 解析 RTL_PROCESS_MODULES
    // 结构: ULONG count; RTL_PROCESS_MODULE_INFORMATION modules[];
    ULONG count = *(ULONG*)buffer.data();
    auto* modules = (uint8_t*)(buffer.data() + sizeof(ULONG));

    // RTL_PROCESS_MODULE_INFORMATION (x64):
    //   HANDLE Section;          // +0x00 (8 bytes)
    //   PVOID  MappedBase;       // +0x08 (8 bytes)
    //   PVOID  ImageBase;        // +0x10 (8 bytes)  ← 基址
    //   ULONG  ImageSize;        // +0x18 (4 bytes)
    //   ULONG  Flags;            // +0x1C (4 bytes)
    //   USHORT LoadOrderIndex;   // +0x20
    //   USHORT InitOrderIndex;   // +0x22
    //   USHORT LoadCount;        // +0x24
    //   USHORT OffsetToFileName; // +0x26
    //   UCHAR  FullPathName[256];// +0x28

    constexpr size_t MODULE_ENTRY_SIZE = 0x128; // Windows 11: 0x128, Win10: may differ

    for (ULONG i = 0; i < count; i++) {
        auto* mod = modules + i * MODULE_ENTRY_SIZE;
        uint64_t imageBase = *(uint64_t*)(mod + 0x10);
        ULONG offsetToName = *(USHORT*)(mod + 0x26);
        char* fullPath = (char*)(mod + 0x28);

        // 提取文件名
        char* name = fullPath + offsetToName;
        if (_stricmp(name, moduleName.c_str()) == 0) {
            return imageBase;
        }
    }

    return 0;
}

// ============================================================
// 初始化 / 清理
// ============================================================

bool KernelMemoryAccessor::Initialize(const BYOVDDriverInfo& driver) {
    m_driverInfo = driver;

    // 1. 检测 HVCI
    if (IsHVCIEnabled()) {
        // HVCI 启用时, 漏洞驱动大概率被 Microsoft 阻止
        // 不中止, 但标记不可用
    }

    // 2. 确保驱动文件存在 (System32\drivers → 嵌入提取到 %TEMP%)
    std::wstring resolvedPath = EnsureDriverFile(driver.driverPath);
    const std::wstring& actualPath = resolvedPath.empty() ? driver.driverPath : resolvedPath;

    // 3. 加载驱动
    if (!LoadDriver(driver.serviceName, actualPath)) {
        return false;
    }

    // 4. 打开设备
    m_hDevice = CreateFileW(driver.devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        UnloadDriver(driver.serviceName);
        return false;
    }

    m_active = true;
    m_ntosBase = GetNtoskrnlBase();
    m_pageTableWalker.reset();

    // v3.25: 探测 IOCTL 验证驱动 R/W 确实可用
    // 尝试读取 ntoskrnl.exe 的 MZ 头确认内核内存访问正常
    if (m_ntosBase) {
        uint16_t magic = 0;
        bool probeOk = ReadKernelVA(m_ntosBase, &magic, 2);
        if (!probeOk || magic != 0x5A4D) { // "MZ"
            // IOCTL 通道阻塞 (微软黑名单 或 驱动版本不兼容)
            // 标记为不可用但不崩溃, 后续回调摘除会静默失败
            m_active = false;
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
            UnloadDriver(driver.serviceName);
            return false;
        }
    } else {
        // 无法定位 ntoskrnl, 驱动虽加载但无法验证
        // 降级: 仍标记为 active, 回调操作将尝试
    }

    return true;
}

void KernelMemoryAccessor::Shutdown() {
    m_active = false;
    m_pageTableWalker.reset();
    g_physMappings.clear();

    // v3.24: 先卸载驱动再关闭句柄, 避免 CloseHandle 期间 IOCTL 竞态
    if (!m_driverInfo.serviceName.empty()) {
        UnloadDriver(m_driverInfo.serviceName);
    }
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
}

void KernelMemoryAccessor::EjectLoadedDrivers() {
    // 主动卸载已加载的 BYOVD 驱动
    // v3.25: 先卸载驱动再关闭句柄, 与 Shutdown() 保持一致
    m_active = false;
    if (!m_driverInfo.serviceName.empty()) {
        UnloadDriver(m_driverInfo.serviceName);
    }
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }
}

bool KernelMemoryAccessor::IsKernelAddressValid(uint64_t va) {
    // 内核地址范围检查 (Windows x64 规范)
    // 内核空间: 0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF
    if (va < 0xFFFF800000000000ULL) return false;
    if (va > 0xFFFFFFFFFFFFFFFFULL) return false;

    // 进一步: 检查页表映射是否存在
    if (!m_active) return false;
    if (!m_pageTableWalker) {
        uint64_t cr3 = ReadCR3();
        m_pageTableWalker.reset(new PageTableWalker(cr3, *this));
    }
    return m_pageTableWalker->VaToPa(va) != 0;
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

    // 获取 EAC 驱动基址
    uint64_t eacBase = kma.GetKernelModuleBase(eacDriverName + ".sys");
    if (!eacBase) {
        eacBase = kma.GetKernelModuleBase("EasyAntiCheat_EOS.sys");
    }
    if (!eacBase) return 0;

    // 遍历 CALLBACK_ENTRY 数组
    // CALLBACK_ENTRY 结构 (x64):
    //   +0x00: LIST_ENTRY  (Flink, Blink)  — 16 bytes
    //   +0x10: OB_OPERATION Operations     — 1 byte
    //   +0x11: OB_OPERATION Active         — 1 byte  
    //   +0x12: USHORT      CallbackCount   — 2 bytes
    //   +0x14: padding (2 bytes)
    //   +0x18: OB_PREOP_CALLBACK_STATUS PreOperation  — 8 bytes
    //   +0x20: PVOID       PreContext      — 8 bytes
    //   +0x28: OB_POSTOP_CALLBACK_STATUS PostOperation — 8 bytes
    //   +0x30: PVOID       PostContext     — 8 bytes
    //   +0x38: PVOID       DriverObject    — 8 bytes  ← 用于匹配 EAC

    constexpr uint32_t CB_ENTRY_SIZE = 0x40;
    constexpr uint32_t MAX_CALLBACKS = 256;

    int removed = 0;
    uint64_t current = cbArrayHead;

    for (uint32_t i = 0; i < MAX_CALLBACKS; i++) {
        uint64_t driverObjVA = current + 0x38;
        uint64_t driverObj = kma.Read<uint64_t>(driverObjVA);

        // 通过 DriverObject → DriverSection → 驱动名匹配
        if (driverObj && driverObj > 0xFFFF800000000000ULL) {
            // 读取 DRIVER_OBJECT.DriverSection → LDR_DATA_TABLE_ENTRY
            uint64_t driverSection = kma.Read<uint64_t>(driverObj + 0x14);
            if (driverSection) {
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

KernelDefense::Result KernelDefense::EnableAll() {
    Result result;
    auto& kma = KernelMemoryAccessor::Instance();

    // 1. 加载 BYOVD 驱动
    result.driverLoaded = kma.Initialize(BYOVDDrivers::RTCore64);
    if (!result.driverLoaded) {
        result.driverLoaded = kma.Initialize(BYOVDDrivers::Gdrv);
    }
    if (!result.driverLoaded) {
        return result; // 无内核可用
    }

    // 2. 摘除 EAC 回调
    auto& cbDisabler = EACCallbackDisabler::Instance();
    result.obCallbacksRemoved      = cbDisabler.DisableObCallbacks("EasyAntiCheat");
    result.processCallbacksRemoved = cbDisabler.DisableProcessNotifyCallbacks("EasyAntiCheat");
    result.imageCallbacksRemoved   = cbDisabler.DisableImageNotifyCallbacks("EasyAntiCheat");

    // 3. DKOM (高风险, 默认跳过)
    // result.processHidden = DKOMProcessHider::Instance().HideProcess();

    return result;
}

void KernelDefense::DisableAll() {
    DKOMProcessHider::Instance().UnhideProcess();
    KernelMemoryAccessor::Instance().Shutdown();
}

} // namespace stealth
