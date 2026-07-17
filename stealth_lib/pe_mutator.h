#pragma once
// ============================================================
// pe_mutator.h — PE 文件自修改 / 完整性校验绕过
// 规避: 签名检测(Rich Header/编译时间戳/PDB路径)
//       完整性检测(.text段哈希/虚表完整性/NetVar值域校验)
// ============================================================

#include <Windows.h>
#include <cstdint>
// ★ BUILD 499: 移除 <vector> <string> — Manual-Map DLL 中 CRT 堆未初始化

namespace stealth {

// ============================================================
// PE 自修改器 — 运行时修改自身 PE 头以消除指纹
// ============================================================

class PeMutator {
public:
    // ---- Rich Header 清除 ----
    // Rich Header 包含编译器版本、构建次数等指纹信息
    // 位于 DOS Stub 和 PE Header 之间
    static bool StripRichHeader();

    // ---- 编译时间戳随机化 ----
    // TimeDateStamp 是反作弊系统的常用特征
    // 将其修改为合法范围内的随机值
    static bool RandomizeTimestamp();

    // ---- PDB 路径清除 ----
    // 调试目录中的 PDB 路径泄露项目结构和开发者信息
    static bool StripDebugInfo();

    // ---- 导入表混淆 ----
    // 将敏感 API 从静态导入表中移除/混淆
    // 策略: 修改导入表, 用无害 API 替换敏感 API 的名称
    static bool ObfuscateImportTable();

    // ---- 区段名称标准化 ----
    // 如果存在 .rdata$zzzdbg 等非标准区段, 重命名为标准名称
    static bool NormalizeSectionNames();

    // ---- 整体哈希变异 ----
    // 在 PE 末尾添加随机垃圾数据以改变文件哈希
    // 同时确保不影响执行
    static bool AddJunkOverlay(size_t sizeBytes);

    // 获取自身模块基址
    static HMODULE GetSelfModule();
    static uintptr_t GetSelfBase();

private:
    PeMutator() = default;

    static PIMAGE_NT_HEADERS GetNtHeaders();
    static PIMAGE_DOS_HEADER GetDosHeader();
};

// ============================================================
// 完整性检测绕过
// ============================================================

class IntegrityBypass {
public:
    // ---- .text 段完整性 ----
    // VAC 等反作弊系统会对比 .text 段的哈希
    // 策略: 在 VAC 扫描前快速恢复原始字节, 扫描后再写回

    // 备份 .text 段原始内容
    static bool BackupTextSection();

    // 恢复 .text 段到原始状态 (用于应对完整性扫描)
    static bool RestoreTextSection();

    // 重新应用修改 (扫描完成后)
    static bool ReapplyTextPatches();

    // ---- VTable 完整性 ----
    // 反作弊系统检查关键虚表指针是否指向已知模块

    // 验证虚表指针完整性
    struct VTableInfo {
        uintptr_t vtableAddr;       // 虚表在目标进程中的地址
        uintptr_t expectedModuleBase; // 预期指向的模块基址
        SIZE_T    expectedModuleSize;
    };

    // ★ BUILD 499: 伪造虚表 — 使用指针+计数替代 std::vector
    static bool ForgeVTable(HANDLE hProcess,
                            const VTableInfo& original,
                            const uintptr_t* newEntries, int entryCount);

    // 验证虚表指针是否安全
    static bool ValidateVTablePointer(uintptr_t vtablePtr, uintptr_t moduleBase, SIZE_T moduleSize);

    // ---- NetVar 值域校验 ----
    // 反作弊系统验证 NetVar 值是否在合法范围内

    // 对 NetVar 的值域进行夹值 (Clamp), 确保不触发异常检测
    template<typename T>
    static T ClampNetVar(T value, T min, T max) {
        if (value < min) return min;
        if (value > max) return max;
        return value;
    }

    // 检查 NetVar 值是否在合理范围
    // 例: m_iHealth 应在 0-100 (或更大取决于游戏模式)
    //      m_bDormant 应为 0 或 1
    static bool IsNetVarValid(uintptr_t value, uintptr_t min, uintptr_t max);

    // ---- VAC 模块完整性 ----
    // VAC 会验证自身模块的完整性

    // 检测 VAC 模块是否存在
    static bool IsVACLoaded(HANDLE hProcess);

    // 获取 VAC 模块基址
    static uintptr_t GetVACModuleBase(HANDLE hProcess);

    // VAC 扫描周期检测 (通过监控 Steam 线程活动)
    static bool IsVACScanning();

    // 设置 VAC 安全回调: 扫描前自动恢复, 扫描后自动重写
    static bool InstallVACSafetyHook();

private:
    IntegrityBypass() = default;

    // .text 段备份
    // ★ BUILD 501: 使用 VirtualAlloc 分配缓冲区, 替代 std::vector — 避免 CRT 堆依赖
    struct TextSectionBackup {
        uintptr_t baseAddress;
        SIZE_T    size;
        uint8_t*  originalBytes = nullptr;  // VirtualAlloc 分配
        uint8_t*  patchedBytes  = nullptr;  // VirtualAlloc 分配
        bool      isPatched = false;

        void Free() {
            if (originalBytes) { VirtualFree(originalBytes, 0, MEM_RELEASE); originalBytes = nullptr; }
            if (patchedBytes)  { VirtualFree(patchedBytes, 0, MEM_RELEASE);  patchedBytes = nullptr; }
        }
    };
    static TextSectionBackup s_textBackup;
};

} // namespace stealth
