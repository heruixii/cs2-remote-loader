#pragma once
// ============================================================
// string_obfuscator.h — 编译期字符串加密 + 运行时API动态解析
// 规避: 签名检测(字符串特征、导入表特征、编译器指纹)
// ============================================================

#include <Windows.h>
#include <cstdint>
#include <array>
#include <cstring>
// ★ BUILD 499: 移除 <vector> <string> — Manual-Map DLL 中 CRT 堆未初始化

namespace stealth {

// ============================================================
// 编译期 XTEA 字符串加密
// 规避: "Dear ImGui"、PDB路径、自删除批处理等字符串特征扫描
// 原理: 编译期加密敏感字符串, 运行时解密到栈上, 用完立即清零
// ============================================================

namespace detail {
    // 编译期 XTEA 加密 (constexpr)
    constexpr uint32_t XTEA_DELTA = 0x9E3779B9;
    constexpr uint32_t XTEA_KEY[4] = {
        0x5A3C9E71, 0xB82D4F16, 0xE107A3D8, 0x3C6F2B9A
    };

    template<size_t N>
    struct EncryptedString {
        std::array<uint32_t, (N + 7) / 4 * 2> data{};
        size_t size = N;

        // 编译期递归初始化缓冲区 (避免 for/goto, gcc 15 constexpr 兼容)
        static constexpr void InitBuf(const char(&str)[N], uint8_t* buf, size_t i) {
            if (i < N) {
                buf[i] = static_cast<uint8_t>(str[i]);
                InitBuf(str, buf, i + 1);
            }
        }

        // 编译期递归执行 XTEA 加密块 (32轮)
        static constexpr void XteaRound(uint32_t& v0, uint32_t& v1, uint32_t& sum, int r) {
            if (r < 32) {
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + XTEA_KEY[sum & 3]);
                sum += XTEA_DELTA;
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + XTEA_KEY[(sum >> 11) & 3]);
                XteaRound(v0, v1, sum, r + 1);
            }
        }

        // 编译期递归处理所有 8字节块
        static constexpr void ProcessBlocks(const uint8_t* buf, std::array<uint32_t, (N + 7) / 4 * 2>& out,
                                              size_t i, size_t paddedSize) {
            if (i < paddedSize) {
                uint32_t v0 = (uint32_t)buf[i] | ((uint32_t)buf[i+1] << 8)
                            | ((uint32_t)buf[i+2] << 16) | ((uint32_t)buf[i+3] << 24);
                uint32_t v1 = (uint32_t)buf[i+4] | ((uint32_t)buf[i+5] << 8)
                            | ((uint32_t)buf[i+6] << 16) | ((uint32_t)buf[i+7] << 24);
                uint32_t sum = 0;
                XteaRound(v0, v1, sum, 0);
                out[i / 4] = v0;
                out[i / 4 + 1] = v1;
                ProcessBlocks(buf, out, i + 8, paddedSize);
            }
        }

        constexpr EncryptedString(const char(&str)[N]) {
            uint8_t buf[256] = {};
            InitBuf(str, buf, 0);
            size_t paddedSize = ((N + 7) / 4) * 4;
            ProcessBlocks(buf, data, 0, paddedSize);
        }
    };
}

// ★ BUILD 499: STEALTH_STR 宏 — 使用栈分配缓冲区替代 std::string
//   用法: char buf[256]; STEALTH_STR_TO("敏感字符串", buf, sizeof(buf));
//   或直接使用 STEALTH_STR_STACK("敏感字符串") 返回解密后的栈缓冲区
//
//   注意: 返回的指针指向调用者栈上的局部缓冲区, 必须在同一作用域内使用
#define STEALTH_STR_DECRYPT_TO(str, outBuf, bufSize) do { \
    constexpr auto enc = detail::EncryptedString<sizeof(str)>(str); \
    size_t paddedSize = ((sizeof(str) + 7) / 4) * 4; \
    for (size_t i = 0; i < paddedSize; i += 8) { \
        uint32_t v0 = enc.data[i / 4]; \
        uint32_t v1 = enc.data[i / 4 + 1]; \
        uint32_t sum = 0xC6EF3720; \
        for (int r = 0; r < 32; r++) { \
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + detail::XTEA_KEY[(sum >> 11) & 3]); \
            sum -= detail::XTEA_DELTA; \
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + detail::XTEA_KEY[sum & 3]); \
        } \
        if (i < sizeof(str) - 1 && i < bufSize - 1) outBuf[i] = static_cast<char>(v0 & 0xFF); \
        if (i + 1 < sizeof(str) - 1 && i + 1 < bufSize - 1) outBuf[i + 1] = static_cast<char>((v0 >> 8) & 0xFF); \
        if (i + 2 < sizeof(str) - 1 && i + 2 < bufSize - 1) outBuf[i + 2] = static_cast<char>((v0 >> 16) & 0xFF); \
        if (i + 3 < sizeof(str) - 1 && i + 3 < bufSize - 1) outBuf[i + 3] = static_cast<char>((v0 >> 24) & 0xFF); \
        if (i + 4 < sizeof(str) - 1 && i + 4 < bufSize - 1) outBuf[i + 4] = static_cast<char>(v1 & 0xFF); \
        if (i + 5 < sizeof(str) - 1 && i + 5 < bufSize - 1) outBuf[i + 5] = static_cast<char>((v1 >> 8) & 0xFF); \
        if (i + 6 < sizeof(str) - 1 && i + 6 < bufSize - 1) outBuf[i + 6] = static_cast<char>((v1 >> 16) & 0xFF); \
        if (i + 7 < sizeof(str) - 1 && i + 7 < bufSize - 1) outBuf[i + 7] = static_cast<char>((v1 >> 24) & 0xFF); \
    } \
    outBuf[sizeof(str) - 1] = '\0'; \
} while(0)

// 运行时字符串 XOR 混淆工具 (用于动态生成的字符串)
class StringObfuscator {
public:
    // ★ BUILD 499: 使用输出缓冲区替代 std::vector<uint8_t> 返回值
    //   outBuf: 预分配缓冲区 (至少 strLen 字节)
    //   返回: 实际加密的字节数
    static int Encrypt(const char* str, uint8_t key, uint8_t* outBuf, int maxLen);

    // 栈上解密, 用后即毁 (防止内存扫描)
    template<size_t N>
    static void DecryptInPlace(uint8_t(&buf)[N], uint8_t key) {
        for (size_t i = 0; i < N; i++) {
            buf[i] ^= key ^ static_cast<uint8_t>(i * 0xAD);
        }
    }

    // 安全清零内存 (防止编译器优化掉)
    static void SecureZero(void* ptr, size_t size);
};

// ============================================================
// API 动态解析器
// 规避: 导入表特征扫描 (WriteProcessMemory + VirtualProtectEx + ... 组合)
// 原理: 使用 GetProcAddress + 哈希名称查找, 不在导入表中留下痕迹
// ============================================================

class ApiResolver {
public:
    struct ApiEntry {
        HMODULE module;
        FARPROC  proc;
    };

    // 通过 DLL 名哈希 + 函数名哈希 动态获取 API 地址
    // 规避: 导入表无敏感 API, 静态扫描看不到
    static FARPROC ResolveApi(const char* dllName, const char* funcName);

    // 延迟解析: 首次调用时解析, 之后缓存
    template<typename FnType>
    static FnType ResolveCached(const char* dllName, const char* funcName) {
        static FARPROC cached = nullptr;
        if (!cached) {
            cached = ResolveApi(dllName, funcName);
        }
        // 反 Hook 检测: 验证返回地址是否在合法模块内
        if (cached && !IsAddressInLegitModule(reinterpret_cast<uintptr_t>(cached))) {
            // 返回地址被 Hook, 重新从磁盘上的 DLL 获取
            cached = ReloadFromDisk(dllName, funcName);
        }
        return reinterpret_cast<FnType>(cached);
    }

    // 检测函数地址是否在合法模块范围内 (反 IAT/Inline Hook)
    static bool IsAddressInLegitModule(uintptr_t addr);

    // 从磁盘加载 DLL 副本读取原始导出表 (绕过 Hook)
    static FARPROC ReloadFromDisk(const char* dllName, const char* funcName);

    // 解析整个模块的基址 (替代 LoadLibrary 的静态导入)
    static HMODULE GetModuleBase(const char* moduleName);

private:
    // djb2 哈希用于快速查找
    static uint32_t HashString(const char* str);
};

} // namespace stealth