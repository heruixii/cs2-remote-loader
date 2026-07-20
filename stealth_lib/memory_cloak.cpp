// ============================================================
// memory_cloak.cpp — 内存隐身模块实现
// ============================================================

#include "memory_cloak.h"
#include "platform.h"
#include "syscall_direct.h"
#include "module_resolver.h"  // ★ BUILD 550: GetModuleBaseFromPEB + ModNameHash (替代 GetModuleHandleW)
// ★ BUILD 551: STEALTH_GET_PROC_ADDRESS_NOREF 宏 (EtwEventWrite / AmsiScanBuffer 加密解析)
#include "string_obfuscator.h"
#include <cmath>
#include <psapi.h>
#include <intrin.h>
// ★ BUILD 567 v3.238 DIAG: EkkoSleep 内部诊断日志所需
#include <cstdio>
#include <cstdarg>
// ★ BUILD 496: 移除 <chrono> <random> — CRT 堆依赖

#pragma comment(lib, "psapi.lib")

namespace stealth {

// ============================================================
// ★ BUILD 496: 自实现 LCG 随机数生成器 — 替代 std::mt19937
//   Manual-Map DLL 中 CRT 堆未初始化, std::mt19937 会崩溃
//   参数: Numerical Recipes 经典 LCG (a=1664525, c=1013904223, m=2^32)
// ============================================================
class SimpleRng {
public:
    SimpleRng(uint32_t seed) : m_state(seed) {}
    uint32_t Next() {
        m_state = m_state * 1664525u + 1013904223u;
        return m_state;
    }
    // 生成 [0, max) 范围内的整数
    uint32_t NextInt(uint32_t max) {
        if (max == 0) return 0;
        return Next() % max;
    }
    // 生成 [0.0, 1.0) 范围内的浮点数
    float NextFloat() {
        return static_cast<float>(Next()) / 4294967296.0f;
    }
    // 生成 [min, max] 范围内的浮点数
    float NextFloatRange(float min, float max) {
        return min + NextFloat() * (max - min);
    }
private:
    uint32_t m_state;
};

// ★ BUILD 496: 获取高精度种子 (替代 std::chrono)
static uint32_t GetRngSeed() {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return static_cast<uint32_t>(counter.LowPart ^ counter.HighPart);
}

// ★ BUILD 496: EkkoSleep 页面标记函数 — 紧邻 EkkoSleep 确保同页
//   编译器将同一 .cpp 的相邻函数放在同一 .text 区段, 
//   此标记函数确保 GetSelfPage() 返回的页面包含 EkkoSleep 代码
static void EkkoSleepPageMarker() {
    __asm__("nop"); // 占位, 永不执行
}

// ★ BUILD 544: 前向声明 — page marker 函数定义在各自目标函数前 (L94/L143/L175)
//   GetEncryptAllPage/GetDecryptAllPage/GetXorCryptPage 在 L115 引用这些 marker,
//   必须前向声明避免编译错误 (C3861: identifier not found)
static void EncryptAllPageMarker();
static void DecryptAllPageMarker();
static void XorCryptPageMarker();

// ============================================================
// SleepObfuscator
// ============================================================

SleepObfuscator& SleepObfuscator::Instance() {
    static SleepObfuscator instance;
    return instance;
}

void SleepObfuscator::RC4Crypt(void* data, SIZE_T size, const BYTE* key, SIZE_T keyLen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = static_cast<BYTE>(i);

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        // ★ BUILD 498: 手动 swap 替代 std::swap — 避免 CRT 依赖
        { BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp; }
    }

    int i_idx = 0;
    j = 0;
    auto* buf = static_cast<BYTE*>(data);
    for (SIZE_T n = 0; n < size; n++) {
        i_idx = (i_idx + 1) % 256;
        j = (j + S[i_idx]) % 256;
        // ★ BUILD 498: 手动 swap 替代 std::swap
        { BYTE tmp = S[i_idx]; S[i_idx] = S[j]; S[j] = tmp; }
        buf[n] ^= S[(S[i_idx] + S[j]) % 256];
    }
}

// ★ BUILD 544: XorCrypt 页面标记 — 紧邻 XorCrypt 定义确保同 4KB 页
//   EkkoSleep 期间 XorCrypt 被 EncryptAll/DecryptAll 调用, 其代码页必须保持明文
static void XorCryptPageMarker() {
    __asm__("nop"); // 占位, 永不执行
}

void SleepObfuscator::XorCrypt(void* data, SIZE_T size, BYTE key) {
    auto* buf = static_cast<BYTE*>(data);
    for (SIZE_T i = 0; i < size; i++) {
        buf[i] ^= key ^ static_cast<BYTE>(i * 0xAD + 0x37);
    }
}

// 返回 EkkoSleep 自身代码所在页面的基地址 (用于 EkkoSleep 自身页豁免)
// ★ BUILD 496: 使用 EkkoSleepPageMarker (紧邻 EkkoSleep 定义) 确保同一 4KB 页面
//   之前的 GetSelfPage 返回自身地址, 可能与 EkkoSleep 不在同一页
uintptr_t SleepObfuscator::GetSelfPage() {
    return reinterpret_cast<uintptr_t>(&EkkoSleepPageMarker) & ~0xFFFULL;
}

// ★ BUILD 544: 返回 EncryptAll/DecryptAll/XorCrypt 所在页面基地址
//   page marker 紧邻目标函数定义, 编译器将它们排到同一 4KB 页
//   EkkoSleep 调用这些函数期间必须豁免其代码页, 否则加密自身 → 崩溃
uintptr_t SleepObfuscator::GetEncryptAllPage() {
    return reinterpret_cast<uintptr_t>(&EncryptAllPageMarker) & ~0xFFFULL;
}
uintptr_t SleepObfuscator::GetDecryptAllPage() {
    return reinterpret_cast<uintptr_t>(&DecryptAllPageMarker) & ~0xFFFULL;
}
uintptr_t SleepObfuscator::GetXorCryptPage() {
    return reinterpret_cast<uintptr_t>(&XorCryptPageMarker) & ~0xFFFULL;
}

void SleepObfuscator::RegisterProtectedRegion(void* addr, SIZE_T size) {
    // ★ v3.125: 固定数组 — 检查容量
    if (m_regionCount >= MAX_REGIONS) return;

    ProtectedRegion& region = m_regions[m_regionCount++];
    region.addr = addr;
    region.size = size;
    region.isCode = false;

    // ★ BUILD 496: 自实现 LCG 替代 std::mt19937
    SimpleRng rng(GetRngSeed());
    region.xorKey = static_cast<BYTE>(rng.Next());
}

void SleepObfuscator::RegisterProtectedCode(void* addr, SIZE_T size) {
    // ★ v3.125: 固定数组 — 检查容量
    if (m_regionCount >= MAX_REGIONS) return;

    ProtectedRegion& region = m_regions[m_regionCount++];
    region.addr = addr;
    region.size = size;
    region.isCode = true;

    // ★ BUILD 496: 自实现 LCG 替代 std::mt19937
    SimpleRng rng(GetRngSeed());
    region.xorKey = static_cast<BYTE>(rng.Next());
}

// ★ BUILD 567 v3.244 DIAG: EK_RAW_LOG — 加密窗口内的原始日志宏
//   根因: v3.243 豁免 sleepObjPage 后仍崩溃, 需精确定位加密窗口内崩溃位置.
//   问题: EkkoDiagLog 内部调用 CRT 函数 (snprintf/strlen/memcpy/vsnprintf),
//         这些函数代码页在 payload.dll .text 段未豁免位置, 被 EncryptAll 加密 → 调用崩溃.
//   方案: EK_RAW_LOG 宏内联展开, 只调用 kernel32 函数 (GetTempPathW/CreateFileW/WriteFile/
//         FlushFileBuffers/CloseHandle), 通过 IAT 调用, IAT 在 .idata 段已豁免, 安全.
//         宏代码在 EkkoSleep/EncryptAll/DecryptAll 内部展开, 这些函数所在页已豁免, 不被加密.
//         不调用任何 CRT 函数, 字符串长度用 sizeof(msg)-1 编译期常量.
//   v3.245: 宏定义移到 EncryptAll 之前, 因为 v3.245 在 EncryptAll/DecryptAll 内部使用.
//   ★ BUILD 567 v3.251 FIX: L"sd.log" 改为栈上构造!
//     根因: v3.250 确认 sd.log 字符串在 .rdata 段 RVA 0x5FC18/0x61804/0x62158/0x62CD8,
//           EkkoSleep EncryptAll 加密 .rdata 段时加密了 sd.log 字符串,
//           下一次 EK_RAW_LOG 调用时 while(_ekSuf[_ekI]) 读取被加密的 sd.log,
//           加密后字节无 0 终止符 → 循环不终止 → 越界读取 → 访问违规崩溃.
//     修复: L"sd.log" 改为栈上 wchar_t 数组逐字节构造, 不读取 .rdata 段.
//   判读: 根据最后出现的日志判断崩溃位置:
//         EA start → EncryptAll 入口
//         EA skip → 跳过覆盖关键页的 region
//         EA r0-r5 → 正在处理第 0-5 个 region
//         EA VP fail → VirtualProtect 失败
//         EA done → EncryptAll 完成
//         EA+ post → EkkoSleep 中 EncryptAll 返回后
//         timer OK → CreateWaitableTimerW 成功
//         set OK → SetWaitableTimer 成功
//         wait OK → WaitForSingleObject 成功
//         DA start/DA skip/DA VP fail/DA done → DecryptAll 内部
//         DA+ post → DecryptAll 成功, EkkoSleep 应该正常返回
#define EK_RAW_LOG(msg) do { \
    wchar_t _ekPath[MAX_PATH]; \
    GetTempPathW(MAX_PATH, _ekPath); \
    size_t _ekPL = 0; while (_ekPath[_ekPL]) _ekPL++; \
    /* ★ v3.251 FIX: 栈上构造 "sd.log" 避免读取 .rdata 段 (EkkoSleep 加密 .rdata → 崩溃) */ \
    wchar_t _ekSuf[7]; \
    _ekSuf[0] = L's'; _ekSuf[1] = L'd'; _ekSuf[2] = L'.'; \
    _ekSuf[3] = L'l'; _ekSuf[4] = L'o'; _ekSuf[5] = L'g'; _ekSuf[6] = 0; \
    size_t _ekI = 0; while (_ekSuf[_ekI]) { _ekPath[_ekPL+_ekI] = _ekSuf[_ekI]; _ekI++; } \
    _ekPath[_ekPL+_ekI] = 0; \
    HANDLE _ekH = CreateFileW(_ekPath, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); \
    if (_ekH != INVALID_HANDLE_VALUE) { \
        DWORD _ekW; \
        WriteFile(_ekH, msg, (DWORD)(sizeof(msg)-1), &_ekW, 0); \
        FlushFileBuffers(_ekH); \
        CloseHandle(_ekH); \
    } \
} while(0)

// ★ BUILD 544: EncryptAll 页面标记 — 紧邻 EncryptAll 定义确保同 4KB 页
//   EkkoSleep 调用 EncryptAll 期间, EncryptAll 自身代码页必须保持明文
//   否则 EncryptAll 加密自身代码页 → 返回时执行已加密代码 → 无日志崩溃
static void EncryptAllPageMarker() {
    __asm__("nop"); // 占位, 永不执行
}

void SleepObfuscator::EncryptAll() {
    // ★ BUILD 567 v3.255 DIAG: EncryptAll 入口诊断
    //   v3.254 仍崩溃在 EA+ pre 之后, 需确认崩溃位置:
    //   - EA enter 出现 → EncryptAll 入口被执行, 崩溃在内部
    //   - EA enter 未出现 → EncryptAll 入口本身被加密 (函数代码页未豁免)
    EK_RAW_LOG("EA enter\n");
    uintptr_t ekkoPg = GetSelfPage();
    EK_RAW_LOG("EA g1\n");
    uintptr_t encAPg = GetEncryptAllPage();
    uintptr_t decAPg = GetDecryptAllPage();
    uintptr_t xorCPg = GetXorCryptPage();
    uintptr_t sleepPg = reinterpret_cast<uintptr_t>(this) & ~0xFFFULL;
    EK_RAW_LOG("EA g2\n");

    for (int ri = 0; ri < m_regionCount; ri++) {
        ProtectedRegion& region = m_regions[ri];
        uintptr_t rStart = reinterpret_cast<uintptr_t>(region.addr);
        uintptr_t rEnd = rStart + region.size;

        // ★ v3.245 FIX: 检查 region 是否覆盖任一关键页, 覆盖则跳过
        bool overlap = false;
        if (rStart < ekkoPg + 0x4000 && rEnd > ekkoPg) overlap = true;   // ekkoPage 4 页
        if (rStart < encAPg + 0x2000 && rEnd > encAPg) overlap = true;   // encryptAllPage 2 页
        if (rStart < decAPg + 0x2000 && rEnd > decAPg) overlap = true;   // decryptAllPage 2 页
        if (rStart < xorCPg + 0x2000 && rEnd > xorCPg) overlap = true;   // xorCryptPage 2 页
        if (rStart < sleepPg + 0x2000 && rEnd > sleepPg) overlap = true; // sleepObjPage 2 页
        if (overlap) continue;

        EK_RAW_LOG("EA r0\n");
        if (region.isCode) {
            DWORD oldProtect;
            if (!VirtualProtect(region.addr, region.size, PAGE_READWRITE, &oldProtect)) continue;
            EK_RAW_LOG("EA vp1\n");
            XorCrypt(region.addr, region.size, region.xorKey);
            EK_RAW_LOG("EA xc1\n");
            VirtualProtect(region.addr, region.size, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), region.addr, region.size);
        } else {
            DWORD oldProtect = 0;
            if (!VirtualProtect(region.addr, region.size, PAGE_READWRITE, &oldProtect)) continue;
            EK_RAW_LOG("EA vp2\n");
            XorCrypt(region.addr, region.size, region.xorKey);
            EK_RAW_LOG("EA xc2\n");
            VirtualProtect(region.addr, region.size, oldProtect, &oldProtect);
        }
    }
    EK_RAW_LOG("EA done\n");
}

// ★ BUILD 544: DecryptAll 页面标记 — 紧邻 DecryptAll 定义确保同 4KB 页
//   EkkoSleep 调用 DecryptAll 期间, DecryptAll 自身代码页必须保持明文
static void DecryptAllPageMarker() {
    __asm__("nop"); // 占位, 永不执行
}

void SleepObfuscator::DecryptAll() {
    // ★ BUILD 567 v3.252 SIMPLIFY: 移除所有 EK_RAW_LOG 诊断 (对称 EncryptAll)
    //   原因: 同 EncryptAll — 简化函数体积, 避免编译器重新布局代码导致 import thunk 位移.
    //   保留: 关键页跳过保护 (v3.245 FIX) — 必须与 EncryptAll 对称跳过, 否则解密未加密的 region → 数据损坏.
    uintptr_t ekkoPg = GetSelfPage();
    uintptr_t encAPg = GetEncryptAllPage();
    uintptr_t decAPg = GetDecryptAllPage();
    uintptr_t xorCPg = GetXorCryptPage();
    uintptr_t sleepPg = reinterpret_cast<uintptr_t>(this) & ~0xFFFULL;

    // ★ v3.125: 固定数组 — 只遍历 m_regionCount 个有效条目
    for (int ri = 0; ri < m_regionCount; ri++) {
        ProtectedRegion& region = m_regions[ri];
        uintptr_t rStart = reinterpret_cast<uintptr_t>(region.addr);
        uintptr_t rEnd = rStart + region.size;

        // ★ v3.245 FIX: 检查 region 是否覆盖任一关键页, 覆盖则跳过 (同 EncryptAll)
        bool overlap = false;
        if (rStart < ekkoPg + 0x4000 && rEnd > ekkoPg) overlap = true;
        if (rStart < encAPg + 0x2000 && rEnd > encAPg) overlap = true;
        if (rStart < decAPg + 0x2000 && rEnd > decAPg) overlap = true;
        if (rStart < xorCPg + 0x2000 && rEnd > xorCPg) overlap = true;
        if (rStart < sleepPg + 0x2000 && rEnd > sleepPg) overlap = true;
        if (overlap) continue;

        if (region.isCode) {
            DWORD oldProtect;
            if (!VirtualProtect(region.addr, region.size, PAGE_EXECUTE_READWRITE, &oldProtect)) continue;
            XorCrypt(region.addr, region.size, region.xorKey);
            VirtualProtect(region.addr, region.size, PAGE_EXECUTE_READ, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), region.addr, region.size);
        } else {
            // ★ v3.37 FIX: 检查 VirtualProtect 返回值 (同 EncryptAll)
            DWORD oldProtect = 0;
            if (!VirtualProtect(region.addr, region.size, PAGE_READWRITE, &oldProtect)) continue;
            XorCrypt(region.addr, region.size, region.xorKey);
            VirtualProtect(region.addr, region.size, oldProtect, &oldProtect);
        }
    }
}

void SleepObfuscator::ObfuscatedSleep(DWORD milliseconds) {
    // ★ v3.125: 固定数组 m_regionCount
    if (m_regionCount == 0) {
        Sleep(milliseconds);
        return;
    }

    // 加密 → 短暂睡眠 → 解密
    // 将长睡眠拆分为多个短周期
    const DWORD CHUNK_MS = 50; // 每 50ms 解密一次

    DWORD remaining = milliseconds;
    while (remaining > 0) {
        DWORD chunk = (remaining < CHUNK_MS) ? remaining : CHUNK_MS;

        // ★ v3.37: EncryptAll/DecryptAll 已安全化, VirtualProtect 失败会自动跳过
        EncryptAll();
        Sleep(chunk);
        DecryptAll();

        remaining -= chunk;
    }
}

// ★ BUILD 567 v3.238 DIAG: EkkoSleep 内部诊断日志函数
//   - 独立实现 (避免依赖 payload.cpp 的 DiagLog)
//   - 紧邻 EkkoSleep 实现, 落入同一 4KB 页 (已被 exemptPages ekkoPage 豁免)
//   - 写入 %TEMP%\sd.log (与 DiagLog 同文件, 共享时间戳格式)
//   - FlushFileBuffers 强制落盘 (防止崩溃时缓存丢失)
//   - 安全性: 仅在 EkkoSleep 入口/出口调用, 不在加密窗口内调用
//              (EncryptAll 之后代码页加密, 调用任何函数都会执行加密代码 → 崩溃)
static void EkkoDiagLog(const char* fmt, ...) {
    char tsBuf[32];
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(tsBuf, sizeof(tsBuf), "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    int tsLen = (int)strlen(tsBuf);

    char buf[640];
    memcpy(buf, tsBuf, tsLen);
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf + tsLen, sizeof(buf) - tsLen, fmt, args);
    va_end(args);
    if (len < 0) len = 0;
    if (len > (int)(sizeof(buf) - tsLen - 1)) len = (int)(sizeof(buf) - tsLen - 1);
    len += tsLen;

    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, MAX_PATH, L"sd.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);
        CloseHandle(h);
    }
}

// ★ BUILD 567 v3.244 DIAG: EK_RAW_LOG 宏定义已移到 EncryptAll 之前 (L166 附近)
//   原因: v3.245 在 EncryptAll/DecryptAll 内部使用 EK_RAW_LOG, 宏定义必须在调用之前

void SleepObfuscator::EkkoSleep(DWORD milliseconds) {
    // Ekko 技术: 使用 WaitableTimer 替代 Sleep
    // 在计时器触发前加密内存, 触发后解密

    // ★ BUILD 567 v3.241 DIAG: EkkoSleep 函数自身地址诊断
    //   使用 GCC &&label 扩展获取 EkkoSleep 内部 label 地址 (近似 EkkoSleep 入口)
    //   v3.240 添加 ekkoPage+0x1000 豁免后仍崩溃 → EkkoSleep 可能跨到 ekkoPage+0x2000
    //   判读: inEkko0=1 → EkkoSleep 在 ekkoPage (已豁免)
    //         inEkko1=1 → EkkoSleep 在 ekkoPage+0x1000 (v3.240 已豁免)
    //         inEkko2=1 → EkkoSleep 在 ekkoPage+0x2000 (v3.241 已豁免, 若仍崩溃需 +0x3000)
    //         全 0 → EkkoSleep 在 [ekkoPage, ekkoPage+0x3000) 之外, 编译器放在远处
    //   安全性: 此日志在 EncryptAll 之前调用, 代码页未加密, 安全
ekko_sleep_entry:
    {
        uintptr_t ekkoSleepAddr = reinterpret_cast<uintptr_t>(&&ekko_sleep_entry);
        uintptr_t ekkoPage = GetSelfPage();
        int sleepInEkko0 = (ekkoSleepAddr >= ekkoPage && ekkoSleepAddr < ekkoPage + 0x1000) ? 1 : 0;
        int sleepInEkko1 = (ekkoSleepAddr >= ekkoPage + 0x1000 && ekkoSleepAddr < ekkoPage + 0x2000) ? 1 : 0;
        int sleepInEkko2 = (ekkoSleepAddr >= ekkoPage + 0x2000 && ekkoSleepAddr < ekkoPage + 0x3000) ? 1 : 0;
        EkkoDiagLog("B241:EK:self ekkoSleep=0x%llX ekkoPage=0x%llX inEkko0=%d inEkko1=%d inEkko2=%d\n",
            (unsigned long long)ekkoSleepAddr,
            (unsigned long long)ekkoPage,
            sleepInEkko0, sleepInEkko1, sleepInEkko2);
    }

    // ★ BUILD 567 v3.239 DIAG: 地址诊断 — 确认 EkkoDiagLog/EkkoSleep 是否在 ekkoPage 中
    //   ekkoPage = GetSelfPage() = EkkoSleepPageMarker 的页 (已豁免)
    //   v3.238 崩溃现象: "B238:EK:EA+ pre" 有日志, "B238:EK:EA+ post" 无日志
    //   根因假设: EkkoDiagLog 不在 ekkoPage 中, 被 EncryptAll 加密 → 调用时执行加密代码 → 崩溃
    //   验证逻辑:
    //     diagInEkko=1 → EkkoDiagLog 在豁免页 → 根因假设错误, 需重新分析
    //     diagInEkko=0 → EkkoDiagLog 不在豁免页 → 根因确认 → v3.240 修复
    //   安全性: 此日志在 EncryptAll 之前调用, 代码页未加密, 安全
    {
        uintptr_t ekkoPage = GetSelfPage();
        uintptr_t diagLogAddr = reinterpret_cast<uintptr_t>(&EkkoDiagLog);
        uintptr_t markerAddr = reinterpret_cast<uintptr_t>(&EkkoSleepPageMarker);
        uintptr_t encAPage = GetEncryptAllPage();
        uintptr_t decAPage = GetDecryptAllPage();
        uintptr_t xorCPage = GetXorCryptPage();
        int diagInEkko = (diagLogAddr >= ekkoPage && diagLogAddr < ekkoPage + 0x1000) ? 1 : 0;
        int markerInEkko = (markerAddr >= ekkoPage && markerAddr < ekkoPage + 0x1000) ? 1 : 0;
        EkkoDiagLog("B239:EK:addr ekkoPage=0x%llX diagLog=0x%llX marker=0x%llX encA=0x%llX decA=0x%llX xorC=0x%llX diagInEkko=%d markerInEkko=%d\n",
            (unsigned long long)ekkoPage,
            (unsigned long long)diagLogAddr,
            (unsigned long long)markerAddr,
            (unsigned long long)encAPage,
            (unsigned long long)decAPage,
            (unsigned long long)xorCPage,
            diagInEkko, markerInEkko);
    }

    // ★ BUILD 567 v3.243 DIAG: SleepObfuscator 对象 (this) 地址诊断
    //   根因假设: m_regions[64] 数组 (~1.5KB) 在 .bss 段, 若所在页未被豁免,
    //             EncryptAll 处理覆盖 .bss 的 region 时会加密 m_regions 本身 → 崩溃
    //   判读: objInEkko=1/encA=1/decA=1 → 对象在已豁免页 (排除根因)
    //         全 0 → 对象在未豁免页 → 根因确认 → v3.243 已在 payload.cpp 添加 sleepObjPage 豁免
    //   安全性: 此日志在 EncryptAll 之前调用, 代码页未加密, 安全
    {
        uintptr_t thisAddr = reinterpret_cast<uintptr_t>(this);
        uintptr_t mregsAddr = reinterpret_cast<uintptr_t>(m_regions);
        uintptr_t ekkoPage = GetSelfPage();
        uintptr_t encAPage = GetEncryptAllPage();
        uintptr_t decAPage = GetDecryptAllPage();
        uintptr_t thisPage = thisAddr & ~0xFFFULL;
        int objInEkko = (thisPage == ekkoPage) ? 1 : 0;
        int objInEncA = (thisPage == encAPage) ? 1 : 0;
        int objInDecA = (thisPage == decAPage) ? 1 : 0;
        EkkoDiagLog("B243:EK:this this=0x%llX m_regions=0x%llX m_regionCount=%d thisPage=0x%llX objInEkko=%d objInEncA=%d objInDecA=%d\n",
            (unsigned long long)thisAddr,
            (unsigned long long)mregsAddr,
            m_regionCount,
            (unsigned long long)thisPage,
            objInEkko, objInEncA, objInDecA);
    }

    // ★ BUILD 567 v3.238 DIAG: EkkoSleep 入口日志
    //   若 "EA+ pre" 有 "EA+ post" 无 → EncryptAll 内部崩溃
    //   若 "DA+ pre" 有 "DA+ post" 无 → DecryptAll 内部崩溃
    EkkoDiagLog("B238:EK:enter ms=%u regions=%d\n",
        (unsigned)milliseconds, m_regionCount);

    // ★ v3.125: 固定数组 m_regionCount
    if (m_regionCount == 0) {
        EkkoDiagLog("B238:EK:no-regions fallback Sleep\n");
        Sleep(milliseconds);
        EkkoDiagLog("B238:EK:exit (no-regions)\n");
        return;
    }

    // ★ v3.38 FIX: 移除冗余的 CreateTimerQueue — 它创建内核线程池
    //   但我们不使用任何 timer callback, 线程池纯属浪费且可能引发未知行为
    //   直接使用 EncryptAll → WaitableTimer → DecryptAll 即可

    // ★ v3.37: EncryptAll/DecryptAll 已安全化 (检查 VirtualProtect 返回值)
    // ★ BUILD 567 v3.238 DIAG: EncryptAll 前后日志
    // ★ BUILD 567 v3.242 FIX: 移除加密窗口内的 EkkoDiagLog 调用
    //   根因: EkkoDiagLog 内部调用 CRT 函数 (vsnprintf/snprintf/strlen/memcpy),
    //         这些函数代码页在 payload.dll .text 段未豁免位置, 被 EncryptAll 加密 → 崩溃
    //   修复: 移除 EncryptAll 之后 / DecryptAll 之前的所有 EkkoDiagLog 调用
    //   保留: EncryptAll 之前 (代码页未加密) 和 DecryptAll 之后 (代码页已解密) 的日志
    EkkoDiagLog("B238:EK:EA+ pre\n");
    EncryptAll();
    // ★ BUILD 567 v3.244 DIAG: 加密窗口内用 EK_RAW_LOG (不调用 CRT 函数)
    //   若 "EA+ post" 出现 → EncryptAll 成功, 崩溃在 CreateWaitableTimerW 或之后
    //   若 "EA+ post" 未出现 → 崩溃在 EncryptAll 内部
    EK_RAW_LOG("EA+ post\n");

    HANDLE hWaitableTimer = CreateWaitableTimerW(nullptr, TRUE, nullptr);
    if (!hWaitableTimer) {
        EK_RAW_LOG("timer FAIL\n");
        DecryptAll();  // 加密后必须解密, 否则内存处于损坏状态
        ObfuscatedSleep(milliseconds);
        EkkoDiagLog("B238:EK:exit (fallback)\n");  // ✅ DecryptAll 之后, 安全
        return;
    }
    EK_RAW_LOG("timer OK\n");

    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -static_cast<LONGLONG>(milliseconds) * 10000LL;
    SetWaitableTimer(hWaitableTimer, &dueTime, 0, nullptr, nullptr, FALSE);
    EK_RAW_LOG("set OK\n");

    WaitForSingleObject(hWaitableTimer, INFINITE);
    EK_RAW_LOG("wait OK\n");

    // ★ BUILD 567 v3.238 DIAG: DecryptAll 前后日志
    //   若 pre 有 post 无 → DecryptAll 内部崩溃 (代码页保持加密)
    // ★ BUILD 567 v3.242 FIX: 移除 "B238:EK:DA+ pre" (DecryptAll 之前, 代码页仍加密)
    // ★ v3.242: 移除 "B238:EK:DA+ pre" (加密窗口内, EkkoDiagLog 调用会崩溃)
    // ★ BUILD 567 v3.244 DIAG: 用 EK_RAW_LOG 替代 (不调用 CRT 函数, 安全)
    EK_RAW_LOG("DA+ pre\n");
    DecryptAll();
    EK_RAW_LOG("DA+ post\n");

    CloseHandle(hWaitableTimer);
    EkkoDiagLog("B238:EK:exit (normal)\n");
}

void SleepObfuscator::FoliageSleep(DWORD milliseconds) {
    // Foliage 技术: 使用 NtWaitForSingleObject 的 APC 变体
    // 当 APC 排队时, 线程被唤醒 → 加密内存 → 继续等待

    // ★ v3.125: 固定数组 m_regionCount
    if (m_regionCount == 0) {
        Sleep(milliseconds);
        return;
    }

    // 简化实现: 使用分段的 WaitForSingleObject
    const DWORD CHUNK_MS = 30;
    DWORD remaining = milliseconds;

    // 循环外创建一次 Event, 避免每30ms创建/销毁内核对象
    HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    // K6: 预先生成 syscall stub, 避免每个30ms循环重复分配 4KB
    auto& resolver = SyscallResolver::Instance();
    DWORD ssn = resolver.GetNumbers().NtWaitForSingleObject;
    void* stub = (ssn && hEvent) ? TartarusGate::GenerateSyscallStub(ssn) : nullptr;
    using NtWaitForSingleObject_t = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
    auto fn = stub ? reinterpret_cast<NtWaitForSingleObject_t>(stub) : nullptr;

    while (remaining > 0) {
        DWORD chunk = stealth_platform::min(remaining, CHUNK_MS);

        // ★ v3.37: EncryptAll/DecryptAll 已安全化
        EncryptAll();

        LARGE_INTEGER timeout;
        timeout.QuadPart = -static_cast<LONGLONG>(chunk) * 10000LL;

        if (fn && hEvent) {
            fn(hEvent, FALSE, &timeout);
        }

        DecryptAll();
        remaining -= chunk;
    }

    if (stub) VirtualFree(stub, 0, MEM_RELEASE);
    if (hEvent) CloseHandle(hEvent);
}

// ============================================================
// ModuleStomper
// ============================================================

ModuleStomper::StompCandidate
ModuleStomper::FindCandidateInSelf(SIZE_T requiredSize) {
    StompCandidate best = {};

    // 候选模块: 加载的不敏感 DLL
    const wchar_t* candidates[] = {
        L"msvcrt.dll", L"userenv.dll", L"uxtheme.dll",
        L"dwmapi.dll", L"version.dll", L"ws2_32.dll",
        L"iphlpapi.dll", L"dnsapi.dll", L"winmm.dll"
    };

    for (auto* modName : candidates) {
        // ★ BUILD 550: PEB Ldr 遍历替代 GetModuleHandleW (规避 PAC 用户态 hook)
        HMODULE hMod = stealth::GetModuleBaseFromPEB(stealth::ModNameHashRT(modName));
        if (!hMod) continue;

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
            continue;

        SIZE_T gap = FindWritableGap(hMod, requiredSize);
        if (gap >= requiredSize) {
            // 找到可用间隙
            best.module = hMod;
            best.baseAddress = reinterpret_cast<uintptr_t>(hMod);
            best.moduleSize = modInfo.SizeOfImage;
            best.availableSize = gap;
            // ★ BUILD 496: 固定数组替代 std::wstring
            wcscpy_s(best.moduleName, modName);
            break;
        }
    }

    return best;
}

ModuleStomper::StompCandidate
ModuleStomper::FindCandidateInProcess(HANDLE hProcess, SIZE_T requiredSize) {
    StompCandidate best = {};

    // 枚举目标进程模块
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return best;

    DWORD modCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < modCount; i++) {
        WCHAR modName[MAX_PATH] = {};
        GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH);

        // 跳过关键系统模块和反作弊模块
        if (_wcsicmp(modName, L"ntdll.dll") == 0 ||
            _wcsicmp(modName, L"kernel32.dll") == 0 ||
            _wcsicmp(modName, L"kernelbase.dll") == 0 ||
            wcsstr(modName, L"steam") ||
            wcsstr(modName, L"vac") ||
            wcsstr(modName, L"overlay")) {
            continue;
        }

        // 查找不重要的游戏 DLL 中的空隙
        MODULEINFO modInfo;
        if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
            // 检查模块中可写的区段间隙
            auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hMods[i]);
            if (IsBadReadPtr(dos, sizeof(IMAGE_DOS_HEADER)) || dos->e_magic != IMAGE_DOS_SIGNATURE)
                continue;

            auto* ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<uintptr_t>(hMods[i]) + dos->e_lfanew);
            if (IsBadReadPtr(ntHdr, sizeof(IMAGE_NT_HEADERS)) || ntHdr->Signature != IMAGE_NT_SIGNATURE)
                continue;

            auto* section = IMAGE_FIRST_SECTION(ntHdr);
            for (int s = 0; s < static_cast<int>(ntHdr->FileHeader.NumberOfSections); s++) {
                bool isWritable = (section[s].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                bool isExecutable = (section[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

                if (isWritable && !isExecutable) {
                    SIZE_T rawSize = section[s].SizeOfRawData;
                    SIZE_T virtSize = section[s].Misc.VirtualSize;
                    if (virtSize > rawSize + requiredSize) {
                        best.module = reinterpret_cast<HMODULE>(hMods[i]);
                        best.baseAddress = reinterpret_cast<uintptr_t>(hMods[i]);
                        best.moduleSize = modInfo.SizeOfImage;
                        best.availableSize = virtSize - rawSize;
                        // ★ BUILD 496: 固定数组替代 std::wstring
                        wcscpy_s(best.moduleName, modName);
                        return best;
                    }
                }
            }
        }
    }

    return best;
}

SIZE_T ModuleStomper::FindWritableGap(HMODULE mod, SIZE_T minSize) {
    // 在模块区段之间找可写的空隙
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(mod) + dos->e_lfanew);

    auto* section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < static_cast<int>(nt->FileHeader.NumberOfSections); i++) {
        char name[9] = {};
        memcpy(name, section[i].Name, 8);

        // 优先选择 .data 或 .bss 区段 (通常有大块无用区域)
        bool isWritable = (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        bool isExecutable = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool isBss = (strstr(name, ".bss") != nullptr);
        bool isData = (strstr(name, ".data") != nullptr);

        if (isWritable && !isExecutable && (isData || isBss)) {
            // .data 区段末尾通常有空隙
            SIZE_T rawSize = section[i].SizeOfRawData;
            SIZE_T virtSize = section[i].Misc.VirtualSize;

            if (virtSize > rawSize + minSize) {
                return virtSize - rawSize;
            }
        }
    }

    return 0;
}

bool ModuleStomper::StompInto(StompCandidate& candidate,
                               const void* payload, SIZE_T payloadSize) {
    // ★ BUILD 496: 固定数组替代 std::vector<BYTE> — 避免 CRT 堆依赖
    //   StompInto 的 payloadSize 通常很小 (< 4KB), 使用栈上数组
    if (payloadSize > 4096) return false; // 超过安全阈值
    BYTE backup[4096];
    memcpy(backup, reinterpret_cast<void*>(candidate.targetAddress), payloadSize);

    // 修改内存保护
    DWORD oldProtect;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(candidate.targetAddress),
                        payloadSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // 写入 payload
    memcpy(reinterpret_cast<void*>(candidate.targetAddress), payload, payloadSize);

    // 刷新缓存
    FlushInstructionCache(GetCurrentProcess(),
        reinterpret_cast<LPCVOID>(candidate.targetAddress), payloadSize);

    return true;
}

bool ModuleStomper::RestoreStomped(const StompCandidate& candidate,
                                    const BYTE* backup, SIZE_T backupSize) {
    DWORD oldProtect;
    VirtualProtect(reinterpret_cast<LPVOID>(candidate.targetAddress),
                   backupSize, PAGE_READWRITE, &oldProtect);

    memcpy(reinterpret_cast<void*>(candidate.targetAddress),
           backup, backupSize);

    VirtualProtect(reinterpret_cast<LPVOID>(candidate.targetAddress),
                   backupSize, oldProtect, &oldProtect);

    return true;
}

bool ModuleStomper::IsInLegitimateModule(uintptr_t addr) {
    // ★ BUILD 550: PEB Ldr 遍历替代 GetModuleHandleExW (规避 PAC 用户态 hook)
    //   原实现: GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, addr, &hMod)
    //   新实现: 遍历 PEB Ldr, 检查 addr 是否落在某模块的 [DllBase, DllBase+SizeOfImage) 范围
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return false;
    // ★ BUILD 550: MinGW 下 _PEB_LDR_DATA 无 InLoadOrderModuleList 字段, 用宏访问
    PLIST_ENTRY head = LDR_INLOAD_HEAD(peb->Ldr);
    PLIST_ENTRY entry = head->Flink;
    while (entry && entry != head) {
        auto* dataEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        HMODULE dllBase = static_cast<HMODULE>(LDR_ENTRY_DLLBASE(dataEntry));
        if (dllBase) {
            // 获取模块大小 (从 PE 头读取 SizeOfImage)
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dllBase);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(dllBase) + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    uintptr_t base = reinterpret_cast<uintptr_t>(dllBase);
                    uintptr_t end = base + nt->OptionalHeader.SizeOfImage;
                    if (addr >= base && addr < end) {
                        // 找到所属模块, 检查路径是否合法
                        // ★ BUILD 496: 手动小写比较替代 std::wstring
                        WCHAR modPath[MAX_PATH] = {};
                        GetModuleFileNameW(dllBase, modPath, MAX_PATH);
                        for (int i = 0; i < MAX_PATH && modPath[i]; i++) {
                            modPath[i] = towlower(modPath[i]);
                        }
                        return (wcsstr(modPath, L"\\system32\\") != nullptr ||
                                wcsstr(modPath, L"\\windows\\") != nullptr ||
                                wcsstr(modPath, L"\\steamapps\\") != nullptr);
                    }
                }
            }
        }
        entry = entry->Flink;
    }
    return false;
}

// ============================================================
// PhantomSection
// ============================================================

void* PhantomSection::AllocatePhantom(SIZE_T size) {
    // 使用 MEM_TOP_DOWN + 特定地址范围使其看起来像系统分配
    // 或使用 NtCreateSection + SEC_IMAGE 标志

    return AllocateAsImageSection(size, L"api-ms-win-core-sysinfo-l1-1-0.dll");
}

void* PhantomSection::AllocateAsImageSection(SIZE_T size, const wchar_t* disguiseName) {
    // 创建 Section 对象, 模仿 DLL 映射
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = {};
    maxSize.QuadPart = static_cast<LONGLONG>(size);

    using NtCreateSection_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    static auto NtCreateSection = reinterpret_cast<NtCreateSection_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtCreateSection"));

    if (!NtCreateSection) return nullptr;

    // 创建 Section (页面文件支持的内存段, VAD 条目表现为正常映射)
    // 注意: 不使用 SEC_IMAGE (需要文件句柄), 而是使用 SEC_COMMIT
    // 此处 VAD 伪装效果有限, 完整实现需要映射到文件支持的对象
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS st = NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        &oa,
        &maxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT, // 不是 SEC_IMAGE, 但 VAD 条目仍正常
        nullptr
    );

    if (!NT_SUCCESS(st)) return nullptr;

    // 映射到随机地址 (模仿 ASLR)
    PVOID baseAddr = nullptr;
    SIZE_T viewSize = size;

    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
        SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    static auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtMapViewOfSection"));

    if (NtMapViewOfSection) {
        NtMapViewOfSection(hSection, GetCurrentProcess(), &baseAddr,
            0, size, nullptr, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    }

    CloseHandle(hSection);
    return baseAddr;
}

uintptr_t PhantomSection::AllocatePhantomInProcess(HANDLE hProcess, SIZE_T size) {
    // 在目标进程中创建幽灵分配
    HANDLE hSection = nullptr;
    LARGE_INTEGER maxSize = {};
    maxSize.QuadPart = static_cast<LONGLONG>(size);

    using NtCreateSection_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    static auto NtCreateSection = reinterpret_cast<NtCreateSection_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtCreateSection"));

    if (!NtCreateSection) return 0;

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS st = NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        &oa, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr
    );

    if (!NT_SUCCESS(st)) return 0;

    PVOID remoteAddr = nullptr;
    SIZE_T viewSize = size;

    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
        SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    static auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtMapViewOfSection"));

    if (NtMapViewOfSection) {
        NtMapViewOfSection(hSection, hProcess, &remoteAddr,
            0, size, nullptr, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    }

    CloseHandle(hSection);
    return reinterpret_cast<uintptr_t>(remoteAddr);
}

// ============================================================
// ★ Fix B2: VAD Hiding — NtQueryVirtualMemory 代理实现
// ============================================================

// ★ v3.125: 固定数组替代 std::vector — 避免 CRT 堆依赖
PhantomSection::VADHiddenRegion PhantomSection::s_vadHiddenRegions[PhantomSection::MAX_VAD_REGIONS];
int PhantomSection::s_vadRegionCount = 0;

void PhantomSection::RegisterForVADHide(void* addr, SIZE_T size) {
    if (!addr || size == 0) return;
    // ★ v3.125: 固定数组 — 检查容量
    if (s_vadRegionCount >= MAX_VAD_REGIONS) return;

    VADHiddenRegion& region = s_vadHiddenRegions[s_vadRegionCount++];
    region.addr = addr;
    region.size = size;
}

bool PhantomSection::IsInVADHiddenRegion(void* addr) {
    uintptr_t target = reinterpret_cast<uintptr_t>(addr);
    // ★ v3.125: 固定数组 — 只遍历 s_vadRegionCount 个有效条目
    for (int i = 0; i < s_vadRegionCount; i++) {
        const VADHiddenRegion& region = s_vadHiddenRegions[i];
        uintptr_t base = reinterpret_cast<uintptr_t>(region.addr);
        if (target >= base && target < base + region.size) {
            return true;
        }
    }
    return false;
}

HMODULE PhantomSection::GetDisguiseModuleBase() {
    // ★ Fix B2: 返回 ntdll.dll 基址用于 VAD AllocationBase 伪装
    // ntdll.dll 是所有 Windows 进程的默认加载模块, 
    // 将其作为 AllocationBase 可使隐藏区域看起来像 ntdll 的正常映射
    return stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
}

PhantomSection::NtQVM_t PhantomSection::GetRealNtQueryVirtualMemory() {
    static NtQVM_t s_realNtQVM = nullptr;
    if (!s_realNtQVM) {
        s_realNtQVM = reinterpret_cast<NtQVM_t>(
            STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtQueryVirtualMemory"));
    }
    return s_realNtQVM;
}

NTSTATUS NTAPI PhantomSection::NtQueryVirtualMemoryProxy(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength)
{
    // ★ Fix B2: 首先调用真实的 NtQueryVirtualMemory 获取真实信息
    auto realNtQVM = GetRealNtQueryVirtualMemory();
    if (!realNtQVM) return STATUS_NOT_SUPPORTED;

    NTSTATUS st = realNtQVM(ProcessHandle, BaseAddress,
                             MemoryInformationClass,
                             MemoryInformation,
                             MemoryInformationLength,
                             ReturnLength);

    // 仅处理 MemoryBasicInformation (class 0) 的伪装
    if (MemoryInformationClass != 0) return st;

    // 仅伪装当前进程的查询 (外部进程不受影响)
    if (ProcessHandle != GetCurrentProcess()) return st;

    if (!NT_SUCCESS(st)) return st;

    // 检查查询地址是否在我们的 VAD 隐藏区域内
    if (!IsInVADHiddenRegion(BaseAddress)) return st;

    // ★ Fix B2: 修改 MEMORY_BASIC_INFORMATION 进行 VAD 伪装
    auto* mbi = static_cast<MEMORY_BASIC_INFORMATION*>(MemoryInformation);

    // Type: 改为 MEM_IMAGE (0x1000000) 伪装成从磁盘映射的 DLL 镜像
    // 而不是暴露 MEM_PRIVATE (0x20000) 的 VirtualAlloc 分配特征
    mbi->Type = MEM_IMAGE;  // 0x1000000

    // State: 保持 MEM_COMMIT (不变, 已提交的内存)
    // mbi->State 保持不变

    // Protection: 改为 PAGE_READONLY 而非 EXECUTE_READ
    // 让区域看起来像只读数据, 不暴露可执行特征
    // 只有当原本就是可执行才需要伪装, 如果是普通数据页则保持原样
    if (mbi->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        mbi->Protect = PAGE_READONLY;
    }
    // AllocationProtect 同样修改
    if (mbi->AllocationProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        mbi->AllocationProtect = PAGE_READONLY;
    }

    // ★ Fix B2: AllocationBase 指向合法模块 (ntdll.dll)
    // 使该区域看起来像是 ntdll 的一部分映射
    HMODULE disguiseMod = GetDisguiseModuleBase();
    if (disguiseMod) {
        mbi->AllocationBase = disguiseMod;
    }

    return st;
}

// ============================================================
// SelfCloaker — 自身 ManualMap 内存隐身
// ============================================================

SelfCloaker::CloakResult SelfCloaker::CloakManualMap(HMODULE dllBase, SIZE_T dllSize) {
    CloakResult result = {};

    if (!dllBase || dllSize < 0x1000) return result;

    // 1. 擦除 PE 头
    result.peStripped = StripPEHeaders(dllBase);

    // 2. 添加假 PEB Ldr 条目
    result.ldrCloaked = AddFakeLdrEntry(dllBase, dllSize, L"dxgi_adapter_cache.dll");

    // 2b. 移除自身 EXE 的 Ldr 条目 (隐藏 loader.exe 模块名)
    // SKIP: ManualMap 场景下 PEB 链表操作不稳定, 自删除已足够隐蔽
    // UnlinkSelfLdrEntry();

    // 3. 随机化页保护
    // SKIP: ManualMap 场景下 RandomizeProtections 不稳定
    result.protectionMixed = true;
    // result.protectionMixed = RandomizeProtections(dllBase, dllSize);

    return result;
}

bool SelfCloaker::StripPEHeaders(HMODULE base) {
    if (!base) return false;

    BYTE* image = reinterpret_cast<BYTE*>(base);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);

    // 验证 MZ 签名
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    DWORD peOffset = dos->e_lfanew;
    if (peOffset < sizeof(IMAGE_DOS_HEADER) || peOffset > 0x1000) return false;

    IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + peOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // --- 步骤1: 擦除 DOS 头 (0x00 - 0x3C) ---
    // 保留 e_lfanew 偏移信息后擦除
    DWORD savedElfanew = dos->e_lfanew;
    
    DWORD oldProtect = 0;
    VirtualProtect(image, 0x1000, PAGE_READWRITE, &oldProtect);

    // 用随机字节填充 DOS 头区域 (0x00 - 0x3C), 人为保留 e_lfanew
    SimpleRng rng(GetRngSeed());
    for (SIZE_T i = 0; i < sizeof(IMAGE_DOS_HEADER); i++) {
        image[i] = static_cast<BYTE>(rng.Next() & 0xFF);
    }
    // 恢复 e_lfanew (后续可能需要定位 NT 头)
    *reinterpret_cast<DWORD*>(image + 0x3C) = savedElfanew;

    // --- 步骤2: 擦除 PE 签名 (4 字节 "PE\0\0") ---
    image[peOffset + 0] = 'R';
    image[peOffset + 1] = 'X';
    image[peOffset + 2] = static_cast<BYTE>(rng.Next());
    image[peOffset + 3] = static_cast<BYTE>(rng.Next());

    // --- 步骤3: 擦除 COFF 文件头 (Machine→NumberOfSections → SizeOfOptionalHeader→Magic) ---
    // COFF 头位置: peOffset + 4
    SIZE_T coffOffset = peOffset + 4;
    SIZE_T coffSize = sizeof(IMAGE_FILE_HEADER);

    for (SIZE_T i = 0; i < coffSize; i++) {
        image[coffOffset + i] = static_cast<BYTE>(rng.Next() & 0xFF);
    }

    // --- 步骤4: 擦除 OptionalHeader 的前半部分 (Magic → SizeOfStackCommit) ---
    // 保留 SizeOfImage (用于 Ldr 条目), AddressOfEntryPoint, BaseOfCode, 
    // 以及 DataDirectory (导入表等已解析)
    SIZE_T optOffset = peOffset + 4 + sizeof(IMAGE_FILE_HEADER);
    SIZE_T optKeepFrom = offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfStackReserve);

    for (SIZE_T i = 0; i < optKeepFrom; i++) {
        image[optOffset + i] = static_cast<BYTE>(rng.Next() & 0xFF);
    }

    VirtualProtect(image, 0x1000, oldProtect, &oldProtect);

    return true;
}

bool SelfCloaker::AddFakeLdrEntry(HMODULE base, SIZE_T size, const wchar_t* disguiseName) {
    if (!base || size == 0) return false;

    // 获取 PEB
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return false;

    PPEB_LDR_DATA ldr = PEB_LDR_PTR(peb);
    if (!ldr) return false;

    // 分配 LDR_DATA_TABLE_ENTRY_FULL (在堆上, 使其看起来像系统分配)
    SIZE_T entrySize = sizeof(LDR_DATA_TABLE_ENTRY_FULL) + 512; // 额外空间给模块名
    auto* fakeEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_FULL*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, entrySize));
    if (!fakeEntry) return false;

    // 填充条目信息
    // 直接用结构体字段写入 (LDR_ENTRY_DLLBASE 在 MinGW 下为函数调用, 不可赋值)
    fakeEntry->DllBase = base;
    fakeEntry->SizeOfImage = static_cast<ULONG>(size);
    fakeEntry->EntryPoint = nullptr; // DLL 入口 (已执行)

    // 复制伪装模块名 (放在结构体后的额外空间)
    auto* nameBuf = reinterpret_cast<wchar_t*>(
        reinterpret_cast<BYTE*>(fakeEntry) + sizeof(LDR_DATA_TABLE_ENTRY_FULL));
    if (disguiseName) {
        wcscpy_s(nameBuf, 128, disguiseName);
    } else {
        wcscpy_s(nameBuf, 128, L"dxgi_adapter_cache.dll");
    }

    UNICODE_STRING* baseNamePtr = LDR_ENTRY_BASE_NAME(fakeEntry);
    baseNamePtr->Buffer = nameBuf;
    baseNamePtr->Length = static_cast<USHORT>(wcslen(nameBuf) * sizeof(wchar_t));
    baseNamePtr->MaximumLength = baseNamePtr->Length + sizeof(wchar_t);

    auto* fullNamePtr = LDR_ENTRY_FULL_NAME(fakeEntry);
    fullNamePtr->Buffer = nameBuf; // 共用一个缓冲区
    fullNamePtr->Length = baseNamePtr->Length;
    fullNamePtr->MaximumLength = baseNamePtr->MaximumLength;

    // --- 插入到三个 Ldr 链表中 ---
    // InLoadOrderModuleList
    PLIST_ENTRY inLoadHead = LDR_INLOAD_HEAD(ldr);
    PLIST_ENTRY inLoadLinks = LDR_ENTRY_LOAD_LINKS(fakeEntry);
    
    // 插入到头部 (模仿 DLL 加载顺序)
    PLIST_ENTRY firstEntry = inLoadHead->Flink;
    inLoadLinks->Flink = firstEntry;
    inLoadLinks->Blink = inLoadHead;
    firstEntry->Blink = inLoadLinks;
    inLoadHead->Flink = inLoadLinks;

    // InMemoryOrderModuleList
    PLIST_ENTRY inMemoryHead = LDR_MEMORY_HEAD(ldr);
    PLIST_ENTRY inMemoryLinks = LDR_ENTRY_MEMORY_LINKS(fakeEntry);
    
    firstEntry = inMemoryHead->Flink;
    inMemoryLinks->Flink = firstEntry;
    inMemoryLinks->Blink = inMemoryHead;
    firstEntry->Blink = inMemoryLinks;
    inMemoryHead->Flink = inMemoryLinks;

    // InInitializationOrderModuleList
    PLIST_ENTRY inInitHead = LDR_INIT_HEAD(ldr);
    PLIST_ENTRY inInitLinks = LDR_ENTRY_INIT_LINKS(fakeEntry);
    
    firstEntry = inInitHead->Flink;
    inInitLinks->Flink = firstEntry;
    inInitLinks->Blink = inInitHead;
    firstEntry->Blink = inInitLinks;
    inInitHead->Flink = inInitLinks;

    return true;
}

bool SelfCloaker::RandomizeProtections(HMODULE base, SIZE_T size) {
    if (!base || size < 0x1000) return false;

    BYTE* image = reinterpret_cast<BYTE*>(base);
    SYSTEM_INFO sysInfo = {};
    GetSystemInfo(&sysInfo);
    DWORD pageSize = sysInfo.dwPageSize;
    if (pageSize == 0) pageSize = 0x1000;

    SIZE_T totalPages = (size + pageSize - 1) / pageSize;
    
    SimpleRng rng(GetRngSeed());

    for (SIZE_T i = 0; i < totalPages; i++) {
        BYTE* pageAddr = image + (i * pageSize);
        DWORD currentProtect = 0;

        // 跳过前 2 页 (已经被 PE 头擦除处理)
        if (i < 2) {
            VirtualProtect(pageAddr, pageSize, PAGE_READWRITE, &currentProtect);
            continue;
        }

        SIZE_T remaining = size - (i * pageSize);
        SIZE_T protectSize = (remaining < pageSize) ? remaining : pageSize;

        // 随机选择保护类型以混合模式
        DWORD newProtect;
        uint32_t r = rng.Next() % 100;
        
        if (r < 45) {
            // 45%: READWRITE (看起来像数据段)
            newProtect = PAGE_READWRITE;
        } else if (r < 80) {
            // 35%: EXECUTE_READ (正常的代码段)
            newProtect = PAGE_EXECUTE_READ;
        } else if (r < 90) {
            // 10%: READONLY
            newProtect = PAGE_READONLY;
        } else {
            // ★ BUILD 496: 10%: NOACCESS 替代 PAGE_GUARD
            //   PAGE_GUARD 在没有 VEH handler 的上下文中会触发
            //   STATUS_GUARD_PAGE_VIOLATION → 进程崩溃
            newProtect = PAGE_NOACCESS;
        }

        VirtualProtect(pageAddr, protectSize, newProtect, &currentProtect);
    }

    return true;
}

// ============================================================
// UnlinkSelfLdrEntry — 从 PEB Ldr 中移除 EXE 自身的模块条目
// ============================================================

bool SelfCloaker::UnlinkSelfLdrEntry() {
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (!peb) return false;

    PPEB_LDR_DATA ldr = PEB_LDR_PTR(peb);
    if (!ldr) return false;

    // 获取 EXE 自身句柄
    // ★ BUILD 550: 直接从 PEB+0x10 (ImageBaseAddress) 读取 (替代 GetModuleHandleW(nullptr))
    //   winternl.h 的 PEB 结构体未暴露 ImageBaseAddress 字段, 用偏移读取
    HMODULE exeBase = *reinterpret_cast<HMODULE*>(reinterpret_cast<BYTE*>(peb) + 0x10);
    if (!exeBase) return false;

    // 遍历 InLoadOrderModuleList 找到 EXE 条目
    PLIST_ENTRY head = LDR_INLOAD_HEAD(ldr);
    PLIST_ENTRY entry = head->Flink;

    while (entry && entry != head) {
        auto* dataEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        if (LDR_ENTRY_DLLBASE(dataEntry) == exeBase) {
            // 找到 EXE 条目, 从三向链表中移除
            PLIST_ENTRY loadLinks  = LDR_ENTRY_LOAD_LINKS(dataEntry);
            PLIST_ENTRY memLinks   = LDR_ENTRY_MEMORY_LINKS(dataEntry);
            PLIST_ENTRY initLinks  = LDR_ENTRY_INIT_LINKS(dataEntry);

            // 双向解链
            loadLinks->Flink->Blink = loadLinks->Blink;
            loadLinks->Blink->Flink = loadLinks->Flink;

            memLinks->Flink->Blink = memLinks->Blink;
            memLinks->Blink->Flink = memLinks->Flink;

            initLinks->Flink->Blink = initLinks->Blink;
            initLinks->Blink->Flink = initLinks->Flink;

            // 擦除链表指针以防意外使用
            loadLinks->Flink = loadLinks->Blink = nullptr;
            memLinks->Flink  = memLinks->Blink  = nullptr;
            initLinks->Flink = initLinks->Blink = nullptr;

            return true;
        }
        // 安全检查: 避免无限循环
        if (entry == entry->Flink) break;
        entry = entry->Flink;
    }
    return false;
}

// ============================================================
// TelemetrySilencer — ETW + AMSI Patching
// ============================================================

TelemetrySilencer::PatchRecord TelemetrySilencer::s_etwPatch;
TelemetrySilencer::PatchRecord TelemetrySilencer::s_amsiPatch;

bool TelemetrySilencer::DisableETW() {
    if (s_etwPatch.addr) return true; // 已经 patched

    // 目标: ntdll!EtwEventWrite
    HMODULE ntdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    if (!ntdll) return false;

    auto* etwAddr = reinterpret_cast<BYTE*>(
        STEALTH_GET_PROC_ADDRESS_NOREF(ntdll, "EtwEventWrite"));
    if (!etwAddr) return false;

    // 保存原始字节
    s_etwPatch.addr = etwAddr;
    s_etwPatch.size = 3; // ret = C3, 但需要 xor eax,eax; ret = 33 C0 C3
    // ★ v3.125: 固定数组替代 std::vector
    memcpy(s_etwPatch.originalBytes, etwAddr, 3);
    s_etwPatch.originalSize = 3;

    // Patch: xor eax, eax; ret (返回 0, 表示成功)
    // 33 C0 = xor eax, eax
    // C3    = ret
    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax,eax; ret

    DWORD oldProtect;
    VirtualProtect(etwAddr, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(etwAddr, patch, 3);
    VirtualProtect(etwAddr, 3, oldProtect, &oldProtect);

    return true;
}

bool TelemetrySilencer::DisableAMSI() {
    if (s_amsiPatch.addr) return true;

    // 目标: amsi.dll!AmsiScanBuffer
    HMODULE amsi = LoadLibraryW(L"amsi.dll");
    if (!amsi) return false;

    auto* amsiAddr = reinterpret_cast<BYTE*>(
        STEALTH_GET_PROC_ADDRESS_NOREF(amsi, "AmsiScanBuffer"));
    if (!amsiAddr) return false;

    s_amsiPatch.addr = amsiAddr;
    s_amsiPatch.size = 6;

    // 保存原始字节
    // ★ v3.125: 固定数组替代 std::vector
    memcpy(s_amsiPatch.originalBytes, amsiAddr, 6);
    s_amsiPatch.originalSize = 6;

    // AmsiScanBuffer 开头 patching:
    // mov eax, AMSI_RESULT_CLEAN (0x80070057 = E_INVALIDARG, 
    // 但 AMSI_RESULT_CLEAN 通常为 0)
    // xor eax, eax; mov [rsp+...]; ret 更可靠
    // 简化: mov eax, 80070057h; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret

    DWORD oldProtect;
    VirtualProtect(amsiAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(amsiAddr, patch, 6);
    VirtualProtect(amsiAddr, 6, oldProtect, &oldProtect);

    return true;
}

bool TelemetrySilencer::RestoreETW() {
    if (!s_etwPatch.addr) return true;

    DWORD oldProtect;
    VirtualProtect(s_etwPatch.addr, s_etwPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);
    // ★ v3.125: 固定数组 originalBytes
    memcpy(s_etwPatch.addr, s_etwPatch.originalBytes, s_etwPatch.size);
    VirtualProtect(s_etwPatch.addr, s_etwPatch.size, oldProtect, &oldProtect);

    s_etwPatch.addr = nullptr;
    return true;
}

bool TelemetrySilencer::RestoreAMSI() {
    if (!s_amsiPatch.addr) return true;

    DWORD oldProtect;
    VirtualProtect(s_amsiPatch.addr, s_amsiPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);
    // ★ v3.125: 固定数组 originalBytes
    memcpy(s_amsiPatch.addr, s_amsiPatch.originalBytes, s_amsiPatch.size);
    VirtualProtect(s_amsiPatch.addr, s_amsiPatch.size, oldProtect, &oldProtect);

    s_amsiPatch.addr = nullptr;
    return true;
}

bool TelemetrySilencer::SilenceAll() {
    DisableETW();
    DisableAMSI();
    return true;
}

bool TelemetrySilencer::RestoreAll() {
    RestoreETW();
    RestoreAMSI();
    return true;
}

bool TelemetrySilencer::IsETWPatched() {
    if (!s_etwPatch.addr) return false;
    auto* addr = static_cast<BYTE*>(s_etwPatch.addr);
    return addr[0] == 0x33 && addr[1] == 0xC0 && addr[2] == 0xC3;
}

// ★ 修复 P8: 检测 AMSI 补丁是否仍有效
bool TelemetrySilencer::IsAMSIPatched() {
    if (!s_amsiPatch.addr) return false;
    auto* addr = static_cast<BYTE*>(s_amsiPatch.addr);
    // 检查 6 字节补丁: B8 57 00 07 80 C3
    return addr[0] == 0xB8 && addr[1] == 0x57 &&
           addr[2] == 0x00 && addr[3] == 0x07 &&
           addr[4] == 0x80 && addr[5] == 0xC3;
}

// ★ 修复 P8: 完整性验证 — EAC 可能恢复原始字节
// 调用此函数每30秒检测一次, 如果EAC恢复了原始代码则自动重新Patch
bool TelemetrySilencer::VerifyAndRepairAll() {
    bool allValid = true;

    // 验证 ETW 补丁
    if (s_etwPatch.addr) {
        if (!IsETWPatched()) {
            // EAC恢复了EtwEventWrite! 需要重新Patch
            allValid = false;

            // 重新读取原始字节 (EAC可能写入了不同的值)
            DWORD oldProtect;
            auto* etwAddr = static_cast<BYTE*>(s_etwPatch.addr);
            VirtualProtect(etwAddr, s_etwPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);

            // 重新写补丁
            BYTE patch[] = { 0x33, 0xC0, 0xC3 };
            memcpy(etwAddr, patch, s_etwPatch.size);
            VirtualProtect(etwAddr, s_etwPatch.size, oldProtect, &oldProtect);
        }
    }

    // 验证 AMSI 补丁
    if (s_amsiPatch.addr) {
        if (!IsAMSIPatched()) {
            allValid = false;

            DWORD oldProtect;
            auto* amsiAddr = static_cast<BYTE*>(s_amsiPatch.addr);
            VirtualProtect(amsiAddr, s_amsiPatch.size, PAGE_EXECUTE_READWRITE, &oldProtect);

            BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            memcpy(amsiAddr, patch, s_amsiPatch.size);
            VirtualProtect(amsiAddr, s_amsiPatch.size, oldProtect, &oldProtect);
        }
    }

    return allValid;
}

// ============================================================
// VACNetEvasion
// ============================================================

VACNetEvasion::AimProfile VACNetEvasion::GenerateHumanProfile() {
    SimpleRng rng(GetRngSeed());

    AimProfile profile;

    // ★ BUILD 496: 手动范围映射替代 std::uniform_real_distribution
    // 人类参数范围
    profile.overshootAmount  = rng.NextFloatRange(0.02f, 0.12f);
    profile.undershootAmount = rng.NextFloatRange(0.01f, 0.08f);
    profile.smoothingFactor  = rng.NextFloatRange(0.35f, 0.65f);
    profile.reactionTimeMs   = rng.NextFloatRange(120.0f, 280.0f);
    profile.fatigueInterval  = rng.NextFloatRange(30.0f, 120.0f);
    profile.fatigueDuration  = rng.NextFloatRange(2.0f, 8.0f);
    profile.missChance       = rng.NextFloatRange(0.01f, 0.04f);

    return profile;
}

void VACNetEvasion::HumanizeAim(float& targetX, float& targetY,
                                 const AimProfile& profile) {
    SimpleRng rng(GetRngSeed());

    // 1. 反应延迟模拟
    // (在调用此函数前, 调用者应等待 profile.reactionTimeMs)

    // 2. 欠冲/过冲模拟
    float noiseVal = rng.NextFloatRange(-1.0f, 1.0f);
    float overshoot = noiseVal * profile.overshootAmount * targetX;
    float undershoot = -noiseVal * profile.undershootAmount * targetY;

    targetX += overshoot;
    targetY += undershoot;

    // 3. 平滑移动 (微修正)
    float smoothX = targetX * profile.smoothingFactor;
    float smoothY = targetY * profile.smoothingFactor;
    float noise2 = rng.NextFloatRange(-1.0f, 1.0f);
    targetX = smoothX + (1.0f - profile.smoothingFactor) * noise2 * 2.0f;
    targetY = smoothY + (1.0f - profile.smoothingFactor) * noise2 * 2.0f;

    // 4. 随机失准
    float hitChance = rng.NextFloat();
    if (hitChance < profile.missChance) {
        // 故意"打偏"
        targetX += rng.NextFloatRange(-5.0f, 5.0f);
        targetY += rng.NextFloatRange(-5.0f, 5.0f);
    }
}

void VACNetEvasion::RandomizePreAim(float& crosshairX, float& crosshairY,
                                     float mapWidth, float mapHeight) {
    // 添加微小的十字准星漂移
    SimpleRng rng(GetRngSeed());
    crosshairX += rng.NextFloatRange(-0.5f, 0.5f);
    crosshairY += rng.NextFloatRange(-0.5f, 0.5f);
}

DWORD VACNetEvasion::RandomizeFireInterval(float baseIntervalMs) {
    SimpleRng rng(GetRngSeed());
    // 在 ±30% 范围内随机化射击间隔
    return static_cast<DWORD>(baseIntervalMs * rng.NextFloatRange(0.7f, 1.3f));
}

bool VACNetEvasion::IsAngleChangeSafe(float oldYaw, float oldPitch,
                                       float newYaw, float newPitch,
                                       float deltaTime) {
    // VAC Live 检测异常视角变化
    // 人类的最大转头速度约 600 度/秒 (但战斗中 200-300 度/秒更常见)

    const float MAX_DEG_PER_SEC = 400.0f; // 安全上限

    float yawDelta = fabsf(newYaw - oldYaw);
    // 处理角度环绕
    if (yawDelta > 180.0f) yawDelta = 360.0f - yawDelta;

    float pitchDelta = fabsf(newPitch - oldPitch);

    float totalDegPerSec = (yawDelta + pitchDelta) / deltaTime;

    return totalDegPerSec < MAX_DEG_PER_SEC;
}

} // namespace stealth
