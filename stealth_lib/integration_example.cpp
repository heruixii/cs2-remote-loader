// ============================================================
// integration_example.cpp — 集成示例
// 展示如何将原有代码迁移到 stealth_lib
// ============================================================

#include "stealth_core.h"
#include <iostream>

// ============================================================
// 原有代码模式 → 新代码模式 对照表
// ============================================================

void Example_BeforeAndAfter() {
    using namespace stealth;

    // ---- 初始化 ----
    // [旧] 无任何保护, 直接开始操作
    // [新] 初始化规避引擎
    StealthConfig config;
    config.stripRichHeader    = true;  // 清除编译器指纹
    config.randomizeTimestamp = true;  // 随机化时间戳
    config.stripDebugInfo     = true;  // 清除 PDB 路径
    config.useDirectSyscalls  = true;  // 启用直接系统调用
    config.enableVACSafety    = true;  // 启用 VAC 扫描保护
    StealthEngine::Instance().Initialize(config);

    // ---- 获取目标进程 ----
    // [旧]
    // HWND hwnd = FindWindow(L"Valve001", L"Counter-Strike 2");
    // DWORD pid; GetWindowThreadProcessId(hwnd, &pid);
    // HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    //
    // [新] 使用隐蔽方式
    StealthEngine::Instance().AttachToProcess(L"cs2.exe");
    // 或
    StealthEngine::Instance().AttachToProcessByWindow(
        nullptr, L"Counter-Strike 2");
    HANDLE hProc = StealthEngine::Instance().GetProcessHandle();

    // ---- 进程枚举 ----
    // [旧]
    // HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // PROCESSENTRY32 pe32; Process32First(hSnap, &pe32); ...
    // CloseHandle(hSnap);
    //
    // [新] 使用 NtQuerySystemInformation (无监控)
    auto processes = StealthProcess::EnumerateProcesses(L"cs2.exe");
    for (auto& proc : processes) {
        // proc.pid, proc.name
    }

    // ---- 内存读取 ----
    // [旧]
    // ReadProcessMemory(hProc, (LPCVOID)addr, &value, sizeof(value), NULL);
    //
    // [新] 使用直接系统调用
    int health = STEALTH_READ(0x12345678, int);
    // 或
    int health2 = StealthEngine::Instance().ReadMemory<int>(0x12345678);

    // ---- 内存写入 ----
    // [旧]
    // DWORD oldProtect;
    // VirtualProtectEx(hProc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    // WriteProcessMemory(hProc, (LPVOID)addr, &value, sizeof(value), NULL);
    // VirtualProtectEx(hProc, (LPVOID)addr, size, oldProtect, NULL);
    //
    // [新] 使用直接系统调用 + 值域校验
    // NtWriteVirtualMemory 只需要目标内存可写即可,
    // 无需先修改内存保护再改回来
    STEALTH_WRITE(0x12345678, 100); // m_iHealth = 100
    // 或
    StealthEngine::Instance().WriteMemory<int>(0x12345678, 100);

    // ---- 权限提升 ----
    // [旧]
    // OpenProcessToken(...); LookupPrivilegeValue(SE_DEBUG_NAME);
    // AdjustTokenPrivileges(...);
    //
    // [新] 静默获取, 仅在必要时调用
    StealthProcess::EnsureDebugPrivilegeSilent();
    // 或更隐蔽的方式:
    StealthProcess::BypassPrivilegeCheck();

    // ---- 模块枚举 ----
    // [旧]
    // HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    // MODULEENTRY32 me32; Module32First(hSnap, &me32);
    //
    // [新] 使用 NtQueryInformationProcess
    auto modules = StealthProcess::GetProcessModules(hProc);

    // ---- 字符串处理 ----
    // [旧]
    // const char* windowName = "Counter-Strike 2";
    // const char* dllName = "client.dll";
    //
    // [新] 编译期加密, 运行时解密
    std::string windowName = S_STR("Counter-Strike 2");
    std::string dllName = S_STR("client.dll");
    // 使用后安全清零
    StringObfuscator::SecureZero(windowName.data(), windowName.size());
}

// ============================================================
// 主循环集成示例
// ============================================================

class GameCheat {
public:
    bool Initialize() {
        using namespace stealth;

        // 初始化规避引擎
        if (!StealthEngine::Instance().Initialize()) {
            return false;
        }

        // 附加到游戏进程
        if (!StealthEngine::Instance().AttachToProcess(L"cs2.exe")) {
            return false;
        }

        // 备份 .text 段 (用于 VAC 保护)
        IntegrityBypass::BackupTextSection();

        return true;
    }

    void Run() {
        while (true) {
            // 每帧调用规避引擎维护
            stealth::StealthEngine::Instance().OnFrame();

            // 原有的作弊逻辑
            DoCheatLogic();

            // 控制帧率 (使用隐蔽 Sleep, 加密内存)
            stealth::StealthEngine::Instance().StealthSleep(1);
        }
    }

    void Shutdown() {
        stealth::StealthEngine::Instance().Shutdown();
    }

private:
    void DoCheatLogic() {
        using namespace stealth;

        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
        if (!hProc) return;

        // 示例: 读取游戏数据 (原来的 RPM 调用)
        int localPlayer = STEALTH_READ(0x12345678, int);
        int entityList = STEALTH_READ(0x87654321, int);

        // 示例: 修改游戏数据 (原来的 WPM 调用)
        // 使用 ClampNetVar 确保值域合法, 避免触发完整性检测
        int newHealth = 100;
        newHealth = IntegrityBypass::ClampNetVar(newHealth, 0, 100);
        STEALTH_WRITE(0xDEADBEEF, newHealth);

        // VTable 安全性检查
        uintptr_t engineVTable = STEALTH_READ(0x00ABCDEF, uintptr_t);
        if (!IntegrityBypass::ValidateVTablePointer(
            engineVTable, GetClientModuleBase(), 0x1000000)) {
            // VTable 可能被 Hook, 采取对策
            // 重新解析或使用备用接口
        }
    }

    uintptr_t GetClientModuleBase() {
        // 获取 client.dll 基址
        HANDLE hProc = stealth::StealthEngine::Instance().GetProcessHandle();
        auto modules = stealth::StealthProcess::GetProcessModules(hProc);
        for (auto& mod : modules) {
            if (_wcsicmp(mod.name.c_str(), L"client.dll") == 0) {
                return mod.baseAddress;
            }
        }
        return 0;
    }
};

// ============================================================
// 入口点
// ============================================================

int main() {
    GameCheat cheat;

    if (!cheat.Initialize()) {
        // 初始化失败, 静默退出 (不弹错误框)
        return 0;
    }

    cheat.Run();
    cheat.Shutdown();

    return 0;
}
