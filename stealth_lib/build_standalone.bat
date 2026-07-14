@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM 独立版 stealth_app.exe 编译脚本
REM 产出: stealth_app.exe — 完整 ESP 透视 + 9层规避引擎
REM ============================================================

set "GPP=C:\msys64\mingw64\bin\g++"
set "CFLAGS=-std=c++20 -O2 -s -fpermissive -DNDEBUG -D_WIN32_WINNT=0x0A00"
set "SRC=."

if not exist "%GPP%.exe" (
    echo [ERROR] 编译器未找到: %GPP%.exe
    pause & exit /b 1
)

echo ============================================
echo 编译 stealth_app.exe (独立完整版)
echo ============================================

%GPP% %CFLAGS% -mwindows -static -o stealth_app.exe ^
    integration_example.cpp ^
    stealth_core.cpp ^
    syscall_direct.cpp ^
    anti_debug.cpp ^
    eac_bypass.cpp ^
    eac_vm_evasion.cpp ^
    eac_syscall_guard.cpp ^
    memory_cloak.cpp ^
    pe_mutator.cpp ^
    stealth_process.cpp ^
    stealth_injection.cpp ^
    cs2_memory.cpp ^
    string_obfuscator.cpp ^
    cheat_overlay.cpp ^
    game_esp.cpp ^
    byovd_kernel.cpp ^
    -lwinhttp -lws2_32 -lntdll -ldwmapi -lgdi32 -luser32 -lshell32

if %ERRORLEVEL% neq 0 (
    echo [ERROR] 编译失败!
    pause & exit /b 1
)

echo [OK] stealth_app.exe 编译完成
echo.
echo 使用方法: 右键以管理员身份运行 stealth_app.exe
echo 启动顺序: 先启动 CS2 + 进大厅 → 再运行 stealth_app.exe
pause
