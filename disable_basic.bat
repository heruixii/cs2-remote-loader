@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM BUILD 547: basic.exe 启用/禁用切换工具
REM
REM 用途: 在 PAC SHV 监控机制完全搞清楚之前, 长期禁用 basic.exe 防止封号
REM       禁用后保留所有其他保护层 (CS2 附加 + BYOVD + DKOM + EkkoSleep)
REM
REM 用法:
REM   disable_basic.bat           — 显示当前状态并切换
REM   disable_basic.bat /on       — 启用 basic.exe (删除 flag)
REM   disable_basic.bat /off      — 禁用 basic.exe (创建 flag)
REM   disable_basic.bat /status   — 仅显示当前状态
REM ============================================================

set "FLAG_PATH=%TEMP%\disable_basic.flag"

if "%1"=="/on" goto enable
if "%1"=="/off" goto disable
if "%1"=="/status" goto status
if "%1"=="" goto interactive
echo Usage: disable_basic.bat [/on ^| /off ^| /status]
exit /b 1

:interactive
echo ============================================================
echo  BUILD 547: basic.exe Enable/Disable Toggle
echo ============================================================
echo.
if exist "%FLAG_PATH%" (
    echo  Current status: basic.exe DISABLED (ban safety mode)
    echo  Flag file: %FLAG_PATH%
    echo.
    echo  All other protections still ACTIVE:
    echo    - CS2 attach
    echo    - BYOVD + DKOM + ObCallbacks
    echo    - EkkoSleep memory encryption
    echo    - Handle re-randomization
    echo.
    set /p choice="Enable basic.exe? (y/n): "
    if /i "%choice%"=="y" goto enable
    echo basic.exe remains DISABLED.
) else (
    echo  Current status: basic.exe ENABLED (normal mode)
    echo.
    echo  WARNING: basic.exe injection may trigger PAC detection!
    echo  Make sure PAC SHV monitoring is fully analyzed before enabling.
    echo.
    set /p choice="Disable basic.exe? (y/n): "
    if /i "%choice%"=="y" goto disable
    echo basic.exe remains ENABLED.
)
exit /b 0

:disable
echo. > "%FLAG_PATH%"
echo [OK] basic.exe DISABLED — flag created at %FLAG_PATH%
echo      Next loader2.exe run will skip basic.exe launch.
echo      All other protections remain active.
exit /b 0

:enable
if exist "%FLAG_PATH%" del /f /q "%FLAG_PATH%"
echo [OK] basic.exe ENABLED — flag removed
echo      Next loader2.exe run will launch basic.exe.
echo      WARNING: Make sure PAC SHV monitoring is fully analyzed!
exit /b 0

:status
echo ============================================================
echo  basic.exe Status
echo ============================================================
if exist "%FLAG_PATH%" (
    echo  Status: DISABLED (ban safety mode)
    echo  Flag: %FLAG_PATH%
    echo  All other protections: ACTIVE
) else (
    echo  Status: ENABLED (normal mode)
    echo  basic.exe will be launched on next loader2.exe run
)
exit /b 0
