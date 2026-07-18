@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM BUILD 532 测试2: E+G 保护层长时间运行验证
REM   - 创建 pac_probe.flag 启用测试模式 (无 CS2, 无 basic.exe)
REM   - 运行 loader2.exe (BUILD 532 overlapped I/O 超时保护)
REM   - 监控 10 分钟: 无蓝屏 + 无卡死 + 周期性日志
REM ============================================================

setlocal enabledelayedexpansion

echo ============================================
echo   BUILD 532 测试2: E+G 保护层验证
echo ============================================
echo.

REM 清理旧进程 (如果有)
taskkill /f /im loader.exe >nul 2>&1
taskkill /f /im loader2.exe >nul 2>&1
timeout /t 2 /nobreak >nul

REM 创建测试模式 flag
echo. > "%TEMP%\pac_probe.flag"
echo [INFO] 已创建测试模式 flag: %TEMP%\pac_probe.flag

REM 清理旧日志
del "%TEMP%\stealth_diag.log" >nul 2>&1
echo [INFO] 已清理旧日志

REM 选择 loader (优先 loader2.exe, 其次 loader.exe)
set "LOADER=loader2.exe"
if not exist "%~dp0loader2.exe" (
    set "LOADER=loader.exe"
)
echo [INFO] 使用 loader: %LOADER%

REM 后台运行 loader
echo [INFO] 启动 %LOADER% ...
start "" /B "%~dp0%LOADER%"

REM 等待 loader 启动
timeout /t 3 /nobreak >nul

REM 监控日志 10 分钟 (600 秒)
set /a TOTAL_SEC=600
set /a CHECK_INTERVAL=10
set /a ELAPSED=0
set /a LAST_LOG_SIZE=0
set /a STUCK_COUNT=0
set /a LOG_UPDATE_COUNT=0

echo [INFO] 开始监控 %TOTAL_SEC% 秒 (每 %CHECK_INTERVAL% 秒检查一次)...
echo.

:monitor_loop
if %ELAPSED% GEQ %TOTAL_SEC% goto :monitor_done

timeout /t %CHECK_INTERVAL% /nobreak >nul
set /a ELAPSED+=%CHECK_INTERVAL%

REM 检查 loader 是否还在运行
tasklist /fi "imagename eq %LOADER%" 2>nul | find /i "%LOADER%" >nul
if !ERRORLEVEL! neq 0 (
    echo [%ELAPSED%/%TOTAL_SEC%s] [WARN] %LOADER% 进程已退出
    goto :check_result
)

REM 检查日志文件大小
set /a CUR_LOG_SIZE=0
if exist "%TEMP%\stealth_diag.log" (
    for %%A in ("%TEMP%\stealth_diag.log") do set /a CUR_LOG_SIZE=%%~zA
)

if !CUR_LOG_SIZE! GTR !LAST_LOG_SIZE! (
    set /a LOG_UPDATE_COUNT+=1
    set /a STUCK_COUNT=0
    echo [%ELAPSED%/%TOTAL_SEC%s] [OK] 日志更新 (size=!CUR_LOG_SIZE!B, updates=!LOG_UPDATE_COUNT!)
) else (
    set /a STUCK_COUNT+=1
    echo [%ELAPSED%/%TOTAL_SEC%s] [WARN] 日志未更新 (stuck=!STUCK_COUNT!, size=!CUR_LOG_SIZE!B)
)

set /a LAST_LOG_SIZE=!CUR_LOG_SIZE!

REM 如果连续 6 次 (60秒) 未更新, 判定为卡死
if !STUCK_COUNT! GEQ 6 (
    echo.
    echo ============================================
    echo   [FAIL] 进程卡死 — 日志连续 60 秒未更新
    echo   可能有 IOCTL 阻塞 (BUILD 532 超时保护未生效?)
    echo ============================================
    goto :check_result
)

goto :monitor_loop

:monitor_done
echo.
echo ============================================
echo   [OK] 监控完成 — 10 分钟无卡死
echo ============================================

:check_result
echo.
echo --- 最终状态 ---
tasklist /fi "imagename eq %LOADER%" 2>nul | find /i "%LOADER%" >nul
if !ERRORLEVEL! equ 0 (
    echo [INFO] %LOADER% 仍在运行
) else (
    echo [INFO] %LOADER% 已退出
)

echo.
echo --- 日志摘要 (最后 30 行) ---
if exist "%TEMP%\stealth_diag.log" (
    powershell -Command "Get-Content '%TEMP%\stealth_diag.log' -Tail 30"
) else (
    echo [WARN] 无日志文件
)

echo.
echo --- IOCTL 超时统计 ---
if exist "%TEMP%\stealth_diag.log" (
    findstr /C:"IOCTL TIMEOUT" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"OverlappedSwitch" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"cooldown" "%TEMP%\stealth_diag.log" 2>nul
)

echo.
echo --- E+G 保护层状态 ---
if exist "%TEMP%\stealth_diag.log" (
    findstr /C:"DKOM" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"ObCallbacks" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"EKGS" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"E+G" "%TEMP%\stealth_diag.log" 2>nul
)

REM 清理测试 flag
del "%TEMP%\pac_probe.flag" >nul 2>&1

echo.
echo ============================================
echo 测试完成。请检查上方日志判断结果:
echo   - [OK] 10分钟无卡死 = BUILD 532 超时保护生效
echo   - [FAIL] 进程卡死 = 超时保护未生效, 需迭代
echo   - 无蓝屏 = 安全
echo ============================================
pause
