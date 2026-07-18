@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM BUILD 535 测试2: E+G 保护层长时间运行验证
REM   - 修复 ntdll!RtlDeactivateActivationContext 崩溃 (BUILD 534 在 346s 崩溃)
REM   - 根因: GetPacTargetName 中 fltlib.dll RPC 创建 worker 线程 → 激活上下文栈损坏
REM   - 修复: 移除 fltlib.dll RPC, 改用硬编码 L"MessageTransfer"
REM   - 关键里程碑: 346s (BUILD 534 崩溃点), 600s (10分钟成功)
REM ============================================================

setlocal enabledelayedexpansion

echo ============================================
echo   BUILD 535 测试2: E+G 保护层验证
echo   修复: RtlDeactivateActivationContext 崩溃
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

REM 选择 loader
set "LOADER=loader.exe"
echo [INFO] 使用 loader: %LOADER%

REM 后台运行 loader
echo [INFO] 启动 %LOADER% ...
start "" /B "%~dp0%LOADER%"

REM 等待 loader 启动
timeout /t 3 /nobreak >nul

REM 监控日志 10 分钟 (600 秒)
set /a TOTAL_SEC=600
set /a CHECK_INTERVAL=30
set /a ELAPSED=0
set /a LAST_LOG_SIZE=0
set /a STUCK_COUNT=0
set /a LOG_UPDATE_COUNT=0
set /a CRASH_COUNT=0

echo [INFO] 开始监控 %TOTAL_SEC% 秒 (每 %CHECK_INTERVAL% 秒检查一次)...
echo [INFO] 关键里程碑:
echo   - 160s  (BUILD 533 卡死点)
echo   - 300s  (BUILD 532 卡死点)
echo   - 346s  (BUILD 534 崩溃点) ← BUILD 535 必须突破此点
echo   - 600s  (10分钟成功)
echo.

:monitor_loop
if %ELAPSED% GEQ %TOTAL_SEC% goto :monitor_done

timeout /t %CHECK_INTERVAL% /nobreak >nul
set /a ELAPSED+=%CHECK_INTERVAL%

REM 检查 loader 是否还在运行
tasklist /fi "imagename eq %LOADER%" 2>nul | find /i "%LOADER%" >nul
if !ERRORLEVEL! neq 0 (
    echo [%ELAPSED%/%TOTAL_SEC%s] [FAIL] %LOADER% 进程已退出
    goto :check_result
)

REM 检查日志文件大小
set /a CUR_LOG_SIZE=0
if exist "%TEMP%\stealth_diag.log" (
    for %%A in ("%TEMP%\stealth_diag.log") do set /a CUR_LOG_SIZE=%%~zA
)

REM 检查是否有崩溃
set /a CUR_CRASH_COUNT=0
if exist "%TEMP%\stealth_diag.log" (
    for /f %%A in ('find /c /i "CRASH:" ^< "%TEMP%\stealth_diag.log"') do set /a CUR_CRASH_COUNT=%%A
)

if !CUR_LOG_SIZE! GTR !LAST_LOG_SIZE! (
    set /a LOG_UPDATE_COUNT+=1
    set /a STUCK_COUNT=0
    set "STATUS=OK"
    if !CUR_CRASH_COUNT! GTR !CRASH_COUNT! (
        set "STATUS=CRASH!"
        set /a CRASH_COUNT=!CUR_CRASH_COUNT!
    )
    echo [%ELAPSED%/%TOTAL_SEC%s] [!STATUS!] 日志更新 (size=!CUR_LOG_SIZE!B, crash=!CUR_CRASH_COUNT!)
) else (
    set /a STUCK_COUNT+=1
    echo [%ELAPSED%/%TOTAL_SEC%s] [WARN] 日志未更新 (stuck=!STUCK_COUNT!, size=!CUR_LOG_SIZE!B)
)

set /a LAST_LOG_SIZE=!CUR_LOG_SIZE!

REM 如果连续 4 次 (120秒) 未更新, 判定为卡死
if !STUCK_COUNT! GEQ 4 (
    echo.
    echo ============================================
    echo   [FAIL] 进程卡死 — 日志连续 120 秒未更新
    echo ============================================
    goto :check_result
)

REM 关键里程碑提醒
if %ELAPSED% EQU 180 (
    echo   *** 已突破 BUILD 533 卡死点 (160s) ***
)
if %ELAPSED% EQU 330 (
    echo   *** 已突破 BUILD 532 卡死点 (300s) ***
)
if %ELAPSED% EQU 360 (
    echo   *** 已突破 BUILD 534 崩溃点 (346s) *** BUILD 535 修复生效!
)

goto :monitor_loop

:monitor_done
echo.
echo ============================================
echo   [OK] 监控完成 — 10 分钟无崩溃无卡死
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
echo --- 日志摘要 (最后 40 行) ---
if exist "%TEMP%\stealth_diag.log" (
    powershell -Command "Get-Content '%TEMP%\stealth_diag.log' -Tail 40"
) else (
    echo [WARN] 无日志文件
)

echo.
echo --- BUILD 535 关键指标 ---
if exist "%TEMP%\stealth_diag.log" (
    echo [崩溃统计]:
    find /c /i "CRASH:" ^< "%TEMP%\stealth_diag.log"
    echo.
    echo [VEH 诊断 (BUILD 535 新增 tid/faultAddr)]:
    findstr /C:"CRASH:" "%TEMP%\stealth_diag.log" 2>nul
    echo.
    echo [IOCTL 超时统计]:
    findstr /C:"IOCTL TIMEOUT" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"OverlappedSwitch" "%TEMP%\stealth_diag.log" 2>nul
    echo.
    echo [E+G 保护层状态]:
    findstr /C:"VERIFY:ObCallbacks" "%TEMP%\stealth_diag.log" 2>nul | find /c "VERIFY" 
    echo VERIFY:ObCallbacks 总次数 (上方数字)
    findstr /C:"ReDisable" "%TEMP%\stealth_diag.log" 2>nul | find /c "ReDisable"
    echo ReDisable 总次数 (上方数字)
)

REM 清理测试 flag
del "%TEMP%\pac_probe.flag" >nul 2>&1

echo.
echo ============================================
echo 测试完成。请检查上方日志判断结果:
echo   - [OK] 10分钟无崩溃 = BUILD 535 修复生效
echo   - [FAIL] 进程崩溃/卡死 = 需继续迭代
echo   - 无蓝屏 = 安全
echo ============================================
pause
