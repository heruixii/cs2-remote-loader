@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM BUILD 536 测试2: E+G 保护层长时间运行验证
REM   - VEH 捕获 ntdll!RtlDeactivateActivationContext 崩溃 (BUILD 535 在 360s 崩溃)
REM   - 根因: worker 线程 TEB+0x98 (ActivationContextStackPointer) 为 NULL
REM   - 修复: VEH 设置 rax 指向安全缓冲区, 让 cmp [rax+0x38],9 正常执行
REM   - 关键里程碑: 160s (B533卡死), 300s (B532卡死), 346s (B534崩溃), 360s (B535崩溃)
REM   - 600s (10分钟成功)
REM ============================================================

setlocal enabledelayedexpansion

echo ============================================
echo   BUILD 536 测试2: E+G 保护层验证
echo   修复: VEH 捕获 RtlDeactivateActivationContext 崩溃
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

REM 选择 loader (BUILD 536 使用 loader2.exe)
set "LOADER=loader2.exe"
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
set /a VEH_CATCH_COUNT=0

echo [INFO] 开始监控 %TOTAL_SEC% 秒 (每 %CHECK_INTERVAL% 秒检查一次)...
echo [INFO] 关键里程碑:
echo   - 160s  (BUILD 533 卡死点)
echo   - 300s  (BUILD 532 卡死点)
echo   - 346s  (BUILD 534 崩溃点)
echo   - 360s  (BUILD 535 崩溃点) ← BUILD 536 必须突破此点
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

REM 检查 VEH-B536 捕获次数
set /a CUR_VEH_CATCH=0
if exist "%TEMP%\stealth_diag.log" (
    for /f %%A in ('find /c "VEH-B536" ^< "%TEMP%\stealth_diag.log"') do set /a CUR_VEH_CATCH=%%A
)

if !CUR_LOG_SIZE! GTR !LAST_LOG_SIZE! (
    set /a LOG_UPDATE_COUNT+=1
    set /a STUCK_COUNT=0
    set "STATUS=OK"
    if !CUR_CRASH_COUNT! GTR !CRASH_COUNT! (
        set "STATUS=CRASH!"
        set /a CRASH_COUNT=!CUR_CRASH_COUNT!
    )
    echo [%ELAPSED%/%TOTAL_SEC%s] [!STATUS!] 日志更新 (size=!CUR_LOG_SIZE!B, crash=!CUR_CRASH_COUNT!, veh_catch=!CUR_VEH_CATCH!)
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
    echo   *** 已突破 BUILD 534/535 崩溃点 (346s/360s) *** BUILD 536 修复生效!
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
echo --- 日志摘要 (最后 50 行) ---
if exist "%TEMP%\stealth_diag.log" (
    powershell -Command "Get-Content '%TEMP%\stealth_diag.log' -Tail 50"
) else (
    echo [WARN] 无日志文件
)

echo.
echo --- BUILD 536 关键指标 ---
if exist "%TEMP%\stealth_diag.log" (
    echo [崩溃统计]:
    find /c /i "CRASH:" ^< "%TEMP%\stealth_diag.log"
    echo.
    echo [BUILD 536 VEH 捕获统计 (VEH-B536)]:
    find /c "VEH-B536" ^< "%TEMP%\stealth_diag.log"
    echo VEH-B536 捕获次数 (上方数字)
    echo.
    echo [VEH-B536 捕获详情]:
    findstr /C:"VEH-B536" "%TEMP%\stealth_diag.log" 2>nul
    echo.
    echo [VEH 诊断 (CRASH 行)]:
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
echo   - [OK] 10分钟无崩溃 = BUILD 536 修复生效
echo   - [FAIL] 进程崩溃/卡死 = 需继续迭代
echo   - VEH-B536 捕获次数 > 0 = 崩溃被成功捕获并修复
echo   - 无蓝屏 = 安全
echo ============================================
pause
