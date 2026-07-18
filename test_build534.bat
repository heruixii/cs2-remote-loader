@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM BUILD 534 测试2: E+G 保护层长时间运行验证
REM   - 修复 ReapplyAllCallbacks 高频调用 (500-1500ms → 60-90s)
REM   - 目标: 10 分钟无蓝屏 + 无卡死 (BUILD 533 在 160s 卡死)
REM   - 预期 5分钟 IOCTL: ~120 (vs BUILD 532 的 7000+)
REM ============================================================

setlocal enabledelayedexpansion

echo ============================================
echo   BUILD 534 测试2: E+G 保护层验证
echo   目标: 10 分钟无蓝屏 + 无卡死
echo   关键: BUILD 533 在 160s 卡死, BUILD 534 应突破 300s+
echo ============================================
echo.

REM 清理旧进程
taskkill /f /im loader.exe >nul 2>&1
taskkill /f /im loader2.exe >nul 2>&1
timeout /t 2 /nobreak >nul

REM 创建测试模式 flag
echo. > "%TEMP%\pac_probe.flag"
echo [INFO] 已创建测试模式 flag

REM 清理旧日志
del "%TEMP%\stealth_diag.log" >nul 2>&1
echo [INFO] 已清理旧日志

REM 检查 loader.exe
if not exist "%~dp0loader.exe" (
    echo [ERROR] loader.exe 不存在, 请先编译
    pause
    exit /b 1
)

REM 后台运行 loader
echo [INFO] 启动 loader.exe ...
start "" /B "%~dp0loader.exe"

REM 等待 loader 启动
timeout /t 5 /nobreak >nul

REM 监控日志 10 分钟 (600 秒)
set /a TOTAL_SEC=600
set /a CHECK_INTERVAL=15
set /a ELAPSED=0
set /a LAST_LOG_SIZE=0
set /a STUCK_COUNT=0
set /a LOG_UPDATE_COUNT=0
set /a LAST_VERIFY_COUNT=0

echo [INFO] 开始监控 %TOTAL_SEC% 秒 (每 %CHECK_INTERVAL% 秒检查)...
echo [INFO] 关键里程碑:
echo   - 160s: BUILD 533 在此处卡死, BUILD 534 应继续运行
echo   - 300s: BUILD 532 在此处卡死, BUILD 534 应继续运行
echo   - 600s: 测试完成
echo.

:monitor_loop
if %ELAPSED% GEQ %TOTAL_SEC% goto :monitor_done

timeout /t %CHECK_INTERVAL% /nobreak >nul
set /a ELAPSED+=%CHECK_INTERVAL%

REM 检查 loader 是否还在运行
tasklist /fi "imagename eq loader.exe" 2>nul | find /i "loader.exe" >nul
if !ERRORLEVEL! neq 0 (
    echo [%ELAPSED%/%TOTAL_SEC%s] [FAIL] loader.exe 进程已退出 (可能是崩溃)
    goto :check_result
)

REM 检查日志文件大小
set /a CUR_LOG_SIZE=0
if exist "%TEMP%\stealth_diag.log" (
    for %%A in ("%TEMP%\stealth_diag.log") do set /a CUR_LOG_SIZE=%%~zA
)

REM 统计 VERIFY 次数 (监控 IOCTL 频率)
set /a CUR_VERIFY_COUNT=0
if exist "%TEMP%\stealth_diag.log" (
    for /f %%A in ('find /c /i "VERIFY:ObCallbacks" "%TEMP%\stealth_diag.log"') do set /a CUR_VERIFY_COUNT=%%A
)

if !CUR_LOG_SIZE! GTR !LAST_LOG_SIZE! (
    set /a LOG_UPDATE_COUNT+=1
    set /a STUCK_COUNT=0
    set /a VERIFY_DELTA=!CUR_VERIFY_COUNT!-!LAST_VERIFY_COUNT!
    echo [%ELAPSED%/%TOTAL_SEC%s] [OK] 日志更新 (size=!CUR_LOG_SIZE!B, verify=+!VERIFY_DELTA!, total=!CUR_VERIFY_COUNT!)
) else (
    set /a STUCK_COUNT+=1
    echo [%ELAPSED%/%TOTAL_SEC%s] [WARN] 日志未更新 (stuck=!STUCK_COUNT!, size=!CUR_LOG_SIZE!B)
)

set /a LAST_LOG_SIZE=!CUR_LOG_SIZE!
set /a LAST_VERIFY_COUNT=!CUR_VERIFY_COUNT!

REM 如果连续 6 次 (90秒) 未更新, 判定为卡死
if !STUCK_COUNT! GEQ 6 (
    echo.
    echo ============================================
    echo   [FAIL] 进程卡死 — 日志连续 90 秒未更新
    echo   BUILD 534 仍有 IOCTL 阻塞问题
    echo ============================================
    goto :check_result
)

REM 关键里程碑
if %ELAPSED% EQU 165 (
    echo.
    echo [%ELAPSED%s] *** 里程碑: 突破 BUILD 533 卡死点 (160s) ***
    echo.
)
if %ELAPSED% EQU 300 (
    echo.
    echo [%ELAPSED%s] *** 里程碑: 突破 BUILD 532 卡死点 (300s) ***
    echo.
)

goto :monitor_loop

:monitor_done
echo.
echo ============================================
echo   [SUCCESS] 10 分钟无卡死无蓝屏!
echo   BUILD 534 IOCTL 频率优化验证通过!
echo ============================================

:check_result
echo.
echo --- 最终状态 ---
tasklist /fi "imagename eq loader.exe" 2>nul | find /i "loader.exe" >nul
if !ERRORLEVEL! equ 0 (
    echo [INFO] loader.exe 仍在运行
    tasklist /fi "imagename eq loader.exe" 2>nul
) else (
    echo [INFO] loader.exe 已退出
)

echo.
echo --- 日志统计 ---
if exist "%TEMP%\stealth_diag.log" (
    echo VERIFY:ObCallbacks 总次数:
    find /c /i "VERIFY:ObCallbacks" "%TEMP%\stealth_diag.log" 2>nul
    echo ReDisablePacCallbacks 总次数:
    find /c /i "ReDisablePacCallbacks" "%TEMP%\stealth_diag.log" 2>nul
    echo ReapplyAllCallbacks 总次数:
    find /c /i "ReapplyAllCallbacks" "%TEMP%\stealth_diag.log" 2>nul
    echo F= (诊断周期) 总次数:
    find /c /i "F=" "%TEMP%\stealth_diag.log" 2>nul
)

echo.
echo --- 日志摘要 (最后 40 行) ---
if exist "%TEMP%\stealth_diag.log" (
    powershell -Command "Get-Content '%TEMP%\stealth_diag.log' -Tail 40"
)

echo.
echo --- 主循环 F= 进度 (应持续增长) ---
if exist "%TEMP%\stealth_diag.log" (
    powershell -Command "(Get-Content '%TEMP%\stealth_diag.log' | Select-String 'F=\d+' | Select-Object -Last 10).Line"
)

REM 清理测试 flag
del "%TEMP%\pac_probe.flag" >nul 2>&1

echo.
echo ============================================
echo 测试结果判断:
echo   - [SUCCESS] 10分钟无卡死 = BUILD 534 修复生效
echo   - [FAIL] 160s 内卡死 = 修复无效, 仍有高频 IOCTL
echo   - [FAIL] 300s 内卡死 = 部分改善, 需进一步优化
echo   - 无蓝屏 = 安全
echo ============================================
pause
