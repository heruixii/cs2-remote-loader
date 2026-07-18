@echo off
chcp 65001 >nul 2>&1
title BUILD 537 Gamma-A Test

echo ============================================================
echo  BUILD 537 Gamma-A Test Script
echo  Duration: 10 minutes monitoring
echo  Mode: E+G Test (no basic.exe injection)
echo ============================================================
echo.

:: Clean old logs
if exist "%TEMP%\stealth_diag.log" del /f /q "%TEMP%\stealth_diag.log"
if exist "%TEMP%\loader_diag.log" del /f /q "%TEMP%\loader_diag.log"

:: Create test mode flag
echo. > "%TEMP%\pac_probe.flag"
echo [OK] Test mode flag created: %TEMP%\pac_probe.flag

:: Kill any existing loader processes
taskkill /f /im loader.exe 2>nul
taskkill /f /im loader2.exe 2>nul
timeout /t 2 /nobreak >nul

:: Start loader
echo [INFO] Starting loader2.exe...
start "" "d:\技术研发\tmp\loader2.exe"
echo [OK] loader2.exe started
echo.

:: Monitor for 10 minutes (600 seconds)
echo ============================================================
echo  Monitoring for 10 minutes (600 seconds)...
echo  Time: %time%
echo ============================================================
echo.

set /a counter=0
:monitor_loop
set /a counter+=1
timeout /t 30 /nobreak >nul

:: Check if loader2.exe is still running
tasklist /fi "imagename eq loader2.exe" 2>nul | find /i "loader2.exe" >nul
if errorlevel 1 (
    echo [%time%] WARNING: loader2.exe not found in task list ^(may be hidden by DKOM^)
) else (
    echo [%time%] [OK] loader2.exe running ^(counter=%counter%/20^)
)

:: Check for crash in log
if exist "%TEMP%\stealth_diag.log" (
    findstr /c:"CRASH" "%TEMP%\stealth_diag.log" >nul 2>&1
    if not errorlevel 1 (
        echo [%time%] [WARNING] Crash detected in log! Check stealth_diag.log
        echo.
        echo === Recent crash log ===
        findstr /c:"CRASH" "%TEMP%\stealth_diag.log"
        echo ========================
    )
)

:: Check for DKOM success
findstr /c:"DKOM hide" "%TEMP%\stealth_diag.log" >nul 2>&1
if not errorlevel 1 (
    if %counter%==1 (
        echo [%time%] [DKOM] DKOM hide result:
        findstr /c:"DKOM hide" "%TEMP%\stealth_diag.log"
    )
)

if %counter% lss 20 goto monitor_loop

echo.
echo ============================================================
echo  10-minute monitoring complete
echo  Time: %time%
echo ============================================================
echo.

:: Final status report
echo === Final Status ===
echo.
echo [1] Process status:
tasklist /fi "imagename eq loader2.exe" 2>nul | find /i "loader2.exe" >nul
if errorlevel 1 (
    echo    loader2.exe: NOT visible ^(DKOM hidden or crashed^)
) else (
    echo    loader2.exe: Running
)

echo.
echo [2] Log file size:
if exist "%TEMP%\stealth_diag.log" (
    for %%A in ("%TEMP%\stealth_diag.log") do echo    stealth_diag.log: %%~z bytes
) else (
    echo    stealth_diag.log: NOT FOUND
)

echo.
echo [3] DKOM status:
if exist "%TEMP%\stealth_diag.log" (
    findstr /c:"DKOM" "%TEMP%\stealth_diag.log"
) else (
    echo    No log file
)

echo.
echo [4] Crash count:
if exist "%TEMP%\stealth_diag.log" (
    find /c /i "CRASH" "%TEMP%\stealth_diag.log"
) else (
    echo    0
)

echo.
echo [5] VEH-B536 captures:
if exist "%TEMP%\stealth_diag.log" (
    find /c "VEH-B536" "%TEMP%\stealth_diag.log"
) else (
    echo    0
)

echo.
echo ============================================================
echo  Test Complete - Review the output above
echo  Full log: type %TEMP%\stealth_diag.log
echo ============================================================
pause
