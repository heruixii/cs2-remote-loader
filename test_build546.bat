@echo off
chcp 65001 >nul 2>&1
title BUILD 546 Half-Test Mode (Stage A)

echo ============================================================
echo  BUILD 546 Half-Test Mode (Stage A) Test Script
echo  Duration: 10 minutes monitoring
echo  Mode: Half-Test (attach CS2, skip basic.exe injection)
echo  Purpose: Verify BUILD 546 does not break E+G protection layer
echo           (ObCallbacks removal + DKOM hiding + handle re-randomization)
echo           BUILD 546 basic.exe features (EkkoSleep/anti-screenshot/embedded)
echo           will be tested in Phase B (no flag) after Phase A passes.
echo ============================================================
echo.

:: Clean old logs
if exist "%TEMP%\stealth_diag.log" del /f /q "%TEMP%\stealth_diag.log"
if exist "%TEMP%\loader_diag.log" del /f /q "%TEMP%\loader_diag.log"

:: Remove pac_probe.flag if exists (it would override half_test.flag)
if exist "%TEMP%\pac_probe.flag" del /f /q "%TEMP%\pac_probe.flag"

:: Create half_test.flag (Stage A: attach CS2, skip basic.exe injection)
echo BUILD 546 stage A regression test > "%TEMP%\half_test.flag"
echo [OK] Half-test mode flag created: %TEMP%\half_test.flag
echo [OK] pac_probe.flag removed ^(if existed^)

:: Kill any existing loader processes
taskkill /f /im loader.exe 2>nul
taskkill /f /im loader2.exe 2>nul
timeout /t 2 /nobreak >nul

:: Verify CS2 is running
echo.
echo [INFO] Checking if CS2 is running...
tasklist /fi "imagename eq cs2.exe" 2>nul | find /i "cs2.exe" >nul
if errorlevel 1 (
    echo [ERROR] CS2 is NOT running! Please start CS2 first.
    echo [INFO] Half-test mode requires CS2 to be running for AttachToProcess.
    echo [INFO] Starting loader2.exe without CS2 will cause AttachToProcess failure
    echo [INFO] and loader2.exe will return 2 (safe exit, no BSOD risk).
    echo.
    pause
    exit /b 1
)
echo [OK] CS2 is running

:: Start loader2.exe (must be after CS2 starts)
echo.
echo [INFO] Starting loader2.exe...
start "" "d:\技术研发\tmp\loader2.exe"
echo [OK] loader2.exe started
echo.

:: Monitor for 10 minutes (600 seconds = 20 iterations x 30s)
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
    echo [%time%] WARNING: loader2.exe not found in task list ^(may be hidden by DKOM or crashed^)
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

:: Check for DKOM success (only first iteration)
if %counter%==1 (
    if exist "%TEMP%\stealth_diag.log" (
        echo.
        echo === BUILD 546 startup logs ===
        findstr /c:"BUILD 546" "%TEMP%\stealth_diag.log"
        findstr /c:"DKOM" "%TEMP%\stealth_diag.log"
        echo ========================
        echo.
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
echo [5] VEH-B536 captures ^(worker thread crash auto-recovery^):
if exist "%TEMP%\stealth_diag.log" (
    find /c "VEH-B536" "%TEMP%\stealth_diag.log"
) else (
    echo    0
)

echo.
echo [6] BUILD 546 specific logs:
if exist "%TEMP%\stealth_diag.log" (
    findstr /c:"BUILD 546" "%TEMP%\stealth_diag.log"
    echo.
    echo NOTE: In half-test mode, BUILD 546 basic.exe features are SKIPPED.
    echo       Only LaunchBasicESP skip log should appear.
) else (
    echo    No log file
)

echo.
echo [7] ObCallbacks status:
if exist "%TEMP%\stealth_diag.log" (
    findstr /c:"ObCallbacks" "%TEMP%\stealth_diag.log"
    findstr /c:"ReapplyAllCallbacks" "%TEMP%\stealth_diag.log"
) else (
    echo    No log file
)

echo.
echo ============================================================
echo  Test Complete - Review the output above
echo  Full log: type %TEMP%\stealth_diag.log
echo.
echo  Expected results for PASS:
echo    - loader2.exe running for 10 minutes ^(no crash, no BSOD^)
echo    - DKOM hide successful
echo    - 0 or few crashes ^(VEH-B536 auto-recovery^)
echo    - No 0x139 or 0x109 BSOD
echo    - ObCallbacks removal active
echo.
echo  If PASS: Proceed to Phase B ^(remove half_test.flag, full test with basic.exe^)
echo  If FAIL: Do NOT proceed to Phase B. Analyze logs and fix issues.
echo ============================================================
pause
