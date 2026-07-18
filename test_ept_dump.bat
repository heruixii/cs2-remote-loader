@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM BUILD 547: EPT Dump Test Script
REM
REM Purpose:
REM   Trigger EPT page table dump via ept_dump.flag
REM   RunEptDump() integrated in payload.dll reuses BYOVD handle
REM   Output: %TEMP%\ept_dump.log
REM
REM CRITICAL SAFETY RULES:
REM   1. NEVER use Task Manager to kill loader2.exe (causes 0x139 BSOD)
REM   2. NEVER force shutdown (may corrupt filesystem)
REM   3. loader2.exe will auto-exit after dump (return 0 safe path)
REM   4. If stuck: close CS2 first, wait 30s for loader2.exe to exit
REM ============================================================

title BUILD 547 EPT Dump Test

echo ============================================================
echo  BUILD 547: EPT Page Table Dump Test
echo  Date: %date% %time%
echo ============================================================
echo.

REM Step 1: Clean old logs
echo [1/5] Cleaning old logs...
if exist "%TEMP%\stealth_diag.log" del /f /q "%TEMP%\stealth_diag.log"
if exist "%TEMP%\ept_dump.log" del /f /q "%TEMP%\ept_dump.log"
echo [OK] Old logs cleaned
echo.

REM Step 2: Create ept_dump.flag trigger
echo [2/5] Creating ept_dump.flag trigger...
echo. > "%TEMP%\ept_dump.flag"
echo [OK] Flag created: %TEMP%\ept_dump.flag
echo.

REM Step 3: Copy loader2.exe (SelfDelete mechanism)
echo [3/5] Preparing loader2.exe...
if not exist "d:\技术研发\tmp\loader.exe" (
    echo [ERROR] loader.exe not found in d:\技术研发\tmp\
    pause
    exit /b 1
)
copy /Y "d:\技术研发\tmp\loader.exe" "d:\技术研发\tmp\loader2.exe" >nul 2>&1
if not exist "d:\技术研发\tmp\loader2.exe" (
    echo [ERROR] Cannot create loader2.exe
    pause
    exit /b 1
)
echo [OK] loader2.exe prepared
echo.

REM Step 4: Check CS2 + PAC running
echo [4/5] Checking prerequisites...
tasklist /fi "imagename eq cs2.exe" 2>nul | find /i "cs2.exe" >nul
if errorlevel 1 (
    echo [WARNING] CS2 not running!
    echo           EPT dump requires PAC (MessageTransfer.sys) to be loaded.
    echo           Please start PerfectWorld Arena + CS2 first.
    echo.
    pause
    exit /b 1
)
echo [OK] CS2 is running (PAC should be active)
echo.

REM Step 5: Start loader2.exe
echo [5/5] Starting loader2.exe...
echo       (loader2.exe will auto-exit after EPT dump completes)
echo.
start "" "d:\技术研发\tmp\loader2.exe"

REM Wait for dump to complete (max 60 seconds)
echo ============================================================
echo  Waiting for EPT dump to complete (max 60 seconds)...
echo  DO NOT use Task Manager to kill loader2.exe!
echo  DO NOT force shutdown!
echo ============================================================
echo.

set /a waitCount=0
:wait_loop
set /a waitCount+=1
timeout /t 2 /nobreak >nul

REM Check if ept_dump.log exists and has content
if exist "%TEMP%\ept_dump.log" (
    for %%A in ("%TEMP%\ept_dump.log") do (
        if %%~z gtr 100 (
            echo [%time%] ept_dump.log detected (%%~z bytes)
            goto dump_done
        )
    )
)

REM Check if loader2.exe still running
tasklist /fi "imagename eq loader2.exe" 2>nul | find /i "loader2.exe" >nul
if errorlevel 1 (
    echo [%time%] loader2.exe exited (may have completed or crashed)
    goto dump_done
)

if %waitCount% lss 30 goto wait_loop

echo [WARNING] Timeout waiting for dump (60s). Checking logs anyway...
echo.

:dump_done
echo.
echo ============================================================
echo  EPT Dump Test Complete
echo  Time: %time%
echo ============================================================
echo.

REM Final status report
echo === Final Status ===
echo.
echo [1] Process status:
tasklist /fi "imagename eq loader2.exe" 2>nul | find /i "loader2.exe" >nul
if errorlevel 1 (
    echo    loader2.exe: Exited (safe exit via return 0)
) else (
    echo    loader2.exe: Still running (wait 30s or close CS2 to trigger exit)
)
echo.

echo [2] Log files:
if exist "%TEMP%\ept_dump.log" (
    for %%A in ("%TEMP%\ept_dump.log") do echo    ept_dump.log: %%~z bytes
) else (
    echo    ept_dump.log: NOT FOUND (dump may have failed)
)
if exist "%TEMP%\stealth_diag.log" (
    for %%A in ("%TEMP%\stealth_diag.log") do echo    stealth_diag.log: %%~z bytes
) else (
    echo    stealth_diag.log: NOT FOUND
)
echo.

echo [3] EPT dump results preview:
if exist "%TEMP%\ept_dump.log" (
    echo ------------------------------------------------------------
    type "%TEMP%\ept_dump.log"
    echo ------------------------------------------------------------
) else (
    echo    No ept_dump.log to display
)
echo.

echo [4] Flag file status:
if exist "%TEMP%\ept_dump.flag" (
    echo    ept_dump.flag: STILL EXISTS (dump may not have completed)
    echo    You can delete it manually: del "%TEMP%\ept_dump.flag"
) else (
    echo    ept_dump.flag: Deleted (dump completed successfully)
)
echo.

echo ============================================================
echo  Test Complete
echo.
echo  Next steps:
echo    1. Review ept_dump.log for EPTP candidates + EPT page tables
echo    2. If no tables found, ensure PAC is fully loaded (enter CS2 main menu)
echo    3. Share ept_dump.log for analysis
echo.
echo  SAFETY REMINDER:
echo    If loader2.exe is still running, DO NOT use Task Manager!
echo    Close CS2 to trigger safe exit, then wait 30 seconds.
echo ============================================================
pause
