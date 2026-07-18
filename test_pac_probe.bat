@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ============================================
echo   PAC Probe Auto-Test (BUILD 511)
echo ============================================
echo.

set MAX_ATTEMPTS=10
set ATTEMPT=0
set PLATFORM_EXE=完美世界竞技平台.exe
set PLATFORM_PATH=C:\Program Files (x86)\PerfectWorldArena\%PLATFORM_EXE%

:loop
set /a ATTEMPT+=1
echo [%ATTEMPT%/%MAX_ATTEMPTS%] Running PAC probe...

REM Create probe flag
echo. > "%TEMP%\pac_probe.flag"

REM Clear old log
del "%TEMP%\stealth_diag.log" >nul 2>&1

REM Run loader
echo Running loader.exe...
loader.exe 2>&1
set LOADER_EXIT=%ERRORLEVEL%

REM Wait for log write
timeout /t 2 /nobreak >nul

REM Check result
if exist "%TEMP%\stealth_diag.log" (
    findstr /C:"SUCCESS" "%TEMP%\stealth_diag.log" >nul
    if !ERRORLEVEL!==0 (
        echo.
        echo ============================================
        echo   [SUCCESS] ATTEMPT %ATTEMPT% -- PAC neutralization confirmed!
        echo ============================================
        type "%TEMP%\stealth_diag.log" | findstr /C:"PAC PROBE:"
        goto :done
    )
    echo --- Diagnostic Summary ---
    findstr /C:"PAC PROBE:" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"callback-range MATCH" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"callback-range fallback" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"no PAC filter found" "%TEMP%\stealth_diag.log" 2>nul
    findstr /C:"FOUND 'MessageT" "%TEMP%\stealth_diag.log" 2>nul
    echo -------------------------
)

echo [FAIL] Attempt %ATTEMPT% failed.
if %ATTEMPT% GEQ %MAX_ATTEMPTS% (
    echo.
    echo [FATAL] All %MAX_ATTEMPTS% attempts failed.
    echo Full diagnostic log:
    type "%TEMP%\stealth_diag.log" 2>nul
    goto :done
)

echo Restarting Perfect World platform...
taskkill /f /im "%PLATFORM_EXE%" >nul 2>&1
taskkill /f /im "PerfectWorldArena.exe" >nul 2>&1
timeout /t 3 /nobreak >nul

echo Starting platform...
if exist "%PLATFORM_PATH%" (
    start "" "%PLATFORM_PATH%"
) else (
    echo WARNING: Platform not found at %PLATFORM_PATH%
    for /d %%p in ("C:\Program Files\PerfectWorldArena" "C:\Program Files (x86)\PerfectWorldArena" "D:\PerfectWorldArena") do (
        if exist "%%~p\%PLATFORM_EXE%" (
            start "" "%%~p\%PLATFORM_EXE%"
            echo Found at: %%~p\%PLATFORM_EXE%
            goto :found_platform
        )
    )
    echo WARNING: Could not find platform. Please start it manually.
    :found_platform
)

echo Waiting 15 seconds for platform to restore MessageTransfer.sys...
timeout /t 15 /nobreak >nul
goto :loop

:done
del "%TEMP%\pac_probe.flag" >nul 2>&1
echo.
echo Done. Press any key to exit...
pause >nul
