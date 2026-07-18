@echo off
:: Gamma-A diagnostic script - writes all output to log file
:: Run as Administrator

set "LOGFILE=%TEMP%\gamma_a_diag.log"

echo ============================================================ > "%LOGFILE%"
echo  Gamma-A Diagnostic Log - %date% %time% >> "%LOGFILE%"
echo ============================================================ >> "%LOGFILE%"
echo. >> "%LOGFILE%"

:: Check admin privileges
echo [1] Checking administrator privileges... >> "%LOGFILE%"
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] NOT running as administrator! >> "%LOGFILE%"
    echo Please right-click and select "Run as administrator" >> "%LOGFILE%"
    goto :write_done
)
echo [OK] Running as administrator >> "%LOGFILE%"
echo. >> "%LOGFILE%"

:: Current bcdedit status
echo [2] Current BCD status (before changes): >> "%LOGFILE%"
bcdedit /enum {current} >> "%LOGFILE%" 2>&1
echo. >> "%LOGFILE%"

:: Step 1: Enable debug
echo [3] Step 1: Enabling kernel debug mode... >> "%LOGFILE%"
bcdedit /debug on >> "%LOGFILE%" 2>&1
echo Exit code: %errorlevel% >> "%LOGFILE%"
echo. >> "%LOGFILE%"

:: Step 2: Configure dbgsettings
echo [4] Step 2: Configuring debug settings... >> "%LOGFILE%"
bcdedit /dbgsettings serial debugport:1 baudrate:115200 /start autoenable /noumex >> "%LOGFILE%" 2>&1
echo Exit code: %errorlevel% >> "%LOGFILE%"
echo. >> "%LOGFILE%"

:: Step 3: Disable testsigning
echo [5] Step 3: Disabling test signing watermark... >> "%LOGFILE%"
bcdedit /set testsigning off >> "%LOGFILE%" 2>&1
echo Exit code: %errorlevel% >> "%LOGFILE%"
echo. >> "%LOGFILE%"

:: Final verification
echo [6] Final BCD status (after changes): >> "%LOGFILE%"
bcdedit /enum {current} >> "%LOGFILE%" 2>&1
echo. >> "%LOGFILE%"

:: Summary
echo ============================================================ >> "%LOGFILE%"
echo  DIAGNOSTIC COMPLETE >> "%LOGFILE%"
echo  Log file: %LOGFILE% >> "%LOGFILE%"
echo ============================================================ >> "%LOGFILE%"

:write_done
echo. >> "%LOGFILE%"
echo --- END OF LOG --- >> "%LOGFILE%"

:: Also display on screen
type "%LOGFILE%"
echo.
echo Log saved to: %LOGFILE%
echo.
pause
