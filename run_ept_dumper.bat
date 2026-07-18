@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM run_ept_dumper.bat - Run PAC SHV EPT Dumper
REM
REM Prerequisites:
REM   1. CS2 + PAC (PerfectWorld Arena) must be running
REM   2. PDFWKRNL.sys must be loaded (run loader2.exe first, or
REM      manually load PDFWKRNL.sys service)
REM   3. Run this script as Administrator
REM ============================================================

title PAC SHV EPT Dumper

echo ============================================================
echo  PAC SHV EPT Page Table Dumper
echo ============================================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo         Right-click and select "Run as administrator".
    pause
    exit /b 1
)

REM Check prerequisites
echo [1/4] Checking prerequisites...
echo.

REM Check CS2 is running
tasklist /fi "imagename eq cs2.exe" 2>nul | find /i "cs2.exe" >nul
if errorlevel 1 (
    echo [WARNING] CS2 is not running.
    echo          EPT analysis requires PAC to be active.
    echo          Continue anyway? (Y/N)
    set /p choice=
    if /i not "%choice%"=="Y" (
        echo Aborted.
        pause
        exit /b 1
    )
) else (
    echo [OK] CS2 is running.
)

REM Check MessageTransfer.sys is loaded
sc query MessageTransfer 2>nul | find /i "RUNNING" >nul
if errorlevel 1 (
    echo [WARNING] MessageTransfer service not found or not running.
    echo          Trying alternative detection...
    echo          If PAC is running, MessageTransfer.sys should be loaded.
) else (
    echo [OK] MessageTransfer service is running.
)

REM Check PDFWKRNL.sys is loaded
sc query PDFWKRNL 2>nul | find /i "RUNNING" >nul
if errorlevel 1 (
    echo [WARNING] PDFWKRNL service not found or not running.
    echo          Run loader2.exe first to load PDFWKRNL.sys, then run this script.
    echo.
    echo          Continue anyway? (Y/N)
    set /p choice2=
    if /i not "%choice2%"=="Y" (
        echo Aborted. Please run loader2.exe first.
        pause
        exit /b 1
    )
) else (
    echo [OK] PDFWKRNL service is running.
)

echo.
echo [2/4] Cleaning old log file...
if exist ept_dump.log del /f /q ept_dump.log
echo [OK] Old log cleaned.
echo.

echo [3/4] Running ept_dumper.exe...
echo ============================================================
echo.
ept_dumper.exe
echo.
echo ============================================================

echo.
echo [4/4] Done.
echo.
echo Log file: %CD%\ept_dump.log
echo.
echo ============================================================
echo  Next steps:
echo   1. Open ept_dump.log in a text editor
echo   2. Look for "[EPTP @ ..." lines (EPTP candidates found)
echo   3. Look for "[VA @ ... 0xFFFFF8..." lines (page table VA candidates)
echo   4. Look for "Validated N EPT page table(s)" line
echo   5. If validated, examine PML4E entries for R/W/X permissions
echo      (pages with '---' permissions are SHV-monitored)
echo ============================================================
pause
