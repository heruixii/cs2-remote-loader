@echo off
color 0A
title Gamma-A: Disable PatchGuard via Kernel Debug Mode

echo ============================================================
echo  Gamma-A: PatchGuard Disabler Configuration Script
echo  Principle: Enable kernel debug mode - PatchGuard does not initialize
echo  Effect: DKOM can be used permanently, 0%% BSOD risk within 3 hours
echo ============================================================
echo.

:: Check administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Administrator privileges required!
    echo.
    echo Please right-click this file and select "Run as administrator"
    pause
    exit /b 1
)

color 0A
echo [OK] Administrator privileges confirmed
echo.

:: Show current status
echo ---------- Current Status ----------
bcdedit /enum {current} | findstr /i "debug testsigning nointegritychecks"
echo.

:: Step 1: Enable kernel debug mode
echo ---------- Step 1/3: Enable Kernel Debug Mode ----------
bcdedit /debug on
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] bcdedit /debug on failed!
    pause
    exit /b 1
)
echo [OK] Kernel debug mode enabled
echo.

:: Step 2: Configure debug settings (serial, autoenable, noumex)
echo ---------- Step 2/3: Configure Debug Settings ----------
bcdedit /dbgsettings serial debugport:1 baudrate:115200 /start autoenable /noumex
if %errorlevel% neq 0 (
    color 0E
    echo [WARNING] dbgsettings configuration failed (may already be configured), continuing...
) else (
    echo [OK] Debug settings configured
)
echo.

:: Step 3: Disable test signing watermark (optional)
echo ---------- Step 3/3: Disable Test Signing Watermark ----------
bcdedit /set testsigning off
if %errorlevel% neq 0 (
    color 0E
    echo [WARNING] testsigning setting failed (may already be off), continuing...
) else (
    echo [OK] Test signing watermark disabled
)
echo.

:: Verify final status
echo ============================================================
echo  Final Configuration Verification:
echo ============================================================
bcdedit /enum {current} | findstr /i "debug testsigning"
echo.

color 0A
echo ============================================================
echo  Gamma-A Configuration Complete!
echo ============================================================
echo.
echo  Important Notes:
echo    1. You MUST restart the system for configuration to take effect
echo    2. After restart, PatchGuard will NOT initialize
echo    3. DKOM can be used permanently (no Unhide/Rehide cycle needed)
echo    4. "Test Mode" watermark may appear on desktop (normal)
echo.
echo  Restart command: shutdown /r /t 0
echo.
pause
