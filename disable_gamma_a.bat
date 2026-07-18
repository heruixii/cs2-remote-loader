@echo off
color 0E
title Restore Normal Mode: Re-enable PatchGuard (disable kernel debug)

echo ============================================================
echo  Restore Normal System Mode (Disable Kernel Debug)
echo ============================================================
echo.
echo  Purpose: Undo Gamma-A configuration, restore PatchGuard
echo           so other games (Vanguard/EAC/BattlEye) work normally
echo.
echo  Effect after reboot:
echo    - Kernel debug mode OFF
echo    - PatchGuard re-enabled (normal security)
echo    - DKOM hidden processes cleared (all processes exit on reboot)
echo    - Other anti-cheat games work normally
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

:: Step 1: Disable kernel debug mode
echo ---------- Step 1/3: Disable Kernel Debug Mode ----------
bcdedit /debug off
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] bcdedit /debug off failed!
    pause
    exit /b 1
)
echo [OK] Kernel debug mode disabled
echo.

:: Step 2: Reset debug settings (set start to disable)
echo ---------- Step 2/3: Reset Debug Settings ----------
bcdedit /dbgsettings serial debugport:1 baudrate:115200 /start disable /noumex
if %errorlevel% neq 0 (
    color 0E
    echo [WARNING] dbgsettings reset failed (may already be disabled), continuing...
) else (
    echo [OK] Debug settings set to disabled
)
echo.

:: Step 3: Ensure test signing is off
echo ---------- Step 3/3: Ensure Test Signing Off ----------
bcdedit /set testsigning off
if %errorlevel% neq 0 (
    color 0E
    echo [WARNING] testsigning setting failed (may already be off), continuing...
) else (
    echo [OK] Test signing off
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
echo  Normal Mode Restoration Complete!
echo ============================================================
echo.
echo  IMPORTANT NOTES:
echo    1. You MUST restart the system for changes to take effect
echo    2. After restart, PatchGuard will re-enable (normal security)
echo    3. DO NOT run loader2.exe after restoring normal mode!
echo       (DKOM + PatchGuard = BSOD risk)
echo    4. Other anti-cheat games (Valorant/Fortnite/Apex) will work
echo    5. To re-enable Gamma-A for CS2 testing later:
echo       run enable_gamma_a.bat + restart
echo.
echo  Restart command: shutdown /r /t 0
echo.
pause
