@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM ept_dumper.exe - PAC SHV EPT Page Table Dumper
REM
REM Independent user-mode tool (not integrated into payload.dll)
REM Uses PDFWKRNL.sys via KernelMemoryAccessor to scan PAC driver
REM .data section for EPTP and EPT page table kernel VAs.
REM ============================================================

set "GPP=C:\msys64\mingw64\bin\g++"
set "CFLAGS=-std=c++20 -O2 -s -fpermissive -DNDEBUG -D_WIN32_WINNT=0x0A00"
set "STEALTH_LIB=stealth_lib"

REM Check compiler
if not exist "%GPP%.exe" (
    echo [ERROR] Compiler not found: %GPP%.exe
    echo Please install MSYS2 MinGW64
    pause
    exit /b 1
)

echo ============================================
echo Compiling ept_dumper.exe
echo ============================================
%GPP% %CFLAGS% -o ept_dumper.exe ^
    -I%STEALTH_LIB% ^
    ept_dumper.cpp ^
    %STEALTH_LIB%/byovd_kernel.cpp ^
    %STEALTH_LIB%/syscall_direct.cpp ^
    %STEALTH_LIB%/anti_debug.cpp ^
    %STEALTH_LIB%/eac_syscall_guard.cpp ^
    -lntdll -ladvapi32 -lpsapi

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Compilation failed!
    pause
    exit /b 1
)

echo [OK] ept_dumper.exe compiled successfully
echo.
echo ============================================
echo Usage:
echo   1. Ensure CS2 + PAC is running
echo   2. Ensure PDFWKRNL.sys is loaded (run loader2.exe first)
echo   3. Run ept_dumper.exe as Administrator
echo   4. Check ept_dump.log for results
echo ============================================
pause
