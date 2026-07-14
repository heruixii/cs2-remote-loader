@echo off & chcp 65001 >nul 2>&1
REM ============================================================
REM 远程加载链构建脚本
REM
REM 产出:
REM   encrypt_tool.exe — Payload 加密工具 (管理端使用)
REM   payload.dll      — 作弊逻辑 DLL (加密后上传服务器)
REM   payload.dat      — 加密后的 Payload (上传到 HTTP 服务器)
REM   loader.exe       — 远程加载 Stager (用户端分发)
REM   libwinpthread-1.dll — 运行时库 (与 loader.exe 同目录分发)
REM
REM 部署流程:
REM   1. 修改 loader.cpp 第29行的 PAYLOAD_URL 为你的服务器地址
REM   2. 运行此 build.bat
REM   3. 上传 payload.dat 到 HTTP/HTTPS 服务器
REM   4. 分发 loader.exe + libwinpthread-1.dll 给用户 (打包在一起)
REM ============================================================

set "GPP=C:\msys64\mingw64\bin\g++"
set "CFLAGS=-std=c++20 -O2 -s -fpermissive -DNDEBUG -D_WIN32_WINNT=0x0A00"
set "STEALTH_LIB=.."

REM 检查编译器是否存在
if not exist "%GPP%.exe" (
    echo [ERROR] 编译器未找到: %GPP%.exe
    echo 请安装 MSYS2 MinGW64 或修改 GPP 路径
    pause
    exit /b 1
)

echo ============================================
echo [1/3] 编译 encrypt_tool.exe (管理工具)
echo ============================================
%GPP% %CFLAGS% -static -o encrypt_tool.exe encrypt.cpp
if %ERRORLEVEL% neq 0 (
    echo [ERROR] encrypt_tool.exe 编译失败!
    pause & exit /b 1
)
echo [OK] encrypt_tool.exe

echo.
echo ============================================
echo [2/3] 编译 payload.dll + 加密 (作弊负载)
echo ============================================
%GPP% %CFLAGS% -shared -o payload.dll ^
    -I%STEALTH_LIB% ^
    payload.cpp ^
    %STEALTH_LIB%/stealth_core.cpp ^
    %STEALTH_LIB%/syscall_direct.cpp ^
    %STEALTH_LIB%/anti_debug.cpp ^
    %STEALTH_LIB%/eac_bypass.cpp ^
    %STEALTH_LIB%/eac_vm_evasion.cpp ^
    %STEALTH_LIB%/memory_cloak.cpp ^
    %STEALTH_LIB%/pe_mutator.cpp ^
    %STEALTH_LIB%/stealth_process.cpp ^
    %STEALTH_LIB%/stealth_injection.cpp ^
    %STEALTH_LIB%/string_obfuscator.cpp ^
    -lwinhttp -lws2_32 -lntdll
if %ERRORLEVEL% neq 0 (
    echo [ERROR] payload.dll 编译失败!
    pause & exit /b 1
)
echo [OK] payload.dll

REM 加密 DLL 为 payload.dat
encrypt_tool.exe payload.dll payload.dat
if %ERRORLEVEL% neq 0 (
    echo [ERROR] 加密失败!
    pause & exit /b 1
)

echo.
echo ============================================
echo [3/3] 编译 loader.exe (远程加载器)
echo ============================================
%GPP% %CFLAGS% -mwindows -static -o loader.exe loader.cpp -lwinhttp -lshell32
if %ERRORLEVEL% neq 0 (
    echo [ERROR] loader.exe 编译失败!
    pause & exit /b 1
)
echo [OK] loader.exe

REM 复制运行库 (若 -static 未完全消除 pthread 依赖)
if exist "C:\msys64\mingw64\bin\libwinpthread-1.dll" (
    copy /Y "C:\msys64\mingw64\bin\libwinpthread-1.dll" . >nul 2>&1
    if exist "libwinpthread-1.dll" (
        echo [OK] libwinpthread-1.dll
    ) else (
        echo [WARN] libwinpthread-1.dll 复制失败, 请手动复制
    )
) else (
    echo [WARN] 未找到 libwinpthread-1.dll, 若 loader.exe 依赖此DLL请手动处理
)

echo.
echo ============================================
echo [全部完成]
echo.
echo 文件清单:
echo   encrypt_tool.exe         管理端 — 重新加密 DLL
echo   payload.dll              管理端 — 源代码 (不需要分发)
echo   payload.dat              上传到 HTTP 服务器
echo   loader.exe               用户端 — 分发 (可改名)
echo   libwinpthread-1.dll      用户端 — 与 loader.exe 同目录
echo.
echo 部署步骤:
echo   1. 修改 loader.cpp 中的 PAYLOAD_URL 为你的服务器地址
echo   2. 运行此 build.bat 重新编译
echo   3. 上传 payload.dat 到你的 HTTP/HTTPS 服务器
echo   4. 将 loader.exe + libwinpthread-1.dll 打包分发给用户
echo ============================================
pause
