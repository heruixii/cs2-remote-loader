@echo off
chcp 65001 >nul
color 0A
title Gamma-A: 禁用 PatchGuard (内核调试模式)

echo ============================================================
echo  Gamma-A: 禁用 PatchGuard 配置脚本
echo  原理: 启用内核调试模式 → PatchGuard 设计上不初始化
echo  效果: DKOM 可永久使用，3小时内 0%% 蓝屏风险
echo ============================================================
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [错误] 需要管理员权限运行此脚本！
    echo.
    echo 请右键此文件 → "以管理员身份运行"
    pause
    exit /b 1
)

color 0A
echo [OK] 已确认管理员权限
echo.

:: 显示当前状态
echo ---------- 当前进启状态 ----------
bcdedit /enum {current} | findstr /i "debug testsigning nointegritychecks"
echo.

:: 步骤1: 启用内核调试
echo ---------- 步骤 1/3: 启用内核调试模式 ----------
bcdedit /debug on
if %errorlevel% neq 0 (
    color 0C
    echo [错误] bcdedit /debug on 失败！
    pause
    exit /b 1
)
echo [OK] 内核调试已启用
echo.

:: 步骤2: 配置调试设置 (串口模式, autoenable, noumex)
echo ---------- 步骤 2/3: 配置调试参数 ----------
bcdedit /dbgsettings serial debugport:1 baudrate:115200 /start autoenable /noumex
if %errorlevel% neq 0 (
    color 0E
    echo [警告] dbgsettings 配置失败 (可能已配置), 继续...
) else (
    echo [OK] 调试参数已配置
)
echo.

:: 步骤3: 关闭测试模式水印 (可选, debug 模式可能显示水印)
echo ---------- 步骤 3/3: 关闭测试签名水印 ----------
bcdedit /set testsigning off
if %errorlevel% neq 0 (
    color 0E
    echo [警告] testsigning 设置失败 (可能已是 off), 继续...
) else (
    echo [OK] 测试签名水印已关闭
)
echo.

:: 验证最终状态
echo ============================================================
echo  最终配置状态验证:
echo ============================================================
bcdedit /enum {current} | findstr /i "debug testsigning"
echo.

color 0A
echo ============================================================
echo  ✓ Gamma-A 配置完成！
echo ============================================================
echo.
echo  重要提示:
echo    1. 必须重启系统使配置生效
echo    2. 重启后 PatchGuard 将不会初始化
echo    3. DKOM 可永久使用 (无需 Unhide/Rehide 循环)
echo    4. 桌面右下角可能显示"测试模式"水印 (正常现象)
echo.
echo  重启命令: shutdown /r /t 0
echo.
pause
