# CS2 Remote Loader — 无文件外挂注入框架

基于 ManualMap + XTEA 加密的远程加载器，payload 全程不落盘，专为规避 EAC/VAC 设计。

## 架构 (v3.32)

```
loader.exe (276KB, 自删)
├─ 嵌入 基础.exe → 释放到 %TEMP%\basic_esp.exe
├─ 从 GitHub 下载 payload.dat
├─ XTEA 内存解密
├─ ManualMap → 注入 CS2 进程
└─ SelfDelete (自删除)

payload.dll (注入 CS2 内部, 276KB)
├─ 12层反检测引擎 (BYOVD/EkkoSleep/HaloGate/...)
├─ 自动启动 基础.exe (GDI Overlay ESP)
└─ 主循环: 反检测维护 + 基础.exe 存活监控
```

## 功能清单 (v3.32)

### 透视 (ESP) — 基础.exe 提供

基础.exe 是经过验证的 CS2 外部透视，使用 ReadProcessMemory + GDI Overlay 渲染。本版本将其嵌入 loader.exe，注入 payload 后自动启动。

- 敌人/队友方框 (Box)
- 血条 (HealthBar)
- 玩家名 / 距离 / 武器
- 头部圆点 / 十字准星
- **支持练习模式 Bot 透视**

### 防检测层 — 12层全部生效

| # | 功能 | 状态 | 说明 |
|---|------|------|------|
| 1 | **BYOVD 内核防御** | 生效 | 加载 RTCore64.sys，摘除 EAC Ob/Process/Image/Thread 所有回调 |
| 2 | **EkkoSleep 内存加密** | 生效 | Sleep 期间 XOR 加密全部 payload 内存，防 EAC 空闲扫描 |
| 3 | **Halo's Gate SSN 恢复** | 生效 | 每 5s 从磁盘 ntdll 恢复被 hook 的 syscall 号 |
| 4 | **EAC VMGate** | 生效 | VEH 拦截 INT1/INT3 硬件断点 + RDTSC 归一化 |
| 5 | **ETW/AMSI 静默** | 生效 | ntdll!EtwEventWrite + amsi!AmsiScanBuffer patch，每 5s 自愈 |
| 6 | **HandleACLGuard** | 生效 | 设置进程句柄 DACL，阻止 EAC 句柄枚举 |
| 7 | **SelfCloak PE 擦除** | 生效 | 擦除 DOS/PE 头 + PEB Ldr 假条目 + 页保护随机化 |
| 8 | **SyscallGuard 自愈** | 生效 | 每 30 帧验证 ntdll syscall stub 完整性，被篡改自动恢复 |
| 9 | **PE 变异** | 生效 | RichHeader 擦除 + 时间戳随机化 + 调试信息剥离 + 随机 Junk Overlay |
| 10 | **反调试检测** | 生效 | 14 项检测，安全模式（不触发 ThreadHideFromDebugger） |
| 11 | **EAC 扫描预测** | 生效 | 预测 EAC 扫描周期，仅在安全窗口内执行操作 |
| 12 | **进程伪装** | 生效 | PEB ImagePathName 伪装为系统进程名 |

### 默认不启用的功能

| 功能 | 原因 |
|------|------|
| `aggressiveAntiDebug` | ThreadHideFromDebugger 触发 EAC 检测 |
| `enableVirtualization` | 代码虚拟化开销大 |
| `enableVACSafety` | 备份的是 payload 自身 .text，非游戏内存 |

## 使用方法（测试前必读）

### 前提

- **管理员权限运行** — BYOVD 内核驱动需要
- **关闭杀毒软件** 或添加白名单
- 需要联网（从 GitHub 下载 payload.dat）

### 正确步骤

```
第1步 → 先启动 CS2，进入练习模式/任意地图（不要在大厅！）
第2步 → 右键 loader.exe → 以管理员身份运行
第3步 → 等待 3~5 秒，基础.exe 窗口弹出，进入游戏即可看到 ESP
第4步 → 关闭 CS2 时 payload + 基础.exe 自动退出，无需手动操作
```

**一句话：先进地图，再右键管理员运行 loader。**

### 错误时机及风险

| 错误的启动时机 | 后果 | 风险等级 |
|---------------|------|----------|
| **CS2 还没开** | 找不到 cs2.exe，loader 静默退出 | 低 |
| **CS2 在大厅** | 注入成功但无 EntityList 数据，基础.exe 弹出但 ESP 空白。空转期间可能被 EAC 空闲扫描 | **高** |
| **先开 loader 后开 CS2** | loader 找不到进程，直接退出 | 低 |
| **没开管理员** | BYOVD 驱动加载失败，基础.exe 的 OpenProcess 被 EAC 监控。**封号风险极高** | **极高** |
| **开着其他反作弊游戏** | EkkoSleep + ETW patch 可能被其他 AC 检测 | **高** |
| **VPN/代理断开** | 无法从 GitHub 下载 payload.dat | 低 |

### 如何确认生效

1. 基础.exe 会自动弹出一个窗口覆盖在 CS2 上方
2. 敌人/Bot 身上出现 ESP 标记
3. 如果没有：检查 `%TEMP%\stealth_diag.log`，查看报错信息

### 注意事项

- loader.exe 运行后自动删除自身，请保留备份
- payload + 基础.exe 在 CS2 进程中存活，关闭 CS2 即自动清理
- 基础.exe 崩溃后 payload 会自动重启（带指数退避）
- 改变游戏分辨率后 ESP 不会自动适配，需重启

## 编译

```bash
# Windows + MinGW-w64 (g++)
build.bat
```

输出：
- `payload.dll` — 注入负载
- `payload.dat` — XTEA 加密 (托管到 GitHub)
- `loader.exe` — 自删型下载/解密/注入器

## 文件结构

```
├── loader.cpp                  # 下载/解密/ManualMap + 嵌入基础.exe
├── payload.cpp                 # DLL 入口 + 反检测主循环
├── build.bat                   # 编译脚本
├── encrypt_tool.cpp            # XTEA 加密工具
├── stealth_lib/
│   ├── stealth_core.cpp/h      # 规避引擎总控 (12层)
│   ├── syscall_direct.cpp/h    # Hell's Gate + Halo's Gate + StackSpoof
│   ├── memory_cloak.cpp/h      # EkkoSleep + SelfCloak + ETW/AMSI
│   ├── cs2_memory.cpp/h        # CS2 实体遍历 + WorldToScreen
│   ├── game_esp.cpp/h          # ESP 渲染 (v3.32 备用)
│   ├── cheat_overlay.cpp/h     # GDI Overlay (v3.32 备用)
│   ├── byovd_kernel.cpp/h      # RTCore64 BYOVD 内核防御
│   ├── eac_bypass.cpp/h        # EAC 深层绕过
│   ├── eac_vm_evasion.cpp/h    # VM 规避 + NMI 欺骗
│   ├── eac_syscall_guard.cpp/h # Syscall stub 完整性
│   ├── anti_debug.cpp/h        # 反调试
│   ├── pe_mutator.cpp/h        # PE 变异
│   ├── stealth_injection.cpp/h # ManualMap
│   ├── stealth_process.cpp/h   # 隐蔽进程操作
│   └── cs2_offsets.h           # CS2 偏移量
└── scripts/
    ├── embed_driver.py         # RTCore64.sys 嵌入
    └── embed_basic_loader.py   # 基础.exe 嵌入
```
