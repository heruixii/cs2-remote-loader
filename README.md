# CS2 Remote Loader — 无文件外挂注入框架 (PAC 特化)

基于 ManualMap + XTEA 加密的远程加载器，payload 全程不落盘，专为规避完美世界 PAC 反作弊设计。

## 架构 (BUILD 451 / v3.127)

```
loader.exe (200KB~, 自删)
├─ 嵌入 基础.exe → 释放到 %TEMP%\basic_esp.exe
├─ 从 GitHub 下载 payload.dat
├─ XTEA 内存解密
├─ ManualMap → 注入 CS2 进程
└─ SelfDelete (自删除)

payload.dll (注入 CS2 内部, ~300KB)
├─ BYOVD 内核防御: 加载 RTCore64.sys → 摘除 PAC Ob/Process/Image 回调
├─ Minifilter Neutralizer: 中和 MessageTransfer.sys 文件回调
├─ KernelTraceCleaner: 清理驱动痕迹 (MmUnloadedDrivers/PiDDBCacheTable/KernelHashBucketList)
├─ 自动启动 基础.exe (GDI Overlay ESP)
└─ 主循环: 每 500-1000ms GuardPac → ReapplyAllCallbacks
```

## 功能清单

### 透视 (ESP) — 基础.exe 提供

- 敌人/队友方框 (Box)
- 血条 (HealthBar)
- 玩家名 / 距离 / 武器
- 头部圆点 / 十字准星
- 支持练习模式 Bot 透视

### 防检测层 — PAC 专用

| # | 功能 | 说明 |
|---|------|------|
| 1 | **BYOVD 内核防御** | 加载 RTCore64.sys，摘除 PAC ObRegisterCallbacks / ProcessNotify / ImageNotify 回调 |
| 2 | **Minifilter Neutralizer** | 内核 R/W 遍历 fltmgr 链表，将 MessageTransfer 全部操作回调替换为 XOR EAX,EAX; RET stub |
| 3 | **KernelTraceCleaner** | 清理 MmUnloadedDrivers / PiDDBCacheTable / ci.dll KernelHashBucketList 中的 RTCore64 痕迹 |
| 4 | **PAC 回调周期性监控** | 每 500-1000ms GuardPac → 检测 PAC 驱动是否重新加载，自动重新摘除 |
| 5 | **PAC 服务禁用** | 删除 MessageTransfer 内核服务注册表项 (SCM) |
| 6 | **动态 PAC 名称识别** | 6 种模糊模式匹配 + 22 个系统驱动黑名单精确排除 |
| 7 | **EkkoSleep 内存加密** | Sleep 期间 XOR 加密全部 payload 内存 |
| 8 | **Halo's Gate SSN 恢复** | 每 5s 从磁盘 ntdll 恢复被 hook 的 syscall 号 |
| 9 | **ETW/AMSI 静默** | ntdll!EtwEventWrite + amsi!AmsiScanBuffer patch，每 5s 自愈 |
| 10 | **HandleACLGuard** | 设置进程句柄 DACL，阻止 PAC 句柄枚举 |
| 11 | **SelfCloak PE 擦除** | 擦除 DOS/PE 头 + PEB Ldr 假条目 + 页保护随机化 |
| 12 | **SyscallGuard 自愈** | 每 30 帧验证 ntdll syscall stub 完整性 |

## 使用方法

### 前提

- **管理员权限运行** — BYOVD 内核驱动需要
- **关闭 HVCI/内核隔离** — Windows 安全中心 → 设备安全性 → 内核隔离 → 关闭
- **已安装完美世界对战平台** — 平台自动安装 PAC (MessageTransfer.sys)
- 需要联网（从 GitHub 下载 payload.dat）

### 正确步骤

```
第1步 → 正常启动完美世界对战平台（自动安装 PAC）
第2步 → 通过平台启动 CS2，进入练习模式/任意地图（不要在大厅！）
第3步 → 右键 loader.exe → 以管理员身份运行
第4步 → 等待 ~5~10 秒，基础.exe 窗口弹出，进入游戏即可看到 ESP
第5步 → 关闭 CS2 时 payload + 基础.exe 自动退出
```

**一句话：先进地图，再右键管理员运行 loader。**

### 错误时机及风险

| 错误的启动时机 | 后果 | 风险 |
|---------------|------|------|
| 完美平台没开 | PAC 未安装 → 无需防检测（但直接跑 loader 无意义） | 低 |
| CS2 还没开 | 找不到 cs2.exe，loader 静默退出 | 低 |
| CS2 在大厅 | 注入成功但无 EntityList 数据，基础.exe 弹出但 ESP 空白 | 中 |
| 没开管理员 | BYOVD 驱动加载失败 → PAC 回调未摘除 → 基础.exe OpenProcess 被监控 | **极高** |
| 系统未重启 (ZOMBIE DEVICE) | RTCore64.sys 设备残留 → 驱动加载失败 → 防御失效 | **极高** |
| HVCI 未关闭 | BYOVD 驱动被阻止加载 | **高** |

### 如何确认生效

1. 基础.exe 弹出一个窗口覆盖在 CS2 上方
2. 敌人/Bot 身上出现 ESP 标记
3. 检查 `%TEMP%\stealth_diag.log`：
   - `BYOVD: SUCCESS with RTCore64.sys` → 驱动加载成功
   - `callbacks removed (PAC/MessageTransfer)` → 回调摘除成功
   - `NEUTRALIZING MessageTransfer` → minifilter 中和成功

### 注意事项

- loader.exe 运行后自动删除自身，请保留备份
- 关闭 CS2 即自动清理，无需手动操作
- 改变游戏分辨率后 ESP 不会自动适配，需重启
- 蓝屏后必须重启清除 RTCore64 残留
- PAC 更新后 `MessageTransfer` 可能改名，代码已支持 6 种模糊匹配 + 内核扫描

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
├── payload.cpp                 # DLL 入口 + PAC 反检测主循环
├── build.bat                   # 编译脚本
├── encrypt_tool.cpp            # XTEA 加密工具
├── stealth_lib/
│   ├── stealth_core.cpp/h      # 规避引擎总控
│   ├── syscall_direct.cpp/h    # Hell's Gate + Halo's Gate + StackSpoof
│   ├── memory_cloak.cpp/h      # EkkoSleep + SelfCloak + ETW/AMSI
│   ├── cs2_memory.cpp/h        # CS2 实体遍历 + WorldToScreen
│   ├── game_esp.cpp/h          # ESP 渲染 (备用)
│   ├── cheat_overlay.cpp/h     # GDI Overlay (备用)
│   ├── byovd_kernel.cpp/h      # BYOVD 内核防御 + PAC Neutralizer + TraceCleaner
│   ├── eac_syscall_guard.cpp/h # Syscall stub 完整性防护
│   ├── anti_debug.cpp/h        # 反调试
│   ├── pe_mutator.cpp/h        # PE 变异
│   ├── stealth_injection.cpp/h # ManualMap
│   ├── stealth_process.cpp/h   # 隐蔽进程操作
│   └── cs2_offsets.h           # CS2 偏移量
└── scripts/
    ├── embed_driver.py         # RTCore64.sys 嵌入
    └── embed_basic_loader.py   # 基础.exe 嵌入
```
