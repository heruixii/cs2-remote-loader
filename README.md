# CS2 Remote Loader — 无文件外挂注入框架

基于 ManualMap + XTEA 加密的远程加载器，payload 全程不落盘，专为规避 EAC/VAC 设计。

## 架构

```
loader.exe                          payload.dll (注入CS2进程)
├─ 从GitHub下载 payload.dat         ├─ 9层规避引擎
├─ XTEA 解密                        ├─ WorldToScreen 投影
├─ SelfDelete (自删除)              ├─ GDI Overlay 渲染
└─ ManualMap → CS2进程              └─ 200FPS ESP主循环
```

## 功能清单 (v3.29)

### 防检测层 — 全部真实生效

| 功能 | 状态 | 说明 |
|------|------|------|
| **StackSpoof 深度栈伪造** | 生效 | 所有 syscall 通过 4+ 帧伪造调用栈，游戏内存读写全面覆盖 |
| **Halo's Gate SSN 恢复** | 生效 | 每 5s 从磁盘 ntdll 恢复被 hook 的 syscall 号 |
| **ETW/AMSI 静默** | 生效 | ntdll!EtwEventWrite + amsi!AmsiScanBuffer patch，每 5s 自愈 |
| **EkkoSleep 内存加密** | 生效 | Sleep 期间 XOR 加密全部 payload 内存，加密/恢复耗时 <0.5ms |
| **BYOVD 内核防御** | 生效 | 加载 RTCore64.sys，摘除 EAC Ob/Process/Image/Thread 回调 |
| **HandleACLGuard** | 生效 | 设置游戏进程句柄 DACL，阻止 EAC 句柄枚举 |
| **SelfCloak PE 擦除** | 生效 | 擦除 DOS/PE 头 + PEB Ldr 假条目，伪装为系统 DLL |
| **反调试检测** | 生效 | 14 项检测，安全模式（不触发 ThreadHideFromDebugger） |
| **EAC 进程伪装** | 生效 | 修改 PEB ImagePathName 为系统进程名 |
| **EAC VMGate** | 生效 | VEH 拦截 INT1/INT3 硬件断点 |
| **EAC NMI 欺骗** | 生效 | VEH 链尾清理 HWBP/段寄存器 |
| **NMI 心跳** | 生效 | 每 8s 安全 syscall 刷新调用栈，降低 NMI 采样命中率 |

### ESP 透视 — v3.29 深度审计修复

| 功能 | 状态 | 详情 |
|------|------|------|
| **方框 (Box)** | 生效 | 外轮廓 + 内框，颜色区分敌我 |
| **血条 (HealthBar)** | 生效 | 绿→黄→红渐变，4px 宽 |
| **玩家名 (Name)** | 生效 | 最多 16 字符 |
| **距离 (Distance)** | 生效 | 米制，游戏单位 ×0.0254 |
| **武器名 (Weapon)** | 生效 | 30+ 武器 ID 映射 |
| **头部圆点 (HeadDot)** | 生效 | 半径自适应 |
| **额外信息 (Info)** | 生效 | HP 数值 + 开镜状态 |
| **十字准星 (Crosshair)** | 生效 | 绿色 + 字 |

**v3.28 修复**：
- 镜头后方玩家不再渲染到错误位置 (WorldToScreen 返回值检查)
- 武器名称不再读取错误 (实体指针标签剥离)
- 休眠实体不再浪费投影计算 (Dormant 检查前置)

**v3.29 深度审计修复**：
- Dormant 标志从 CGameSceneNode 正确读取 (`gameSceneNode+0xE7`)，此前从 pawn 实体基址读取到无关字段
- 移除冗余 WorldToScreen 调用 (`ent.screenPos` 全代码库零引用，节省 syscall)

### 默认不启用

| 功能 | 原因 |
|------|------|
| `enableVACSafety` | 备份的是 payload 自身 .text，非游戏内存 |
| `enableVirtualization` | 代码虚拟化开销大，默认关闭 |
| `aggressiveAntiDebug` | ThreadHideFromDebugger 触发 EAC 检测 |
| 队友渲染 | onlyAlive 模式仅显示敌人 |

## 使用方法（测试前必读）

### 前提

- **管理员权限运行** — BYOVD 内核驱动需要，右键 `以管理员身份运行`
- **关闭杀毒软件** 或添加白名单，否则 loader 可能被杀
- 需要联网（从 GitHub 下载 payload.dat）

### 正确步骤

```
 第1步 → 先启动 CS2，进入任意地图/对局（不要在大厅！）
 第2步 → 右键 loader.exe → 以管理员身份运行
 第3步 → 等待 2~3 秒，控制台消失后进入游戏即可看到 ESP
 第4步 → 关闭 CS2 时 payload 自动退出，无需手动操作
```

**一句话：先进地图，再右键管理员运行 loader。**

### 错误时机及风险

| 错误的启动时机 | 后果 | 风险等级 |
|---------------|------|----------|
| **CS2 还没开** | 找不到 cs2.exe，loader 静默退出。payload 白下载一次 | 低 |
| **CS2 开着但在大厅** | 注入成功，但没有 EntityList 数据，ESP 空白不显示。payload 空转期间可能被 EAC 空闲扫描命中 | **高** |
| **先开 loader，后开 CS2** | loader 启动时找不到进程，直接退出。需要重新运行 | 低 |
| **没开管理员** | BYOVD 驱动加载失败，EAC 内核回调摘除不生效。**封号风险极高** | **极高** |
| **开着其他反作弊游戏** | EkkoSleep 内存加密 + ETW patch 可能被别的 AC 检测 | **高** |
| **VPN/代理断开** | 无法从 GitHub 下载 payload.dat，loader 卡住后退出 | 低 |

### 如何确认生效

1. 游戏中应看到 **绿色十字准星** 在屏幕中央（无论有没有敌人都会显示）
2. 敌人身上出现 **红色方框 + 血条 + 名字 + 距离 + 武器名**
3. 如果没有：检查 `%TEMP%\stealth_diag.log`，看报错信息

### 注意事项

- loader.exe 运行后会自动删除自身，如需再次使用请保留备份
- payload 在当前 CS2 进程中存活，关闭 CS2 即自动清理
- 窗口最小化后 overlay 可能仍浮在桌面上，切回游戏即正常
- 改变游戏分辨率后 overlay 不会自动适配，需重启

## 编译

```bash
# Windows + MinGW-w64 (g++ 15.x)
build.bat
```

输出：
- `payload.dll` — 注入负载
- `payload.dat` — XTEA 加密 (托管到 HTTP)
- `loader.exe` — 下载解密注入器

## 文件结构

```
├── loader.cpp                  # 下载/解密/ManualMap 注入器
├── payload.cpp                 # DLL 入口 + ESP 主循环
├── build.bat                   # 编译脚本
├── encrypt_tool.cpp            # XTEA 加密工具
├── stealth_lib/
│   ├── stealth_core.cpp/h      # 规避引擎总控
│   ├── syscall_direct.cpp/h    # Hell's Gate + StackSpoof
│   ├── memory_cloak.cpp/h      # EkkoSleep + SelfCloak + ETW/AMSI
│   ├── cs2_memory.cpp/h        # CS2 实体遍历 + WorldToScreen
│   ├── game_esp.cpp/h          # ESP 渲染
│   ├── cheat_overlay.cpp/h     # GDI Overlay 窗口
│   ├── byovd_kernel.cpp/h      # RTCore64 内核防御
│   ├── eac_bypass.cpp/h        # EAC 深层绕过
│   ├── eac_vm_evasion.cpp/h    # VM 规避 + NMI 欺骗
│   ├── eac_syscall_guard.cpp/h # Syscall stub 完整性
│   ├── anti_debug.cpp/h        # 反调试
│   ├── pe_mutator.cpp/h        # PE 变异
│   ├── stealth_injection.cpp/h # ManualMap
│   ├── stealth_process.cpp/h   # 隐蔽进程操作
│   └── cs2_offsets.h           # CS2 2026.07 偏移量
└── scripts/
    └── embed_driver.py         # RTCore64.sys 嵌入
```
