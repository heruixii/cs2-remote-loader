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

## 编译

```bash
# Windowns + MinGW-w64 (g++ 15.x)
build.bat
```

输出：
- `payload.dll` — 注入负载
- `payload.dat` — XTEA 加密 (托管到 HTTP)
- `loader.exe` — 下载解密注入器

## 使用

```powershell
# 管理员权限运行
.\loader.exe
```

1. 启动 CS2 进入游戏
2. 以管理员运行 loader.exe（BYOVD 驱动需要）
3. loader 自删除 → 下载 payload.dat → 解密 → ManualMap 注入
4. Overlay 自动附着到 CS2 窗口，开始 ESP 渲染
5. 关闭 CS2 时 payload 自动退出并清理

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
