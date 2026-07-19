# CS2 Remote Loader — 无文件外挂注入框架 (PAC 特化)

基于 ManualMap + XTEA 加密的远程加载器，payload 全程不落盘，专为规避完美世界 PAC 反作弊设计。

**当前版本：BUILD 550 / v3.208**

## 架构 (BUILD 550)

```
loader.exe (~280KB, 自删)
├─ 从 HTTP 服务器下载 payload.dat
├─ XTEA 内存解密 → payload.dll
├─ ManualMap → 注入 CS2 进程
└─ SelfDelete (自删除)

payload.dll (~413KB, 注入 CS2 内部, -static 静态链接)
├─ BYOVD 内核防御: 加载 PDFWKRNL.sys → 摘除 PAC Ob/Process/Image 回调
├─ Minifilter Neutralizer: 中和 MessageTransfer.sys 文件回调
├─ KernelTraceCleaner: 清理驱动痕迹 (MmUnloadedDrivers/PiDDBCacheTable/KernelHashBucketList)
├─ CS2 内存补丁: ApplyCs2Patch (NOP '32 c0' 保持 client.dll 解密)
├─ 影子页 PTE: PAC 扫描见原始字节, CS2 执行补丁字节 (500ms 周期, 10% 占空比)
├─ 截图防护: 检测 5 种截图工具, 临时回退补丁
├─ DKOM 进程隐藏: 摘除 loader2.exe 进程链表项
├─ EkkoSleep 内存加密: Sleep 期间 XOR 加密 payload 内存
└─ 主循环: 每 5s MaintainCs2Patch → GuardPac → ReapplyAllCallbacks
```

## BUILD 550 关键改进

### 字符串/ IAT 清理
- **-static 全局静态链接**: 消除 libgcc_s_seh-1/libstdc++-6/libwinpthread-1 依赖
- **动态 API 解析**: CreateToolhelp32Snapshot/Process32FirstW/Process32NextW/Thread32First/Thread32Next 通过 GetProcAddress + XTEA 加密名动态解析
- **PEB Ldr 遍历**: 替代 GetModuleHandleW/GetModuleHandleExW, 消除 IAT 中的敏感 API
- **RTCore64.sys 嵌入移除**: 死代码清理, 消除 .rdata 中 \Device\RTCore64 / ntoskrnl.exe 等明文

### 影子页 PTE (BUILD 549)
- CS2 执行补丁代码 (pageB: 90 90) 保持内存解密
- PAC 扫描见原始字节 (pageA: 32 c0) 无法检测
- 500ms 周期, 50ms pageA 窗口 (10% 占空比)

### 日志安全 (BUILD 549)
- DiagLogEnc 宏: XTEA 加密 + B549:XX 短标签
- 集中日志: %TEMP%\sd.log (替代 stealth_diag.log)
- NtQuerySystemInformation 替代 CreateToolhelp32Snapshot (截图工具检测)

## 7 层保护体系

| # | 功能 | 说明 |
|---|------|------|
| 1 | **BYOVD 内核防御** | 加载 PDFWKRNL.sys (AMD 合法签名), 摘除 PAC ObRegisterCallbacks / ProcessNotify / ImageNotify 回调 |
| 2 | **Minifilter Neutralizer** | 内核 R/W 遍历 fltmgr 链表, 将 MessageTransfer 全部操作回调替换为 XOR EAX,EAX; RET stub |
| 3 | **KernelTraceCleaner** | 清理 MmUnloadedDrivers / PiDDBCacheTable / ci.dll KernelHashBucketList 中的 PDFWKRNL 痕迹 |
| 4 | **DKOM 进程隐藏** | 摘除 loader2.exe 进程链表项 (ActiveProcessLinks), 动态偏移扫描 Win11 24H2 |
| 5 | **EkkoSleep 内存加密** | Sleep 期间 XOR 加密全部 payload 内存 (含 cross-process 同步) |
| 6 | **ObCallbacks 重应用** | 60-90s 周期重应用 PAC 回调摘除 (防止 PAC 驱动重新注册) |
| 7 | **VEH 自愈** | 捕获 ntdll!RtlDeactivateActivationContext 崩溃 (最多 3 次), g_vehRestoring 原子标志防递归 |

## CS2 内存补丁机制

**原理**: CS2 的 client.dll 使用 `xor al, ah` (机器码 `32 c0`) 加密内存段, PAC 扫描时内存处于加密状态。补丁将 `32 c0` NOP 为 `90 90`, 使内存保持解密状态, CS2 自身的 ESP 渲染逻辑即可正常工作。

**影子页 PTE 方案**:
- 分配两个物理页: pageA (原始字节 `32 c0`) + pageB (补丁字节 `90 90`)
- PTE 指向 pageB 时 CS2 执行补丁代码 (内存解密)
- 500ms 周期中 50ms 切换到 pageA, 让 PAC 扫描命中原始字节
- 截图工具检测时临时完全回退到 pageA

## 使用方法

### 前提

- **管理员权限运行** — BYOVD 内核驱动需要
- **关闭 HVCI/内核隔离** — Windows 安全中心 → 设备安全性 → 内核隔离 → 关闭
- **已安装完美世界竞技平台** — 平台自动安装 PAC (MessageTransfer.sys)
- 需要联网（从 HTTP 服务器下载 payload.dat）

### 正确步骤

```
第1步 → 正常启动完美世界竞技平台（自动安装 PAC）
第2步 → 通过平台启动 CS2, 进入主菜单/任意地图
第3步 → 右键 loader.exe → 以管理员身份运行
第4步 → 等待 ~5~10 秒, payload.dll 注入完成
第5步 → 进入游戏, CS2 自身 ESP 渲染生效（内存已解密）
第6步 → 关闭 CS2 时 payload 自动安全退出 (DisableAll → return 0)
```

**一句话：先启动 CS2 进入主菜单，再右键管理员运行 loader。**

### 错误时机及风险

| 错误的启动时机 | 后果 | 风险 |
|---------------|------|------|
| 完美平台没开 | PAC 未安装 → 无需防检测（但直接跑 loader 无意义） | 低 |
| CS2 还没开 | 找不到 cs2.exe, loader 静默退出 (return 2) | 低 |
| CS2 在大厅 | 注入成功但无 EntityList 数据, ESP 空白 | 中 |
| 没开管理员 | BYOVD 驱动加载失败 → PAC 回调未摘除 → 检测概率极高 | **极高** |
| HVCI 未关闭 | BYOVD 驱动被阻止加载 | **高** |
| 蓝屏后未重启 | 系统状态不稳定, 必须重启清除残留 | **极高** |

### 如何确认生效

1. 检查 `%TEMP%\sd.log`:
   - `B549:SP:11 OK` / `sp_ok` → 影子页 PTE 切换成功
   - `B549:I:01` → ApplyCs2Patch 成功
   - `B549:ML:01` → 主循环运行中
   - `BYOVD: SUCCESS with PDFWKRNL.sys` → 驱动加载成功
   - `callbacks removed (PAC/MessageTransfer)` → 回调摘除成功
2. 进入游戏后 CS2 自身 ESP 正常显示（内存补丁生效）
3. 截图工具检测: 使用截图工具时 ESP 临时消失（影子页回退）

### 注意事项

- **loader.exe 运行后自动删除自身**, 请保留备份
- **关闭 CS2 即自动清理**, 无需手动操作
- **绝不用任务管理器强制结束 loader2.exe** — 触发 0x139 蓝屏, 应关闭 CS2 触发安全退出
- **蓝屏后必须重启** 清除不稳定状态
- **MessageTransfer.sys 不可删除/卸载** — 只停止服务, 避免 CS2 反作弊检测
- **PDFWKRNL.sys IOCTL 必须异步** — 2s 超时 + 10s 冷却, 防止永久阻塞
- PAC 更新后 `MessageTransfer` 可能改名, 代码已支持 6 种模糊匹配 + 内核扫描

## 编译

```bash
# Windows + MinGW-w64 (g++) - 需要 MSYS2
build.bat
```

**BUILD 550 编译要求**:
- MinGW-w64 g++ (C:\msys64\mingw64\bin\g++)
- C++20 标准
- `-static` 全局静态链接 (消除 libgcc/libstdc++/libwinpthread 依赖)

输出文件:
- `encrypt_tool.exe` — XTEA 加密工具 (管理端)
- `payload.dll` — 注入负载 (~413KB, 仅依赖 Windows 系统 DLL)
- `payload.dat` — XTEA 加密后的 payload (上传到 HTTP 服务器)
- `loader.exe` — 自删型下载/解密/注入器 (~280KB)

**payload.dll 依赖** (BUILD 550 -static 后):
- ADVAPI32.dll, KERNEL32.dll, USER32.dll, msvcrt.dll, ntdll.dll
- 全部为 Windows 系统 DLL, 无第三方 DLL 依赖

## 文件结构

```
├── loader.cpp                  # 下载/解密/ManualMap 注入器
├── payload.cpp                 # DLL 入口 + PAC 反检测主循环 + CS2 补丁
├── encrypt.cpp                 # XTEA 加密工具
├── build.bat                   # 编译脚本 (-static 静态链接)
├── PDFWKRNL.sys                # BYOVD 驱动 (AMD 合法签名)
├── stealth_lib/
│   ├── stealth_core.cpp/h      # 规避引擎总控
│   ├── syscall_direct.cpp/h    # Hell's Gate + Halo's Gate + StackSpoof
│   ├── memory_cloak.cpp/h      # EkkoSleep + SelfCloak + ETW/AMSI + 影子页 PTE
│   ├── cs2_memory.cpp/h        # CS2 内存访问 + ApplyCs2Patch
│   ├── byovd_kernel.cpp/h      # BYOVD 内核防御 + PAC Neutralizer + TraceCleaner + DKOM
│   ├── eac_syscall_guard.cpp/h # Syscall stub 完整性防护
│   ├── anti_debug.cpp/h        # 反调试 (动态 API 解析)
│   ├── pe_mutator.cpp/h        # PE 变异 (IAT 混淆)
│   ├── stealth_injection.cpp/h # ManualMap (动态 API 解析)
│   ├── stealth_process.cpp/h   # 隐蔽进程操作 + 截图工具检测
│   ├── string_obfuscator.h     # STEALTH_STR/WSTR_DECRYPT_TO 宏 (XTEA 编译期加密)
│   ├── module_resolver.h       # GetModuleBaseFromPEB + ModNameHash (PEB Ldr 遍历)
│   ├── platform.h              # 跨编译器宏 (LDR_INLOAD_HEAD 等)
│   ├── pdfwkrnl_embed.h        # PDFWKRNL.sys 嵌入数据
│   └── cs2_offsets.h           # CS2 偏移量
└── scripts/
    └── embed_driver.py         # 驱动嵌入工具 (生成 *_embed.h)
```

## BUILD 历史

| BUILD | 版本 | 关键变更 |
|-------|------|---------|
| 537 | v3.197 | Gamma-A 方案: 永久启用 DKOM 摘除进程链表 |
| 540 | v3.200 | CS2 退出检测: 触发安全退出 (DisableAll → return 0) |
| 541 | v3.201 | UnhideProcess 列表一致性检查: 防止 0x139 蓝屏 |
| 546 | v3.204 | basic.exe 7 层外部保护: cross-process EkkoSleep |
| 548 | v3.205 | 移除 basic.exe: 集成补丁逻辑到 payload.dll (ApplyCs2Patch) |
| 549 | v3.206-207 | 影子页 PTE: PAC 扫描见原始字节, DiagLog 加密, PEB Ldr 遍历 |
| **550** | **v3.208** | **-static 静态链接, 动态 API 解析, RTCore64 嵌入移除** |

## 检测概率评估

| BUILD | 检测概率 | 主要攻击面 |
|-------|---------|-----------|
| 544 | 30-50% | basic.exe 独立进程 (4 个未保护攻击面) |
| 546 | 5-10% | basic.exe 7 层保护, 但仍有独立进程 |
| 548 | ~80% | CS2 补丁明文可见 (无影子页) |
| 549 | <10% | 影子页 PTE + DiagLog 加密 |
| **550** | **<10%** | **+ IAT 清理 + -static 链接 + RTCore64 移除** |

## 安全约束

- **EkkoSleep 必须豁免 memory_cloak.cpp 代码页** — 防止自加密崩溃
- **EPT Dumper .data 段扫描不超过 64KB** — maxValidate ≤8, 避免 PatchGuard 0x109 BSOD
- **Win11 24H2 EPROCESS 偏移动态扫描** — UniqueProcessId @0x1D0, ActiveProcessLinks @0x1D8
- **DKOM 使用动态偏移** — 写邻居节点 Flink/Blink (prev.Flink=&current, next.Blink=&current)
- **用户态代码避免 CRT 依赖** — 不使用 std::vector/wstring (手动映射 DLL 堆未初始化)
- **截图工具检测频率 5s** — NtQuerySystemInformation 替代 CreateToolhelp32Snapshot
