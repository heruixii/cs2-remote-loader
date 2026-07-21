# CS2 Remote Loader — 无文件外挂注入框架 (PAC 特化)

基于 ManualMap + XTEA 加密的远程加载器，payload 全程不落盘，专为规避完美世界 PAC 反作弊设计。

**当前版本：BUILD 567 / v3.296 (安全退出 + 全面审查加固)**

## 架构 (BUILD 567 / v3.296)

```
loader.exe (~237KB, 自删)
├─ 从 HTTP 服务器下载 payload.dat
├─ XTEA 内存解密 → payload.dll
├─ ManualMap → 注入 CS2 进程
└─ SelfDelete (自删除)

payload.dll (~440KB, 注入 CS2 内部, -static 静态链接)
├─ BYOVD 内核防御: 加载 PDFWKRNL.sys → 摘除 PAC Ob/Process/Image/Thread 回调
├─ Minifilter Neutralizer: 中和 MessageTransfer.sys 文件回调 (5 种多样化 stub)
├─ KernelTraceCleaner: 清理驱动痕迹 (MmUnloadedDrivers/PiDDBCacheTable/KernelHashBucketList)
├─ DKOM 进程隐藏: 摘除 loader2.exe 进程链表项 (Win11 24H2 动态偏移, SelfLoopHarden 防 0x139)
├─ CS2 内存补丁: ApplyCs2Patch (NOP '32 c0' 保持 client.dll 解密)
├─ VirtualProtect 模式: 临时回退补丁 (替代影子页, BUILD 556+)
├─ ★ BUILD 566: ShvInstallPatcher — VmxOnWrapper + SHV_Install 双重 patch
│  ├─ PatchVmxOnWrapper (RVA 0xEAEC4): 31 C0 C3 (xor eax,eax; ret) → VMX 永不启动
│  ├─ PatchShvInstallEntry: B8 FB FF FF FF C3 (mov eax,-5; ret) → SHV 失败兜底
│  ├─ 独立降级模式: VmxOn 与 SHV 各自 3 次失败阈值 + 5 分钟自恢复
│  └─ 周期性维护 (60-90s): IsVmxOnPatched + IsPatched → 自动重 patch
├─ ★ BUILD 567 v3.289: PvpAlivePatcher — 内核跨进程 patch PvpAlive.dll 的 PacNova::Is*Hack 函数
│  ├─ BYOVD driver 物理内存 R/W, 完全绕过 PAC 用户态 hook
│  ├─ Patch 4 个检测函数 (IsWallTransparentHack 等) 返回 0
│  └─ Maintain 周期检测 PvpAlive 重载自动重新 patch + 进程存活检查
├─ ★ BUILD 567 v3.295: NtReadHooker — 仅 IAT hook PvpAlive (移除 inline hook ntdll)
│  └─ 过滤 client.dll .text 段读取, 返回原始字节 (PAC 扫描见 32 c0)
├─ ★ BUILD 564: PsLoadedModuleList DKOM — PDFWKRNL.sys 从内核模块链表摘除
├─ ★ BUILD 567 v3.296: 安全退出机制 — CS2 退出 → DisableAll → ExitProcess(0)
│  ├─ PDFWKRNL.sys 用 kernel VA memcpy, 无 MmMapIoSpace → 退出不蓝屏
│  ├─ DKOM SelfLoopHarden → RemoveEntryList 是 no-op → 不 0x139
│  └─ PAC 回调保持摘除 (CS2 已退出, 无游戏可检测)
├─ 截图防护: 检测 8 种截图工具, 临时回退补丁 (仅在中和成功时恢复)
├─ EkkoSleep 内存加密: Sleep 期间 XOR 加密 payload 内存
└─ 主循环: 每 30-45s MaintainCs2Patch → GuardPac → ReapplyAllCallbacks → VmxOnWrapper 维护
```

## BUILD 567 / v3.296 关键改进

### 安全退出机制 (v3.296)
- **CS2 退出 → 自动 ExitProcess(0)**: 替代 v3.291 的无限 Sleep (进程残留需重启清理)
- **安全性分析**:
  - PDFWKRNL.sys 用 kernel VA memcpy (非 MmMapIoSpace), 释放页表不蓝屏
  - DKOM SelfLoopHarden 使 EPROCESS.Flink/Blink 指向自己, RemoveEntryList 是 no-op
  - PAC 回调保持摘除 (CS2 已退出, 无游戏可检测, 重启或新 loader 实例会重新摘除)
  - 单线程, 无 EkkoSleep race (主循环 StealthSleep 返回后才检测 CS2 退出)

### PvpAlivePatcher (v3.289 + v3.296 加固)
- **内核跨进程 patch**: BYOVD driver 物理内存 R/W, 绕过 PAC 用户态 hook
- **Patch 4 个 PacNova::Is*Hack 函数**: 返回 0, 阻止检测上报
- **进程存活检查 (v3.296 FIX-10/11)**:
  - `Uninstall`: OpenProcess + Toolhelp32 fallback 验证完美平台进程存活
  - `Maintain`: 同样验证, 已退出则标记 inactive (避免用已释放 CR3 翻译页表)

### NtReadHooker (v3.295)
- **仅 IAT hook PvpAlive**: 移除 inline hook ntdll (被 CS2 自检检测)
- **失败不回退**: IAT hook 失败直接返回 false, 不 hook ntdll

### 早期退出路径恢复 PAC 回调 (v3.296 FIX-9)
- `return 2` (CS2 未运行) + `return 3` (cs2::Memory 初始化失败): 添加 `RestoreAllCallbacks`
- 避免 loader.exe 退出后 PAC 检测到回调缺失 → 封号

### 内存泄漏修复 (v3.296 FIX-12)
- `ScanDataSectionForFltGlobals`: chunk VirtualAlloc 失败时释放 sections

### VmxOnWrapper patch 独立降级模式 (566-5, 沿用)
- 连续失败 ≥3 次进入降级 (跳过周期性 VmxOnWrapper 检查, 节省 IOCTL)
- 5 分钟自恢复 (与 SHV_Install 降级一致)

## 7+ 层保护体系

| # | 功能 | 说明 |
|---|------|------|
| 1 | **BYOVD 内核防御** | 加载 PDFWKRNL.sys (AMD 合法签名), 摘除 PAC ObRegisterCallbacks / ProcessNotify / ImageNotify / ThreadNotify 回调 |
| 2 | **Minifilter Neutralizer** | 内核 R/W 遍历 fltmgr 链表, 将 MessageTransfer 全部操作回调替换为 5 种多样化 XOR EAX,EAX; RET stub |
| 3 | **KernelTraceCleaner** | 清理 MmUnloadedDrivers / PiDDBCacheTable / ci.dll KernelHashBucketList 中的 PDFWKRNL 痕迹 |
| 4 | **DKOM 进程隐藏** | 摘除 loader2.exe 进程链表项 (ActiveProcessLinks), 动态偏移扫描 Win11 24H2 |
| 5 | **EkkoSleep 内存加密** | Sleep 期间 XOR 加密全部 payload 内存 (含 cross-process 同步) |
| 6 | **ObCallbacks 重应用** | 30-45s 周期重应用 PAC 回调摘除 (防止 PAC 驱动重新注册) |
| 7 | **VEH 自愈** | 捕获 ntdll!RtlDeactivateActivationContext 崩溃 (最多 3 次), g_vehRestoring 原子标志防递归 |
| 8 | **★ BUILD 564 DKOM 驱动隐藏** | PsLoadedModuleList DKOM 摘除 PDFWKRNL.sys (内核模块链表) |
| 9 | **★ BUILD 565 NtRead Hook** | Hook NtReadVirtualMemory 双重保险 (IAT + inline), .text 段扫描过滤 |
| 10 | **★ BUILD 566 VmxOnWrapper patch** | patch VmxOnWrapper 为 xor eax,eax; ret → VMX 永不启动, EPT 永不构造 |
| 11 | **★ BUILD 566 SHV_Install patch** | patch SHV_Install 为 mov eax,-5; ret → SHV 失败兜底 (双重保险) |
| 12 | **★ BUILD 566 加固 周期性维护** | 60-90s 验证 VmxOn + SHV patch, 自动重 patch (独立降级模式) |

## CS2 内存补丁机制

**原理**: CS2 的 client.dll 使用 `xor al, ah` (机器码 `32 c0`) 加密内存段, PAC 扫描时内存处于加密状态。补丁将 `32 c0` NOP 为 `90 90`, 使内存保持解密状态, CS2 自身的 ESP 渲染逻辑即可正常工作。

**影子页 PTE 方案**:
- 分配两个物理页: pageA (原始字节 `32 c0`) + pageB (补丁字节 `90 90`)
- PTE 指向 pageB 时 CS2 执行补丁代码 (内存解密)
- 500ms 周期中 50ms 切换到 pageA, 让 PAC 扫描命中原始字节
- 截图工具检测时临时完全回退到 pageA

**NtRead Hook 双重保险 (BUILD 565)**:
- 即使影子页失效, NtReadVirtualMemory hook 仍会过滤 .text 段读取
- PAC 扫描 client.dll .text 段时, hook 在 Buffer 中恢复原始字节 (32 c0)
- 双重保险: 影子页 (硬件级) + NtRead hook (软件级)

## SHV (Secure Hypervisor View) 对抗 (BUILD 566)

**PAC SHV 架构** (基于逆向分析报告):
- PAC 通过 MessageTransfer.sys 实现完整 VMX/EPT hypervisor
- 每个 CPU 上启动 VMX, 使用 EPT 监控内存访问
- EPT+OCR 联动: 截图游戏画面 → OCR 识别外挂文字 → 上报服务器

**BUILD 567 双重 patch 对抗**:
1. **VmxOnWrapper patch** (优先, 隐蔽性最高):
   - patch VmxOnWrapper (RVA 0xEAEC4) 为 `31 C0 C3` (xor eax,eax; ret)
   - vmxon 指令永不执行 → VMX 永不启动 → EPT 永不构造
   - SHV_Install 仍返回 STATUS_SUCCESS (failed_cpus=0), PAC 自检通过
   - OCR 无画面源 (EPT 不启动)
2. **SHV_Install patch** (兜底):
   - patch SHV_Install 入口为 `B8 FB FF FF FF C3` (mov eax,-5; ret)
   - -5 是 CheckPhysicalMemoryLimit 的自然错误码 (物理内存超 2GB EPT 限制)
   - PAC 误认为是自然失败, 不会怀疑 patch

**BUILD 566 加固 v3.226 持久对抗**:
- 60-90s 周期性验证 VmxOnWrapper + SHV_Install patch 仍然有效
- PAC 恢复 patch 字节后自动重 patch
- 独立降级模式: 连续失败 ≥3 次跳过周期性检查 (节省 IOCTL), 5 分钟自恢复

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
第6步 → 关闭 CS2 时 loader.exe 自动安全退出 (DisableAll → ExitProcess(0))
```

**v3.296 安全退出**: 关闭 CS2 后 loader.exe 自动退出, 无需重启清理。重新运行 loader.exe 即可再次注入。

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
   - ★ `BYOVD:VmxOn: SUCCESS — VmxOnWrapper patched @ 0x...` → VmxOnWrapper patch 成功
   - ★ `BYOVD:ShvPatch: VmxOnWrapper patch SUCCESS` → PatchShvInstallEntry 入口确认
   - ★ `BYOVD:ShvPatch: SUCCESS — SHV_Install patched @ 0x...` → SHV_Install patch 成功
2. 进入游戏后 CS2 自身 ESP 正常显示（内存补丁生效）
3. 截图工具检测: 使用截图工具时 ESP 临时消失（影子页回退）
4. 长时间运行 (1小时+): sd.log 无频繁 `BYOVD:VmxOn:` 重 patch 日志 (PAC 未频繁恢复)

### BUILD 566 加固 v3.226 验证日志

**首次启动 (PAC 已加载)**:
```
BYOVD:VmxOn: VmxOnWrapper @ 0x...
BYOVD:VmxOn: SUCCESS — VmxOnWrapper patched @ 0x... (xor eax,eax; ret — VMX 永不启动)
BYOVD:ShvPatch: VmxOnWrapper patch SUCCESS (continuing to SHV_Install patch)
BYOVD:ShvPatch: SHV_Install entry @ 0x...
BYOVD:ShvPatch: SUCCESS — SHV_Install patched @ 0x... (mov eax,-5; ret)
```

**主循环周期性验证 (PAC 未恢复)**:
```
(无 VmxOn 日志 — IsVmxOnPatched 返回 true, 不触发重 patch)
```

**PAC 恢复 VmxOnWrapper 字节后 (自动重 patch)**:
```
BYOVD:VmxOn: VmxOnWrapper @ 0x...
BYOVD:VmxOn: SUCCESS — VmxOnWrapper patched @ 0x... (重 patch)
```

**VmxOnWrapper 连续失败 3 次 (进入降级模式)**:
```
BYOVD:VmxOn: DEGRADED MODE entered (failures=3)
```

**5 分钟自恢复**:
```
BYOVD:VmxOn: DEGRADED MODE auto-recover after 300123ms
```

### 注意事项

- **loader.exe 运行后自动删除自身**, 请保留备份
- **关闭 CS2 即自动清理**, loader.exe 自动 ExitProcess(0) 退出, 无需重启 (v3.296)
- **绝不用任务管理器强制结束 loader2.exe** — 触发 0x139 蓝屏, 应关闭 CS2 触发安全退出
- **蓝屏后必须重启** 清除不稳定状态
- **MessageTransfer.sys 不可删除/卸载** — 只停止服务, 避免 CS2 反作弊检测
- **PDFWKRNL.sys IOCTL 必须异步** — 2s 超时 + 10s 冷却, 防止永久阻塞
- PAC 更新后 `MessageTransfer` 可能改名, 代码已支持 6 种模糊匹配 + 内核扫描
- ★ **VmxOnWrapper RVA 0xEAEC4 是 PAC v1.0.0.2 的值**, PAC 更新后可能改变 (FindVmxOnWrapperEntry 字节验证失败时回退到 SHV_Install patch)

## 编译

```bash
# Windows + MinGW-w64 (g++) - 需要 MSYS2
build.bat
```

**BUILD 566 编译要求**:
- clang++ (C:\msys64\mingw64\bin\clang++)
- C++20 标准 (-std:c++20)
- -O2 优化 + -s � stripped + -fpermissive + -DNDEBUG + -fvisibility=hidden

输出文件:
- `encrypt_tool.exe` — XTEA 加密工具 (管理端)
- `payload.dll` — 注入负载 (~440KB, 仅依赖 Windows 系统 DLL)
- `payload.dat` — XTEA 加密后的 payload (上传到 HTTP 服务器)
- `loader.exe` — 自删型下载/解密/注入器 (~237KB)

**payload.dll 依赖** (BUILD 566 -static 后):
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
│   ├── byovd_kernel.cpp/h      # BYOVD 内核防御 + PAC Neutralizer + TraceCleaner + DKOM + ShvInstallPatcher + NtReadHooker
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
| 550 | v3.208 | -static 静态链接, 动态 API 解析, RTCore64 嵌入移除 |
| 551 | v3.209 | PsSetCreateThreadNotifyRoutine 摘除 (PAC IAT 确认注册) |
| 552 | v3.210 | ShvInstallPatcher — patch SHV_Install 入口 (方案 D) |
| 553 | v3.211 | SIG1 特征码 XOR 加密 + PDFWKRNL.sys IOCTL 异步 (2s 超时 + 10s 冷却) |
| 554 | v3.212 | VADConcealer 周期性重新隐藏 (60-90s) |
| 555 | v3.213 | SHV patch 降级模式 (3 次失败阈值 + 5 分钟自恢复) |
| 556 | v3.214 | 主循环间隔随机化 (30-45s) |
| 559 | v3.218 | SHV patch 字节改为 mov eax,-5 (CheckPhysicalMemoryLimit 自然错误码) |
| 561 | v3.221 | IsValidPrologueByte 统一辅助函数 (放宽 0x53/0x56/0x57) |
| 562 | v3.222 | SIG2 兜底 (BroadcastToAllCpus + WaitForCompletion 配对) |
| 563 | v3.222 | .data 段修复: GetPacPatterns + g_cachedPacName 改为栈变量 |
| 564 | v3.223 | PsLoadedModuleList DKOM 隐藏 PDFWKRNL.sys |
| 565 | v3.224 | Hook NtReadVirtualMemory 双重保险 (IAT + inline) |
| 566 | v3.225 | VmxOnWrapper patch + NtReadHooker shellcode 参数化 |
| 566 加固 | v3.226 | VmxOnWrapper patch 独立降级模式 + 周期性维护 |
| 567 | v3.235-3.289 | VAD-DKOM 顺序修复 + EPROCESS 缓存 + PvpAlivePatcher 内核跨进程 patch |
| 567 | v3.295 | NtReadHooker 仅 IAT hook (移除 inline hook ntdll, 被 CS2 自检检测) |
| **567** | **v3.296** | **安全退出 (ExitProcess) + PvpAlive 进程存活检查 + 早期退出恢复 PAC 回调 + 内存泄漏修复** |

## 检测概率评估

| BUILD | 检测概率 | 主要攻击面 |
|-------|---------|-----------|
| 544 | 30-50% | basic.exe 独立进程 (4 个未保护攻击面) |
| 546 | 5-10% | basic.exe 7 层保护, 但仍有独立进程 |
| 548 | ~80% | CS2 补丁明文可见 (无影子页) |
| 549 | <10% | 影子页 PTE + DiagLog 加密 |
| 550 | <10% | + IAT 清理 + -static 链接 + RTCore64 移除 |
| 552 | 7-14% | + SHV EPT 监控 (2-3%) + OCR (3-8%) 未对抗 |
| 565 | 5-12% | + NtRead Hook (.text 完整性 1-2% → 0.5-1%) |
| 566 | 2-5% | + VmxOnWrapper patch (EPT 0.5-1% + OCR 1-2%) |
| 566 加固 | 1.5-4% | + VmxOnWrapper patch 持久有效 (PAC 恢复后自动重 patch) |
| 567 v3.289 | 1-3% | + PvpAlivePatcher 内核跨进程 patch PacNova::Is*Hack (绕过用户态 hook) |
| 567 v3.295 | 0.8-2.5% | + NtReadHooker 仅 IAT hook (移除 inline hook, CS2 自检不发现) |
| **567 v3.296** | **0.8-2.5%** | **+ 安全退出 (无残留) + 进程存活检查 + 早期退出恢复回调 (防封号)** |

## 安全约束

- **EkkoSleep 必须豁免 memory_cloak.cpp 代码页** — 防止自加密崩溃
- **EPT Dumper .data 段扫描不超过 64KB** — maxValidate ≤8, 避免 PatchGuard 0x109 BSOD
- **Win11 24H2 EPROCESS 偏移动态扫描** — UniqueProcessId @0x1D0, ActiveProcessLinks @0x1D8
- **DKOM 使用动态偏移** — 写邻居节点 Flink/Blink (prev.Flink=&current, next.Blink=&current)
- **用户态代码避免 CRT 依赖** — 不使用 std::vector/wstring (手动映射 DLL 堆未初始化)
- **截图工具检测频率 5s** — NtQuerySystemInformation 替代 CreateToolhelp32Snapshot
- **PDFWKRNL.sys IOCTL 频率 < 1400/min** — 卡死基线, ShvInstallPatcher 降级模式保护
- **VmxOnWrapper patch 仅 3 字节写入** — 31 C0 C3 (xor eax,eax; ret), 无新内存访问模式
- **VmxOn + SHV 降级状态完全独立** — 避免互相污染, 各自 3 次失败阈值 + 5 分钟自恢复
- **★ v3.296 安全退出**: CS2 退出 → DisableAll (UnhideAll + kma.Shutdown) → ExitProcess(0)
  - PDFWKRNL.sys 用 kernel VA memcpy (非 MmMapIoSpace), 释放页表不蓝屏
  - DKOM SelfLoopHarden → RemoveEntryList 是 no-op → 不 0x139
  - PAC 回调保持摘除 (CS2 已退出, 无游戏可检测)
- **★ v3.296 PvpAlive 进程存活检查**: Uninstall/Maintain 前用 OpenProcess + Toolhelp32 验证
  - 避免用已释放 CR3 翻译页表 → 数据损坏
- **★ v3.296 早期退出恢复 PAC 回调**: return 2/3 路径调用 RestoreAllCallbacks
  - 避免 loader.exe 退出后 PAC 检测到回调缺失 → 封号

## 详细使用说明

详见 [USAGE.md](file:///d:/技术研发/tmp/USAGE.md) — 完整使用说明 + 故障排查 + 日志解读
