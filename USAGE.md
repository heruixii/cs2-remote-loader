# CS2 Remote Loader — 完整使用说明

**当前版本：BUILD 567 v3.296（19 项关键修复）**
**适用对象：CS2 + 完美世界竞技平台 PAC 反作弊环境**

---

## 1. 环境要求

### 1.1 硬件
- Windows 10 22H2 / Windows 11 23H2 / Windows 11 24H2 / 25H2 (Build 26100+)
- x64 架构
- 至少 8GB RAM (推荐 16GB+)
- CPU 支持 VMX (Intel VT-x) — PAC SHV 需要, 但 BUILD 567 已对抗

### 1.2 软件
- 完美世界竞技平台 (最新版, 自动安装 PAC MessageTransfer.sys)
- CS2 (通过完美平台启动)
- .NET Framework 4.x (完美平台依赖)

### 1.3 系统设置（必须）
- **管理员权限** — loader.exe 必须以管理员身份运行 (BYOVD 内核驱动需要)
- **关闭 HVCI/内核隔离** — Windows 安全中心 → 设备安全性 → 内核隔离 → 关闭
- **关闭 PatchGuard** — 通过 `bcdedit /debug on` 启用内核调试模式 (自动禁用 PG)
- **关闭 Secure Boot** — 部分 BYOVD 驱动需要

### 1.4 验证系统设置
```powershell
# 以管理员身份运行 PowerShell, 验证:
bcdedit /enum | Select-String "debug"  # 应显示 "debug Yes"

# 检查 HVCI 状态 (应返回 0 或无输出):
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
```

---

## 2. 部署

### 2.1 获取文件
```
loader.exe   # 用户端, 分发给玩家 (可改名)
payload.dat  # XTEA 加密的 payload, 上传到 HTTP 服务器
```

### 2.2 配置 HTTP 服务器
1. 将 `payload.dat` 上传到 HTTP/HTTPS 服务器
2. 修改 `loader.cpp` 中的 `PAYLOAD_URL` 为你的服务器地址
3. 重新编译 `loader.exe` (运行 `build.bat`)

### 2.3 服务器要求
- HTTP/HTTPS 任一即可
- 服务器需支持 Range 请求 (推荐, 但非必需)
- payload.dat 大小 ~480KB, 带宽要求低

---

## 3. 使用步骤

### 3.1 正确启动顺序（重要）

```
第1步 → 启动完美世界竞技平台 (自动安装 PAC)
第2步 → 通过平台启动 CS2, 进入主菜单或任意地图
第3步 → 右键 loader.exe → 以管理员身份运行
第4步 → 等待 5-10 秒, payload.dll 注入完成
第5步 → 进入游戏, CS2 自身 ESP 渲染生效 (内存已解密)
第6步 → 关闭 CS2 时 payload 自动安全退出
```

**一句话：先启动 CS2 进入主菜单，再右键管理员运行 loader。**

### 3.2 启动后验证

#### 检查 sd.log 日志
```powershell
type $env:TEMP\sd.log | Select-String "BYOVD|B549|B553|FLT"
```

#### 预期输出 (v3.296)
```
BYOVD: SUCCESS with PDFWKRNL.sys
BYOVD:PreDisableOb
BYOVD:PostDisableOb ob=2
BYOVD:PostDisableProc proc=1
BYOVD:PostDisableImg img=1
BYOVD:PostDisableThread thread=1
FLT:NtrlOK   ← minifilter 中和成功
B549:I:01    ← CS2 patch 成功
B565:I:01 ok ← NtReadHooker 安装成功
B549:ML:01   ← 主循环运行
```

#### 进入游戏验证
- CS2 自身 ESP 正常显示 (内存补丁生效)
- 截图工具检测: 使用截图工具时 ESP 临时消失 (回退保护)

### 3.3 长时间运行验证

运行 1 小时+ 后, 检查 sd.log 是否有异常:
```powershell
# 检查 minifilter 中和状态
type $env:TEMP\sd.log | Select-String "FLT:NtrlOK|B553:PN"

# 检查降级模式 (异常)
type $env:TEMP\sd.log | Select-String "DEGRADED|FAIL"

# 检查 BSOD 前兆 (VEH 自愈)
type $env:TEMP\sd.log | Select-String "VEH"
```

**预期结果**:
- `FLT:NtrlOK` 出现在启动时, 之后偶尔出现 (GuardPac 30-45s 周期)
- 无 DEGRADED/FAIL 日志
- 无 VEH 自愈日志 (无崩溃)

---

## 4. 错误时机及风险

| 错误的启动时机 | 后果 | 风险 |
|---------------|------|------|
| 完美平台没开 | PAC 未安装 → 无需防检测 (但直接跑 loader 无意义) | 低 |
| CS2 还没开 | 找不到 cs2.exe, loader 静默退出 | 低 |
| CS2 在大厅 | 注入成功但无 EntityList 数据, ESP 空白 | 中 |
| 没开管理员 | BYOVD 驱动加载失败 → PAC 回调未摘除 → 检测概率极高 | **极高** |
| HVCI 未关闭 | BYOVD 驱动被阻止加载 | **高** |
| 蓝屏后未重启 | 系统状态不稳定, 必须重启清除残留 | **极高** |
| loader 重复运行 | 第二个 loader 静默退出 (互斥锁保护) | 低 |

---

## 5. v3.296 关键改进

### 5.1 封号防护（10 个场景全覆盖）
- **PAC 中和失败时跳过 patch** — 防止 minifilter 扫描发现 patch 封号
- **PAC 延迟加载保护** — 7 个检查点（初始化/主循环/截图/CS2 重开/ReapplyAllCallbacks）
- **g_pacNeutralized 状态机** — 确保只在 minifilter 中和成功时才 patch
- **截图恢复 patch 检查中和状态** — 防止截图期间中和失效后恢复 patch 封号

### 5.2 蓝屏防护
- **ReadKernelVA/WriteKernelVA 范围扩展** — 覆盖 Win11 24H2 非分页池扩展区域
- **FltGlobals/Ret0Stubs 缓存** — GuardPac IOCTL 频率从 1000+ 降到 ~50
- **Operations 数组遍历 MJ 范围验证** — 防止遍历超出数组到相邻池内存
- **FindFilterByStringScan 栈缓冲区溢出保护**

### 5.3 性能优化
- FltGlobals/Ret0Stubs 永久缓存（fltmgr.sys 加载后不变）
- GetKernelModuleBase 负缓存（15s TTL，避免重复枚举）
- 中和失败重试退避（3 次失败后降频到 30s）

### 5.4 兼容性
- Win11 24H2/25H2 RegisteredFilters.rList@+0x0a0 偏移支持
- FilterList 偏移 0x080-0x180 范围覆盖
- Operations 固定偏移 +0x1a8 + MJ 验证

---

## 6. 故障排查

### 6.1 loader.exe 启动后无反应

**可能原因**:
1. 未以管理员身份运行
2. CS2 未启动
3. HVCI 未关闭
4. HTTP 服务器无法访问

**排查步骤**:
```powershell
# 检查 sd.log
type $env:TEMP\sd.log -Tail 20

# 检查 CS2 进程
Get-Process cs2 -ErrorAction SilentlyContinue
```

### 6.2 注入成功但 ESP 不显示

**可能原因**:
1. CS2 在大厅 (无 EntityList 数据)
2. PAC 中和失败 → 跳过 patch (防封号保护)
3. CS2 补丁未生效

**排查步骤**:
```powershell
# 检查 PAC 中和状态
type $env:TEMP\sd.log | Select-String "FLT:NtrlOK|B553:PN|B549:I:"

# 如果看到 "B549:I:03 skip (pac neutralize failed)" — 中和失败, 等待 GuardPac 重试
# 如果看到 "B549:I:04 skip (pac not installed)" — PAC 未加载, 主循环会自动处理
```

### 6.3 蓝屏 (BSOD)

**可能原因**:
1. DKOM 断链错误 (0x139) — v3.296 已修复 SelfLoopHarden
2. PatchGuard 触发 (0x109) — 确认 `bcdedit /debug on`
3. PDFWKRNL.sys IOCTL 卡死 — v3.296 已优化缓存

**应对**:
1. **重启电脑** — 清除不稳定状态
2. 检查 `bcdedit /debug on` 是否生效
3. 检查 HVCI 是否关闭
4. 查看蓝屏 dump 文件 (`C:\Windows\Minidump\`)

**绝对禁止**:
- 蓝屏后不重启直接再次运行 loader
- 用任务管理器强制结束 loader2.exe (触发 0x139 蓝屏)

### 6.4 PAC 中和失败（ESP 不显示但不封号）

**症状**: sd.log 显示 `FLT:NtrlFail` 或 `B549:I:03 skip`

**说明**: 这是 v3.296 的防封号保护 — 中和失败时跳过 patch。
**自愈**: GuardPac 每 30-45s 自动重试中和，成功后主循环 5s 内自动补 patch。

**排查**:
```powershell
# 检查中和失败原因
type $env:TEMP\sd.log | Select-String "FLT:NTRL:|FLT:STRSCAN:|FLT:VERIFY:"
```

---

## 7. 日志解读

### 7.1 sd.log 位置
```
%TEMP%\sd.log
# 通常: C:\Users\<用户名>\AppData\Local\Temp\sd.log
```

### 7.2 关键日志标签（v3.296）

| 标签 | 含义 |
|------|------|
| `BYOVD: SUCCESS with PDFWKRNL.sys` | BYOVD 驱动加载成功 |
| `BYOVD:PostDisableOb ob=2` | PAC Ob 回调摘除成功 |
| `FLT:NtrlOK` | minifilter 中和成功 |
| `B549:I:01` | ApplyCs2Patch 成功 |
| `B549:I:03 skip (pac neutralize failed)` | 中和失败, 跳过 patch (防封号) |
| `B549:I:04 skip (pac not installed)` | PAC 未加载, 主循环处理 |
| `B553:PN:ok` | GuardPac 中和状态更新成功 |
| `B553:PN:fail` | GuardPac 检测到中和失效 |
| `B565:I:01 ok` | NtReadHooker IAT hook 安装成功 |
| `B549:ML:01` | 主循环运行中 |
| `B291:REOPEN:pac=1` | CS2 重开, PAC 中和状态正常 |

### 7.3 正常运行日志示例

```
[启动]
BYOVD: SUCCESS with PDFWKRNL.sys
BYOVD:PreDisableOb
BYOVD:PostDisableOb ob=2
BYOVD:PostDisableProc proc=1
BYOVD:PostDisableImg img=1
BYOVD:PostDisableThread thread=1
FLT:NtrlOK
B549:I:01
B565:I:01 ok
B549:ML:01

[运行中 — 每 30-45s]
CB REAPPLIED tick=...
B553:PN:ok

[CS2 关闭]
B291:EXIT:safe-exit
```

---

## 8. 安全退出

### 8.1 正常退出
- 关闭 CS2 → payload 自动检测 → 安全退出
- 恢复 IAT hook + PvpAlive patch + DKOM 链表

### 8.2 异常退出
- 蓝屏 → 重启电脑
- 任务管理器结束 loader → 可能触发 0x139 蓝屏（禁用）

---

## 9. 文件清单

### 9.1 用户端（分发）
```
loader.exe   # 236KB, 可改名
```

### 9.2 服务器端
```
payload.dat  # 488KB, XTEA 加密
```

### 9.3 开发端（不分发）
```
payload.cpp              # payload 源代码
stealth_lib/             # 隐身库源代码
loader.cpp               # loader 源代码
encrypt.cpp              # 加密工具源代码
build.bat                # 编译脚本
encrypt_tool.exe         # 加密工具
PDFWKRNL.sys             # BYOVD 内核驱动
```
