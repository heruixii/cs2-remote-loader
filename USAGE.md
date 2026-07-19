# CS2 Remote Loader — 完整使用说明

**当前版本：BUILD 566 加固 / v3.226**
**适用对象：CS2 + 完美世界竞技平台 PAC 反作弊环境**

---

## 1. 环境要求

### 1.1 硬件
- Windows 10 22H2 / Windows 11 23H2 / Windows 11 24H2 (Build 26100)
- x64 架构
- 至少 8GB RAM (推荐 16GB+)
- CPU 支持 VMX (Intel VT-x) — PAC SHV 需要, 但 BUILD 566 已对抗

### 1.2 软件
- 完美世界竞技平台 (最新版, 自动安装 PAC MessageTransfer.sys)
- CS2 (通过完美平台启动)
- .NET Framework 4.x (完美平台依赖)

### 1.3 系统设置
- **管理员权限** — loader.exe 必须以管理员身份运行 (BYOVD 内核驱动需要)
- **关闭 HVCI/内核隔离** — Windows 安全中心 → 设备安全性 → 内核隔离 → 关闭
- **关闭 PatchGuard** — 通过 `bcdedit /debug on` 启用内核调试模式 (自动禁用 PG)
- **关闭 Secure Boot** — 部分 BYOVD 驱动需要

### 1.4 验证系统设置
```powershell
# 以管理员身份运行 PowerShell, 验证:
bcdedit /enum | Select-String "debug"  # 应显示 "debug Yes"

# 检查 HVCI 状态:
mountvol X: /l  # 不报错即未启用 (HVCI 启用时会显示)
```

---

## 2. 部署

### 2.1 获取文件
从 GitHub 仓库下载或编译:
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
- payload.dat 大小 ~440KB, 带宽要求低

---

## 3. 使用步骤

### 3.1 正确启动顺序

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
type $env:TEMP\sd.log | Select-String "B566|VmxOn|ShvPatch|BYOVD"
```

#### 预期输出 (BUILD 566 加固 v3.226)
```
BYOVD: SUCCESS with PDFWKRNL.sys
callbacks removed (PAC/MessageTransfer)
BYOVD:VmxOn: VmxOnWrapper @ 0xFFFF...
BYOVD:VmxOn: SUCCESS — VmxOnWrapper patched @ 0xFFFF... (xor eax,eax; ret — VMX 永不启动)
BYOVD:ShvPatch: VmxOnWrapper patch SUCCESS (continuing to SHV_Install patch)
BYOVD:ShvPatch: SHV_Install entry @ 0xFFFF...
BYOVD:ShvPatch: SUCCESS — SHV_Install patched @ 0xFFFF... (mov eax,-5; ret)
B549:SP:11 OK
B549:I:01
B549:ML:01
```

#### 进入游戏验证
- CS2 自身 ESP 正常显示 (内存补丁生效)
- 截图工具检测: 使用截图工具时 ESP 临时消失 (影子页回退)

### 3.3 长时间运行验证

运行 1 小时+ 后, 检查 sd.log 是否有异常:
```powershell
# 检查 VmxOnWrapper 是否被 PAC 频繁恢复 (重 patch 日志)
type $env:TEMP\sd.log | Select-String "BYOVD:VmxOn: SUCCESS" | Measure-Object -Line

# 检查降级模式是否触发 (异常)
type $env:TEMP\sd.log | Select-String "DEGRADED MODE"

# 检查 BSOD 前兆 (VEH 自愈)
type $env:TEMP\sd.log | Select-String "VEH"
```

**预期结果**:
- VmxOnWrapper 重 patch 次数 < 5 次/小时 (PAC 偶尔恢复, 自动重 patch)
- 无 DEGRADED MODE 日志 (或仅有 5 分钟自恢复日志)
- 无 VEH 自愈日志 (无崩溃)

---

## 4. 错误时机及风险

| 错误的启动时机 | 后果 | 风险 |
|---------------|------|------|
| 完美平台没开 | PAC 未安装 → 无需防检测 (但直接跑 loader 无意义) | 低 |
| CS2 还没开 | 找不到 cs2.exe, loader 静默退出 (return 2) | 低 |
| CS2 在大厅 | 注入成功但无 EntityList 数据, ESP 空白 | 中 |
| 没开管理员 | BYOVD 驱动加载失败 → PAC 回调未摘除 → 检测概率极高 | **极高** |
| HVCI 未关闭 | BYOVD 驱动被阻止加载 | **高** |
| 蓝屏后未重启 | 系统状态不稳定, 必须重启清除残留 | **极高** |
| loader 重复运行 | 第二个 loader 静默退出 (互斥锁保护) | 低 |

---

## 5. 故障排查

### 5.1 loader.exe 启动后无反应

**可能原因**:
1. 未以管理员身份运行
2. CS2 未启动
3. HVCI 未关闭
4. HTTP 服务器无法访问

**排查步骤**:
```powershell
# 检查 sd.log
type $env:TEMP\sd.log -Tail 20

# 检查网络连接
Test-NetConnection -ComputerName your-server.com -Port 80

# 检查 CS2 进程
Get-Process cs2 -ErrorAction SilentlyContinue
```

### 5.2 注入成功但 ESP 不显示

**可能原因**:
1. CS2 在大厅 (无 EntityList 数据)
2. 影子页 PTE 切换失败
3. CS2 补丁未生效

**排查步骤**:
```powershell
# 检查影子页状态
type $env:TEMP\sd.log | Select-String "B549:SP"

# 检查 ApplyCs2Patch
type $env:TEMP\sd.log | Select-String "B549:I:"
```

**预期输出**: `B549:SP:11 OK` + `B549:I:01`

### 5.3 蓝屏 (BSOD)

**可能原因**:
1. DKOM 断链错误 (0x139)
2. PatchGuard 触发 (0x109)
3. PDFWKRNL.sys IOCTL 卡死

**应对**:
1. **重启电脑** — 清除不稳定状态
2. 检查 `bcdedit /debug on` 是否生效 (PG 应被禁用)
3. 检查 HVCI 是否关闭
4. 查看蓝屏 dump 文件 (`C:\Windows\Minidump\`)

**绝对禁止**:
- ❌ 蓝屏后不重启直接再次运行 loader
- ❌ 用任务管理器强制结束 loader2.exe (触发 0x139 蓝屏)

### 5.4 VmxOnWrapper patch 失败

**可能原因**:
1. PAC 更新导致 RVA 0xEAEC4 失效
2. PAC 驱动未加载
3. vmxon 指令字节验证失败

**排查步骤**:
```powershell
# 检查 VmxOnWrapper patch 日志
type $env:TEMP\sd.log | Select-String "BYOVD:VmxOn:"
```

**预期日志 (失败情况)**:
```
BYOVD:VmxOn: PAC driver not loaded
# 或
BYOVD:VmxOn: VmxOnWrapper not found (RVA mismatch or vmxon instr missing)
```

**应对**: VmxOnWrapper patch 失败时, 自动回退到 SHV_Install patch (双重保险), 仍有一定防护. 连续失败 3 次进入降级模式, 5 分钟自恢复.

### 5.5 检测概率异常升高

**可能原因**:
1. PAC 更新 (MessageTransfer.sys 改名/特征变化)
2. VmxOnWrapper RVA 失效
3. NtRead Hook 被 PAC 检测并绕过
4. 内核回调被 PAC 重新注册

**排查步骤**:
```powershell
# 检查 PAC 驱动名
type $env:TEMP\sd.log | Select-String "PAC driver"

# 检查回调重应用
type $env:TEMP\sd.log | Select-String "callbacks" | Select-Object -Last 10

# 检查 VmxOnWrapper 维护
type $env:TEMP\sd.log | Select-String "VmxOn" | Select-Object -Last 10
```

---

## 6. 日志解读

### 6.1 sd.log 位置
```
%TEMP%\sd.log
# 通常: C:\Users\<用户名>\AppData\Local\Temp\sd.log
```

### 6.2 关键日志标签

| 标签 | 含义 |
|------|------|
| `B549:SP:11 OK` | 影子页 PTE 切换成功 |
| `B549:I:01` | ApplyCs2Patch 成功 |
| `B549:ML:01` | 主循环运行中 |
| `BYOVD: SUCCESS with PDFWKRNL.sys` | BYOVD 驱动加载成功 |
| `callbacks removed (PAC/MessageTransfer)` | PAC 回调摘除成功 |
| `BYOVD:VmxOn: SUCCESS` | VmxOnWrapper patch 成功 |
| `BYOVD:ShvPatch: SUCCESS` | SHV_Install patch 成功 |
| `BYOVD:VmxOn: DEGRADED MODE entered` | VmxOn 降级模式 (3 次失败) |
| `BYOVD:VmxOn: DEGRADED MODE auto-recover` | VmxOn 降级模式自恢复 |
| `BYOVD:ShvPatch: DEGRADED MODE` | SHV 降级模式 |
| `VEH` | VEH 自愈触发 (崩溃捕获) |

### 6.3 正常运行日志示例

```
[启动]
BYOVD: SUCCESS with PDFWKRNL.sys
callbacks removed (PAC/MessageTransfer) ob=2 proc=1 img=1 thread=1
B549:SP:11 OK
B549:I:01
BYOVD:VmxOn: VmxOnWrapper @ 0xFFFFF805...
BYOVD:VmxOn: SUCCESS — VmxOnWrapper patched @ 0xFFFFF805... (xor eax,eax; ret — VMX 永不启动)
BYOVD:ShvPatch: VmxOnWrapper patch SUCCESS (continuing to SHV_Install patch)
BYOVD:ShvPatch: SHV_Install entry @ 0xFFFFF805...
BYOVD:ShvPatch: SUCCESS — SHV_Install patched @ 0xFFFFF805... (mov eax,-5; ret)
B549:ML:01

[主循环 (60-90s 周期)]
(无 VmxOn 日志 — IsVmxOnPatched 返回 true, 不触发重 patch)

[PAC 恢复后 (自动重 patch)]
BYOVD:VmxOn: VmxOnWrapper @ 0xFFFFF805...
BYOVD:VmxOn: SUCCESS — VmxOnWrapper patched @ 0xFFFFF805... (重 patch)
```

---

## 7. 安全退出

### 7.1 正常退出
- 关闭 CS2 → payload 自动检测 CS2 退出 → DisableAll → return 0
- DKOM 自动恢复进程链表
- VEH 自愈计数器重置

### 7.2 异常退出
- 任务管理器结束 CS2 → 同正常退出
- 任务管理器结束 loader2.exe → **❌ 触发 0x139 蓝屏** (绝对禁止)
- 蓝屏 → 重启电脑清除残留

### 7.3 退出后清理
- loader.exe 已自删除 (运行后立即删除)
- payload.dll 随 CS2 进程退出而释放
- PDFWKRNL.sys 服务自动卸载 (一用即卸)
- 内核回调自动恢复 (RestoreAll)
- DKOM 自动恢复 (UnhideAll)

---

## 8. 常见问题

### Q1: 为什么必须先启动 CS2 再运行 loader?
A: loader 通过进程名查找 cs2.exe, CS2 未启动时找不到目标进程, 静默退出.

### Q2: 为什么必须以管理员身份运行?
A: BYOVD 内核驱动加载需要 SeLoadDriverPrivilege 权限, 仅管理员拥有.

### Q3: payload.dat 是什么?
A: XTEA 加密后的 payload.dll, loader 下载后内存解密, 全程不落盘.

### Q4: VmxOnWrapper patch 是什么?
A: PAC 通过 VmxOnWrapper 函数启动 VMX (硬件虚拟化), EPT 监控内存. patch 该函数为 `xor eax,eax; ret` 让 vmxon 永不执行, EPT 永不构造, OCR 无画面源.

### Q5: VmxOnWrapper + SHV_Install 双重 patch 有什么区别?
A: VmxOnWrapper patch (优先, 隐蔽性最高) 让 VMX 永不启动, SHV_Install 仍返回成功. SHV_Install patch (兜底) 让 SHV_Install 直接返回 -5 (自然错误码). 两者独立维护, 互不干扰.

### Q6: 降级模式是什么?
A: 连续 patch 失败 ≥3 次进入降级模式, 跳过周期性检查 (节省 IOCTL, 避免驱动卡死). 5 分钟后自动恢复重新尝试. VmxOn 与 SHV 降级状态完全独立.

### Q7: 如何判断 BUILD 566 加固生效?
A: 检查 sd.log 是否有 `BYOVD:VmxOn: SUCCESS` 日志, 且长时间运行 (1小时+) 无频繁重 patch 日志.

### Q8: PAC 更新后 VmxOnWrapper RVA 失效怎么办?
A: FindVmxOnWrapperEntry 会验证 vmxon 指令字节 (0F 01 C1), 失败时自动回退到 SHV_Install patch. 降级模式 5 分钟自恢复后会重新尝试.

---

## 9. 技术支持

### 9.1 提交问题
提交 issue 时请附上:
1. sd.log 完整日志 (`%TEMP%\sd.log`)
2. 系统版本 (winver)
3. CS2 版本
4. 完美平台版本
5. 蓝屏 dump 文件 (如有, `C:\Windows\Minidump\`)

### 9.2 编译问题
- 确保 clang++ 在 PATH 中 (C:\msys64\mingw64\bin\clang++)
- 确保 C++20 支持
- 运行 `build.bat` 编译

### 9.3 更新日志
- **BUILD 566 加固 v3.226** (当前): VmxOnWrapper patch 独立降级模式 + 周期性维护
- **BUILD 566 v3.225**: VmxOnWrapper patch + NtReadHooker shellcode 参数化
- **BUILD 565 v3.224**: Hook NtReadVirtualMemory 双重保险
- **BUILD 564 v3.223**: PsLoadedModuleList DKOM 隐藏 PDFWKRNL.sys
- 完整历史见 [README.md](file:///d:/技术研发/tmp/README.md) BUILD 历史章节
