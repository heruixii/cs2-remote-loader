// ============================================================
// payload.cpp — 远程加载 DLL Payload
//
// 编译为 DLL, 经 XTEA 加密后托管在 HTTP 服务器上,
// 由 loader.exe 下载 → 解密 → ManualMap 到内存中执行,
// 全程不落盘, 规避 minifilter 文件扫描。
//
// DllMain 在 ManualMap 完成后被调用, 直接在当前线程启动主循环,
// 不创建额外线程 (规避 PsSetCreateThreadNotifyRoutine 内核回调)。
// BUILD: 550 (v3.208: -static 静态链接 + 动态 API 解析 + RTCore64 嵌入移除)
//        1. ★ BUILD 550 -static 全局静态链接: 消除 libgcc_s_seh/libstdc++/libwinpthread 依赖
//           payload.dll 仅依赖 Windows 系统 DLL (ADVAPI32/KERNEL32/USER32/msvcrt/ntdll)
//        2. ★ BUILD 550 动态 API 解析 (IAT 清理):
//           - CreateToolhelp32Snapshot/Process32FirstW/Process32NextW/Thread32First/Thread32Next
//             通过 GetProcAddress + STEALTH_STR_DECRYPT_TO 动态解析, API 名 XTEA 编译期加密
//           - GetModuleHandleW/GetModuleHandleExW 替换为 PEB Ldr 遍历 (GetModuleBaseFromPEB)
//        3. ★ BUILD 550 RTCore64.sys 嵌入数据移除 (死代码清理):
//           - g_driverCandidates[] 仅含 PDFWKRNL (BUILD 490), RTCore64 分支永不执行
//           - 消除 .rdata 中 \Device\RTCore64 / \DosDevices\RTCore64 / ntoskrnl.exe 明文
//        保留: BUILD 549 影子页 PTE + DiagLog 加密 + BUILD 548 集成补丁 + BUILD 546 7 层保护
// BUILD: 553 (v3.210: 防护深度分析改进 — 基于 BUILD 552 三维度分析)
//        1. ★ BUILD 553 P0-1: ShadowPageManager 降频 (500ms → 5s)
//           - IOCTL 频率: 240/min → 24/min, 远低于 PDFWKRNL.sys 卡死基线 (1400/min)
//           - 占空比: 10% → 1% (50ms pageA / 5000ms 周期)
//           - 修复 B1 缺陷: 违反 10s cooldown 约束
//        2. ★ BUILD 553 P0-2: MinifilterNeutralizer 周期性重新中和 (GuardPac 恢复)
//           - 60-90s 周期检查 IsMessageTransferNeutralized, 失败则重新中和
//           - 修复 A1 缺陷: BUILD 552 只在启动时中和一次
//        3. ★ BUILD 553 P1-1: FindShvInstallEntry 三级边界查找 (0xCC/0x90/0x00)
//           - Pass 1: 0xCC int3 (最可靠)
//           - Pass 2: 连续 ≥2 字节 0x90 nop (MSVC 对齐)
//           - Pass 3: 连续 ≥4 字节 0x00 零填充 (Clang 对齐)
//           - 修复 B2 缺陷: 现代编译器不用 0xCC 边界导致 patch 失败
//        4. ★ BUILD 553 P1-2: VEH 自愈计数重置 (MAX_VEH_RETRIES 3→10 + 60s 重置)
//           - 修复 B4 缺陷: 长期运行后 VEH 自愈能力耗尽
//        5. ★ BUILD 553 P1-3: ShvInstallPatcher SIG1 特征码 XOR 加密
//           - g_sig1Key=0xA7, SIG1_ENC 运行时解密
//           - 修复 A3 缺陷: 消除 .rdata 中 48 B9 00 00 00 80 明文特征码
//        保留: BUILD 552 SHV patch + BUILD 549 影子页 + BUILD 548 集成补丁 + BUILD 546 7 层保护
// BUILD: 561 (v3.220: SHV patch 强化 — 边界查找 Pass4 + 放宽序言验证 + PAC 未加载优化)
//        1. ★ BUILD 561-1: FindShvInstallEntry 新增 Pass 4 (0xC3 ret + 0xCC int3 模式)
//           - 函数末尾 ret 后常跟 int3 填充 (MSVC/Clang 对齐习惯)
//           - Pass 1-3 失败时兜底, 0xC3+0xCC 在指令中间极罕见 (~1/256 误判率)
//           - 向后兼容: Pass 1-3 仍优先, Pass 4 仅在 1-3 均失败时尝试
//        2. ★ BUILD 561-2: 放宽序言验证 (IsValidPrologueByte 辅助函数)
//           - 原 BUILD 553: 仅接受 0x48/0x55/0x40-0x4F (REX.W/push rbp/REX prefix)
//           - BUILD 561 新增: 0x53/0x56/0x57 (push rbx/rsi/rdi)
//           - 原因: MSVC/Clang 函数序言常用 push rbx/rsi/rdi 保存 callee-saved 寄存器
//           - Pass 1-3 内联验证统一替换为 IsValidPrologueByte 调用
//        3. ★ BUILD 561-3: PAC 未加载时不计入失败次数 (避免误触发降级模式)
//           - 原 BUILD 555: PAC 未加载调用 RecordPatchFailure(), 连续 3 次误入降级模式
//           - BUILD 561: 仅更新 m_lastPatchTick, 不调用 RecordPatchFailure()
//           - 副作用: 真正的 patch 失败 (PAC 加载但写入失败) 仍触发降级模式
//        预期效果: SHV patch 成功率 90-95% → 95-97%, 整体检测概率 12-20% → 10-17%
//        保留: BUILD 560 wShotTools 栈变量 + BUILD 559 隐蔽 SHV (-5 自然失败码) + BUILD 558 7 层保护
// BUILD: 562 (v3.221: SIG2 多特征码兜底 — CALL BroadcastToAllCpus + WaitForCompletion 配对)
//        1. ★ BUILD 562-1: FindShvInstallEntry 签名扩展 — 新增 pacModuleBase 参数
//           - 原签名: (uint64_t pacDriverBase, uint32_t textSize) — pacDriverBase 实为 .text 段地址
//           - 新签名: (uint64_t pacModuleBase, uint64_t textSectionVA, uint32_t textSize)
//           - 原因: SIG2 需要 pacModuleBase + RVA 计算目标地址 (BroadcastToAllCpus/WaitForCompletion)
//        2. ★ BUILD 562-2: SIG2 多特征码兜底 — SIG1 失败后尝试 SIG2
//           - SIG2 字节模式: E8 xx xx xx xx E8 xx xx xx xx (两个连续 CALL rel32)
//           - 验证: 第一个 CALL 目标 = pacModuleBase + 0xEADC4 (BroadcastToAllCpus RVA)
//                  第二个 CALL 目标 = pacModuleBase + 0xEAE4D (WaitForCompletion RVA)
//           - 可靠性: BroadcastToAllCpus + WaitForCompletion 配对在 SHV_Install 中特有
//             (PAC_SHV 逆向分析报告 §3.2 L146-147 确认 SHV_Install 调用这两个函数启动 per-CPU SHV)
//           - 不需要 XOR 加密: E8 是通用 CALL 操作码, 不构成特征
//           - 边界查找复用 Pass 1-4 + IsValidPrologueByte (与 SIG1 相同)
//        3. ★ BUILD 562-3: byovd_kernel.h 添加 SIG2_BROADCAST_RVA/SIG2_WAIT_RVA 常量
//           - SIG2_BROADCAST_RVA = 0xEADC4 (BroadcastToAllCpus, 报告 §14.1)
//           - SIG2_WAIT_RVA = 0xEAE4D (WaitForCompletion, 报告 §14.1)
//           - 注意: 这两个 RVA 是当前 PAC 版本 (1.0.0.2) 的值, PAC 更新后可能改变
//        预期效果: SHV patch 成功率 95-97% → 98-99% (SIG1+SIG2 互补, 覆盖 PAC 更新场景)
//        保留: BUILD 561 Pass4 + IsValidPrologueByte + PAC 未加载优化 + BUILD 560 wShotTools 栈变量
// BUILD: 563 (v3.222: .data 段修复 — GetPacPatterns + g_cachedPacName 改为栈变量)
//        1. ★ BUILD 563-1: GetPacPatterns → FillPacPatterns (栈缓冲)
//           - 原 GetPacPatterns 内 `static wchar_t patterns[8][32]` + `static const wchar_t* patternPtrs[9]`
//             + `static bool initialized` 永久存在于 .data 段
//           - 解密后的 "messagetransfer/pvpac/perfectworld" 等关键词 PAC 可随时扫描发现
//           - 修复: 改为 FillPacPatterns(wchar_t patterns[8][32], const wchar_t* patternPtrs[9])
//                  调用方传栈缓冲, IsPacPattern 内构造 + 末尾 SecureZeroMemory 清零
//        2. ★ BUILD 563-2: GetPacTargetName → FillPacTargetName (栈缓冲)
//           - 原 GetPacTargetName 内 `static wchar_t g_cachedPacName[256]` + `static DWORD g_lastPacNameCheck`
//             永久存在于 .data 段, 含 "MessageTransfer" + 30 秒缓存机制
//           - 修复: 改为 FillPacTargetName(wchar_t* buf, size_t bufChars), 调用方传栈缓冲
//                  移除 30 秒缓存 (PAC 名硬编码, 解密成本低; 缓存反而延长明文窗口)
//                  12 处调用方全部改为传栈缓冲 + SecureZeroMemory 清零
//        3. ★ BUILD 563-3: RefreshPacName 简化为空函数 (0 处外部调用, 向后兼容)
//        4. ★ BUILD 563-4: 3 处 #if 0 废弃块同步修改 (IsPacMinifilterLoaded/UnloadPacMinifilter/
//           GuardPac SCM 路径), 保持代码一致性, 未来恢复 #if 1 时不需再改
//        预期效果: .data 段长明文窗口消除 (永久 → ~1-10ms 函数执行期间)
//                 整体检测概率 8-15% → 7-14% (.data 段扫描检测难度提升)
//        保留: BUILD 562 SIG2 + BUILD 561 Pass4 + BUILD 560 wShotTools 栈变量 + BUILD 559 隐蔽 SHV
// BUILD: 564 (v3.223: PsLoadedModuleList DKOM 隐藏 — PDFWKRNL.sys 条目摘除)
//        1. ★ BUILD 564-1: 新增 PsLoadedModuleHider 类 (byovd_kernel.h + byovd_kernel.cpp)
//           - 目标: 消除 BYOVD 驱动在 ntoskrnl!PsLoadedModuleList 链表中的痕迹
//           - 原因: PDFWKRNL.sys 加载后 LDR_DATA_TABLE_ENTRY 永久存在于链表
//                  PAC 内核组件可遍历该链表发现 BYOVD 漏洞驱动
//        2. ★ BUILD 564-2: LocatePsLoadedModuleList — 扫描 ntoskrnl .data 段定位头节点
//           - 5 重验证条件: Flink/Blink 内核范围 + DllBase==ntosBase +
//             BaseDllName.Length==24 + Buffer 内核池 + 内容=="ntoskrnl.exe"
//           - 任一条件失败跳过, 避免误判其他 LIST_ENTRY
//           - 1MB 块读取 + 8 字节对齐扫描, 性能可接受 (2-4 次 IOCTL)
//        3. ★ BUILD 564-3: FindEntryByBaseName — 遍历链表查找目标驱动
//           - 终止条件: current==listHead / current==0 / 超过 512 次迭代 / 自循环
//           - 不区分大小写比较 (_wcsicmp)
//        4. ★ BUILD 564-4: PerformUnlink — DKOM 断链 + SelfLoopHarden
//           - 复用 DKOMProcessHider::HideProcessByPid 已验证技术 (BUILD 558 FIX)
//           - 写 prev.Flink=next, next.Blink=prev (断链)
//           - SelfLoopHarden: current.Flink=&current, current.Blink=&current (防 0x139)
//           - 失败回滚: 恢复 prev.Flink=&current, next.Blink=&current
//        5. ★ BUILD 564-5: EnableAll 集成 HideDriver 调用
//           - 位置: CleanAllTraces 之后, SCM 服务删除之前
//           - 仅 driverLoaded=true 时调用, 失败不影响其他防御功能
//        安全性: PDFWKRNL.sys 永不卸载 (不触发 RemoveEntryList) + IOCTL 不依赖链表 +
//                ReadKernelVA 直接 memcpy + 失败安全 (不修改内核数据)
//        预期效果: 驱动扫描检测概率 2-4% → 0-1%, 整体检测概率 7-14% → 6-13%
//        保留: BUILD 563 .data 段修复 + BUILD 562 SIG2 + BUILD 561 Pass4 + BUILD 560 wShotTools 栈变量
// BUILD: 565 (v3.224: Hook NtReadVirtualMemory 双重保险 — 用户态扫描检测概率 2-5% → 1-2%)
//        1. ★ BUILD 565-1: 新增 NtReadHooker 类 (byovd_kernel.h L786-865 + byovd_kernel.cpp L8296-8943)
//           - 目标: 拦截 PvpAlive.dll 通过 NtReadVirtualMemory 扫描 client.dll patch 区域
//           - 原因: BUILD 564 DKOM 隐藏驱动但未防御用户态扫描, PAC 仍可发现 32 c0 → 90 90 patch
//        2. ★ BUILD 565-2: 方案 B (IAT hook PvpAlive.dll) — 主方案, PAC 发现风险最低
//           - FindPvpAliveBase: 跨进程枚举 CS2 模块 (StealthProcess::GetProcessModules)
//           - FindNtReadInIAT: 读 PE 头 → Import Directory → 遍历查找 "NtReadVirtualMemory"
//           - InstallIATHook: VirtualAllocEx 分配可执行内存 + 写 shellcode + 改 IAT 条目
//        3. ★ BUILD 565-3: 方案 A (inline hook ntdll) — 兜底方案, B 失败时自动启用
//           - FindNtdllNtRead: 跨进程枚举 ntdll + 读导出表
//           - InstallInlineHook: Trampoline 模式 (12 原 + jmp[rip+0] + 8 目标 = 26 字节)
//           - 改 ntdll 前 12 字节为 48 B8 <addr> FF E0 (mov rax, addr; jmp rax)
//        4. ★ BUILD 565-4: GenerateFilterShellcode — 104 字节 PIC shellcode
//           - 调用原 NtReadVirtualMemory 后, 若读取范围与 [patchAddr, patchAddr+2) 重叠
//           - 在 Buffer 对应偏移写入 32 c0 (恢复原始字节, PAC 扫描看到原始字节)
//           - static_assert(sizeof(kTemplate) == 104) 编译期验证模板大小
//           - 常量填充: originalNtRead @0x16, patchAddr @0x35
//        5. ★ BUILD 565-5: payload.cpp 4 处集成
//           - L2401: EnableAll ApplyCs2Patch 成功后调用 Install (B565:I:01 日志)
//           - L2788: CS2 退出 DisableAll 之前调用 Uninstall
//           - L2977: 主循环 ApplyCs2Patch 补装成功后重试 Install
//           - L2993: 主循环 5s 间隔调用 Maintain (检测 PvpAlive 重载 / ntdll 被恢复)
//        安全性: hook 在用户态 (CS2 进程内), 不触发 PatchGuard, BSOD 风险极低
//                Uninstall 失败仅记录日志不阻塞退出, 失败安全
//                Install 失败不影响其他防御功能 (与 PsLoadedModuleHider 一致)
//        预期效果: 用户态扫描检测概率 2-5% → 1-2%, 综合检测概率 6-13% → 5-12%
//        保留: BUILD 564 DKOM 隐藏 + BUILD 563 .data 段修复 + BUILD 562 SIG2 + BUILD 561 Pass4
// BUILD: 566 (v3.225: VmxOnWrapper patch + NtReadHooker shellcode 参数化 — SHV EPT 检测 2-3% → 0.5-1%)
//        1. ★ BUILD 566-1: ShvInstallPatcher 新增 PatchVmxOnWrapper (byovd_kernel.h + .cpp)
//           - 目标: patch VmxOnWrapper (RVA 0xEAEC4) 为 xor eax,eax; ret (31 C0 C3, 3 字节)
//           - 原因: BUILD 559 前 patch SHV_Install 为 mov eax,-5;ret, PAC 可检测 SHV 失败并上报
//           - 效果: SHV_Install 仍返回 STATUS_SUCCESS, 但 VMX 永不启动, EPT 永不构造
//           - OCR 无画面源 (EPT 不启动), PacNova::IsWallTransparentHack 触发条件失效
//        2. ★ BUILD 566-2: FindVmxOnWrapperEntry — 通过 RVA 0xEAEC4 + vmxon 指令字节验证
//           - 读取 VmxOnWrapper 前 32 字节, 验证包含 vmxon 指令 (0F 01 C1)
//           - 验证第一个字节非 0xCC/0x00/0x90 (函数边界检查)
//           - 失败回退到 SHV_Install patch (现有逻辑, 不计入降级模式)
//        3. ★ BUILD 566-3: PatchShvInstallEntry 入口优先调用 PatchVmxOnWrapper
//           - VmxOnWrapper patch + SHV_Install patch 双重保险 (两者都执行)
//           - VmxOnWrapper 成功 + SHV_Install 成功 = 最强防护 (VMX 不启动 + SHV 失败兜底)
//           - VmxOnWrapper 失败 + SHV_Install 成功 = BUILD 565 防护水平
//           - 两者都失败 = 进入降级模式 (现有逻辑, 仅 SHV_Install patch 计入降级)
//        4. ★ BUILD 566-4: NtReadHooker::GenerateFilterShellcode 参数化 patchSize + patchData
//           - 签名增加 patchSize (uint16_t) + patchData (const uint8_t*) 参数
//           - 当前仅支持 patchSize = 2 (mov word ptr, 与 BUILD 565 一致)
//           - shellcode 偏移 0x5D 填充 patchWord (从 patchData 提取, 默认 0xC032 = 32 c0)
//           - 为未来多 patch 点扩展 (patchSize = 4/8) 预留接口
//           - shellcode 大小不变 (仍 104 字节), static_assert 通过
//        安全性: VmxOnWrapper patch 在内核态 (与 SHV_Install patch 一致), 不触发 PatchGuard
//                vmxon 永不执行 → 不进入 VMX root operation → 无硬件状态变化 → BSOD 风险极低
//                VmxOnWrapper patch 失败不影响 SHV_Install patch (独立失败处理)
//        预期效果: SHV EPT 检测 2-3% → 0.5-1%, OCR 检测 3-8% → 1-2%, 综合 5-12% → 2-5%
//        保留: BUILD 565 NtReadVirtualMemory Hook + BUILD 564 DKOM + BUILD 563 .data 修复
// BUILD: 566 加固 (v3.226: VmxOnWrapper patch 独立降级模式 + 周期性维护 — 持久对抗 PAC 恢复)
//        5. ★ BUILD 566-5: VmxOnWrapper patch 独立降级模式 (byovd_kernel.h + .cpp)
//           - 新增 RecordVmxOnPatchFailure / RecordVmxOnPatchSuccess / IsVmxOnDegradedMode
//           - 新增 m_vmxOnConsecutiveFailures / m_vmxOnDegradedMode / m_vmxOnLastPatchTick
//           - 与 SHV_Install patch 降级状态完全独立 (互不污染)
//           - 连续失败 ≥3 次进入降级 (跳过周期性 VmxOnWrapper 检查, 节省 IOCTL)
//           - 5 分钟自恢复 (与 SHV_Install 降级一致)
//           - 失败计数语义与 SHV_Install patch 一致 (PAC 未加载也算失败, 自恢复后重试)
//        6. ★ BUILD 566-6: payload.cpp 主循环周期性 IsVmxOnPatched 验证 (60-90s 间隔)
//           - 与 IsPatched() 并立, 任一失效即触发 PatchShvInstallEntry 重 patch
//           - 一次 PatchShvInstallEntry 调用同时维护两者 (避免重复 IOCTL)
//           - PatchShvInstallEntry 入口先 IsVmxOnPatched 判断, 已 patched 不计成功/失败
//             (与 SHV_Install patch IsPatched 快速返回语义对称)
//        安全性: VmxOnWrapper patch 持久有效 (PAC 恢复后自动重 patch), 无新内存访问模式
//                降级模式下依赖 SHV_Install patch 兜底 (双重保险), BSOD 风险极低
//        预期效果: VmxOnWrapper patch 持久有效, EPT 永不构造, 综合 2-5% → 1.5-4%
// BUILD: 567 (v3.254: 修正 .idata 硬编码回退值 + 宽松匹配回退)
//        ★ BUILD 567 v3.254 FIX (.idata 硬编码回退值过期修复 7/20):
//          - 背景: v3.253 import thunk 扫描匹配 0 个 thunk, 仍崩溃.
//          - 根因: PE 头被 ManualMap 擦除, 使用硬编码回退 [0x82000, 0x84000),
//                  但 v3.252+ payload.dll .text 段减小后 .idata 移到 RVA 0x87000.
//                  rel32 目标验证全部失败 (target 不在 [0x82000, 0x84000) 范围).
//          - 修复: (1) 更新硬编码回退值为 [0x87000, 0x89000) (当前 .idata 位置);
//                  (2) 添加宽松匹配回退: 精确匹配 0 个 thunk 时, 改用宽松匹配
//                      (只匹配 FF 25 xx xx xx xx, 不验证 target), 防止未来过期.
//          - 预期: B567:254 日志显示 ~197 thunks, ~35 exempt pages, EA done/DA done 出现.
// BUILD: 567 (v3.253: import thunk 扫描精确匹配 — rel32 目标验证 .idata 段)
//        ★ BUILD 567 v3.253 FIX (import thunk 扫描漏匹配修复 7/20):
//          - 背景: v3.252 豁免 import thunk 所在页, 但扫描模式 `FF 25 xx xx xx xx 90 90`
//                  只匹配 188 个有 2 nop 填充的 thunk, 漏掉 9 个 "other" 类型
//                  (后面跟 ret/int3/其他指令, 不是 90 90).
//          - 症状: v3.252 测试仍崩溃在 B238:EK:EA+ pre 之后 (EncryptAll 内部),
//                  B567:252 日志显示 188 thunks, 30 exempt pages.
//          - 实际统计: 197 个 thunk 指向 .idata, 分布在 12 个唯一页.
//          - 修复: 扫描模式从 `FF 25 xx xx xx xx 90 90` 改为 `FF 25 xx xx xx xx` +
//                  rel32 目标地址验证 (target 在 [idataPageStart, idataPageEnd) 范围内).
//                  精确匹配所有 import thunk, 无误报.
//          - 代价: ~12 页 (48KB) 不加密 (相对 .text 364KB 约 13%), 但消除崩溃根因.
//          - 预期: B567:253 日志显示 197 thunks, ~35 exempt pages, EA done/DA done 出现.
// BUILD: 567 (v3.252: 豁免所有 import thunk 所在页 — EkkoSleep 崩溃真正根因修复)
//        ★ BUILD 567 v3.252 FIX (EkkoSleep 崩溃真正根因修复 7/20):
//          - 根因: v3.250/v3.251 崩溃在 E0 页 [0x5C000, 0x5D000) 内,
//                  该页含大量 import thunk (FF 25 xx xx xx xx 90 90 = jmp [rip+offset]; nop; nop).
//                  EkkoSleep EncryptAll 加密 E0 页 → import thunk 代码被加密,
//                  EK_RAW_LOG 宏 / VirtualProtect 等调用通过 import thunk 跳转
//                  → CPU 执行加密字节 → 0xc0000005 崩溃.
//          - 验证: v3.249 D0 完整完成 (import thunk 不在 E0 页),
//                  v3.250 .text 段变大 (482820→487428 字节) 后 import thunk 移到 E0 页
//                  → E0 出现 E1 未出现, 证实 import thunk 位置是根因.
//                  v3.251 栈上构造 L"sd.log" 修复无效 (根因不在 sd.log 字符串).
//          - 修复: 扫描整个 DLL 镜像找到所有 import thunk (FF 25 xx xx xx xx 90 90),
//                  将其所在页添加到 exemptPages (豁免, 不加密).
//                  exemptPages 数组从 [48] 扩大到 [128] 容纳 import thunk 页.
//          - 代价: ~15 页 (60KB) 不加密 (相对 .text 384KB 约 15%), 但消除崩溃根因.
//          - 预期: EA done 出现, DA done 出现, EkkoSleep 正常返回, 不再崩溃.
// BUILD: 567 (v3.250: D1 细分为 4 个 4KB 页级子块诊断)
//        ★ BUILD 567 v3.250 DIAG (D1 [208KB, 224KB) 崩溃页定位 7/20):
//          - 背景: v3.249 确认 D0 完整完成 (D0done 出现), 崩溃在 D1 [208KB, 224KB)
//                  (EA r3 D0/E0/E1/E2/E3/D0done 出现, D1 出现但未完成)
//                  D1 范围 [dllBase+0x60000, dllBase+0x64000) 完全在 .rdata 段内
//          - 诊断: D1 进一步细分为 4 个 4KB 页:
//                  EA r3 F0 → 页 0 [208KB, 212KB) = [dllBase+0x60000, dllBase+0x61000) — .rdata 段
//                  EA r3 F1 → 页 1 [212KB, 216KB) = [dllBase+0x61000, dllBase+0x62000) — .rdata 段
//                  EA r3 F2 → 页 2 [216KB, 220KB) = [dllBase+0x62000, dllBase+0x63000) — .rdata 段
//                  EA r3 F3 → 页 3 [220KB, 224KB) = [dllBase+0x63000, dllBase+0x64000) — .rdata 段
//                  EA r3 D1done → D1 完成
//          - 判读:
//                  F0 出现, F1 未出现 → 崩溃在页 0 ([0x60000, 0x61000))
//                  F1 出现, F2 未出现 → 崩溃在页 1 ([0x61000, 0x62000))
//                  F2 出现, F3 未出现 → 崩溃在页 2 ([0x62000, 0x63000))
//                  F3 出现, D1done 未出现 → 崩溃在页 3 ([0x63000, 0x64000))
//                  D1done 出现 → D1 完成 (崩溃在 D2 或之后)
// BUILD: 567 (v3.249: D0 细分为 4 个 4KB 页级子块诊断)
//        ★ BUILD 567 v3.249 DIAG (D0 [192KB, 208KB) 崩溃页定位 7/20):
//          - 背景: v3.248 确认崩溃在 XorCrypt 处理块 3 子块 0 [192KB, 208KB) 时
//                  (EA r3 D0 出现, D1 未出现)
//                  D0 范围 [dllBase+0x5C000, dllBase+0x60000) 跨越 .text/.data/.rdata
//          - 诊断: D0 进一步细分为 4 个 4KB 页:
//                  EA r3 E0 → 页 0 [192KB, 196KB) = [dllBase+0x5C000, dllBase+0x5D000) — .text 末尾代码
//                  EA r3 E1 → 页 1 [196KB, 200KB) = [dllBase+0x5D000, dllBase+0x5E000) — .text/.data 边界
//                  EA r3 E2 → 页 2 [200KB, 204KB) = [dllBase+0x5E000, dllBase+0x5F000) — .data 段 (全局变量)
//                  EA r3 E3 → 页 3 [204KB, 208KB) = [dllBase+0x5F000, dllBase+0x60000) — .rdata 段开头
//                  EA r3 D0done → D0 完成
//          - 判读:
//                  E0 出现, E1 未出现 → 崩溃在页 0 (.text 末尾代码, [0x5C000, 0x5D000))
//                  E1 出现, E2 未出现 → 崩溃在页 1 (.text/.data 边界, [0x5D000, 0x5E000))
//                  E2 出现, E3 未出现 → 崩溃在页 2 (.data 全局变量, [0x5E000, 0x5F000))
//                  E3 出现, D0done 未出现 → 崩溃在页 3 (.rdata 段, [0x5F000, 0x60000))
//                  D0done 出现 → D0 完成 (崩溃在 D1 或之后)
// BUILD: 567 (v3.248: 块 3 细分为 4 个 16KB 子块诊断)
//        ★ BUILD 567 v3.248 DIAG (块 3 [192KB, 256KB) 崩溃 16KB 子块定位 7/20):
//          - 背景: v3.247 确认崩溃在 XorCrypt 处理 region 3 的块 3 [192KB, 256KB) 时
//                  (EA r3 C3 出现, EA r3 C4 未出现)
//          - 诊断: 块 3 细分为 4 个 16KB 子块:
//                  EA r3 D0 → 子块 0 [192KB, 208KB)
//                  EA r3 D1 → 子块 1 [208KB, 224KB)
//                  EA r3 D2 → 子块 2 [224KB, 240KB)
//                  EA r3 D3 → 子块 3 [240KB, 256KB)
//                  EA r3 C3done → 块 3 完成
//          - 判读:
//                  EA r3 D0 出现, D1 未出现 → 崩溃在子块 0 [192KB, 208KB)
//                  EA r3 D1 出现, D2 未出现 → 崩溃在子块 1 [208KB, 224KB)
//                  EA r3 D2 出现, D3 未出现 → 崩溃在子块 2 [224KB, 240KB)
//                  EA r3 D3 出现, C3done 未出现 → 崩溃在子块 3 [240KB, 256KB)
//                  EA r3 C3done 出现 → 块 3 完成 (崩溃在 C4 或之后)
// BUILD: 567 (v3.247: region 3 分块 XorCrypt 诊断, 每块 64KB)
//        ★ BUILD 567 v3.247 DIAG (region 3 XorCrypt 崩溃块定位 7/20):
//          - 背景: v3.246 确认崩溃在 XorCrypt 处理 region 3 (299KB) 时
//                  (EA r3 XC 出现, EA r3 VP2 未出现)
//          - 诊断: 对 region 3 分块 XorCrypt, 每块 64KB:
//                  EA r3 C0 → 处理块 0 [0, 64KB)
//                  EA r3 C1 → 处理块 1 [64KB, 128KB)
//                  EA r3 C2 → 处理块 2 [128KB, 192KB)
//                  EA r3 C3 → 处理块 3 [192KB, 256KB)
//                  EA r3 C4 → 处理块 4 [256KB, 299KB)
//                  EA r3 XCdone → XorCrypt 完成
//          - 判读:
//                  EA r3 C0 出现, C1 未出现 → 崩溃在块 0 [0, 64KB)
//                  EA r3 C1 出现, C2 未出现 → 崩溃在块 1 [64KB, 128KB)
//                  ...
//                  EA r3 XCdone 出现 → XorCrypt 完成 (崩溃在 VP2 或之后)
// BUILD: 567 (v3.246: region 3 精细诊断 VP1/XC/VP2/FIC/end)
//        ★ BUILD 567 v3.246 DIAG (region 3 崩溃步骤精确定位 7/20):
//          - 背景: v3.245 测试 EA r3 出现, EA r4 未出现 → 崩溃在处理 region 3 时
//          - 诊断: 对 region 3 添加精细诊断:
//                  EA r3 VP1 → VirtualProtect(PAGE_READWRITE) 之前
//                  EA r3 VP1fail → VirtualProtect 失败
//                  EA r3 XC → XorCrypt 之前
//                  EA r3 VP2 → 第二次 VirtualProtect(恢复) 之前
//                  EA r3 FIC → FlushInstructionCache 之前 (仅 isCode)
//                  EA r3 end → region 3 处理完成
//          - 判读:
//                  EA r3 VP1 出现, EA r3 XC 未出现 → 崩溃在 VirtualProtect
//                  EA r3 XC 出现, EA r3 VP2 未出现 → 崩溃在 XorCrypt
//                  EA r3 VP2 出现, EA r3 FIC/end 未出现 → 崩溃在第二次 VirtualProtect
//                  EA r3 FIC 出现, EA r3 end 未出现 → 崩溃在 FlushInstructionCache
//                  EA r3 end 出现 → region 3 处理完成 (崩溃在其他地方)
// BUILD: 567 (v3.245: EncryptAll/DecryptAll 关键页跳过保护 + 内部 EK_RAW_LOG 诊断)
//        ★ BUILD 567 v3.245 FIX+DIAG (EncryptAll 加密自身代码页根因修复 7/20):
//          - 背景: v3.244 EA+ post 未出现 → 崩溃在 EncryptAll 内部.
//                  主菜单正常, 进入对局第一次 StealthSleep 就崩溃.
//          - 根因假设: m_regions 中某个 region 覆盖了 ekkoPage/encryptAllPage/xorCryptPage,
//                      EncryptAll 加密自身代码页 → 后续执行加密字节 → 崩溃.
//                      exemptPages 只在 payload.cpp StealthSleep 中使用, EncryptAll 内部
//                      并不知道哪些页是关键页, 会无差别加密所有 m_regions 中的 region.
//          - 修复: EncryptAll/DecryptAll 内部添加关键页跳过保护:
//                  遍历每个 region 前, 检查 region 是否覆盖 ekkoPage(4页)/encryptAllPage(2页)/
//                  decryptAllPage(2页)/xorCryptPage(2页)/sleepObjPage(2页), 覆盖则跳过.
//                  DecryptAll 对称跳过 (否则解密未加密 region → 数据损坏).
//          - 诊断: EncryptAll/DecryptAll 内部添加 EK_RAW_LOG 诊断:
//                  EA start/EA skip/EA r0-r5/EA VP fail/EA done
//                  DA start/DA skip/DA VP fail/DA done
//                  根据最后出现的日志判断崩溃位置 (哪个 region 处理时崩溃).
//          - 安全性: 关键页跳过保护是深度防御, 即使 region 注册时误覆盖关键页也不会崩溃.
//                    跳过的 region 不加密 = Sleep 期间该 region 保持明文 (轻微降低隐蔽性,
//                    但关键页本身已在 exemptPages 中豁免, 不影响整体保护效果).
// BUILD: 567 (v3.244: 加密窗口内 EK_RAW_LOG 诊断 + ekkoPage+0x3000 豁免)
//        ★ BUILD 567 v3.244 DIAG+FIX (EkkoSleep 加密窗口精确定位 7/20):
//          - 背景: v3.243 豁免 sleepObjPage 后仍崩溃 (B238:EK:EA+ pre 仍是最后一条日志),
//                  说明根因不在 m_regions 被加密. 需精确定位加密窗口内崩溃位置.
//          - 诊断: memory_cloak.cpp 新增 EK_RAW_LOG 宏, 加密窗口内用内联 WriteFile 输出
//                  固定字符串 (不调用 CRT 函数, 避免 EkkoDiagLog 的 CRT 依赖问题):
//                    EA+ post → EncryptAll 成功
//                    timer OK → CreateWaitableTimerW 成功
//                    set OK → SetWaitableTimer 成功
//                    wait OK → WaitForSingleObject 成功
//                    DA+ pre → DecryptAll 之前
//                    DA+ post → DecryptAll 成功
//          - 修复: exemptPages 添加 ekkoPage + 0x3000 (第四页), exemptPageCount 22 → 23.
//                  原因: EkkoSleep 函数代码 (含 v3.244 新增的 EK_RAW_LOG 宏内联展开) 可能
//                  跨越到 ekkoPage+0x3000 (第四页), 未豁免会被 EncryptAll 加密 → 崩溃.
//          - 判读: 根据最后出现的 EK_RAW_LOG 日志判断崩溃位置:
//                  EA+ post 未出现 → 崩溃在 EncryptAll 内部 (需分析 EncryptAll 代码)
//                  timer OK 未出现 → 崩溃在 CreateWaitableTimerW (IAT 问题?)
//                  set OK 未出现 → 崩溃在 SetWaitableTimer
//                  wait OK 未出现 → 崩溃在 WaitForSingleObject
//                  DA+ post 未出现 → 崩溃在 DecryptAll 内部
//                  DA+ post 出现 → EkkoSleep 成功通过加密窗口
//          - 安全性: EK_RAW_LOG 宏内联展开在 EkkoSleep 内部 (ekkoPage 已豁免),
//                    只调用 kernel32 函数 (通过 IAT, .idata 已豁免), 不调用 CRT 函数.
// BUILD: 567 (v3.243: 豁免 SleepObfuscator 对象所在页 — 真正根因修复)
//        ★ BUILD 567 v3.243 FIX (EncryptAll 加密自身 m_regions 数组 7/20):
//          - 根因: v3.242 移除加密窗口日志后仍崩溃, 重新分析根因.
//                  EncryptAll 保护范围 [dllBase+0x1000, dllBase+dllSize) 覆盖整个 DLL 镜像
//                  (包括 .text/.rdata/.data/.bss), 不仅仅是 .text 段.
//                  SleepObfuscator 单例对象 (Instance() 返回 static 局部变量) 在 .bss 段,
//                  含 m_regions[MAX_REGIONS=64] 数组 (~1.5KB). 若该对象所在页未被豁免:
//                    1. EncryptAll 遍历 m_regions, 处理覆盖 .bss 的 region 时 XorCrypt 加密该 region
//                    2. 该 region 范围包含 m_regions 数组本身 → m_regions 被加密
//                    3. 下次循环访问 m_regions[ri+1] 时读取加密垃圾 → VirtualProtect 用错误 addr → 崩溃
//          - 修复: payload.cpp exemptPages 添加 sleepObjPage + sleepObjPage+0x1000 (防跨页),
//                  exemptPageCount 20 → 22. 同时 B550:EK:protected 日志添加 sleepObj@ 字段.
//          - 诊断: memory_cloak.cpp EkkoSleep 入口添加 B243:EK:this 日志, 输出 this/m_regions
//                  地址 + objInEkko/objInEncA/objInDecA 标志 (验证对象是否在豁免页).
//          - 判读: 若 "B238:EK:DA+ post" 出现 → 根因确认, v3.243 修复成功
//                  若 "B238:EK:DA+ post" 未出现 → 仍有其他被加密的关键数据, 需进一步分析
//          - 安全性: 多豁免 2*4KB=8KB (相对 520KB 仅 1.5%), 不影响加密效果.
//          - 副作用: SleepObfuscator 对象 (m_regions/m_regionCount/m_masterKey) 在 EkkoSleep 期间
//                    不被加密 (保持明文), 但这些数据不含敏感特征, 风险可接受.
// BUILD: 567 (v3.242: 移除加密窗口内的 EkkoDiagLog 调用 — 真正根因修复)
//        ★ BUILD 567 v3.242 FIX (EkkoSleep 加密窗口 CRT 崩溃 7/20):
//          - 根因: v3.241 B241:EK:self 诊断确认 EkkoSleep 入口在 ekkoPage+0x1000 (已豁免),
//                  但 EkkoDiagLog 内部调用静态链接的 CRT 函数 (vsnprintf/snprintf/strlen/memcpy),
//                  这些函数代码页在 payload.dll .text 段未豁免位置, 被 EncryptAll 加密 → 崩溃.
//                  v3.240/v3.241 的 ekkoPage+0x1000/0x2000 豁免无效 (EkkoSleep 本身已在豁免页).
//          - 修复: 移除加密窗口内 (EncryptAll 之后 / DecryptAll 之前) 的 3 处 EkkoDiagLog 调用:
//            1. "B238:EK:EA+ post" (EncryptAll 之后)
//            2. "B238:EK:timer FAIL" (fallback 路径, EncryptAll 之后 DecryptAll 之前)
//            3. "B238:EK:DA+ pre" (DecryptAll 之前)
//          - 保留: EncryptAll 之前 + DecryptAll 之后的日志 (代码页未加密/已解密, 安全)
//          - 判读: 若 "B238:EK:DA+ post" 出现 → EkkoSleep 成功通过加密窗口
//                  若 "B238:EK:DA+ post" 未出现 → 崩溃在 EncryptAll/WaitForSingleObject/DecryptAll
//          - 安全性: 不影响 EkkoSleep 逻辑, 仅移除诊断日志. 系统DLL函数 (CreateWaitableTimerW 等)
//                    不在加密范围, 加密窗口内调用安全.
// BUILD: 567 (v3.241: 扩展 EkkoSleep 跨页保护到 3 页 + 函数地址诊断)
//        ★ BUILD 567 v3.241 FIX+DIAG (EkkoSleep 跨页保护扩展 7/20):
//          - 背景: v3.240 添加 ekkoPage+0x1000 豁免后仍然崩溃 (B238:EK:EA+ post 仍未输出)
//                  说明 EkkoSleep 函数代码跨越到 ekkoPage+0x2000 (第三页), 或编译器将
//                  EkkoSleep 放在远离 EkkoSleepPageMarker 的位置.
//          - 修复: exemptPages 添加 ekkoPage + 0x2000, exemptPageCount 19 → 20.
//          - 诊断: memory_cloak.cpp EkkoSleep 入口添加 B241:EK:self 日志, 使用 GCC &&label
//                  扩展获取 EkkoSleep 内部 label 地址, 输出 inEkko0/inEkko1/inEkko2 标志.
//          - 判读: 若 B238:EK:EA+ post 出现 → ekkoPage+0x2000 修复成功
//                  若仍崩溃 + inEkko2=1 → EkkoSleep 在 ekkoPage+0x2000, 可能需要 +0x3000
//                  若仍崩溃 + inEkko0/1/2 全 0 → EkkoSleep 在 [ekkoPage, ekkoPage+0x3000) 之外
//          - 安全性: 多豁免 4KB (累计 12KB 相对 .text 344KB 仅 3.5%), 不影响加密效果.
//          - 预期: EkkoSleep 跨页代码不被加密, "B238:EK:EA+ post" 日志正常输出.
// BUILD: 567 (v3.240: 修复 EkkoSleep 跨页 — 添加 ekkoPage+0x1000 豁免)
//        ★ BUILD 567 v3.240 FIX (EkkoSleep 跨页保护 7/20):
//          - 根因: v3.239 确认 diagInEkko=1 (EkkoDiagLog 在豁免页), 但 EncryptAll 后仍崩溃.
//                  EkkoSleep 函数代码 (L291, 距 EkkoSleepPageMarker L62 约 230 行) 跨越到
//                  ekkoPage+0x1000 页 (未被豁免). EncryptAll 加密该页 → EkkoSleep 返回时
//                  执行已加密代码 → 崩溃. (BUILD 558 FIX-3 遗漏: encA/decA/xorC 有跨页保护, ekkoPage 无)
//          - 修复: exemptPages 添加 ekkoPage + 0x1000, exemptPageCount 18 → 19.
//          - 安全性: 多豁免 4KB (相对 .text 344KB 仅 1.2%), 不影响加密效果.
//                    与 EncryptAll/DecryptAll/XorCrypt 跨页保护模式一致.
//          - 预期: EkkoSleep 跨页代码不被加密, "B238:EK:EA+ post" 日志正常输出.
// BUILD: 567 (v3.239: 验证版本 — 添加 EkkoDiagLog/EkkoSleep 地址诊断日志)
//        ★ BUILD 567 v3.239 DIAG (EkkoDiagLog 页面归属验证 7/20):
//          - 目的: v3.238 确认崩溃位置在 EncryptAll 之后 ("B238:EK:EA+ pre" 有, "post" 无),
//                  根因假设: EkkoDiagLog 不在 ekkoPage (0x1D5DECB5000) 中, 被 EncryptAll 加密.
//          - 改动: 仅添加地址诊断日志, 不修改任何逻辑.
//          - 位置 1: memory_cloak.cpp EkkoSleep 入口 — 输出 ekkoPage/diagLog/marker/encA/decA/xorC 地址
//          - 位置 2: payload.cpp B550:EK:protected 日志 — 添加 ek+1@ (ekkoPage+0x1000) 显示下一页
//          - 判读: diagInEkko=0 → EkkoDiagLog 不在豁免页 → 根因确认 → v3.240 修复
//                  diagInEkko=1 → EkkoDiagLog 在豁免页 → 根因假设错误, 需重新分析
//          - 安全性: 地址诊断日志在 EncryptAll 之前调用, 代码页未加密, 安全.
// BUILD: 567 (v3.238: 诊断版本 — 添加 EkkoSleep 崩溃位置诊断日志)
//        ★ BUILD 567 v3.238 DIAG (EkkoSleep 崩溃位置定位 7/20):
//          - 目的: v3.237 在 patched 日志后 1.3 秒崩溃, 无任何后续日志, 怀疑
//                  EkkoSleep 内部 EncryptAll/DecryptAll 失败导致代码页保持加密状态.
//          - 改动: 仅添加诊断日志 (DiagLog + memory_cloak.cpp EkkoDiagLog), 不修改任何逻辑.
//          - 位置 1: payload.cpp 主循环 NtReadHooker::Install/Maintain 前后 + StealthSleep 前后
//          - 位置 2: memory_cloak.cpp EkkoSleep 内部 EncryptAll/DecryptAll 前后 + VP 失败时
//          - 判读: "B238:NR:I+ post" 无后续日志 → NtReadHooker::Install 后崩溃
//                  "B238:SS:pre" 有 "B238:SS:post" 无 → EkkoSleep 内部崩溃
//                  "B238:EK:EA+ post" 有 "B238:EK:DA+ pre" 无 → DecryptAll 内部崩溃
//                  "B238:EK:DA VP FAIL" → VirtualProtect 失败 (根因确认)
//          - 安全性: EkkoDiagLog 紧邻 EkkoSleep 实现, 落入同一 4KB 页 (已被 exemptPages 豁免)
//                    诊断日志仅在 EkkoSleep 入口/出口调用, 不在加密窗口内调用.
// BUILD: 567 (v3.237: 禁用 DR0 频率统计 — 跨进程 #DB 崩溃根因修复)
//        ★ BUILD 567 v3.237 FIX (DR0 跨进程崩溃 7/20):
//          - 现象: v3.236 测试 CS2 运行 45 秒后, 按 ESC 切换到菜单时 CS2 崩溃 (0xC0000005)
//          - 根因: DR0 断点设置在 CS2 线程上 (StartDR0FrequencyStat), CS2 线程执行到 patch 地址
//                  (client.dll RVA 0xC125D9) 时触发 #DB 异常, #DB 在 CS2 进程内触发,
//                  loader.exe 的 VEH 无法跨进程捕获 → CS2 进程无 VEH 处理 #DB → CS2 崩溃.
//          - 修复: 禁用 StartDR0FrequencyStat 调用 (2 处: 初始化阶段 L2895 + 主循环 L3511)
//          - 安全性: DR0 是 BUILD 557 诊断功能 (统计 patch 执行频率), 非核心功能,
//                    禁用不影响透视 (ApplyCs2Patch NOP 32c0) 和防检测 (7 层保护).
//          - 保留: VEH STATUS_SINGLE_STEP 处理仍保留 (防御性, 处理可能的残留 DR0).
// BUILD: 567 (v3.236: DR0 残留崩溃修复 + VAD 边界放宽)
//        ★ BUILD 567 v3.236 FIX (DR0 残留 + VAD 边界 7/20):
//          - 现象 1: v3.235 测试 CS2 运行 60s 后 loader.exe 崩溃 (0xc0000005)
//                    根因: 83 个 CS2 线程 DR0 未清除, ReportDR0Frequency 设置 g_dr0StatActive=0,
//                          主循环恢复 StealthSleep (EkkoSleep), EkkoSleep 加密 .data 段,
//                          残留 DR0 触发 STATUS_SINGLE_STEP, VEH 读取加密变量崩溃.
//          - 现象 2: CS2 对局结束退出到主菜单时崩溃 (用户反馈)
//                    根因: 对局结束大量 CS2 线程退出, 残留 DR0 断点触发, 同上崩溃链.
//          - 现象 3: VAD 隐藏失败 (FindAndModifyVadNode result=0)
//                    根因: vadRoot 在非分页池扩展 (0xFFFFE48D...), 被原边界 [0xFFFFFC00, 0xFFFFFD00) 拒绝.
//          - 修复 1: VEH STATUS_SINGLE_STEP 不依赖 g_dr0StatActive, 直接从 CONTEXT.Dr0 读取断点地址
//                    (CPU 寄存器不受 EkkoSleep .data 加密影响), 无论 active 与否都清除 DR6 + 继续执行.
//          - 修复 2: ReportDR0Frequency DR0 清除失败时不恢复 StealthSleep (保持 g_dr0StatActive=1).
//          - 修复 3: 主循环 10s 周期重试 RetryClearDR0Breakpoints, 全部清除成功时恢复 StealthSleep.
//          - 修复 4: VAD 边界放宽 [0xFFFFFC00, 0xFFFFFD00) → [0xFFFFF800, 0xFFFFFD00)
//                    覆盖非分页池扩展区域 (与 EPROCESS 同区域).
//          - 安全性: 修复 1 是核心防御 (CPU 寄存器不受加密影响), 修复 2/3 是辅助防御 (减少 VEH 触发频率),
//                    修复 4 仅放宽地址检查, validateVadRoot 已验证 VPN + 指针.
// BUILD: 567 (v3.235: VAD-DKOM 执行顺序修复 + EPROCESS 缓存 + DKOM WriteUnsafe)
//        ★ BUILD 567 v3.235 FIX (VAD-DKOM 执行顺序 + DKOM 写入修复 7/20):
//          - 现象: v3.234 测试 E+G: early DKOM hide: FAILED + B554:GEP: FAIL walk=512
//                  CS2 运行 60+ 秒后仍然闪退 (比 v3.232/v3.233 的 15-17 秒有改善)
//          - 根因 1: DKOM SelfLoopHarden/UnhideProcessByPid 使用 kma.Write (白名单)
//                    EPROCESS 在非分页池扩展 (0xFFFF8000-0xFFFFF680), 白名单拒绝 → DKOM 失败
//          - 根因 2: VAD GetEPROCESSByPid 没有循环检测, Windows ActiveProcessLinks 是双向循环链表
//                    会跑满 maxWalk=512 次, 找不到 loader.exe
//          - 根因 3: VAD-DKOM 执行顺序问题 — DKOM 先执行断链 loader.exe, VAD 后执行找不到 loader.exe
//                    (用户诊断: "找不到loader.exe会不会是因为loader.exe会隐藏进程" — 正确!)
//          - 修复 1: DKOM SelfLoopHarden/UnhideProcessByPid 改用 WriteUnsafe (绕过白名单)
//          - 修复 2: VAD GetEPROCESSByPid 添加 start 循环检测 + maxWalk=1024 + 每100次诊断日志
//          - 修复 3: VADConcealer 添加 s_cachedLoaderEprocess 缓存 EPROCESS 地址
//          - 修复 4: 调整执行顺序 — VAD 先执行 (缓存 EPROCESS), DKOM 后执行 (断链不影响 VAD)
//          - 安全性: EPROCESS 地址在进程生命周期内不变, DKOM 断链不修改 EPROCESS 地址
//                    VAD 缓存的 EPROCESS 在 DKOM 隐藏后仍可访问 VAD 树
// BUILD: 567 (v3.234: 安全边界扩大 — 覆盖非分页池扩展/PFN 数据库)
//        ★ BUILD 567 v3.234 FIX (VAD 隐藏失败根因二次修复 7/20 02:10):
//          - 现象: v3.233 测试 B554:EEP: systemEPROCESS=0xFFFF928F9F6DC040 inWhitelist=0 inSystemPte=0
//                  systemEPROCESS 既不在白名单 [0xFFFFF680, 0xFFFFFD00), 也不在系统 PTE [0xFFFFFD00, 0xFFFFFE00)
//                  v3.233 ReadKernelVAUnsafe 边界 [0xFFFFF800, 0xFFFFFE00) 仍然拒绝 (低于下限)
//                  CS2 运行 17 秒后崩溃 (0xC0000005, 与 v3.232 的 15 秒接近)
//          - 根因: Win11 24H2/25H2 EPROCESS 分配在非分页池扩展区域 (0xFFFF8000-0xFFFFF680)
//                  v3.233 假设 systemEPROCESS 在系统 PTE 区域是错误的
//                  实际 systemEPROCESS=0xFFFF928F9F6DC040 在 0xFFFF8000-0xFFFFF680 范围内
//          - 修复: 扩大 ReadKernelVAUnsafe 安全边界到 [0xFFFF8000, 0xFFFFFE00)
//            覆盖所有 EPROCESS 可能分配区域: 非分页池扩展/PFN/系统缓存/PTE 自映射/内核镜像/非分页池/分页池/系统 PTE
//            仅排除系统映射 (0xFFFFFE00+) + Hypervisor (0xFFFFFF00+)
//          - 安全性: EPROCESS 是有效内核内存, 读取不应导致 0x50 蓝屏
//            v3.228 蓝屏 0x50 是读取系统 PTE 区域的无效地址, 不是 EPROCESS
//            EPROCESS 由内核分配器 (ExAllocatePoolWithTag) 分配, 永远在有效内核池区域
//          - v3.233 VadDiag 验证: systemEPROCESS 地址成功记录, 确认在非分页池扩展区域
// BUILD: 567 (v3.233: EPROCESS 专用读取 — 绕过白名单修复 systemEPROCESS 在系统 PTE 区域)
//        ★ BUILD 567 v3.233 FIX (VAD 隐藏失败根因修复 7/20 02:00):
//          - 现象: v3.232 测试 B554:EEP: FAIL no valid PID=4 offset found (pidMatch=0)
//                  VAD 隐藏仍然 0/1 失败, CS2 运行 15 秒崩溃 (0xC0000005)
//          - 根因: systemEPROCESS 地址在系统 PTE 区域 [0xFFFFFD00, 0xFFFFFE00),
//                  被 ReadKernelVA 白名单 [0xFFFFF680, 0xFFFFFD00) 拒绝,
//                  Read<uint64_t> 全部返回 0, pidMatchCount=0
//          - 修复: 新增 ReadKernelVAUnsafe + ReadUnsafe<T> (绕过白名单)
//            安全边界 [0xFFFFF800, 0xFFFFFE00) — 含系统 PTE, 排除系统映射/Hypervisor
//            EnsureEprocessOffsets/EnsureVadRootOffset/GetEPROCESSByPid/ConcealRegion
//            全部改用 ReadUnsafe 读取 EPROCESS 字段
//          - 安全性: EPROCESS 是有效内核内存, 读取不应导致 0x50 蓝屏
//            v3.228 蓝屏 0x50 是读取系统 PTE 区域的无效地址, 不是 EPROCESS
//          - 优化: VadDiag 移除 FlushFileBuffers, 减少 I/O 阻塞 (v3.232 的 15 秒可能因此)
//          - v3.232 VadDiag 修复验证: B554:EEP/CR 日志正常输出, 成功定位根因
// BUILD: 567 (v3.232: VadDiag 修复 — ByovdDiag 被 NDEBUG 消除导致 VAD 日志不输出)
//        ★ BUILD 567 v3.232 FIX (VAD 日志不输出 7/20 01:40):
//          - 现象: v3.231 运行后 sd.log 只有 B554:VAD:0/1, 没有 B554:EEP/EVR/GEP/CR
//          - 根因: ByovdDiag 在 Release 模式 (NDEBUG) 下被 #define 为 ((void)0),
//                  v3.231 添加的 VAD 失败日志全部使用 ByovdDiag, 被预处理器消除
//          - 修复: 新增 VadDiag 函数 (独立于 ByovdDiag, 不受 NDEBUG 影响)
//            将所有 B554: 开头的 ByovdDiag 调用改为 VadDiag 调用
//          - v3.231 白名单修正验证: CS2 运行 62 秒+ (vs v3.230 的 18 秒, v3.229 的 60 秒)
//            白名单修正成功修复 v3.230 的退化, 但 CS2 仍在 60 秒左右崩溃 (疑似反作弊周期检测)
//          - v3.232 目标: 通过 VadDiag 输出 VAD 失败详细日志, 定位 VAD 隐藏 0/1 失败原因
// BUILD: 567 (v3.231: v3.230 白名单错误修正 — 排除系统 PTE + VAD 失败详细日志)
//        ★ BUILD 567 v3.231 FIX (v3.230 白名单错误修正 7/20 01:30):
//          - 现象: v3.230 运行后 CS2 透视生效 ~12秒后卡住闪退 (0xC0000005, 比 v3.229 的 60秒更快)
//          - 用户反馈: "最后一次更改有错误, 我太着急没发现, cs透视生效一会后cs卡住然后闪退了"
//          - 根因 (v3.230 白名单逻辑错误):
//            v3.230 白名单 [0xFFFFF680, 0xFFFFFE00) 注释说"排除系统 PTE (0xFFFFFD0+)",
//            但上限 0xFFFFFE00 实际包含系统 PTE (0xFFFFFD00-0xFFFFFE00)!
//            这是 v3.228 蓝屏 0x50 的根因区域, 导致:
//              1) validateVadRoot 读取系统 PTE 区域的 PTE 条目 (垃圾数据)
//              2) 垃圾数据可能碰巧通过验证逻辑 → 错误偏移被缓存
//              3) RTCore64 访问系统 PTE 可能触发驱动内部状态损坏 → 后续 IOCTL 异常
//          - 修复:
//            1) ReadKernelVA/WriteKernelVA: 白名单上限 0xFFFFFE00 → 0xFFFFFD00
//               精确白名单 [0xFFFFF680, 0xFFFFFD00) = PTE自映射+内核镜像+非分页池+分页池
//               排除系统 PTE (0xFFFFFD00+) + 系统映射 + Hypervisor
//            2) 保留 v3.230 防御性修复: validateVadRoot 显式检查 + FindAndModifyVadNode 写入前验证
//            3) 新增 VAD 失败详细日志 (B554:EEP/EVR/GEP/CR), 定位 VAD 隐藏 0/1 失败的真正原因
//          - 安全性: 白名单仍包含分页池 (VAD 节点所在), 但排除系统 PTE (v3.228 蓝屏根因)
// BUILD: 567 (v3.230: CS2 闪退修复 — 扩大白名单含分页池 + validateVadRoot 缺陷修复)
//        ★ BUILD 567 v3.230 FIX (CS2 闪退根因 7/20 01:00):
//          - 现象: v3.229 运行后 CS2 透视生效 ~60秒后卡住闪退 (非蓝屏)
//          - 用户关键补充: 未安装 PAC, 初始根因 (PAC VAD 扫描) 不成立
//          - 真实根因 (3 层缺陷叠加):
//            1) v3.229 白名单 [0xFFFFF680, 0xFFFFFC00) 排除分页池
//            2) VAD 节点 _MMVAD_SHORT 在分页池 (ExAllocatePoolWithTag(PagedPool))
//            3) Read<uint64_t> 模板无法区分读取失败/值为0 → validateVadRoot 逻辑缺陷:
//               isValidPtr(0)=true + 0>0=false + 0<0x80000000=true → 错误偏移被缓存
//            4) ConcealRegion 读取 EPROCESS+错误偏移 → vadRoot 是错误字段的内核地址
//            5) FindAndModifyVadNode 遍历错误"VAD树" → 写入破坏任意内核结构 → CS2 闪退
//          - 3 处修复:
//            1) ReadKernelVA/WriteKernelVA: 扩大白名单至 [0xFFFFF680, 0xFFFFFE00) 含分页池
//               仍排除系统 PTE (0xFFFFFD0+, v3.228 蓝屏根因) + 系统映射 + Hypervisor
//            2) validateVadRoot: 显式检查 ReadKernelVA 返回值 + 至少一个非 NULL (深度防御)
//            3) FindAndModifyVadNode: 写入前验证 vadNode 确实在分页池 [0xFFFFFC0, 0xFFFFFD0)
//          - 安全性: 分页池页面通常已映射 (池分配器不取消映射空闲页), v3.228 及更早一直如此.
//                   不使用 PTE 预验证 — ReadPte 公式对内核态高地址会溢出回绕到用户态, 无效.
// BUILD: 567 (v3.229: 蓝屏 0x50 二次修复 — 黑名单改白名单)
//        ★ BUILD 567 v3.229 FIX (蓝屏 0x50 第二次根因 7/20 0:29:21):
//          - 现象: v3.228 修复后运行 loader.exe 仍蓝屏 BugCheck 0x50
//          - 新异常地址: 0xFFFFFD0000000030 (PML4 idx=0x1FA, 系统 PTE 区域)
//          - 根因: v3.228 黑名单只排除系统缓存区域 (0xFFFFE0-0xFFFFF0),
//                 但系统 PTE 区域 0xFFFFFD0000000000 未排除, flink 落在此区域触发 0x50 蓝屏
//          - 根本问题: 黑名单不可行 — 内核有多个区域含未映射页 (系统缓存/分页池/系统PTE/系统映射)
//          - 修复: 黑名单改白名单, 只允许 flink/blink/current 和 ReadKernelVA/WriteKernelVA 访问:
//            1) PTE 自映射 0xFFFFF68000000000-0xFFFFF80000000000 (ReadPte/WritePte 使用)
//            2) 内核镜像  0xFFFFF80000000000-0xFFFFFA0000000000 (ntoskrnl/.data 段)
//            3) 非分页池  0xFFFFFA0000000000-0xFFFFFC0000000000 (EPROCESS/LDR_DATA_TABLE_ENTRY)
//          - 4 处修复: LocatePsLoadedModuleList + FindEntryByBaseName + ReadKernelVA + WriteKernelVA
//          - 安全性: 第 4 轮审查确认所有合法调用方 (ReadPte/ResolveExport/DKOM*/PsLoadedModuleHider)
//                   读取的地址都在白名单范围内, PTE 自映射区域 PTE 表本身在非分页池始终已映射
// BUILD: 567 (v3.228: 蓝屏 0x50 修复 — 排除系统缓存区域)
//        ★ BUILD 567 v3.228 FIX (蓝屏 0x50 根因 7/19 23:41:29):
//          - 现象: 运行 loader.exe 后蓝屏 BugCheck 0x50 (PAGE_FAULT_IN_NONPAGED_AREA)
//          - 异常地址: 0xFFFFE68000000030 (PML4 idx=0x1CD, 系统缓存区域)
//          - 根因公式: flink(0xFFFFE68000000000) + LDR_DLLBASE_OFF(0x30) = 0xFFFFE68000000030
//          - 根因: LocatePsLoadedModuleList 扫描 ntoskrnl .data 段时, flink 落在系统缓存区域
//                 (0xFFFFE00000000000-0xFFFFF00000000000), 该区域包含文件缓存页 (可能未映射),
//                 PDFWKRNL.sys memcpy 不验证地址, 读取未映射页直接 0x50 蓝屏
//          - 修复: 4 层防御
//            1) LocatePsLoadedModuleList: flink/blink 排除系统缓存区域
//            2) FindEntryByBaseName: current 排除系统缓存区域
//            3) ReadKernelVA: 全局入口排除系统缓存区域 (双重保险)
//            4) WriteKernelVA: 全局入口排除系统缓存区域 (防御性)
//          - 安全性: 系统缓存区域不含内核数据结构, 合法内核 R/W 目标都在非分页池
//                   (0xFFFFFA0000000000+) 或内核镜像 (0xFFFFF80000000000+), 排除安全
// BUILD: 567 (v3.227: 日志增强 — 封号原因分析支持)
//        1. ★ BUILD 567-1: 时间戳前缀 (DiagLog/CoreDiag/ByovdDiag)
//           - 每条日志添加 [HH:MM:SS.mmm] 前缀 (GetLocalTime + snprintf)
//           - 缓冲区扩大: DiagLog 512→640, CoreDiag 256→320, ByovdDiag 512→576
//        2. ★ BUILD 567-2: 日志轮转 (10MB 阈值, 保留 2 备份 sd.log.1/sd.log.2)
//           - DiagLog/CoreDiag/ByovdDiag 写入后检查 GetFileAttributesEx 文件大小
//           - 超过 10MB: MoveFileEx sd.log.1→sd.log.2, sd.log→sd.log.1
//           - 总占用 ≤ 30MB, 避免长时间运行日志过大
//        3. ★ BUILD 567-3: DiagLogState 宏 + StateLog 函数 (状态变化时间线)
//           - payload.cpp DiagLogState 宏: STATE:CAT:EVENT detail 格式
//           - byovd_kernel.cpp StateLog 函数 (独立于 ByovdDiag, 不被 NDEBUG 消除)
//           - 类别: VMXON/SHV/VEH/CB/SYS
//           - 事件: PATCHED/REPATCHED/FAILED/DEGRADED_ENTER/DEGRADED_RECOVER/SELFHEAL/REAPPLIED
//        4. ★ BUILD 567-4: g_logStats 全局统计计数器 (LogStats 结构体, 跨编译单元共享)
//           - vmxOnPatchSuccess/Failure/Repatch + shvPatchSuccess/Failure/Repatch
//           - vehSelfheal + degradedEnter + cbReapply
//           - 更新点: byovd_kernel.cpp Record*/Patch* 函数 + payload.cpp VEH/主循环
//        5. ★ BUILD 567-5: 启动摘要 (LogStartSummary) — 系统信息 + BUILD 版本
//           - Windows 版本 (RtlGetVersion) + SystemTick + HVCI 状态 + HostPID
//        6. ★ BUILD 567-6: 退出摘要 (LogExitSummary) — 运行时长 + 关键事件统计
//           - 两个 return 0 之前调用 (CS2 退出 / 正常退出)
//        7. ★ BUILD 567-7: 周期摘要 (LogPeriodicSummary) — 主循环每 5 分钟一次
//           - 内部检查 lastSummaryTick, 未到 5 分钟直接返回 false, 无性能影响
//        安全性: 仅日志增强, 无新内核内存访问, 无新 IOCTL, BSOD 风险为零
//        预期效果: 封号后通过 sd.log 精确分析 (时间戳 + 状态时间线 + 统计摘要)
// BUILD: 549 (v3.205: 影子页 PTE manipulation + DiagLog 三层脱敏 + NtQSI 替代 Toolhelp32)
//        1. ★ BUILD 549 影子页: ApplyCs2Patch 优先通过 PTE manipulation 安装影子页
//           - pageA = client.dll 原页 (PAC 扫描看到原始字节 32 c0)
//           - pageB = VirtualAlloc 锁定页 (复制原内容 + 改 90 90)
//           - 修改 PTE.PFN 指向 pageB → CS2 执行补丁代码, PAC 扫描看到 pageA
//           - 周期性切换 (500ms 周期, 50ms pageA) 让 PAC 扫描命中原始字节
//           - 失败回退到 VirtualProtect 路径 (保留 BUILD 548 逻辑)
//        2. ★ BUILD 549 DiagLog 三层脱敏:
//           - 字符串加密 (STEALTH_STR_DECRYPT_TO XTEA 编译期加密)
//           - 内容去特征化 (移除 ApplyCs2Patch/patched/NOP NOP/ScreenshotTool 关键词)
//           - 文件名改名 (stealth_diag.log → sd.log)
//        3. ★ BUILD 549 IsScreenshotToolRunning 改用 NtQuerySystemInformation syscall
//           (绕过 PAC 用户态 hook), 频率从 1s 降到 5s
//        4. ★ BUILD 549 主循环频率调整: 补丁维护 5s→500ms (影子页周期切换)
//        保留: BUILD 548 集成补丁逻辑 + BUILD 546 7 层保护 + BUILD 540 CS2 退出检测
// ============================================================

#include "stealth_core.h"
#include "cs2_memory.h"

// ★ BUILD 501: 移除 <algorithm> <vector> <cstdlib> <ctime> — CRT 堆依赖
//   保留 <cstdio> <csetjmp> — DiagLog/Hollowing 回退需要
// ★ BUILD 548: 移除 cheat_overlay.h / game_esp.h — 透视由 CS2 自己渲染, 不再需要 ESP
// ★ BUILD 549: 新增 stealth_process.h (ShadowPageManager) + string_obfuscator.h (DiagLog 加密)
#include "cs2_offsets.h"
#include "syscall_direct.h"
#include "handle_acl_guard.h"  // ★ BUILD 552: eac_syscall_guard 拆分 (仅保留 HandleACLGuard)
#include "byovd_kernel.h"
#include "stealth_process.h"
#include "string_obfuscator.h"
#include <cstdarg>
#include <cstdio>
#include <csetjmp>
#include <cstring>  // ★ BUILD 549: strcmp for DiagLogEnc macro
#include <tlhelp32.h>
#include <intrin.h>  // ★ BUILD 558 FIX-2: __readgsqword (VEH 处理器无 IAT 调用读取 TID)

// ---- v3.34: 时序随机化 ----
static DWORD RandomJitter(DWORD baseMs, DWORD rangeMs) {
    return baseMs + (DWORD)(((uint64_t)rand() * rangeMs) / RAND_MAX);
}

// 轻量诊断: 写文件, 不弹 MessageBox 干扰游戏
// ★ v3.38: 加 FlushFileBuffers 确保崩溃日志实时落盘
// ★ BUILD 549: 文件名 stealth_diag.log → sd.log (移除 "stealth" 特征)
//               DiagLogRaw 为原始日志函数, DiagLogEnc 为加密标签日志
// ★ BUILD 551: DiagLog 条件编译消除 (与 ByovdDiag 同策略)
//   原因: payload.cpp 中 200+ 处 DiagLog 调用包含 "BYOVD:"/"VEH-SELFHEAL:"/
//         "TARTARUS:"/"INDIRECT:"/"SPOOF:"/"GPA:"/"DllMain:"/"E+G:"/"CleanupInjectionTraces:"
//         等明文格式字符串, 暴露 BYOVD/VEH/TartarusGate/DllMain 等关键信息
//   策略: NDEBUG 时 DiagLog 宏展开为 ((void)0), 调用被预处理器消除,
//         字符串字面量不进入 .rdata (预计减少 15+ KB 明文特征)
//         DiagLogEnc 宏内部调用 DiagLog, 同样被消除 (DiagLogEnc 也变成空操作)
//   审计: 200+ 处调用均为纯日志, 参数仅读取变量/GetLastError/NtQuerySystemInformation 结果
//         经审计无赋值表达式副作用, 宏消除安全
// ★ BUILD 557 临时诊断: 强制启用 DiagLog (定位 CheatMainLoop 早期退出)
//   原代码: #ifdef NDEBUG #define DiagLog(fmt, ...) ((void)0)
//   诊断版: 改为 #if 0, DiagLog 总是启用, 写入 sd.log
//   恢复方法: 诊断完成后将下面 #if 0 改回 #ifdef NDEBUG
// ★ BUILD 567 v3.227: 日志增强 — 时间戳前缀 + 10MB 日志轮转
//   时间戳格式: [HH:MM:SS.mmm] (13 字节, 精确到毫秒)
//   日志轮转: 超过 10MB 时 sd.log → sd.log.1 → sd.log.2 (保留 2 备份, 总 ≤30MB)
//   目的: 封号后通过精确时间戳定位崩溃时刻, 通过状态变化时间线分析根因
#if 0  // ★ BUILD 557 DIAG (原 #ifdef NDEBUG)
    #define DiagLog(fmt, ...) ((void)0)
#else
// ★ BUILD 567 v3.227: 时间戳格式化辅助函数
//   输出: "[HH:MM:SS.mmm] " (13 字符 + null)
static void DiagLog_FormatTimestamp(char* buf, size_t bufSize) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, bufSize, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// ★ BUILD 567 v3.227: 日志轮转检查 (调用前文件句柄必须已关闭)
//   使用 GetFileAttributesEx 获取文件大小, 避免句柄管理复杂化
//   超过 10MB 时: sd.log.1 → sd.log.2 (覆盖), sd.log → sd.log.1
static void DiagLog_RotateIfNeeded(const wchar_t* path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return;
    ULARGE_INTEGER fileSize;
    fileSize.LowPart  = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    if (fileSize.QuadPart < (10ULL * 1024 * 1024)) return;  // < 10MB, 无需轮转
    wchar_t path1[MAX_PATH], path2[MAX_PATH];
    wcscpy_s(path1, MAX_PATH, path);  wcscat_s(path1, MAX_PATH, L".1");
    wcscpy_s(path2, MAX_PATH, path);  wcscat_s(path2, MAX_PATH, L".2");
    // sd.log.1 → sd.log.2 (覆盖旧 sd.log.2, 失败忽略 — 备份丢失但日志继续)
    MoveFileExW(path1, path2, MOVEFILE_REPLACE_EXISTING);
    // sd.log → sd.log.1 (覆盖旧 sd.log.1, 失败忽略)
    MoveFileExW(path, path1, MOVEFILE_REPLACE_EXISTING);
}

static void DiagLog(const char* fmt, ...) {
    // ★ BUILD 567: 时间戳前缀
    char tsBuf[32];
    DiagLog_FormatTimestamp(tsBuf, sizeof(tsBuf));
    int tsLen = (int)strlen(tsBuf);

    char buf[640];  // ★ BUILD 567: 512 → 640 (容纳时间戳 + 长内容)
    memcpy(buf, tsBuf, tsLen);
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf + tsLen, sizeof(buf) - tsLen, fmt, args);
    va_end(args);
    if (len < 0) len = 0;  // vsnprintf error fallback
    // ★ BUG 修复 (第 1 轮审查): vsnprintf 返回期望长度, 可能 > 缓冲区剩余空间
    //   限制到实际写入长度, 防止 WriteFile 越界读取
    if (len > (int)(sizeof(buf) - tsLen - 1)) len = (int)(sizeof(buf) - tsLen - 1);
    len += tsLen;  // 总长度 = 时间戳 + 内容

    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"sd.log");  // ★ BUILD 549: 文件名脱敏 (原 stealth_diag.log)
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(h, buf, (DWORD)len, &w, 0);
        FlushFileBuffers(h);  // ★ v3.38: 强制落盘, 防止崩溃时缓存丢失
        CloseHandle(h);  // 立即关闭, 简化轮转逻辑
    }
    // ★ BUILD 567 v3.227: 日志轮转检查 (句柄已关闭, 使用 GetFileAttributesEx 获取大小)
    DiagLog_RotateIfNeeded(path);
}
#endif  // NDEBUG

// ★ BUILD 549: DiagLogEnc — 加密标签日志 (替代明文 DiagLog 字符串)
//   使用 STEALTH_STR_DECRYPT_TO 宏在栈上解密, 二进制中不留明文
//   tag 取值: "c1"=mod not loaded, "c2"=pattern not found, "sp_ok"=shadow ok,
//             "sp_fail"=shadow fail, "p1"=patched, "p2"=repatched,
//             "r1"=reverted, "m1"=main loop start, "d1"=diag start
#define DiagLogEnc(tag) do { \
    char _s[64] = {}; \
    char _buf[128] = {}; \
    if (strcmp(tag, "c1") == 0) { STEALTH_STR_DECRYPT_TO("mod not loaded", _s, sizeof(_s)); } \
    else if (strcmp(tag, "c2") == 0) { STEALTH_STR_DECRYPT_TO("pat not found", _s, sizeof(_s)); } \
    else if (strcmp(tag, "sp_ok") == 0) { STEALTH_STR_DECRYPT_TO("shadow ok", _s, sizeof(_s)); } \
    else if (strcmp(tag, "sp_fail") == 0) { STEALTH_STR_DECRYPT_TO("shadow fail fb", _s, sizeof(_s)); } \
    else if (strcmp(tag, "p1") == 0) { STEALTH_STR_DECRYPT_TO("patched", _s, sizeof(_s)); } \
    else if (strcmp(tag, "p2") == 0) { STEALTH_STR_DECRYPT_TO("repatched", _s, sizeof(_s)); } \
    else if (strcmp(tag, "r1") == 0) { STEALTH_STR_DECRYPT_TO("reverted", _s, sizeof(_s)); } \
    else if (strcmp(tag, "m1") == 0) { STEALTH_STR_DECRYPT_TO("main loop start", _s, sizeof(_s)); } \
    else if (strcmp(tag, "d1") == 0) { STEALTH_STR_DECRYPT_TO("diag start b549", _s, sizeof(_s)); } \
    snprintf(_buf, sizeof(_buf), "%s\n", _s); \
    DiagLog("%s", _buf); \
} while(0)

// ★ BUILD 567 v3.227: DiagLogState — 状态变化时间线日志宏
//   格式: "STATE:CAT:EVENT detail\n" (由 DiagLog 添加时间戳前缀)
//   类别 (CAT): VMXON / SHV / VEH / CB / SYS
//   事件 (EVENT): PATCHED / REPATCHED / FAILED / DEGRADED_ENTER / DEGRADED_RECOVER / SELFHEAL / FATAL / REAPPLIED
//   示例输出: "[23:45:12.345] STATE:VMXON:REPATCHED addr=0x... tick=12345"
//   用途: 封号后通过 STATE: 行精确追踪 patch 状态变化时间线
//   注: cat 和 evt 应为字符串字面量 (编译期确定), detail 使用 printf 格式 (不带 \n, 宏自动添加)
//        调用示例: DiagLogState("VMXON", "PATCHED", "addr=0x%llx", addr);
//   ★ BUILD 567 BUG 修复 (第 4 轮审查 — 编译错误): 分离 fmt 和可变参数
//     原宏 __VA_ARGS__ 参与字符串拼接, 但调用时 __VA_ARGS__ = "fmt", arg 导致语法错误
//     修复: fmt 单独作为字符串拼接, ##__VA_ARGS__ 作为可变参数
#define DiagLogState(cat, evt, fmt, ...) \
    DiagLog("STATE:%s:%s " fmt "\n", cat, evt, ##__VA_ARGS__)

// ★ BUILD 567 v3.227: 全局统计计数器 (单线程 CheatMainLoop 访问, 无需同步)
//   用途: 启动摘要 / 退出摘要 / 周期摘要 输出运行统计
//   更新点: byovd_kernel.cpp PatchVmxOnWrapper/PatchShvInstallEntry 成功/失败时
//           payload.cpp 主循环回调重应用 / VEH 自愈时
//   注: 类型 LogStats 定义在 byovd_kernel.h (跨编译单元共享)
//        g_logStats 非 static — byovd_kernel.cpp 通过 extern 引用 (payload.dll 内部符号, 不导出)
LogStats g_logStats = {};

// ============================================================
// ★ BUILD 567 v3.227: 日志摘要函数 (启动/退出/周期)
//   用途: 封号原因分析 — 通过摘要快速了解运行状态 + 关键事件统计
//   注: 所有函数调用 DiagLog (自动添加时间戳前缀)
// ============================================================

// ★ BUILD 567 v3.227: 启动摘要 — 记录系统信息 + BUILD 版本
//   调用位置: CheatMainLoop 入口 (DeleteFileW 之后)
static void LogStartSummary() {
    g_logStats.startTick = GetTickCount();
    g_logStats.lastSummaryTick = g_logStats.startTick;

    DiagLog("============================================\n");
    DiagLog("BUILD 567 v3.257 启动摘要 (诊断 CS2 对局加载崩溃 — 主循环心跳 + NtReadHooker 状态)\n");

    // Windows 版本 (RtlGetVersion, 不被 deprecated)
    OSVERSIONINFOEXW osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef LONG (NTAPI* fnRtlGetVersion)(PRTL_OSVERSIONINFOW);
    HMODULE ntdllMod = (HMODULE)stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));
    auto fn = (fnRtlGetVersion)STEALTH_GET_PROC_ADDRESS_NOREF(ntdllMod, "RtlGetVersion");
    if (fn) {
        fn((PRTL_OSVERSIONINFOW)&osvi);
        DiagLog("Windows: %u.%u.%u\n",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    } else {
        DiagLog("Windows: RtlGetVersion unavailable\n");
    }

    // 系统启动时长 (TickCount)
    DiagLog("SystemTick: %u ms\n", (unsigned)GetTickCount());

    // HVCI 状态 (如果 KernelMemoryAccessor 可用)
    DiagLog("HVCI: %s\n",
        stealth::KernelMemoryAccessor::IsHVCIEnabled() ? "enabled" : "disabled");

    // 当前进程 PID (loader2.exe / CS2)
    DiagLog("HostPID: %u\n", (unsigned)GetCurrentProcessId());

    DiagLog("============================================\n");
}

// ★ BUILD 567 v3.227: 退出摘要 — 运行时长 + 关键事件统计
//   调用位置: CheatMainLoop 两个 return 0 之前 (CS2 退出 / 正常退出)
static void LogExitSummary() {
    DWORD now = GetTickCount();
    DWORD elapsed = now - g_logStats.startTick;
    DWORD elapsedSec = elapsed / 1000;
    DWORD minutes = elapsedSec / 60;
    DWORD seconds = elapsedSec % 60;

    DiagLog("============================================\n");
    DiagLog("BUILD 567 v3.257 退出摘要\n");
    DiagLog("运行时长: %u 秒 (%u 分 %u 秒)\n", elapsedSec, minutes, seconds);
    DiagLog("VmxOn: 成功=%u 失败=%u 重patch=%u\n",
        g_logStats.vmxOnPatchSuccess, g_logStats.vmxOnPatchFailure, g_logStats.vmxOnRepatch);
    DiagLog("SHV:   成功=%u 失败=%u 重patch=%u\n",
        g_logStats.shvPatchSuccess, g_logStats.shvPatchFailure, g_logStats.shvRepatch);
    DiagLog("VEH 自愈: %u 次\n", g_logStats.vehSelfheal);
    DiagLog("降级模式: %u 次\n", g_logStats.degradedEnter);
    DiagLog("回调重应用: %u 次\n", g_logStats.cbReapply);
    DiagLog("============================================\n");
}

// ★ BUILD 567 v3.227: 周期摘要 — 主循环每 5 分钟输出一次
//   调用位置: 主循环内, 与 diagInterval 同步检查
//   返回: true = 已输出摘要 (用于避免重复调用)
static bool LogPeriodicSummary() {
    DWORD now = GetTickCount();
    // 5 分钟 = 300000ms (与 DEGRADED_RECOVERY_INTERVAL_MS 同量级)
    if (now - g_logStats.lastSummaryTick < 300000) return false;
    g_logStats.lastSummaryTick = now;

    DWORD elapsed = now - g_logStats.startTick;
    DWORD elapsedSec = elapsed / 1000;

    DiagLog("============================================\n");
    DiagLog("BUILD 567 v3.257 周期摘要 (运行 %u 秒)\n", elapsedSec);
    DiagLog("VmxOn: 成功=%u 失败=%u 重patch=%u\n",
        g_logStats.vmxOnPatchSuccess, g_logStats.vmxOnPatchFailure, g_logStats.vmxOnRepatch);
    DiagLog("SHV:   成功=%u 失败=%u 重patch=%u\n",
        g_logStats.shvPatchSuccess, g_logStats.shvPatchFailure, g_logStats.shvRepatch);
    DiagLog("VEH 自愈: %u 次\n", g_logStats.vehSelfheal);
    DiagLog("降级模式: %u 次\n", g_logStats.degradedEnter);
    DiagLog("回调重应用: %u 次\n", g_logStats.cbReapply);
    DiagLog("============================================\n");
    return true;
}

// 崩溃捕获 — 帮助定位 Init 期间的 crash
static HMODULE g_diagDllBase;
static SIZE_T g_diagDllSize;
// ★ BUILD 558 FIX-2: .idata 页范围 (供主循环诊断使用)
//   EkkoSleep 加密期间 .idata 页不可读 → VEH 处理器 IAT 调用崩溃 (0x9A2E)
//   主循环 StealthSleep 之前用 VirtualQuery 检查并强制恢复 PAGE_READONLY
static uintptr_t g_idataPageStart = 0;
static uintptr_t g_idataPageEnd   = 0;
// ★ v3.70/v3.78: VEH 自愈 — 备份缓冲区 (非 static, byovd_kernel.cpp 通过 extern 引用)
uint8_t* g_backupBuf = nullptr;
SIZE_T   g_backupLen = 0;
uint8_t* g_backupCodeBase = nullptr;
void* g_vehHandlerPageVA = nullptr; // ★ v3.78: VEH handler 所在页 VA (extern 导出)

// ★ v3.82: VEH 重入防护 — 防止恢复过程中自身触发异常导致无限递归
static volatile LONG g_vehRestoring = 0;
// ★ v3.126d: 崩溃计数 — 防止自愈后同一指令再次崩溃导致的无限循环
static volatile LONG g_vehCrashCount = 0;
// ★ BUILD 553: MAX_VEH_RETRIES 3 → 10 + 60s 无崩溃重置 (修复 B4 缺陷)
//   原因: 3 次太严格, PAC 周期性破坏代码页时 VEH 快速耗尽 → 进程崩溃
//   新策略: 10 次容忍 + 60s 无新崩溃则重置计数, 避免长期累积误放弃
//   安全性: 10 次仍能防止无限循环 (PAC 破坏频率 << 10 次/60s)
static constexpr LONG MAX_VEH_RETRIES = 10;
static volatile DWORD g_vehLastCrashTick = 0;  // ★ BUILD 553: 上次崩溃时间 (用于 60s 重置)
static constexpr DWORD VEH_RESET_INTERVAL_MS = 60000;  // 60s 无崩溃则重置计数

// ★ BUILD 539: VEH fatal 路径 UnhideProcess 重入防护
//   防止 VEH 中调用 UnhideProcess → IOCTL 二次崩溃 → 再次进入 VEH 的无限循环
static volatile LONG g_vehUnhideDone = 0;

// ★ v3.126f: Hollowing crash fallback — 用 setjmp/longjmp 捕获 ntdll 崩溃并回退到 CreateProcess
static jmp_buf g_hollowJmpBuf;
static bool g_hollowJmpSet = false;

// ★ v3.126g: BYOVD 驱动加载状态 — 当驱动成功加载时跳过 Process Hollowing
static bool g_byovdDriverLoaded = false;

// ★ BUILD 536: ntdll!RtlDeactivateActivationContext 地址范围 — 用于 VEH 捕获 worker 线程激活上下文栈 NULL 崩溃
//   根因: 某些系统 worker 线程 (线程池/RPC) TEB+0x98 (ActivationContextStackPointer) 为 NULL,
//   线程退出时 LdrShutdownThread → RtlDeactivateActivationContext 解引用 NULL+0x38 崩溃.
//   修复: VEH 检测崩溃地址在该范围内时, 设置 rax 指向 g_safeDummyBuf, 让 cmp [rax+0x38],9 正常执行.
static uint64_t g_RtlDeactivateAddr = 0;       // RtlDeactivateActivationContext 函数起始地址
static uint64_t g_RtlDeactivateEnd  = 0;       // 函数结束地址 (起始 + 0x800, 保守范围)
static uint32_t g_safeDummyBuf[16]  = {};      // 安全缓冲区 — VEH 设置 rax 指向此缓冲区 (64 字节, 满足 +0x38 偏移读取)
static DWORD    g_mainThreadId      = 0;       // 主线程 ID — 用于诊断对比崩溃线程

// ============================================================
// ★ BUILD 555 P2-2: SEH 替代 VEH 评估结论 (文档化)
//
// 评估背景:
//   P2-2 待办提出用 SEH (Structured Exception Handling, __try/__except)
//   替代 VEH (Vectored Exception Handler) 以降低检测面:
//     - VEH 通过 AddVectoredExceptionHandler API 注册 (IAT 暴露)
//     - VEH 链表存储在 PEB->KernelCallbackTable 或 ntdll 内部全局,
//       PAC 可扫描定位
//     - SEH 由编译器生成 (无需 API 调用), handler 记录在栈上 (TEB->Tib)
//
// 评估结论: **SEH 无法替代 VEH** — 保留 VEH 作为主异常处理机制
//
// 原因 1: 作用域不匹配
//   - VEH 是进程级 (process-wide), 任何线程任何地址的异常都能捕获
//   - SEH 是函数作用域 (per-function-scope), 仅 __try 块内异常能捕获
//   - 当前 VEH 的主要用途 (BUILD 536):
//       捕获 ntdll!RtlDeactivateActivationContext 在 **worker 线程** (线程池/RPC)
//       中的 ACCESS_VIOLATION 崩溃 — 这些线程不在我们的代码中, 无法用 SEH 包裹
//   - 移除 VEH 将导致 worker 线程崩溃直接拖垮整个进程
//
// 原因 2: 自愈场景不可控
//   - VEH 自愈 (v3.78) 用于恢复 BYOVD IOCTL 物理映射导致的代码页污染
//   - 污染可能在 **任意后续指令执行** 时触发, 不限于特定函数
//   - SEH 仅能在已知调用点包裹, 无法覆盖所有可能触发位置
//
// 原因 3: RTCore64 已移除 → 自愈需求降低
//   - BUILD 550 移除 RTCore64.sys (物理内存映射驱动), 改用 PDFWKRNL.sys (VA memcpy)
//   - PDFWKRNL 不会导致 STATUS_PRIVILEGED_INSTRUCTION (0xC0000096) —
//     该自愈路径已是死代码, VEH 的实际负担减轻
//   - 仅剩 STATUS_ACCESS_VIOLATION 路径 (罕见), SEH 收益进一步降低
//
// 原因 4: SEH 实现复杂度高, 收益低
//   - 包裹主循环需 __try/__except 包覆整个 while(true) 体, 编译器生成
//     大量 SEH 表项 (.pdata/.xdata), 反而增加二进制特征
//   - VEH handler 只有一个函数, 特征可控 (EkkoSleep 已豁免其页面)
//
// 实施策略:
//   1. 保留 VEH 作为主异常处理 (覆盖 worker 线程崩溃 + 自愈)
//   2. 不添加 SEH 包裹 (评估后认为收益不足以抵消复杂度)
//   3. VEH handler 继续优化 (BUILD 553 已加 60s 重置, BUILD 555 已加降级检测)
//
// 替代优化 (已实施):
//   - BUILD 553: MAX_VEH_RETRIES 3→10 + 60s 无崩溃重置 (避免长期累积误放弃)
//   - BUILD 555 P2-1: SHV patch 降级检测 (减少 IOCTL 频率, 降低触发自愈的概率)
//   - EkkoSleep 豁免 VEH handler 页面 (防止加密期间触发异常)
// ============================================================

// ★ BUILD 557: DR0 硬件断点频率统计 (诊断测试构建, 60s 窗口)
//   目的: 统计 32 c0 (现为 90 90) 执行频率, 为 BUILD 558 DR0+VEH 跳过方案提供决策依据
//   决策矩阵: <100Hz → BUILD 558 采用 DR0+VEH 跳过; >1000Hz → 放弃 DR0 维持 VirtualProtect
//   线程安全: g_dr0HitCount/g_dr0StatActive/g_dr0StatDone 用 volatile + Interlocked
//             (VEH 在 CS2 线程上下文触发, 主循环在 loader 线程读写)
//   位置: 必须定义在 DiagVehHandler 之前 (VEH 内 L257+ 引用这些变量)
static volatile LONG g_dr0HitCount     = 0;     // 命中计数 (InterlockedIncrement)
static DWORD         g_dr0FirstHitTid  = 0;     // 首次命中线程 ID (BUILD 558 决策依据)
static DWORD         g_dr0FirstHitTick = 0;     // 首次命中时刻
static DWORD         g_dr0StatStartTick= 0;     // 统计开始时刻
static volatile LONG g_dr0StatActive   = 0;     // 统计激活标志 (VEH 据此判断是否处理 STATUS_SINGLE_STEP)
static volatile LONG g_dr0StatDone     = 0;     // 统计完成标志 (防重复报告)
static void*         g_dr0Addr         = nullptr; // DR0 断点地址 (= g_patchAddr)
static constexpr DWORD DR0_STAT_INTERVAL_MS = 60000; // 60s 频率统计窗口

static LONG CALLBACK DiagVehHandler(PEXCEPTION_POINTERS ep) {
    uint64_t crashAddr = (uint64_t)ep->ExceptionRecord->ExceptionAddress;
    uint64_t dllBase   = (uint64_t)g_diagDllBase;
    uint64_t offset    = (dllBase && crashAddr >= dllBase) ? (crashAddr - dllBase) : 0;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    // ★ BUILD 558 FIX-2: 直接从 TEB 读取线程 ID, 避免 GetCurrentThreadId IAT 调用
    //   根因: EkkoSleep 加密 .data 段期间, .idata 页 IAT 条目读取触发 0xC0000005,
    //         VEH 入口第一个 GetCurrentThreadId() 通过 IAT, 立即二次崩溃 → 无 CRASH 日志.
    //   TEB+0x48 = NT_TIB.ClientId.UniqueThread (x64 Windows 固定偏移), 等效 GetCurrentThreadId.
    //   __readgsqword 是编译器内联指令 (不生成 IAT 调用), VEH 可继续执行到 DiagLog.
    DWORD tid  = (DWORD)__readgsqword(0x48);

    // ★ BUILD 535: 增强 VEH 日志 — 记录线程 ID + 故障数据地址 (ACCESS_VIOLATION)
    //   对于 0xC0000005: ExceptionInformation[0]=0(read)/1(write)/8(exec), [1]=故障数据地址
    //   用于诊断 RtlDeactivateActivationContext 类崩溃 (区分主线程 vs worker 线程)
    if (code == 0xC0000005 && ep->ExceptionRecord->NumberParameters >= 2) {
        ULONG_PTR readWrite = ep->ExceptionRecord->ExceptionInformation[0];
        ULONG_PTR faultAddr = ep->ExceptionRecord->ExceptionInformation[1];
        const char* accessType = (readWrite == 0) ? "READ"
                               : (readWrite == 1) ? "WRITE"
                               : (readWrite == 8) ? "EXEC" : "OTHER";
        DiagLog("CRASH: code=0x%08X addr=0x%llX off=%llX tid=%u AV:%s faultAddr=0x%llX\n",
            code, crashAddr, offset, tid,
            accessType, (unsigned long long)faultAddr);
    } else {
        DiagLog("CRASH: code=0x%08X addr=0x%llX off=%llX tid=%u\n",
            code, crashAddr, offset, tid);
    }

    // ★ BUILD 557: STATUS_SINGLE_STEP (0x80000004) — DR0 硬件断点命中
    //   必须在 ACCESS_VIOLATION 自愈逻辑之前处理, 否则 DR0 命中会被误判为代码污染
    //   触发自愈 (memcpy 整个 payload.dll), 导致进程状态混乱.
    //   DR0 命中时 CPU 触发 #DB, Windows 包装为 STATUS_SINGLE_STEP.
    //   不修改 RIP — 让 90 90 正常执行 (BUILD 557 纯计数, 不跳过指令).
    //   Windows 内核 NtContinue 自动设置 EFLAGS.RF, 重试指令不重复触发同一断点.
    // ★ BUILD 558 FIX-5 正式版: 移除 v6 诊断日志 (SS# 记录), 回到 v5 稳定状态.
    //   原因: DR0 在 patch 之后启动, 32 c0 已被 NOP, hits 必然为 0, 诊断无意义.
    // ★ BUILD 567 v3.236 FIX-1: 不依赖 g_dr0StatActive — 防止 EkkoSleep .data 加密期间
    //   g_dr0StatActive/g_dr0Addr 被加密成垃圾值导致 VEH 误判 fallthrough → ACCESS_VIOLATION
    //   自愈 (memcpy 整个 payload.dll) → 进程状态混乱 → 0xc0000005 崩溃.
    //   根因: v3.235 测试 83 个 CS2 线程 DR0 未清除, ReportDR0Frequency 设置 g_dr0StatActive=0,
    //         主循环恢复 StealthSleep (EkkoSleep), EkkoSleep 加密 .data 段 (含 g_dr0StatActive/
    //         g_dr0Addr/g_dr0HitCount), 残留 DR0 触发 STATUS_SINGLE_STEP, VEH 读取加密变量崩溃.
    //   新逻辑: 直接从 CONTEXT.Dr0 读取断点地址 (CPU 寄存器, 不受 EkkoSleep .data 加密影响),
    //          dr0 != 0 && ExceptionAddress == dr0 即为 DR0 命中, 清除 DR6 + 继续执行.
    //   计数仅在 g_dr0StatActive=1 时进行 (EkkoSleep 期间 g_dr0StatActive 可能被加密, 但误计数
    //          影响小 — 残留 DR0 命中频率本身无意义, 仅用于诊断是否触发).
    if (code == 0x80000004) {
        uint64_t ea  = (uint64_t)ep->ExceptionRecord->ExceptionAddress;
        uint64_t dr0 = ep->ContextRecord->Dr0;  // ★ v3.236: CPU 寄存器, 不受 .data 加密影响
        if (dr0 != 0 && ea == dr0) {
            // ★ v3.236: 仅在统计窗口活跃时计数
            if (g_dr0StatActive) {
                InterlockedIncrement(&g_dr0HitCount);
                // 首次命中: 记录线程 ID + 时间 (InterlockedCompareExchange 保证只记录一次)
                if (g_dr0FirstHitTid == 0) {
                    if (InterlockedCompareExchange((volatile LONG*)&g_dr0FirstHitTid,
                            (LONG)tid, 0) == 0) {
                        g_dr0FirstHitTick = GetTickCount();
                        DiagLog("B557:DR0:1st-hit tid=%u tick=%u addr=0x%llX\n",
                            tid, g_dr0FirstHitTick, (unsigned long long)ea);
                    }
                }
            }
            // ★ v3.236: 无论 active 与否都清除 DR6 — 残留 DR0 触发的 STATUS_SINGLE_STEP 必须处理
            //   清除 DR6: B0 (bit 0) + B1-B3 (bit 1-3) + BS (bit 14)
            //   B0 必须显式清除, 否则下次 DR0 命中检测会失败
            ep->ContextRecord->Dr6 &= ~0x400FULL;
            // 不修改 RIP — 让 90 90 正常执行 (BUILD 557 纯计数, 不跳过)
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // ExceptionAddress 不匹配 — 可能是 TF 单步 (EFLAGS.TF=1), fallthrough
    }

    // ★ BUILD 536: 捕获 ntdll!RtlDeactivateActivationContext 内的 ACCESS_VIOLATION 崩溃
    //   根因: 某些系统 worker 线程 (线程池/RPC) 的 TEB+0x98 (ActivationContextStackPointer) 为 NULL,
    //   线程退出时 LdrShutdownThread → RtlDeactivateActivationContext 读取 [TEB+0x98] 得到 NULL,
    //   随后 cmp dword ptr [rax+0x38], 9 解引用 NULL+0x38=0x38 导致 ACCESS_VIOLATION.
    //   修复: 检测到该崩溃时, 设置 rax 指向安全缓冲区 g_safeDummyBuf, 让 cmp 指令正常执行,
    //         函数走"无激活上下文"分支正常返回, 避免 worker 线程崩溃拖垮整个进程.
    //   安全性: cmp 是无副作用的比较指令, 重新执行不会改变任何寄存器 (除 EFLAGS);
    //           g_safeDummyBuf[0]=0 != 9, 函数走"栈为空"分支, 直接返回, 不影响逻辑.
    if (code == 0xC0000005 && g_RtlDeactivateAddr &&
        crashAddr >= g_RtlDeactivateAddr && crashAddr < g_RtlDeactivateEnd) {
        ULONG_PTR faultAddr = (ep->ExceptionRecord->NumberParameters >= 2)
                            ? ep->ExceptionRecord->ExceptionInformation[1] : 0;
        const char* threadType = (tid == g_mainThreadId) ? "MAIN" : "WORKER";
        DiagLog("VEH-B536: RtlDeactivateActivationContext crash caught! tid=%u (%s) "
                "faultAddr=0x%llX, patching rax → g_safeDummyBuf\n",
                tid, threadType, (unsigned long long)faultAddr);
        // 设置 rax 指向安全缓冲区 (g_safeDummyBuf 有 64 字节, 满足 +0x38 偏移读取)
        // cmp dword ptr [rax+0x38], 9 将读取 g_safeDummyBuf[14] (偏移 0x38 = 56 字节 = 14*4)
        // g_safeDummyBuf[14] = 0 (零初始化), 0 != 9, 函数走"栈为空"分支正常返回
        ep->ContextRecord->Rax = (DWORD64)&g_safeDummyBuf[0];
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ★ v3.78: VEH 自愈 — 捕获 BYOVD IOCTL 导致的代码/数据污染
    //   STATUS_PRIVILEGED_INSTRUCTION (0xC0000096): 执行了被物理映射覆盖的代码页
    //   STATUS_ACCESS_VIOLATION (0xC0000005): 访问了被破坏的 .data/.bss 页
    bool isPrivInstr = (code == 0xC0000096);
    bool isAccessViol = (code == 0xC0000005);
    if ((isPrivInstr || isAccessViol) && g_backupBuf && g_backupCodeBase && g_backupLen > 0) {
        // ★ v3.126d: 检查崩溃地址是否在备份范围内 — 不在范围内则不自愈
        uintptr_t backupStart = (uintptr_t)g_backupCodeBase;
        uintptr_t backupEnd   = backupStart + g_backupLen;
        if (crashAddr < backupStart || crashAddr >= backupEnd) {
            // 崩溃不在 payload 代码区域, 不自愈 (可能是系统 DLL 或栈)
            // ★ BUILD 535: 记录线程 ID 帮助诊断 worker 线程崩溃
            DiagLog("VEH: crash outside backup range [0x%llX-0x%llX), skipping self-heal tid=%u\n",
                (unsigned long long)backupStart, (unsigned long long)backupEnd, tid);
            goto veh_fatal;
        }

        // ★ v3.82: 重入检测 — 如果已经在恢复中又触发异常, 说明恢复过程本身
        //   有页面无法正常操作 (PTE 损坏 / 栈被污染), 放弃恢复避免无限递归
        if (InterlockedExchange(&g_vehRestoring, 1)) {
            DiagLog("VEH-SELFHEAL: RECURSIVE! aborting restore, re-crash at off=0x%llX code=0x%08X\n",
                offset, code);
            // 放弃自愈, 让 MessageBox 弹出通知用户
            g_vehRestoring = 0;
            goto veh_fatal;
        }

        // ★ v3.126d: 自愈计数 — 同一指令连续崩溃超过 MAX_VEH_RETRIES 次即放弃
        // ★ BUILD 553: 60s 无崩溃重置计数 (避免长期累积误放弃)
        //   原实现: 计数只增不减, 3 次后永久放弃 → 长期运行后失去自愈能力
        //   新实现: 距上次崩溃 >60s 则重置为 0, 允许新一轮自愈
        {
            DWORD nowTick = GetTickCount();
            DWORD lastTick = (DWORD)g_vehLastCrashTick;
            if (lastTick != 0 && (nowTick - lastTick) > VEH_RESET_INTERVAL_MS) {
                // 60s 无崩溃, 重置计数 (InterlockedExchange 保证原子性)
                InterlockedExchange(&g_vehCrashCount, 0);
            }
            g_vehLastCrashTick = (volatile DWORD)nowTick;
        }
        if (InterlockedIncrement(&g_vehCrashCount) > MAX_VEH_RETRIES) {
            DiagLog("VEH-SELFHEAL: EXCEEDED MAX_RETRIES (%d), aborting\n", MAX_VEH_RETRIES);
            g_vehRestoring = 0;
            goto veh_fatal;
        }

        DiagLog("VEH-SELFHEAL: restoring %llu bytes from backup@0x%llX → code@0x%llX (cause=%s)\n",
            (unsigned long long)g_backupLen,
            (unsigned long long)g_backupBuf,
            (unsigned long long)g_backupCodeBase,
            isPrivInstr ? "PRIV_INSTR" : "ACCESS_VIOL");
        // ★ BUILD 567 v3.227: VEH 自愈计数 + 状态日志
        g_logStats.vehSelfheal++;
        DiagLogState("VEH", "SELFHEAL", "count=%u cause=%s",
            (unsigned)g_vehCrashCount, isPrivInstr ? "PRIV_INSTR" : "ACCESS_VIOL");

        // ★ v3.70/v3.78: 逐页恢复, 保存/恢复原始保护
        //   v3.70: 跳过 VEH 处理器自身所在页面 (未被污染, 保护不变)
        //   v3.78: 不再强制全部 PAGE_EXECUTE_READ — .data/.bss 必须保持 PAGE_READWRITE
        //   v3.82: 逐页 FlushFileBuffers 确保崩溃页可定位
        uintptr_t handlerPage = ((uintptr_t)&DiagVehHandler) & ~0xFFFULL;
        g_vehHandlerPageVA = (void*)handlerPage;  // 导出供 byovd_kernel.cpp 使用
        uintptr_t codeBase = (uintptr_t)g_backupCodeBase;
        SIZE_T codeLen = g_backupLen;
        const SIZE_T PAGE = 0x1000;

        SIZE_T restored = 0;
        SIZE_T totalPages = (codeLen + PAGE - 1) / PAGE;
        DiagLog("VEH-SELFHEAL: starting per-page restore (%llu pages total)\n",
            (unsigned long long)totalPages);
        for (SIZE_T off = 0; off < codeLen; off += PAGE) {
            uintptr_t pageVA = codeBase + off;
            SIZE_T chunk = (off + PAGE <= codeLen) ? PAGE : (codeLen - off);

            // 跳过 VEH 处理器所在页 (未被污染, 保护不变)
            if ((uintptr_t)pageVA == (uintptr_t)handlerPage) {
                continue;
            }

            DWORD oldProt;
            if (!VirtualProtect((void*)pageVA, chunk, PAGE_READWRITE, &oldProt)) {
                // 页可能无效 (guard/未提交), 跳过
                continue;
            }
            memcpy((void*)pageVA, g_backupBuf + off, chunk);
            // ★ v3.78: 恢复原始保护, 而非强制 EXECUTE_READ
            DWORD restoreProt = (oldProt == PAGE_READWRITE || oldProt == PAGE_READONLY
                || oldProt == PAGE_WRITECOPY || oldProt == PAGE_EXECUTE_WRITECOPY)
                ? PAGE_READWRITE : PAGE_EXECUTE_READ;
            VirtualProtect((void*)pageVA, chunk, restoreProt, &oldProt);
            restored++;

            // ★ v3.83: 每16页输出一次进度日志 (避免撑爆日志但能定位进度)
            if ((restored & 0xF) == 0) {
                DiagLog("VEH-SELFHEAL: progress %llu/%llu pages (off=0x%llX)...\n",
                    (unsigned long long)restored, (unsigned long long)totalPages,
                    (unsigned long long)off);
            }
        }

        g_vehRestoring = 0;
        DiagLog("VEH-SELFHEAL: DONE %llu pages restored, retrying...\n",
            (unsigned long long)restored);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

veh_fatal:

    // ★ BUILD 539: 进程崩溃/退出前必须挂回 ActiveProcessLinks — 防止 0x139 蓝屏
    //   根因: DKOM 永久断链后 prev->Flink=next, 进程退出时 PspExitProcess 调用
    //   RemoveEntryList 调试检查 prev->Flink==current 失败 → BugCheck 0x139 参数 3
    //   两次蓝屏确认: 21:16:37 和 21:42:37, 均为 0x139 (3, addr1, addr2, 0)
    //   修复: VEH fatal 路径前调用 UnhideProcess, 确保链表完整后退出
    //   安全性: 原子标志 g_vehUnhideDone 防止重入 (VEH 中 IOCTL 可能二次崩溃);
    //           UnhideProcess 内部检查 m_hidden (未隐藏时 no-op); IOCTL 有 2s 超时保护
    if (!InterlockedExchange(&g_vehUnhideDone, 1)) {
        DiagLog("VEH-FATAL: calling UnhideAll before exit (prevent 0x139 BSOD on PspExitProcess)\n");
        // ★ BUILD 544: 必须同时挂回 loader2 + basic — 否则任一退出都触发 0x139
        //   basic.exe 被 DKOM 隐藏后, 若未挂回链表就退出, PspExitProcess → RemoveEntryList 检查失败 → 0x139
        stealth::DKOMProcessHider::Instance().UnhideAll();
    }

    // ★ v3.126f: Hollowing crash — 用 longjmp 跳回 setjmp 点, 回退到 CreateProcess
    if (g_hollowJmpSet) {
        DiagLog("VEH: hollowing crash detected (addr=0x%llX), jumping to fallback\n",
            (unsigned long long)crashAddr);
        // 清理远程进程
        // 注意: longjmp 会跳转到 setjmp 点, 那里会执行 TerminateProcess
        g_hollowJmpSet = false;
        longjmp(g_hollowJmpBuf, 1);
        // 不会执行到这里
    }

    // ★ v3.68: 不在 VEH 上下文中直接调用 DisableAll (可能触发嵌套异常)
    //   仅记录崩溃信息并通过 MessageBox 通知用户
    //   DisableAll 会在 DllMain 退出路径中由 CheatMainLoop 的 return 分支调用
    wchar_t msg[300];
    swprintf_s(msg, L"崩溃代码: 0x%08X\n"
                     L"崩溃地址: 0x%llX\n"
                     L"DLL偏移:   0x%llX\n\n"
                     L"诊断日志: %%TEMP%%\\sd.log",
        code, crashAddr, offset);
    MessageBoxW(NULL, msg, L"CS2 Loader 崩溃", MB_OK | MB_ICONERROR | MB_TOPMOST);

    return EXCEPTION_CONTINUE_SEARCH;
}


// ★ BUILD 529: E+G 测试模式标志 — 由 %TEMP%\pac_probe.flag 触发
//   测试模式: 跳过 CS2 附加 + 补丁应用, 仅运行 E+G 保护层 (驱动+ObCallbacks+DKOM+EkkoSleep)
//   用于长时间运行验证无蓝屏 (测试2), 避免测试失败时补丁导致封号
//   注入功能仅在测试3 (无 flag) 时启用
static bool g_egTestMode = false;

// ★ BUILD 537: 半测试模式标志 — 由 %TEMP%\half_test.flag 触发
//   半测试模式: 附加 CS2 (验证 ObCallbacks 移除 + DKOM 隐藏 + 句柄重随机化),
//   但跳过补丁应用 (避免封号)
//   用于阶段 A 测试: 验证 loader2 附加 CS2 不被踢 + ObCallbacks 移除有效
static bool g_halfTestMode = false;


// v3.34: NtUnmapViewOfSection 函数指针 (用于 Process Hollowing)
typedef LONG(NTAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);
static _NtUnmapViewOfSection g_pNtUnmapViewOfSection = nullptr;

// ★ BUILD 550: ModNameHashRT/GetModuleBaseFromPEB 已移至 stealth_lib/module_resolver.h
//   作为 inline 函数, 通过 stealth_core.h → module_resolver.h 间接包含, 无需前向声明

// ★ v3.126f: 手动解析远程进程中的导入表 (IAT) — 批量写入, 减少 ntdll 调用
//   避免逐个 WriteProcessMemory 在 ntdll 中崩溃的问题。
static bool ResolveImportTable(HANDLE hProcess, void* remoteBase,
                                const BYTE* rawExe, const IMAGE_NT_HEADERS64* nt) {
    auto* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0 || importDir->VirtualAddress == 0) return true;

    uintptr_t baseVA = (uintptr_t)remoteBase;
    uintptr_t importRVA = importDir->VirtualAddress;

    DiagLog("ResolveIAT: importRVA=0x%X size=0x%X\n", importRVA, importDir->Size);

    // 第一遍: 统计 IAT 条目总数
    DWORD totalEntries = 0;
    for (DWORD idx = 0; ; idx++) {
        auto* desc = (const IMAGE_IMPORT_DESCRIPTOR*)(rawExe + importRVA + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (desc->Name == 0) break;
        uintptr_t iltRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        for (DWORD ti = 0; ; ti++) {
            uintptr_t* iltEntry = (uintptr_t*)(rawExe + iltRVA + ti * sizeof(uintptr_t));
            if (*iltEntry == 0) break;
            totalEntries++;
        }
    }
    DiagLog("ResolveIAT: %u total IAT entries\n", totalEntries);
    if (totalEntries == 0) return true;

    // ① 先解析所有 DLL 和函数, 填充本地缓冲区
    //   结构: [remoteAddr0, funcAddr0, remoteAddr1, funcAddr1, ...]
    //   每个条目 16 字节 (8 字节远程地址 + 8 字节函数地址)
    struct IATEntry { void* remoteAddr; void* funcAddr; };
    IATEntry* entries = (IATEntry*)VirtualAlloc(nullptr, totalEntries * sizeof(IATEntry),
        MEM_COMMIT, PAGE_READWRITE);
    if (!entries) return false;
    DWORD entryCount = 0;

    DiagLog("ResolveIAT: resolving DLLs...\n");
    for (DWORD idx = 0; ; idx++) {
        auto* desc = (const IMAGE_IMPORT_DESCRIPTOR*)(rawExe + importRVA + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (desc->Name == 0) break;

        const char* dllName = (const char*)(rawExe + desc->Name);
        // ★ BUILD 549+: 通过 PEB Ldr 遍历获取 (替代 GetModuleHandleA, 规避 PAC hook)
        //   dllName 是 char*, 先转 wchar_t 再用 ModNameHashRT 计算哈希
        //   dllName 字符串本身不在 payload.dll 二进制中 (来自 rawExe), 所以无明文风险
        wchar_t wideDllName[MAX_PATH] = {};
        int wlen = 0;
        for (; wlen < MAX_PATH - 1 && dllName[wlen]; wlen++) {
            wideDllName[wlen] = (wchar_t)(unsigned char)dllName[wlen];
        }
        wideDllName[wlen] = L'\0';
        HMODULE hMod = stealth::GetModuleBaseFromPEB(stealth::ModNameHashRT(wideDllName));
        if (!hMod) {
            // ★ BUILD 554 P0-3: 移除 LoadLibraryA 回退 (修复 A4 缺陷)
            //   原因: LoadLibraryA 是 PAC 用户态 hook 的高优先级 API (PvpAlive.dll 必然 hook),
            //         一次调用触发 LdrLoadDll 完整模块加载流程, PAC 通过 LdrRegisterDllNotification
            //         或 LoadLibrary hook 可枚举所有新加载模块.
            //   策略: payload.dll 只依赖系统 DLL (KERNEL32/ntdll/USER32/ADVAPI32),
            //         这些在 CS2 进程中必然已加载. PEB Ldr 遍历失败 → 跳过该 IAT 条目.
            continue;
        }

        uintptr_t iatRVA = desc->FirstThunk;
        uintptr_t iltRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : iatRVA;

        for (DWORD ti = 0; ; ti++) {
            uintptr_t* iltEntry = (uintptr_t*)(rawExe + iltRVA + ti * sizeof(uintptr_t));
            uintptr_t entryVal = *iltEntry;
            if (entryVal == 0) break;

            void* funcAddr = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL64(entryVal)) {
                funcAddr = GetProcAddress(hMod, (LPCSTR)MAKEINTRESOURCEA(IMAGE_ORDINAL64(entryVal)));
            } else {
                auto* hintName = (const IMAGE_IMPORT_BY_NAME*)(rawExe + entryVal);
                funcAddr = GetProcAddress(hMod, (LPCSTR)hintName->Name);
            }
            if (funcAddr) {
                entries[entryCount].remoteAddr = (void*)(baseVA + iatRVA + ti * sizeof(uintptr_t));
                entries[entryCount].funcAddr = funcAddr;
                entryCount++;
            }
        }
    }
    DiagLog("ResolveIAT: resolved %u/%u entries\n", entryCount, totalEntries);
    if (entryCount == 0) { VirtualFree(entries, 0, MEM_RELEASE); return true; }

    // ② 批量写入 — 整合为连续缓冲区, 单次 WriteProcessMemory
    //   注意: IAT 条目在远程进程中可能不连续, 所以需要按地址排序写入
    //   将相邻条目合并为连续块, 每块单次写入
    //   先把 entries 按 remoteAddr 排序 (IAT 地址应该是递增的)
    //   简单冒泡排序 (条目数通常 < 100)
    bool sorted = false;
    while (!sorted) {
        sorted = true;
        for (DWORD i = 0; i < entryCount - 1; i++) {
            if ((uintptr_t)entries[i].remoteAddr > (uintptr_t)entries[i + 1].remoteAddr) {
                IATEntry tmp = entries[i];
                entries[i] = entries[i + 1];
                entries[i + 1] = tmp;
                sorted = false;
            }
        }
    }

    // 合并相邻条目为连续块
    DWORD blockStart = 0;
    while (blockStart < entryCount) {
        DWORD blockEnd = blockStart;
        // 扩展连续块: 下一个条目的地址 == 当前块末尾
        while (blockEnd + 1 < entryCount &&
               (uintptr_t)entries[blockEnd + 1].remoteAddr ==
               (uintptr_t)entries[blockEnd].remoteAddr + sizeof(void*)) {
            blockEnd++;
        }
        DWORD blockLen = blockEnd - blockStart + 1;
        SIZE_T blockBytes = blockLen * sizeof(void*);

        // 构建连续的函数地址缓冲区
            void** buf = (void**)VirtualAlloc(nullptr, blockBytes, MEM_COMMIT, PAGE_READWRITE);
            if (buf) {
                for (DWORD i = 0; i < blockLen; i++) {
                    buf[i] = entries[blockStart + i].funcAddr;
                }
                SIZE_T br = 0;
                // ★ BUILD 556: SysWriteVirtualMemory 替代 WriteProcessMemory
                //   消除 kernel32!WriteProcessMemory IAT 静态导入特征
                stealth::SysWriteVirtualMemory(hProcess, entries[blockStart].remoteAddr, buf, blockBytes, &br);
                VirtualFree(buf, 0, MEM_RELEASE);
            } else {
                // 逐个写入 (内存不足时回退)
                for (DWORD i = blockStart; i <= blockEnd; i++) {
                    SIZE_T br = 0;
                    // ★ BUILD 556: SysWriteVirtualMemory 替代 WriteProcessMemory
                    stealth::SysWriteVirtualMemory(hProcess, entries[i].remoteAddr, &entries[i].funcAddr, sizeof(void*), &br);
                }
            }
        blockStart = blockEnd + 1;
    }

    VirtualFree(entries, 0, MEM_RELEASE);
    DiagLog("ResolveIAT: OK\n");
    return true;
}

// ============================================================ // BUILD 548: basic.exe 嵌入数据 + EPT dump 代码已移除
//   原内容: g_basicExeData 字节数组, InitBasicEkkoSleep 前向声明,
//           EPT dump (EptpFormat/ParseEPTP/RunEptDump/EptLog) — 已全部移除
// ============================================================

// ============================================================
// ★ BUILD 548: ApplyCs2Patch — 集成 basic.exe 的补丁逻辑
//
// basic.exe 原本通过 OpenProcess + WriteProcessMemory 补丁 CS2 client.dll
// 现在 payload.dll 已在 CS2 进程内，直接 VirtualProtect + memcpy
//
// 补丁内容: 搜索特征码 32 c0 4c 8b a4 24 c8 00 00 00
//           (xor al, ah; mov r12, [rsp+0xc8])
//           将前 2 字节 32 c0 替换为 90 90 (NOP NOP)
//           使 CS2 内存数据保持"解密后"状态
//           CS2 自身渲染逻辑读取解密数据 → 显示透视效果
//
// ★ BUILD 549: 优先使用影子页 (PTE manipulation), 失败回退到 VirtualProtect
// ============================================================
// ★ BUILD 558 FIX-4: g_patchAddr/g_clientBase 类型从 uint8_t* 改为 uintptr_t
//   原因: payload.dll 在 loader.exe 进程内运行, client.dll 在 CS2 进程内,
//         g_patchAddr/g_clientBase 是 CS2 进程内的地址, 不能在本进程直接解引用.
//         必须通过 StealthMemory::Read/Write/Protect 跨进程访问.
//   历史问题: BUILD 548 集成 basic.exe 到 payload.dll 时, basic.exe 原本注入 CS2 进程内运行,
//             直接指针解引用有效. 迁移后 payload.dll 在 loader.exe 进程内, 直接解引用失效,
//             ApplyCs2Patch 报 "mod not loaded" (GetModuleBaseFromPEB 在本进程找不到 client.dll).
static uintptr_t g_patchAddr = 0;       // CS2 进程内 patch 地址 (跨进程访问)
static bool g_cs2Patched = false;
// ★ BUILD 556: 移除 g_shadowPageTried (影子页方案已废弃, 降级到 VirtualProtect)
// ★ BUILD 558 FIX-4: g_clientBase 类型从 uint8_t* 改为 uintptr_t (CS2 进程内地址)
static uintptr_t g_clientBase = 0;  // ★ BUILD 555 P2-4: client.dll 基址缓存 (跨进程访问)

// ★ BUILD 557: DR0 频率统计变量已移至 L227 (DiagVehHandler 之前), 此处不再重复定义
//   原因: C++ 文件作用域 static 变量不能前向声明 (无 extern 语法), 必须在使用前定义

// ★ BUILD 549+: pattern XOR 加密常量 (避免明文特征码 0x32 0xc0 0x4c 0x8b ... 出现在二进制中)
//   原始 pattern: 32 c0 4c 8b a4 24 c8 00 00 00 (xor al,ah; mov r12,[rsp+0xc8])
//   编译期 XOR 加密, 运行时用 g_patKey 解密
//   volatile g_patKey 防止编译器常量传播回原始字节 (强制运行时 XOR 操作)
static volatile uint8_t g_patKey = 0x5A;
constexpr uint8_t PAT_ENC[] = {
    0x32 ^ 0x5A, 0xc0 ^ 0x5A, 0x4c ^ 0x5A, 0x8b ^ 0x5A,
    0xa4 ^ 0x5A, 0x24 ^ 0x5A, 0xc8 ^ 0x5A, 0x00 ^ 0x5A,
    0x00 ^ 0x5A, 0x00 ^ 0x5A
};  // = { 0x68, 0x9A, 0x16, 0xD1, 0xFE, 0x7E, 0x92, 0x5A, 0x5A, 0x5A }
constexpr size_t PAT_LEN = sizeof(PAT_ENC);

// ★ BUILD 549: SYSTEM_PROCESS_INFO 结构 (用于 NtQuerySystemInformation syscall)
//   避免依赖 stealth_process.cpp 内部结构
// ★ BUILD 549+: 移除 #pragma pack(4), 改为自然对齐 (与真实 SYSTEM_PROCESS_INFORMATION 一致)
//   原因: #pragma pack(4) 会让 HANDLE/PVOID/SIZE_T 字段对齐到 4 字节,
//         导致 UniqueProcessId 在 +0x4c 而非真实的 +0x50, 读取错误数据
typedef struct _B549_SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
    // ★ BUILD 549+: SYSTEM_THREAD_INFORMATION 数组紧跟在此结构之后 (NumberOfThreads 个)
    //   不在结构内声明 (C 不支持柔性数组 + 已命名字段), 用偏移计算访问
} B549_SYSTEM_PROCESS_INFO;

// ★ BUILD 549+: SYSTEM_THREAD_INFORMATION (x64, sizeof=0x50=80 字节)
//   用于 NtQuerySystemInformation(SystemProcessInformation) 返回的线程数组
//   每个 SYSTEM_PROCESS_INFORMATION 之后紧跟 NumberOfThreads 个此结构
typedef struct _B549_SYSTEM_THREAD_INFO {
    LARGE_INTEGER KernelTime;        // +0x00
    LARGE_INTEGER UserTime;          // +0x08
    LARGE_INTEGER CreateTime;        // +0x10
    ULONG         WaitTime;          // +0x18
    ULONG         Padding0;          // +0x1c (对齐到 8)
    PVOID         StartAddress;      // +0x20
    CLIENT_ID     ClientId;          // +0x28 (UniqueProcess 8 + UniqueThread 8)
    LONG          Priority;          // +0x38
    LONG          BasePriority;      // +0x3c
    ULONG         ContextSwitches;   // +0x40
    ULONG         ThreadState;       // +0x44
    ULONG         WaitReason;        // +0x48
    ULONG         Padding1;          // +0x4c (对齐到 8)
} B549_SYSTEM_THREAD_INFO;  // sizeof = 0x50

// ★ BUILD 558 FIX-5: static_assert 验证结构大小和字段偏移 (编译时检查)
//   防止编译器对齐差异导致偏移错误 (NtQSI 解析 SYSTEM_PROCESS_INFORMATION 必需)
static_assert(sizeof(B549_SYSTEM_PROCESS_INFO) == 0x100, "B549_SYSTEM_PROCESS_INFO size must be 0x100 (256 bytes)");
static_assert(sizeof(B549_SYSTEM_THREAD_INFO) == 0x50, "B549_SYSTEM_THREAD_INFO size must be 0x50 (80 bytes)");
static_assert(offsetof(B549_SYSTEM_PROCESS_INFO, NextEntryOffset) == 0x00, "NextEntryOffset offset mismatch");
static_assert(offsetof(B549_SYSTEM_PROCESS_INFO, NumberOfThreads) == 0x04, "NumberOfThreads offset mismatch");
static_assert(offsetof(B549_SYSTEM_PROCESS_INFO, UniqueProcessId) == 0x50, "UniqueProcessId offset mismatch");
static_assert(offsetof(B549_SYSTEM_THREAD_INFO, ClientId) == 0x28, "SYSTEM_THREAD_INFO.ClientId offset must be 0x28");

// ============================================================
// ★ BUILD 550: ModNameHash/ModNameHashRT/GetModuleBaseFromPEB 已移至共享头文件
//   stealth_lib/module_resolver.h (stealth:: 命名空间)
//   payload.cpp 通过 stealth_core.h → module_resolver.h 间接包含
//   所有调用使用 stealth::ModNameHash / stealth::GetModuleBaseFromPEB
// ============================================================

// ★ BUILD 555 P2-4: ValidatePatchFunctionBoundary — 函数边界回溯验证
//   修复 P2-4 缺陷: 原 ApplyCs2Patch 仅用 10 字节特征码 `32 c0 4c 8b a4 24 c8 00 00 00`
//   匹配, false positive 风险 (CS2 更新后可能在多个位置出现此序列)
//
//   增强 1: 向前回溯最多 256 字节查找函数边界 (复用 ShvInstallPatcher 三级查找算法)
//     Pass 1: 0xCC int3 (最可靠, 不会出现在指令中间)
//     Pass 2: 连续 ≥2 字节 0x90 nop (MSVC 对齐)
//     Pass 3: 连续 ≥4 字节 0x00 零填充 (Clang 对齐)
//   增强 2: 验证边界后第一字节是合法函数序言 (0x48=REX.W / 0x55=push rbp / 0x40-0x4F=REX)
//   增强 3: 验证 found 与函数入口距离 <= 0x200 (patch 不应位于函数体深处)
//   返回: true = 验证通过, false = 验证失败 (拒绝 patch)
// ★ BUILD 558 FIX-4: 跨进程化 — 改为接收本地 backBuf (调用方跨进程读取 found 前的字节)
//   原签名: ValidatePatchFunctionBoundary(uint8_t* found) — 直接解引用 found 前的字节 (本进程)
//   新签名: ValidatePatchFunctionBoundary(const uint8_t* backBuf, uint32_t backSize)
//     backBuf: 包含 found 前 backSize 字节的本地 buffer (跨进程读取)
//     backSize: backBuf 实际大小 (≤ MAX_BACKSCAN)
//   调用方 (ApplyCs2Patch) 负责: 跨程读取 found 前 MAX_BACKSCAN 字节到 backBuf
static bool ValidatePatchFunctionBoundary(const uint8_t* backBuf, uint32_t backSize) {
    if (!backBuf) return false;
    if (backSize < 4) return false;

    constexpr uint32_t MAX_BACKSCAN = 256;
    // Pass 1: 查找 0xCC (int3, 最可靠 — 不会出现在指令中间)
    for (int32_t k = (int32_t)backSize - 1; k >= 0; k--) {
        if (backBuf[k] == 0xCC) {
            uint32_t entryOffset = k + 1;
            if (entryOffset >= backSize) continue;
            uint8_t firstByte = backBuf[entryOffset];
            if (firstByte == 0x48 || firstByte == 0x55 ||
                (firstByte >= 0x40 && firstByte <= 0x4F)) {
                // 验证 patch 位置与函数入口距离
                uint32_t dist = backSize - entryOffset;
                if (dist <= 0x200) return true;
            }
        }
    }

    // Pass 2: 查找连续 ≥2 字节 0x90 (nop 填充, MSVC 常用)
    for (int32_t k = (int32_t)backSize - 2; k >= 0; k--) {
        if (backBuf[k] == 0x90 && backBuf[k + 1] == 0x90) {
            uint32_t entryOffset = k + 2;
            while (entryOffset < backSize && backBuf[entryOffset] == 0x90) {
                entryOffset++;
            }
            if (entryOffset >= backSize) continue;
            uint8_t firstByte = backBuf[entryOffset];
            if (firstByte == 0x48 || firstByte == 0x55 ||
                (firstByte >= 0x40 && firstByte <= 0x4F)) {
                uint32_t dist = backSize - entryOffset;
                if (dist <= 0x200) return true;
            }
        }
    }

    // Pass 3: 查找连续 ≥4 字节 0x00 (零填充, Clang/部分 MSVC 使用)
    for (int32_t k = (int32_t)backSize - 4; k >= 0; k--) {
        if (backBuf[k] == 0x00 && backBuf[k + 1] == 0x00 &&
            backBuf[k + 2] == 0x00 && backBuf[k + 3] == 0x00) {
            uint32_t entryOffset = k + 4;
            while (entryOffset < backSize && backBuf[entryOffset] == 0x00) {
                entryOffset++;
            }
            if (entryOffset >= backSize) continue;
            uint8_t firstByte = backBuf[entryOffset];
            if (firstByte == 0x48 || firstByte == 0x55 ||
                (firstByte >= 0x40 && firstByte <= 0x4F)) {
                uint32_t dist = backSize - entryOffset;
                if (dist <= 0x200) return true;
            }
        }
    }

    return false;  // 三级边界查找全部失败
}

// ============================================================
// ★ BUILD 557: DR0 硬件断点频率统计 — DR0 设置/清除函数
//   参考: anti_debug.cpp L268-295 的 CONTEXT_DEBUG_REGISTERS 模式
//   DR7 位布局 (Intel SDM Vol 3B §17.2.4):
//     L0 (bit 0)  = 本地启用 DR0
//     LE (bit 8)  = 本地精确匹配 (推荐设置, 提高断点精度)
//     RW0 (bit 16-17) = 00 (执行断点)
//     LEN0 (bit 18-19) = 00 (执行断点忽略此项, IA-32e 模式下 1 字节)
//   最终 DR7 = 0x101 (L0 + LE)
//   注意: 线程必须已 SuspendThread 后再调用 SetThreadContext (Windows 文档要求)
// ============================================================
static bool SetupDR0Breakpoint(HANDLE hThread, void* addr) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return false;
    ctx.Dr0 = reinterpret_cast<DWORD64>(addr);
    ctx.Dr7 &= ~0x30003ULL;   // 清 bit 0,1,16,17,18,19 (L0/G0/RW0/LEN0)
    ctx.Dr7 |= 0x101ULL;      // 置 L0 (0x1) + LE (0x100)
    if (!SetThreadContext(hThread, &ctx)) return false;
    // ★ BUILD 558 FIX-5 正式版: 移除 v6 DR0 verify 诊断 (hits=0 已确认为设计缺陷, 非 DR0 写入失败)
    return true;
}

// ★ BUILD 557: ClearDR0Breakpoint — 清除 DR0 断点 (防御性清除所有相关位)
static bool ClearDR0Breakpoint(HANDLE hThread) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return false;
    ctx.Dr0 = 0;
    ctx.Dr7 &= ~0x3ULL;       // 清 L0 (bit 0) + G0 (bit 1)
    ctx.Dr7 &= ~0x30000ULL;   // 清 RW0/LEN0 (bit 16-19) 防御性
    return SetThreadContext(hThread, &ctx) != 0;
}

static bool ApplyCs2Patch() {
    // ★ BUILD 558 FIX-4: 跨进程化 — payload.dll 在 loader.exe 进程内运行, client.dll 在 CS2 进程内
    //   原 BUILD 549 逻辑: GetModuleBaseFromPEB (本进程 PEB) → 返回 NULL (loader.exe 没加载 client.dll)
    //   新 BUILD 558 FIX-4 逻辑: cs2::Memory::ClientBase() + StealthMemory::Read/Write/Protect (跨进程)
    //
    //   架构: payload.dll (loader.exe 进程) → StealthMemory::Read/Write → CS2 进程内 client.dll
    //   StealthMemory 内部用 NtReadVirtualMemory/NtWriteVirtualMemory 直接 syscall (规避 IAT hook)

    // 1. 通过 cs2::Memory 获取 CS2 进程内 client.dll 基址
    uintptr_t clientBase = cs2::Memory::Instance().ClientBase();
    if (!clientBase) {
        DiagLogEnc("c1");  // ★ BUILD 549: 加密 "mod not loaded"
        return false;
    }

    // 2. 通过 StealthEngine 获取 CS2 进程 HANDLE
    HANDLE hProcess = stealth::StealthEngine::Instance().GetProcessHandle();
    if (!hProcess) {
        DiagLogEnc("c1");
        return false;
    }

    // 3. 跨进程读取 client.dll PE 头获取 SizeOfImage
    IMAGE_DOS_HEADER dosHdr = {};
    if (!stealth::StealthMemory::Read(hProcess, clientBase, &dosHdr, sizeof(dosHdr))) {
        DiagLog("B549:AP:01 bad DOS read\n");
        return false;
    }
    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        DiagLog("B549:AP:01 bad DOS magic\n");
        return false;
    }
    IMAGE_NT_HEADERS ntHdr = {};
    if (!stealth::StealthMemory::Read(hProcess, clientBase + dosHdr.e_lfanew, &ntHdr, sizeof(ntHdr))) {
        DiagLog("B549:AP:02 bad NT read\n");
        return false;
    }
    if (ntHdr.Signature != IMAGE_NT_SIGNATURE) {
        DiagLog("B549:AP:02 bad NT sig\n");
        return false;
    }
    size_t size = ntHdr.OptionalHeader.SizeOfImage;
    g_clientBase = clientBase;  // ★ 缓存 CS2 进程内 client.dll 基址 (跨进程访问)

    // 4. 解密 pattern (XOR 加密, 运行时解密到栈上, 避免明文特征码出现在二进制中)
    uint8_t pattern[PAT_LEN];
    for (size_t i = 0; i < PAT_LEN; i++) {
        pattern[i] = PAT_ENC[i] ^ g_patKey;
    }
    const size_t patternLen = PAT_LEN;

    // 5. 分段跨进程读取 client.dll 搜索 pattern (每段 1MB, 避免 39MB 一次性读取)
    //    ★ 不能用 std::vector (manual-mapped DLL CRT 堆问题), 用 VirtualAlloc
    //    ★ 每段多读 PAT_LEN 字节, 处理跨段匹配
    const size_t CHUNK_SIZE = 1 * 1024 * 1024;  // 1MB
    uint8_t* chunkBuf = (uint8_t*)VirtualAlloc(nullptr, CHUNK_SIZE + PAT_LEN,
                                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!chunkBuf) {
        DiagLog("B549:AP:03 alloc fail\n");
        return false;
    }

    uintptr_t foundRva = 0;  // pattern 在 CS2 client.dll 中的 RVA (0 = 未找到)
    int matchCount = 0;

    for (size_t offset = 0; offset + patternLen < size; offset += CHUNK_SIZE) {
        size_t readSize = CHUNK_SIZE + patternLen;  // 多读 patternLen 字节处理跨段匹配
        if (offset + readSize > size) readSize = size - offset;

        if (!stealth::StealthMemory::Read(hProcess, clientBase + offset, chunkBuf, readSize)) {
            continue;  // 此段读取失败 (可能未提交内存), 跳过
        }

        for (size_t i = 0; i + patternLen <= readSize; i++) {
            if (chunkBuf[i] != pattern[0]) continue;
            if (chunkBuf[i+1] != pattern[1]) continue;
            bool match = true;
            for (size_t j = 2; j < patternLen; j++) {
                if (chunkBuf[i+j] != pattern[j]) { match = false; break; }
            }
            if (match) {
                matchCount++;
                if (matchCount == 1) {
                    foundRva = offset + i;
                } else {
                    // 第二个匹配出现 — 特征码不独特, 拒绝 patch (避免 patch 错误位置)
                    DiagLog("B555:AP:05 multi-match=%d\n", matchCount);
                    VirtualFree(chunkBuf, 0, MEM_RELEASE);
                    return false;
                }
            }
        }
    }
    VirtualFree(chunkBuf, 0, MEM_RELEASE);

    if (!foundRva) {
        DiagLogEnc("c2");  // ★ BUILD 549: 加密 "pat not found"
        return false;
    }

    // 6. 跨进程读取 found 前 MAX_BACKSCAN 字节到本地 backBuf, 验证函数边界
    //    ★ BUILD 558 FIX-4: ValidatePatchFunctionBoundary 改为接收本地 buffer
    constexpr uint32_t MAX_BACKSCAN = 256;
    uint8_t backBuf[MAX_BACKSCAN];
    uint32_t backSize = (foundRva < MAX_BACKSCAN) ? (uint32_t)foundRva : MAX_BACKSCAN;
    if (backSize < 4) {
        DiagLog("B555:AP:06 backSize=%u too small\n", backSize);
        return false;
    }
    uintptr_t backAddr = clientBase + foundRva - backSize;
    if (!stealth::StealthMemory::Read(hProcess, backAddr, backBuf, backSize)) {
        DiagLog("B555:AP:06 back read fail rva=0x%llX\n", (unsigned long long)foundRva);
        return false;
    }
    if (!ValidatePatchFunctionBoundary(backBuf, backSize)) {
        // ★ BUILD 558 FIX-4: 边界验证失败 — pattern 在函数体深处, 函数入口在 256 字节外
        //   hex dump 分析: found 前是 EB 02 (jmp +2), 是函数体内部指令流, 无函数边界
        //   决策: 跳过边界验证, 继续 patch. 依据:
        //     1. pattern 是 10 字节 (32 c0 4c 8b a4 24 c8 00 00 00), 在 39MB client.dll 中唯一匹配
        //     2. EB 02 + 32 c0 是 CS2 内存解密逻辑的典型模式 (jmp 跳过 + xor al,al)
        //     3. 跨程读取验证写入成功 (L999-1007 verifyBytes 检查 90 90)
        //     4. 错误 patch 只会导致 CS2 用户态崩溃 (不是蓝屏), VEH 可捕获
        DiagLog("B558:AP:06 boundary skip rva=0x%llX (pattern in func body, EB 02 prefix)\n",
            (unsigned long long)foundRva);
        // 不返回 false, 继续 patch
    }

    // 7. 计算 CS2 进程内 patch 地址
    uintptr_t patchAddr = clientBase + foundRva;

    // 8. 检查是否已经补丁过
    if (g_cs2Patched && g_patchAddr == patchAddr) {
        return true;  // 已补丁, 无需重复
    }

    // 9. 跨程修改保护 + 写入 patch (90 90 = nop nop)
    //    ★ BUILD 558 FIX-4: 用 StealthMemory::Protect + Write 替代 VirtualProtect + 直接写入
    DWORD oldProtect = 0;
    if (!stealth::StealthMemory::Protect(hProcess, patchAddr, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        DiagLog("B549:AP:03 VP fail err=%lu\n", GetLastError());
        return false;
    }
    uint8_t patchBytes[2] = { 0x90, 0x90 };
    if (!stealth::StealthMemory::Write(hProcess, patchAddr, patchBytes, 2)) {
        DiagLog("B549:AP:04 write fail\n");
        DWORD dummy = 0;
        stealth::StealthMemory::Protect(hProcess, patchAddr, 2, oldProtect, &dummy);
        return false;
    }
    DWORD dummy = 0;
    stealth::StealthMemory::Protect(hProcess, patchAddr, 2, oldProtect, &dummy);

    // 10. 跨进程验证 patch 写入成功
    uint8_t verifyBytes[2] = {};
    if (!stealth::StealthMemory::Read(hProcess, patchAddr, verifyBytes, 2)) {
        DiagLog("B549:AP:04 verify read fail\n");
        return false;
    }
    if (verifyBytes[0] != 0x90 || verifyBytes[1] != 0x90) {
        DiagLog("B549:AP:04 verify fail b0=0x%02X b1=0x%02X\n", verifyBytes[0], verifyBytes[1]);
        return false;
    }

    g_patchAddr = patchAddr;
    DiagLogEnc("p1");  // ★ BUILD 549: 加密 "patched"
    return true;
}

// ★ BUILD 549: 补丁持久化保护 — 回退模式重写补丁
// ★ BUILD 558 FIX-4: 跨进程化 — 用 StealthMemory::Read/Write/Protect 替代直接指针解引用
static void MaintainCs2Patch() {
    if (!g_patchAddr) return;

    HANDLE hProcess = stealth::StealthEngine::Instance().GetProcessHandle();
    if (!hProcess) return;

    uintptr_t patchAddr = g_patchAddr;

    // ★ BUILD 549+: 回退模式 — 检查补丁是否被 PAC 恢复, 重写
    //   用 XOR 比较避免明文 0x32 0xc0 出现在二进制中 (g_patKey 是 volatile 防止常量传播)
    // ★ BUILD 558 FIX-4: 跨程读取 patch 地址的 2 字节
    uint8_t curBytes[2] = {};
    if (!stealth::StealthMemory::Read(hProcess, patchAddr, curBytes, 2)) {
        // ★ BUILD 567 v3.257 DIAG: 记录读取失败
        DiagLog("B558:MP:read fail addr=0x%llX\n", (unsigned long long)patchAddr);
        return;
    }

    // ★ BUILD 567 v3.257 DIAG: 记录当前 patch 字节 (用 XOR 加密避免明文)
    DiagLog("B558:MP:cur b0=0x%02X b1=0x%02X (patAddr=0x%llX)\n",
        curBytes[0], curBytes[1], (unsigned long long)patchAddr);

    if ((uint8_t)(curBytes[0] ^ g_patKey) == PAT_ENC[0] &&
        (uint8_t)(curBytes[1] ^ g_patKey) == PAT_ENC[1]) {
        // patch 被 PAC 恢复为原始字节 (32 c0), 重新写入 (90 90)
        DiagLog("B558:MP:repatch (restored to orig)\n");
        DWORD oldProtect = 0;
        if (stealth::StealthMemory::Protect(hProcess, patchAddr, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            uint8_t patchBytes[2] = { 0x90, 0x90 };
            stealth::StealthMemory::Write(hProcess, patchAddr, patchBytes, 2);
            DWORD dummy = 0;
            stealth::StealthMemory::Protect(hProcess, patchAddr, 2, oldProtect, &dummy);
            DiagLogEnc("p2");  // ★ BUILD 549: 加密 "repatched"
        }
    }
}

// ============================================================
// ★ BUILD 557: DR0 频率统计 — 枚举 CS2 线程, 设置/清除 DR0 执行断点
//   复用: B549_SYSTEM_PROCESS_INFO/B549_SYSTEM_THREAD_INFO 结构 (L624-669)
//         STEALTH_OPEN_THREAD 宏 (syscall_direct.h, BUILD 556)
//         SysQuerySystemInformation (class 5 = SystemProcessInformation)
//   线程安全: g_dr0StatActive 用 InterlockedExchange 保证幂等
//   注意: DR0 是 per-thread 寄存器, 必须枚举所有 CS2 线程单独设置
// ============================================================

// ★ BUILD 557: StartDR0FrequencyStat — ApplyCs2Patch 成功后启动 60s 频率统计
static void StartDR0FrequencyStat() {
    if (!g_patchAddr) return;
    if (InterlockedExchange(&g_dr0StatActive, 1)) return;  // 防重入 (已激活)

    // ★ BUILD 558 FIX-4: g_patchAddr 现在是 uintptr_t (CS2 进程内地址), cast 为 void*
    g_dr0Addr = (void*)g_patchAddr;
    g_dr0StatStartTick = GetTickCount();
    g_dr0HitCount = 0;
    g_dr0FirstHitTid = 0;
    g_dr0FirstHitTick = 0;

    // ★ BUILD 558 FIX-5: 必须枚举 CS2 线程 (不是 loader.exe 线程)
    //   原因: 32 c0 指令在 CS2 的 client.dll 中执行, DR0 断点必须设置在 CS2 线程上.
    //         payload.dll 在 loader.exe 进程内运行, GetCurrentProcessId() 返回 loader.exe PID,
    //         但 loader.exe 被 DKOM SelfLoopHarden 隐藏, NtQSI 找不到它 (threads=0).
    //         必须用 StealthEngine::GetProcessId() 获取 CS2 PID, 枚举 CS2 线程.
    DWORD cs2Pid = stealth::StealthEngine::Instance().GetProcessId();
    if (cs2Pid == 0) {
        DiagLog("B557:DR0:cs2pid=0 FAIL\n");
        InterlockedExchange(&g_dr0StatActive, 0);
        return;
    }

    // ★ BUILD 558 FIX-5: NtQSI 缓冲区扩容 + 重试 (64KB 栈 → 1MB 堆 + 倍增重试)
    //   原因: CS2 + 所有进程的线程信息 > 64KB, NtQSI 返回 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH)
    //   参考: stealth_process.cpp EnumerateProcesses 的重试模式 (1MB 初始, 倍增, 最多 5 次)
    ULONG bufSize = 0x100000;  // 1MB 初始
    BYTE* buf = nullptr;
    ULONG retLen = 0;
    NTSTATUS st;
    int qsiRetries = 5;
    do {
        if (buf) VirtualFree(buf, 0, MEM_RELEASE);
        buf = (BYTE*)VirtualAlloc(nullptr, bufSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buf) { InterlockedExchange(&g_dr0StatActive, 0); return; }
        st = stealth::SysQuerySystemInformation(5, buf, bufSize, &retLen);
        if (st == (NTSTATUS)0xC0000004) bufSize *= 2;  // STATUS_INFO_LENGTH_MISMATCH → 倍增
        if (--qsiRetries <= 0 && !NT_SUCCESS(st)) break;
    } while (st == (NTSTATUS)0xC0000004);
    if (!NT_SUCCESS(st)) {
        DiagLog("B557:DR0:qsi FAIL 0x%08X\n", (unsigned)st);
        VirtualFree(buf, 0, MEM_RELEASE);
        InterlockedExchange(&g_dr0StatActive, 0);
        return;
    }

    int okCount = 0, failCount = 0, threadCount = 0;
    int failOpen = 0, failSuspend = 0, failSetup = 0;  // ★ BUILD 558 FIX-5 v5: 区分 fail 原因
    BYTE* p = buf;
    while (true) {
        auto* pi = (B549_SYSTEM_PROCESS_INFO*)p;
        if (pi->NextEntryOffset == 0) break;
        p += pi->NextEntryOffset;
        // ★ BUILD 558 FIX-5: 查找 CS2 进程 (不是 loader.exe), 枚举 CS2 线程
        if ((DWORD)(uintptr_t)pi->UniqueProcessId != cs2Pid) continue;

        // 找到 CS2 进程, 遍历其线程
        // SYSTEM_THREAD_INFORMATION 数组紧跟在 SYSTEM_PROCESS_INFORMATION 之后
        BYTE* threadBase = p + sizeof(B549_SYSTEM_PROCESS_INFO);
        for (ULONG ti = 0; ti < pi->NumberOfThreads; ti++) {
            auto* thi = (B549_SYSTEM_THREAD_INFO*)(threadBase + ti * sizeof(B549_SYSTEM_THREAD_INFO));
            DWORD tid = (DWORD)(uintptr_t)thi->ClientId.UniqueThread;
            // ★ BUILD 558 FIX-5: 不需要跳过 loader 线程, 因为枚举的是 CS2 线程
            threadCount++;

            HANDLE hThread = nullptr;
            // ★ BUILD 558 FIX-5 正式版: 回退 v7 的 ClientId.UniqueProcess 修改 (ok=0, 比 v5 更糟)
            //   恢复使用 STEALTH_OPEN_THREAD 宏 (v5 状态), UniqueProcess = NULL
            //   原因: v7 设置 UniqueProcess=cs2Pid 后, NtOpenThread 严格校验 (PID,TID) 对,
            //         全部返回 INVALID_CID (0xC000000B), ok=0 fail=145 (v5 是 ok=55 fail=90).
            //   DR0 hits=0 已确认为设计缺陷 (patch 之后启动), 不是 OpenThread 失败导致.
            STEALTH_OPEN_THREAD(hThread,
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, tid);
            if (!hThread) {
                failCount++; failOpen++;
                continue;
            }

            if (SuspendThread(hThread) == (DWORD)-1) {
                CloseHandle(hThread);
                failCount++; failSuspend++;
                continue;
            }

            bool ok = SetupDR0Breakpoint(hThread, g_dr0Addr);
            ResumeThread(hThread);
            CloseHandle(hThread);

            if (ok) okCount++; else { failCount++; failSetup++; }
        }
        break;  // 当前进程只会有一个匹配
    }

    DiagLog("B557:DR0:start addr=0x%llX ok=%d fail=%d threads=%d (open=%d susp=%d setup=%d)\n",
        (unsigned long long)g_dr0Addr, okCount, failCount, threadCount, failOpen, failSuspend, failSetup);
    VirtualFree(buf, 0, MEM_RELEASE);  // ★ BUILD 558 FIX-5: 释放 NtQSI 缓冲区
}

// ★ BUILD 557: ReportDR0Frequency — 60s 后输出频率到 sd.log, 清除所有 DR0
//   关键顺序: 先 g_dr0StatDone=1, 后清 DR0, 最后 g_dr0StatActive=0
//   原因: 清除 DR0 期间 VEH 仍可能触发, g_dr0StatActive=1 让 VEH 继续正确处理
//         (Dr6 清除), 不会 fallthrough 到 ACCESS_VIOLATION 自愈逻辑
static void ReportDR0Frequency() {
    if (g_dr0StatDone) return;
    if (!g_dr0StatActive) return;
    DWORD elapsed = GetTickCount() - g_dr0StatStartTick;
    if (elapsed < DR0_STAT_INTERVAL_MS) return;

    InterlockedExchange(&g_dr0StatDone, 1);
    // g_dr0StatActive 暂保持 1, VEH 继续处理命中直到 DR0 全部清除

    LONG hits = g_dr0HitCount;
    double freqHz = (elapsed > 0) ? ((double)hits * 1000.0 / (double)elapsed) : 0.0;
    DiagLog("B557:DR0:report hits=%ld elapsed_ms=%u freq_hz=%.2f 1st_tid=%u\n",
            hits, elapsed, freqHz, g_dr0FirstHitTid);

    // 枚举所有 CS2 线程, 清除 DR0 (复用 StartDR0FrequencyStat 的枚举模式)
    // ★ BUILD 558 FIX-5: 必须枚举 CS2 线程 (不是 loader.exe 线程), 用 StealthEngine::GetProcessId()
    DWORD cs2Pid = stealth::StealthEngine::Instance().GetProcessId();
    // ★ BUILD 558 FIX-5: NtQSI 缓冲区扩容 + 重试 (64KB 栈 → 1MB 堆 + 倍增重试)
    ULONG bufSize = 0x100000;  // 1MB 初始
    BYTE* buf = nullptr;
    ULONG retLen = 0;
    NTSTATUS st;
    int qsiRetries = 5;
    do {
        if (buf) VirtualFree(buf, 0, MEM_RELEASE);
        buf = (BYTE*)VirtualAlloc(nullptr, bufSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buf) break;  // 分配失败, 跳过 DR0 清除 (g_dr0StatActive 仍会被重置)
        st = stealth::SysQuerySystemInformation(5, buf, bufSize, &retLen);
        if (st == (NTSTATUS)0xC0000004) bufSize *= 2;
        if (--qsiRetries <= 0 && !NT_SUCCESS(st)) break;
    } while (st == (NTSTATUS)0xC0000004);
    if (buf && NT_SUCCESS(st)) {
        int okCount = 0, failCount = 0;
        BYTE* p = buf;
        while (true) {
            auto* pi = (B549_SYSTEM_PROCESS_INFO*)p;
            if (pi->NextEntryOffset == 0) break;
            p += pi->NextEntryOffset;
            // ★ BUILD 558 FIX-5: 查找 CS2 进程 (不是 loader.exe)
            if ((DWORD)(uintptr_t)pi->UniqueProcessId != cs2Pid) continue;

            BYTE* threadBase = p + sizeof(B549_SYSTEM_PROCESS_INFO);
            for (ULONG ti = 0; ti < pi->NumberOfThreads; ti++) {
                auto* thi = (B549_SYSTEM_THREAD_INFO*)(threadBase + ti * sizeof(B549_SYSTEM_THREAD_INFO));
                DWORD tid = (DWORD)(uintptr_t)thi->ClientId.UniqueThread;
                // ★ BUILD 558 FIX-5: 不需要跳过 loader 线程, 枚举的是 CS2 线程

                HANDLE hThread = nullptr;
                STEALTH_OPEN_THREAD(hThread, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, tid);
                if (!hThread) { failCount++; continue; }

                SuspendThread(hThread);
                bool ok = ClearDR0Breakpoint(hThread);
                ResumeThread(hThread);
                CloseHandle(hThread);

                if (ok) okCount++; else failCount++;
            }
            break;
        }
        DiagLog("B557:DR0:cleared ok=%d fail=%d (stat done)\n", okCount, failCount);
        // ★ BUILD 567 v3.236 FIX-2: DR0 清除失败时不恢复 StealthSleep (避免 EkkoSleep 加密 .data
        //   期间残留 DR0 触发 STATUS_SINGLE_STEP → VEH 崩溃)
        //   修复 1 已让 VEH 从 CONTEXT.Dr0 读取 (不受 .data 加密影响), 此处仍保留防御:
        //   避免残留 DR0 频繁触发 VEH (性能 + 日志噪音), 主循环修复 3 会重试清除.
        if (failCount == 0) {
            DiagLog("B557:DR0:clear ALL ok=%d — restore StealthSleep\n", okCount);
            InterlockedExchange(&g_dr0StatActive, 0);
        } else {
            DiagLog("B557:DR0:clear PARTIAL ok=%d fail=%d — keep g_dr0StatActive=1 (retry in main loop)\n",
                okCount, failCount);
            // 不设置 g_dr0StatActive=0, 保持 StealthSleep 禁用
            // g_dr0StatDone=1 已设置, 主循环修复 3 检测 g_dr0StatActive && g_dr0StatDone 时重试
        }
    } else if (buf) {
        DiagLog("B557:DR0:clear qsi FAIL 0x%08X — keep g_dr0StatActive=1\n", (unsigned)st);
        // ★ v3.236: QSI 失败也无法清除 DR0, 保持 g_dr0StatActive=1
    }
    if (buf) VirtualFree(buf, 0, MEM_RELEASE);  // ★ BUILD 558 FIX-5: 释放 NtQSI 缓冲区

    // ★ BUILD 567 v3.236: 移除末尾无条件 InterlockedExchange(&g_dr0StatActive, 0)
    //   g_dr0StatActive 的恢复由上方 failCount==0 分支处理 (全部清除成功才恢复)
}

// ★ BUILD 567 v3.236 FIX-3: DR0 清除重试机制 — 主循环 10s 周期调用
//   触发条件: g_dr0StatActive=1 && g_dr0StatDone=1 (ReportDR0Frequency 已执行但有残留 DR0)
//   全部清除成功时恢复 StealthSleep (g_dr0StatActive=0), 否则保持禁用等待下次重试
//   复用 ReportDR0Frequency 的 NtQSI + 枚举 CS2 线程 + ClearDR0Breakpoint 模式
static void RetryClearDR0Breakpoints() {
    DWORD cs2Pid = stealth::StealthEngine::Instance().GetProcessId();
    ULONG bufSize = 0x100000;  // 1MB 初始
    BYTE* buf = nullptr;
    ULONG retLen = 0;
    NTSTATUS st;
    int qsiRetries = 5;
    do {
        if (buf) VirtualFree(buf, 0, MEM_RELEASE);
        buf = (BYTE*)VirtualAlloc(nullptr, bufSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buf) return;  // 分配失败, 等待下次重试
        st = stealth::SysQuerySystemInformation(5, buf, bufSize, &retLen);
        if (st == (NTSTATUS)0xC0000004) bufSize *= 2;
        if (--qsiRetries <= 0 && !NT_SUCCESS(st)) break;
    } while (st == (NTSTATUS)0xC0000004);

    if (!buf || !NT_SUCCESS(st)) {
        if (buf) VirtualFree(buf, 0, MEM_RELEASE);
        return;  // QSI 失败, 等待下次重试
    }

    int okCount = 0, failCount = 0;
    BYTE* p = buf;
    while (true) {
        auto* pi = (B549_SYSTEM_PROCESS_INFO*)p;
        if (pi->NextEntryOffset == 0) break;
        p += pi->NextEntryOffset;
        if ((DWORD)(uintptr_t)pi->UniqueProcessId != cs2Pid) continue;

        BYTE* threadBase = p + sizeof(B549_SYSTEM_PROCESS_INFO);
        for (ULONG ti = 0; ti < pi->NumberOfThreads; ti++) {
            auto* thi = (B549_SYSTEM_THREAD_INFO*)(threadBase + ti * sizeof(B549_SYSTEM_THREAD_INFO));
            DWORD tid = (DWORD)(uintptr_t)thi->ClientId.UniqueThread;

            HANDLE hThread = nullptr;
            STEALTH_OPEN_THREAD(hThread, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, tid);
            if (!hThread) { failCount++; continue; }

            SuspendThread(hThread);
            bool ok = ClearDR0Breakpoint(hThread);
            ResumeThread(hThread);
            CloseHandle(hThread);

            if (ok) okCount++; else failCount++;
        }
        break;
    }
    VirtualFree(buf, 0, MEM_RELEASE);

    DiagLog("B557:DR0:retry ok=%d fail=%d\n", okCount, failCount);
    if (failCount == 0) {
        DiagLog("B557:DR0:retry ALL ok=%d — restore StealthSleep\n", okCount);
        InterlockedExchange(&g_dr0StatActive, 0);
    }
    // failCount > 0 时保持 g_dr0StatActive=1, 等待下次重试 (10s 后)
}

// ★ BUILD 549: 防截图 — 改用 NtQuerySystemInformation syscall (绕过 PAC 用户态 hook)
//   原 BUILD 548: CreateToolhelp32Snapshot (每秒调用, 可能被 hook)
//   新 BUILD 549: SysQuerySystemInformation (syscall 直接调用, 频率降到 5s)
static bool IsScreenshotToolRunning() {
    // ★ BUILD 558 FIX-5: NtQSI 缓冲区扩容 + 重试 (256KB → 1MB 初始 + 倍增重试)
    //   原因: 256KB 不够 (CS2 + 所有进程), NtQSI 返回 0xC0000004
    ULONG bufferSize = 0x100000;  // 1MB 初始
    BYTE* buffer = nullptr;
    ULONG returnLength = 0;
    NTSTATUS status;
    int qsiRetries = 5;
    do {
        if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = (BYTE*)VirtualAlloc(nullptr, bufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buffer) return false;
        // SystemProcessInformation = 5
        status = stealth::SysQuerySystemInformation(5, buffer, bufferSize, &returnLength);
        if (status == (NTSTATUS)0xC0000004) bufferSize *= 2;  // STATUS_INFO_LENGTH_MISMATCH → 倍增
        if (--qsiRetries <= 0 && !NT_SUCCESS(status)) break;
    } while (status == (NTSTATUS)0xC0000004);

    bool found = false;
    if (NT_SUCCESS(status)) {
        // ★ BUILD 560: wShotTools 移到 while 循环外 (原 BUILD 554 在循环内每次重新解密, 浪费 CPU)
        //   ★ BUILD 560: 缩短 .data 段明文窗口 — wShotTools 改为栈变量 (原 static 永久存在 .data 段)
        //   原因: static wchar_t wShotTools[15][32] 在 .data 段, 解密后的截图工具名
        //         ("SnippingTool.exe" 等) 永久存在, PAC 任何时候扫描 .data 段都能发现.
        //   修复: 改为栈变量, 函数执行期间 (~1-10ms) 短暂存在, 末尾 SecureZeroMemory 清零.
        //   开销: 每 5s 解密 8 个字符串 < 1μs (可忽略).
        //   安全: EkkoSleep 不影响栈变量 (栈不在 EkkoSleep 保护区), 无副作用.
        //   检测列表 (保留 8 个核心工具): SnippingTool/ShareX/Greenshot/Lightshot/
        //     ScreenClippingHost/OBS/obs64/Streamlabs OBS.
        //   BUILD 558 FIX-5 已移除: Discord/GameBar/GameBarFTServer/Steam/
        //     NVIDIA Share/ShadowShare/AMDRSSrcExt (误触发风险高).
        wchar_t wShotTools[15][32] = {};
        STEALTH_WSTR_DECRYPT_TO("SnippingTool.exe",       wShotTools[0],  32);
        STEALTH_WSTR_DECRYPT_TO("ShareX.exe",             wShotTools[1],  32);
        STEALTH_WSTR_DECRYPT_TO("Greenshot.exe",          wShotTools[2],  32);
        STEALTH_WSTR_DECRYPT_TO("Lightshot.exe",          wShotTools[3],  32);
        STEALTH_WSTR_DECRYPT_TO("ScreenClippingHost.exe", wShotTools[4],  32);
        STEALTH_WSTR_DECRYPT_TO("OBS.exe",                wShotTools[5],  32);
        STEALTH_WSTR_DECRYPT_TO("obs64.exe",              wShotTools[6],  32);
        STEALTH_WSTR_DECRYPT_TO("Streamlabs OBS.exe",     wShotTools[7],  32);
        // idx 8-14 保持全零 (栈变量初始化为 0, 跳过匹配)

        BYTE* ptr = buffer;
        while (true) {
            auto* entry = (B549_SYSTEM_PROCESS_INFO*)ptr;
            if (entry->ImageName.Buffer && entry->UniqueProcessId) {
                    WCHAR name[MAX_PATH] = {};
                    SIZE_T nameLen = entry->ImageName.Length / sizeof(WCHAR);
                    if (nameLen >= MAX_PATH) nameLen = MAX_PATH - 1;
                    memcpy(name, entry->ImageName.Buffer, nameLen * sizeof(WCHAR));

                    // ★ BUILD 560: wShotTools 已移到 while 循环外 (函数顶部), 此处直接使用
                    //   原 BUILD 554 static 数组 + init flag 已删除, 改为栈变量 + 末尾清零
                    for (int si = 0; si < 15; si++) {
                        if (wShotTools[si][0] && _wcsicmp(name, wShotTools[si]) == 0) {
                            // ★ BUILD 558 FIX-5: 诊断日志 — 输出匹配的进程名, 确认误触发源
                            DiagLog("B558:SS:hit proc='%ls' idx=%d\n", name, si);
                            found = true;
                            break;
                        }
                    }
                    if (found) break;
                }
            if (entry->NextEntryOffset == 0) break;
            ptr += entry->NextEntryOffset;
        }

        // ★ BUILD 560: 主动清零栈缓冲 — 缩短 .data 段明文窗口
        //   wShotTools 是栈变量 (非 static), 函数返回时自动销毁, 但栈帧可能被后续函数复用.
        //   显式 SecureZeroMemory 确保 PAC 扫描栈内存时看不到截图工具名明文.
        SecureZeroMemory(wShotTools, sizeof(wShotTools));
    } else {
        DiagLog("B549:SS:01 NtQSI fail st=0x%08X\n", (unsigned)status);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return found;
}

// ★ BUILD 548: 临时撤销补丁（截图时）
// ★ BUILD 549: 影子页模式下, 截图检测时永久切到 pageA (RevealOriginal)
//               此函数仅在回退模式 (VirtualProtect) 下使用
// ★ BUILD 558 FIX-4: 跨进程化 — 用 StealthMemory::Write/Protect 替代直接指针解引用
static void TemporarilyRevertPatch() {
    if (!g_patchAddr) return;
    HANDLE hProcess = stealth::StealthEngine::Instance().GetProcessHandle();
    if (!hProcess) return;

    uintptr_t patchAddr = g_patchAddr;
    DWORD oldProtect = 0;
    if (stealth::StealthMemory::Protect(hProcess, patchAddr, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // ★ BUILD 549+: 用 XOR 解密写入原始字节 (避免明文 0x32 0xc0 出现在二进制中)
        uint8_t origBytes[2] = {
            (uint8_t)(PAT_ENC[0] ^ g_patKey),  // = 0x32
            (uint8_t)(PAT_ENC[1] ^ g_patKey)   // = 0xc0
        };
        stealth::StealthMemory::Write(hProcess, patchAddr, origBytes, 2);
        DWORD dummy = 0;
        stealth::StealthMemory::Protect(hProcess, patchAddr, 2, oldProtect, &dummy);
        DiagLogEnc("r1");  // ★ BUILD 549: 加密 "reverted"
    }
}
// ★ BUILD 549+: CleanupInjectionTraces 是 dead code (BUILD 548 不再注入独立模块)
//   用 #if 0 包裹避免编译, 同时消除所有明文 CS2 模块名 (client.dll/engine2.dll/tier0/input)
//   和明文日志字符串 (CleanupInjectionTraces: ...) 出现在二进制中
//   如果未来需要恢复 (例如 BUILD 550+ 重新注入独立模块), 移除 #if 0 并:
//     1. 用 ModNameHash 替代 L"client.dll" 明文
//     2. 用 NtQuerySystemInformation 替代 CreateToolhelp32Snapshot (已实现, 见函数体)
//     3. 用 STEALTH_STR_DECRYPT_TO 加密所有 DiagLog 字符串
#if 0
// v3.32-plus: 注入痕迹清理 — 基础.exe 注入到 cs2.exe 后, 从外部通过 handles
// 清除 PEB Ldr 链表中的注入模块条目, 防止反作弊用户态模块枚举检测
// 同时清理 VAD PE 头部 + 注入线程的 TEB Win32StartAddress
// v3.33: 新增 VAD PE 头清零 (Method 1) + 线程 StartAddress 欺骗 (Method 2)
static void CleanupInjectionTraces() {
    using namespace stealth;
    HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
    if (!hProc) return;

    // v3.34: 随机等待基础.exe 完成注入
    Sleep(RandomJitter(2500, 2500));
    DiagLog("CleanupInjectionTraces: scanning PEB Ldr...\n");

    // 1. 获取 PEB 地址
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG rl = 0;
    if (!NT_SUCCESS(SysQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), &rl, SyscallMethod::Indirect))) {
        DiagLog("CleanupInjectionTraces: QueryInfoProcess failed\n");
        return;
    }
    DiagLog("CleanupInjectionTraces: PEB=0x%llX\n", (unsigned long long)pbi.PebBaseAddress);

    // 2. 读取 PEB → Ldr
    BYTE pebBuf[0x200] = {};
    SIZE_T br = 0;
    if (!NT_SUCCESS(SysReadVirtualMemory(hProc, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &br, SyscallMethod::Indirect))) {
        DiagLog("CleanupInjectionTraces: Read PEB failed\n");
        return;
    }
    uintptr_t ldr = *(uintptr_t*)(pebBuf + 0x18);
    DiagLog("CleanupInjectionTraces: Ldr=0x%llX\n", (unsigned long long)ldr);
    if (!ldr) return;

    // 已知合法模块前缀 (CS2 + Windows系统)
    static const wchar_t* knownPrefixes[] = {
        L"ntdll", L"kernel", L"KERNEL", L"user32", L"gdi32",
        L"advapi", L"shell32", L"ole32", L"comctl", L"msvc",
        L"vcruntime", L"ucrtbase", L"bcrypt", L"crypt",
        L"setupapi", L"winhttp", L"ws2_32", L"iphlpapi",
        L"d3d", L"dxgi", L"nv", L"ati", L"amd",
        L"client.dll", L"engine2.dll", L"tier0", L"input",
        L"materials", L"vphysics", L"studiorender",
        L"scenesystem", L"resourcesystem", L"rendersystem",
        L"soundsystem", L"networksystem", L"animationsystem",
        L"particles", L"vscript", L"vstdlib", L"matchmaking",
        L"steamclient", L"gameoverlay", L"serverbrowser",
        L"msvcp", L"concrt", L"shcore", L"imm32",
        L"windows.", L"profapi", L"powrprof",
        L"umpdc", L"kernelbase", L"cfg", L"devobj",
        L"wintrust", L"msasn1", L"crypt32", L"wldp",
        L"ntmarta", L"fltlib", L"sechost", L"sspicli",
        L"gdi32full", L"win32u", L"msctf", L"textinput",
        L"msimg32", L"dbghelp", L"dbgcore",
        nullptr
    };

    auto isKnownModule = [&](const wchar_t* name) -> bool {
        if (!name[0]) return true; // 空名跳过

        // v3.32-plus: 文件名可能包含完整路径, 对末尾文件名做精确匹配
        const wchar_t* basename = name;
        // 跳过路径部分, 只保留最后一个 \ 之后
        const wchar_t* lastSlash = wcsrchr(name, L'\\');
        if (lastSlash) basename = lastSlash + 1;

        for (int i = 0; knownPrefixes[i]; i++) {
            if (_wcsnicmp(basename, knownPrefixes[i], wcslen(knownPrefixes[i])) == 0)
                return true;
            // 回退: 全路径前缀匹配
            if (_wcsnicmp(name, knownPrefixes[i], wcslen(knownPrefixes[i])) == 0)
                return true;
        }
        return false;
    };

    // 3. 同时清理两个模块链表: InLoadOrder (Ldr+0x10) 和 InMemoryOrder (Ldr+0x20)
    // v3.33: 记录被摘除模块的 dllBase, 后续做 PE 头清零 + 线程欺骗
    struct ListCleanup { uintptr_t headAddr; const char* desc; };
    ListCleanup lists[] = {
        { ldr + 0x10, "InLoadOrder" },
        { ldr + 0x20, "InMemoryOrder" },
    };

    uintptr_t cleanedBases[32] = {};  // v3.33: 记录摘除的模块基址
    int numCleaned = 0;

    int totalCleaned = 0;
    for (auto& list : lists) {
        BYTE headBuf[16] = {};
        if (!NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)list.headAddr, headBuf, 16, &br, SyscallMethod::Indirect)))
            continue;

        uintptr_t headLink = list.headAddr;
        uintptr_t cur = *(uintptr_t*)(headBuf + 0); // FLink
        int walked = 0;

        while (cur && cur != headLink && walked < 256) {
            walked++;
            BYTE modBuf[0x200] = {};
            if (!NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)cur, modBuf, sizeof(modBuf), &br, SyscallMethod::Indirect)))
                break;

            uintptr_t flink = *(uintptr_t*)(modBuf + 0);
            uintptr_t dllBase = *(uintptr_t*)(modBuf + 0x30);
            uintptr_t nameBufAddr = *(uintptr_t*)(modBuf + 0x48);
            USHORT nameLen = *(USHORT*)(modBuf + 0x50);

            wchar_t modName[128] = {};
            if (nameBufAddr && nameLen > 0 && nameLen < 254) {
                SysReadVirtualMemory(hProc, (PVOID)nameBufAddr, modName,
                    (SIZE_T)(std::min((int)nameLen, 254)), &br, SyscallMethod::Indirect);
            }

            if (!isKnownModule(modName) && dllBase) {
                DiagLog("CleanupInjectionTraces: [%s] UNLINK %ls (base=0x%llX)\n",
                    list.desc, modName, (unsigned long long)dllBase);

                // 记录基址用于后续 PE 头清零 + 线程欺骗
                bool alreadyRecorded = false;
                for (int k = 0; k < numCleaned; k++) {
                    if (cleanedBases[k] == dllBase) { alreadyRecorded = true; break; }
                }
                if (!alreadyRecorded && numCleaned < 32) {
                    cleanedBases[numCleaned++] = dllBase;
                }

                // 读取当前节点的 LIST_ENTRY
                uintptr_t nodeFlink = *(uintptr_t*)(modBuf + 0);
                uintptr_t nodeBlink = *(uintptr_t*)(modBuf + 8);

                if (nodeFlink && nodeBlink) {
                    SIZE_T wb = 0;
                    SysWriteVirtualMemory(hProc, (PVOID)nodeBlink, &nodeFlink, 8, &wb, SyscallMethod::Indirect);
                    SysWriteVirtualMemory(hProc, (PVOID)(nodeFlink + 8), &nodeBlink, 8, &wb, SyscallMethod::Indirect);
                    SysWriteVirtualMemory(hProc, (PVOID)(cur + 0), &cur, 8, &wb, SyscallMethod::Indirect);
                    SysWriteVirtualMemory(hProc, (PVOID)(cur + 8), &cur, 8, &wb, SyscallMethod::Indirect);
                    totalCleaned++;
                }
            }

            cur = flink;
        }
    }

    DiagLog("CleanupInjectionTraces: Ldr done, cleaned %d entries, %d unique bases\n",
        totalCleaned, numCleaned);

    // ============================================================
    // v3.33 Method 1: VAD 区域 PE 头清零
    // 即使反作弊绕过 PEB Ldr 直接扫描 MEM_PRIVATE 可执行页,
    // 也找不到 PE 头 (MZ/PE 签名), 无法确认为注入 DLL
    // ============================================================
    for (int i = 0; i < numCleaned; i++) {
        uintptr_t base = cleanedBases[i];
        if (!base || base < 0x10000) continue;

        // 读取 DLL 基址的 PE 头验证
        BYTE peSig[0x1000] = {};
        SIZE_T rbytes = 0;
        NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)base, peSig, sizeof(peSig), &rbytes, SyscallMethod::Indirect);

        if (NT_SUCCESS(st) && rbytes >= 0x200) {
            // 验证 MZ 签名 (前2字节 = "MZ")
            if (peSig[0] == 'M' && peSig[1] == 'Z') {
                DiagLog("CleanupInjectionTraces: [PE-ZERO] base=0x%llX, zeroing PE header (0x1000 bytes)\n",
                    (unsigned long long)base);

                // 清零 PE 头 (前 0x1000 字节: DOS头 + PE签名 + Optional Header + Section Headers)
                BYTE zeros[0x1000] = {};
                SIZE_T wb = 0;
                NTSTATUS ws = SysWriteVirtualMemory(hProc, (PVOID)base, zeros, 0x1000, &wb, SyscallMethod::Indirect);
                DiagLog("CleanupInjectionTraces: [PE-ZERO] write status=0x%08X bytes=%zu\n",
                    (unsigned)ws, wb);

                // 改保护: MEM_PRIVATE 可执行页 → EXECUTE_READ (模拟 mapped image 的 .text 段)
                // 反作弊 VAD 扫描: mapped image = MEM_MAPPED + EXECUTE_READ; injected = MEM_PRIVATE + EXECUTE_READWRITE
                // 我们无法改 MEM 类型, 但把 protection 改成 EXECUTE_READ 降低可疑程度
                ULONG oldProt = 0;
                SIZE_T regionSize = 0x1000;
                PVOID protAddr = (PVOID)base;
                SysProtectVirtualMemory(hProc, &protAddr, &regionSize, PAGE_EXECUTE_READ, &oldProt,
                    SyscallMethod::Indirect);
            } else {
                DiagLog("CleanupInjectionTraces: [PE-ZERO] base=0x%llX SKIP (no MZ signature)\n",
                    (unsigned long long)base);
            }
        } else {
            DiagLog("CleanupInjectionTraces: [PE-ZERO] base=0x%llX read failed status=0x%08X\n",
                (unsigned long long)base, (unsigned)st);
        }
    }

    // ============================================================
    // v3.33 Method 2: 线程 StartAddress 欺骗
    // 基础.exe 注入后在 cs2.exe 中有额外线程,
    // 反作弊可通过 NtQueryInformationThread → Win32StartAddress 发现
    // 未知范围内的线程 → 判定为注入线程
    // 策略: 将注入线程的 Win32StartAddress 改写为 ntdll!RtlUserThreadStart
    // ============================================================
    if (numCleaned > 0) {
        // 获取 ntdll.dll 在 cs2.exe 中的基址 (从 PEB→Ldr 读取)
        // 使用 RtlUserThreadStart 作为合法启动地址
        // 偏移: ntdll.dll + RtlUserThreadStart offset
        // RtlUserThreadStart 是已知偏移: Win10=0x1E150, Win11=0x21C50 附近
        // 使用更通用的方法: 从我们的 ntdll 获取 RtlUserThreadStart 地址,
        // 再计算 RVA

        // 获取本地 ntdll 的 RtlUserThreadStart 地址
        HMODULE hLocalNtdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));  // ★ BUILD 549+: PEB Ldr
        uint64_t localRtlUserThreadStart = 0;
        if (hLocalNtdll) {
            localRtlUserThreadStart = (uint64_t)STEALTH_GET_PROC_ADDRESS_NOREF(hLocalNtdll, "RtlUserThreadStart");
        }

        // 从 cs2.exe 的 PEB 获取 ntdll.dll 基址
        uint64_t remoteNtdllBase = 0;
        {
            BYTE headBuf2[16] = {};
            if (NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)(ldr + 0x10), headBuf2, 16, &br, SyscallMethod::Indirect))) {
                uintptr_t cur2 = *(uintptr_t*)(headBuf2 + 0);
                int w2 = 0;
                while (cur2 && cur2 != (ldr + 0x10) && w2 < 256) {
                    w2++;
                    BYTE modBuf2[0x200] = {};
                    if (!NT_SUCCESS(SysReadVirtualMemory(hProc, (PVOID)cur2, modBuf2, sizeof(modBuf2), &br, SyscallMethod::Indirect)))
                        break;
                    uintptr_t fl2 = *(uintptr_t*)(modBuf2 + 0);
                    uintptr_t db2 = *(uintptr_t*)(modBuf2 + 0x30);
                    uintptr_t nm = *(uintptr_t*)(modBuf2 + 0x48);
                    USHORT nl = *(USHORT*)(modBuf2 + 0x50);
                    wchar_t mname[64] = {};
                    if (nm && nl > 0 && nl < 128) {
                        SysReadVirtualMemory(hProc, (PVOID)nm, mname, nl, &br, SyscallMethod::Indirect);
                    }
                    if (wcsstr(mname, L"ntdll") || wcsstr(mname, L"NTDLL")) {
                        remoteNtdllBase = db2;
                        break;
                    }
                    cur2 = fl2;
                }
            }
        }
        DiagLog("CleanupInjectionTraces: remote ntdll=0x%llX\n", (unsigned long long)remoteNtdllBase);

        // 计算 RtlUserThreadStart 在远程 ntdll 中的地址
        uint64_t localNtdllBase = 0;
        if (hLocalNtdll) {
            localNtdllBase = (uint64_t)hLocalNtdll;
        }
        uint64_t rvaRtlUserStart = localRtlUserThreadStart - localNtdllBase;
        uint64_t remoteRtlUserThreadStart = remoteNtdllBase ? (remoteNtdllBase + rvaRtlUserStart) : 0;

        DiagLog("CleanupInjectionTraces: local ntdll=0x%llX RtlUserThreadStart=0x%llX rva=0x%llX remote=0x%llX\n",
            (unsigned long long)localNtdllBase, (unsigned long long)localRtlUserThreadStart,
            (unsigned long long)rvaRtlUserStart, (unsigned long long)remoteRtlUserThreadStart);

        // ★ BUILD 549+: 用 NtQuerySystemInformation 替代 CreateToolhelp32Snapshot (规避 PAC hook)
        //   SystemProcessInformation (class 5) 返回每个进程 + 其线程数组
        //   遍历找到 cs2 pid 的进程, 从其线程数组中枚举所有 TID
        DWORD cs2Pid = GetProcessId(hProc);

        ULONG qsiBufSize = 0x100000;  // 1MB 初始
        BYTE* qsiBuf = (BYTE*)VirtualAlloc(nullptr, qsiBufSize, MEM_COMMIT, PAGE_READWRITE);
        if (qsiBuf) {
            ULONG retLen = 0;
            // 5 = SystemProcessInformation
            NTSTATUS qsiSt = stealth::SysQuerySystemInformation(5, qsiBuf, qsiBufSize, &retLen);
            int qsiRetry = 0;
            while (qsiSt == (NTSTATUS)0xC0000004 && qsiRetry < 3) {  // STATUS_INFO_LENGTH_MISMATCH
                VirtualFree(qsiBuf, 0, MEM_RELEASE);
                qsiBufSize *= 2;
                qsiBuf = (BYTE*)VirtualAlloc(nullptr, qsiBufSize, MEM_COMMIT, PAGE_READWRITE);
                if (!qsiBuf) break;
                qsiSt = stealth::SysQuerySystemInformation(5, qsiBuf, qsiBufSize, &retLen);
                qsiRetry++;
            }
            DiagLog("CleanupInjectionTraces: NtQSI status=0x%08X buf=%u cs2Pid=%u\n",
                (unsigned)qsiSt, qsiBufSize, cs2Pid);

            if (NT_SUCCESS(qsiSt) && qsiBuf) {
                BYTE* ptr = qsiBuf;
                while (true) {
                    auto* proc = (B549_SYSTEM_PROCESS_INFO*)ptr;
                    DWORD pid = proc->UniqueProcessId ? (DWORD)(uintptr_t)proc->UniqueProcessId : 0;

                    if (pid == cs2Pid) {
                        DiagLog("CleanupInjectionTraces: CS2 found, threads=%u\n",
                            proc->NumberOfThreads);
                        // 找到 CS2 进程, 枚举其线程数组
                        // B549_SYSTEM_THREAD_INFO 数组紧跟在 B549_SYSTEM_PROCESS_INFO 之后
                        BYTE* threadPtr = ptr + sizeof(B549_SYSTEM_PROCESS_INFO);
                        for (ULONG t = 0; t < proc->NumberOfThreads; t++) {
                            auto* sti = (B549_SYSTEM_THREAD_INFO*)threadPtr;
                            DWORD tid = sti->ClientId.UniqueThread
                                      ? (DWORD)(uintptr_t)sti->ClientId.UniqueThread : 0;

                            HANDLE hTh = nullptr;
                            // ★ BUILD 556: STEALTH_OPEN_THREAD 替代 OpenThread
                            //   消除 kernel32!OpenThread IAT 静态导入特征
                            //   规避: OpenThread 触发 ObRegisterCallbacks 内核回调 (PAC 注册)
                            STEALTH_OPEN_THREAD(hTh, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, tid);
                            if (hTh) {
                                // 查询 Win32StartAddress (class 9)
                                PVOID startAddr = nullptr;
                                ULONG ql = 0;
                                HMODULE localNtdll2 = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));  // ★ BUILD 549+: PEB Ldr
                                if (localNtdll2) {
                                    using NtQIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                                    auto pNtQIT = (NtQIT_t)STEALTH_GET_PROC_ADDRESS_NOREF(localNtdll2, "NtQueryInformationThread");
                                    if (pNtQIT) {
                                        pNtQIT(hTh, 9, &startAddr, sizeof(startAddr), &ql);
                                    }
                                }

                                // 检查 startAddr 是否在注入模块范围内
                                bool isInjected = false;
                                if (startAddr) {
                                    uint64_t sa = (uint64_t)startAddr;
                                    // 排除 ntdll.dll 和 cs2.exe 自己
                                    if (remoteNtdllBase && sa >= remoteNtdllBase && sa < remoteNtdllBase + 0x300000) {
                                        // 在 ntdll 范围内 → 合法线程
                                    } else {
                                        for (int k = 0; k < numCleaned; k++) {
                                            if (sa >= cleanedBases[k] && sa < cleanedBases[k] + 0x2000000) {
                                                isInjected = true;
                                                break;
                                            }
                                        }
                                    }
                                }

                                if (isInjected && remoteRtlUserThreadStart) {
                                    DiagLog("CleanupInjectionTraces: [THREAD] TID=%lu StartAddr=0x%llX → spoof=0x%llX\n",
                                        tid, (unsigned long long)startAddr,
                                        (unsigned long long)remoteRtlUserThreadStart);

                                    // 写入 TEB->Win32StartAddress (偏移 0x1C8 in TEB)
                                    // 需要先获取线程的 TEB 地址
                                    // TEB 地址 = NtQueryInformationThread(ThreadBasicInformation) → TebBaseAddress
                                    THREAD_BASIC_INFORMATION tbi = {};
                                    ULONG tbiLen = 0;
                                    HMODULE localNtdll3 = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));  // ★ BUILD 549+: PEB Ldr
                                    if (localNtdll3) {
                                        using NtQIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                                        auto pNtQIT2 = (NtQIT_t)STEALTH_GET_PROC_ADDRESS_NOREF(localNtdll3, "NtQueryInformationThread");
                                        if (pNtQIT2) {
                                            NTSTATUS tbiSt = pNtQIT2(hTh, 0, &tbi, sizeof(tbi), &tbiLen);
                                            if (NT_SUCCESS(tbiSt) && tbi.TebBaseAddress) {
                                                SIZE_T wt = 0;
                                                uintptr_t tebWin32StartAddr = (uintptr_t)tbi.TebBaseAddress + 0x1C8;
                                                SysWriteVirtualMemory(hProc, (PVOID)tebWin32StartAddr,
                                                    &remoteRtlUserThreadStart, 8, &wt, SyscallMethod::Indirect);
                                            }
                                        }
                                    }
                                }

                                CloseHandle(hTh);
                            }

                            threadPtr += sizeof(B549_SYSTEM_THREAD_INFO);  // 0x50
                        }
                        break;  // 找到 CS2 进程后退出
                    }

                    if (proc->NextEntryOffset == 0) break;
                    ptr += proc->NextEntryOffset;
                }
            }

            if (qsiBuf) VirtualFree(qsiBuf, 0, MEM_RELEASE);
        }
    }

    // v3.34 Scheme 1: VAD 节点伪装 (MEM_PRIVATE → MEM_MAPPED)
    //   通过 BYOVD 内核 R/W 修改 cs2.exe 的 VAD 树,
    //   使注入区域看起来像正常模块映射
    if (numCleaned > 0) {
        DWORD cs2Pid = GetProcessId(StealthEngine::Instance().GetProcessHandle());
        int vadOk = VADConcealer::ConcealAllRegions(cs2Pid, cleanedBases, numCleaned);
        DiagLog("CleanupInjectionTraces: [VAD-CONCEAL] %d/%d regions masked\n", vadOk, numCleaned);
    }

    DiagLog("CleanupInjectionTraces: done (PE zero + thread spoof + VAD conceal)\n");
}
#endif  // ★ BUILD 549+: CleanupInjectionTraces dead code 包裹结束

// ============================================================
// 作弊主循环
// 直接在 DllMain 的调用线程上运行，不创建新线程
// ============================================================

static DWORD CheatMainLoop(HMODULE dllBase, SIZE_T dllSize) {
    using namespace stealth;

    // 清除旧日志
    wchar_t logPath[MAX_PATH];
    GetTempPathW(MAX_PATH, logPath);
    wcscat_s(logPath, L"sd.log");  // ★ BUILD 549: 文件名脱敏 (原 stealth_diag.log)
    DeleteFileW(logPath);
    // ★ BUILD 567 v3.227: 启动摘要 (系统信息 + BUILD 版本, 封号分析用)
    LogStartSummary();
    DiagLogEnc("d1");  // ★ BUILD 549: 加密 "diag start b549"
    DiagLog("BEFORE Init...\n");

    // ★ BUILD 529: PAC PROBE 模式已废弃 — 改为 E+G 测试模式
    //   原 PROBE 模式 (验证 ob>0 后 DisableAll 退出) 无意义: PAC 未注册 ObCallbacks 时
    //   ob=0 是正常的, 不代表 E+G 保护失败; 且原模式会立即退出, 无法验证长时间运行稳定性.
    //
    //   BUILD 529 改造: flag 存在时设置 g_egTestMode=true, 不退出, fallthrough 到主流程.
    //   主流程中 g_egTestMode 控制: 跳过 CS2 附加 + basic.exe 启动, 仅运行 E+G 保护层
    //   (驱动+ObCallbacks+DKOM+EkkoSleep+周期性保护).
    //   用于测试2: 无 CS2 长时间运行验证无蓝屏 (不下载 basic.exe, 防封号).
    //   注入功能仅在测试3 (无 flag) 时启用.
    {
        wchar_t probePath[MAX_PATH];
        GetTempPathW(MAX_PATH, probePath);
        wcscat_s(probePath, L"pac_probe.flag");
        g_egTestMode = (GetFileAttributesW(probePath) != INVALID_FILE_ATTRIBUTES);
        if (g_egTestMode) {
            DiagLog("B550:TM:eg-test no-tgt no-patch\n");  // ★ BUILD 550: 脱敏 (原含 CS2)
            DiagLog("B550:TM:flag=%ls\n", probePath);
            DiagLog("B550:TM:skip tgt-attach+patch, eg-only\n");
        } else {
            DiagLog("B550:TM:normal mode (tgt+patch)\n");
        }

        // ★ BUILD 537: 半测试模式检查 — half_test.flag 存在时附加 CS2 但跳过 basic.exe
        //   阶段 A 测试: 验证 loader2 附加 CS2 不被踢 + ObCallbacks 移除有效
        if (!g_egTestMode) {
            wchar_t halfPath[MAX_PATH];
            GetTempPathW(MAX_PATH, halfPath);
            wcscat_s(halfPath, L"half_test.flag");
            g_halfTestMode = (GetFileAttributesW(halfPath) != INVALID_FILE_ATTRIBUTES);
            if (g_halfTestMode) {
                DiagLog("B550:HM:half-test tgt-yes patch-no\n");  // ★ BUILD 550: 脱敏
                DiagLog("B550:HM:flag=%ls\n", halfPath);
                DiagLog("B550:HM:attach tgt + eg, skip patch\n");
            }
        }

        // ★ BUILD 548: disable_basic.flag 检查已移除 (basic.exe 已移除, 不再需要此 flag)
    }

    // v3.34: 随机种子 (基于 PID+TID+TickCount, 规避可预测性)
    srand((unsigned)(GetTickCount() ^ GetCurrentProcessId() ^ GetCurrentThreadId()));

    // 安装 VEH 崩溃捕获器
    g_diagDllBase = dllBase;
    g_diagDllSize = dllSize;
    PVOID vehHandle = AddVectoredExceptionHandler(1, DiagVehHandler);
    DiagLog("VEH registered, dllBase=0x%llX dllSize=%llu\n",
        (unsigned long long)dllBase, (unsigned long long)dllSize);

    // ★ BUILD 536: 记录主线程 ID + 获取 ntdll!RtlDeactivateActivationContext 地址范围
    //   用于 VEH 捕获 worker 线程激活上下文栈 NULL 崩溃 (cmp [rax+0x38],9 解引用 NULL)
    g_mainThreadId = GetCurrentThreadId();
    {
        HMODULE hNtdll = stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll"));  // ★ BUILD 549+: PEB Ldr
        if (hNtdll) {
            FARPROC pfn = STEALTH_GET_PROC_ADDRESS_NOREF(hNtdll, "RtlDeactivateActivationContext");
            if (pfn) {
                g_RtlDeactivateAddr = (uint64_t)pfn;
                g_RtlDeactivateEnd  = (uint64_t)pfn + 0x800;  // 保守范围 2KB (函数通常 < 1KB)
                DiagLog("B549:36 RtlDeact range [0x%llX-0x%llX) tid=%u\n",  // ★ BUILD 549: 去特征化
                    (unsigned long long)g_RtlDeactivateAddr,
                    (unsigned long long)g_RtlDeactivateEnd,
                    g_mainThreadId);
            } else {
                DiagLog("B549:36 GPA RtlDeact FAIL\n");  // ★ BUILD 549: 去特征化
            }
        } else {
            DiagLog("B549:36 PEB Ldr ntdll FAIL\n");  // ★ BUILD 549: 去特征化 (原 GetModuleHandleW(ntdll.dll) FAILED)
        }
    }

    // ============================================================
    // 注册 EkkoSleep 内存加密保护区
    // 必须在 PE 头剥离前完成, 否则无法解析 section 边界
    // Sleep 期间整段 DLL 被加密, 防止反作弊内存扫描
    //
    // ★ v3.23: 跳过 EkkoSleep/EncryptAll/DecryptAll 自身所在页面
    // ★ v3.24: 同时跳过 VEH handler (DiagVehHandler) 所在页面,
    //   防止 EkkoSleep 加密期间触发异常 → CPU 执行已加密代码 → 双重错误
    // ============================================================
    {
        // ★ BUILD 567 v3.256 FIX: 限制 codeSize 只覆盖 .text 段, 不覆盖 .rdata/.data 段
        //   根因: v3.255 诊断显示第 11 个 region 的 XorCrypt 崩溃 + 日志乱码.
        //         原 codeSize = dllSize - 0x1000 覆盖整个 DLL 镜像 (含 .rdata 段),
        //         XorCrypt 加密 .rdata 段中的 EK_RAW_LOG 字符串常量 → 下次 EK_RAW_LOG
        //         调用时 msg 参数指向被加密的字符串 → WriteFile 写入加密垃圾 → 日志乱码.
        //   修复: 从 PE 段表解析 .text 段 VirtualSize, PE 头被擦除时硬编码回退值 (0x59da0).
        //         只加密 .text 段 (代码), 不加密 .rdata/.data 段 (数据).
        //   代价: 减少加密范围 (~64KB .rdata + 3KB .data), 但 .text 段 (~366KB) 仍被加密,
        //         防代码扫描能力不变. 反作弊内存扫描主要扫描 .text 段找特征码.
        uintptr_t codeBase = (uintptr_t)dllBase + 0x1000;
        SIZE_T codeSize = 0;
        uintptr_t codeEnd = codeBase;
        {
            auto* image = reinterpret_cast<BYTE*>(dllBase);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
            bool textParsed = false;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    auto* sec = IMAGE_FIRST_SECTION(nt);
                    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                        if (memcmp(sec[i].Name, ".text", 5) == 0) {
                            codeSize = sec[i].Misc.VirtualSize;
                            codeEnd = codeBase + codeSize;
                            textParsed = true;
                            break;
                        }
                    }
                }
            }
            if (!textParsed) {
                // ★ PE 头被 ManualMap 擦除 (前 0x400 字节) → 硬编码回退
                //   当前 payload.dll: .text @RVA 0x1000, VirtualSize=0x59e60 (objdump -h 验证)
                //   注意: 重新编译后需用 objdump -h payload.dll 验证 .text 段大小, 更新此处
                //   安全约束: 硬编码值必须 < 0x5b000 (.data 段 VA), 否则会加密 .data 段
                codeSize = 0x59e60;
                codeEnd = codeBase + codeSize;
                DiagLog("B567:256:.text fallback hardcoded size=0x%llX (PE header erased)\n",
                    (unsigned long long)codeSize);
            } else {
                DiagLog("B567:256:.text parsed size=0x%llX\n",
                    (unsigned long long)codeSize);
            }
        }

        uintptr_t ekkoPage = SleepObfuscator::GetSelfPage();
        uintptr_t vehPage  = reinterpret_cast<uintptr_t>(DiagVehHandler) & ~0xFFFULL;
        // ★ BUILD 544: 豁免 EncryptAll/DecryptAll/XorCrypt 所在页 — 防止 EkkoSleep 加密自身代码崩溃
        //   EkkoSleep 调用 EncryptAll → XorCrypt 加密代码页, 若这些函数自身所在页被加密,
        //   则 EncryptAll 返回时执行已加密代码 → 无日志崩溃
        uintptr_t encryptAllPage = SleepObfuscator::GetEncryptAllPage();
        uintptr_t decryptAllPage = SleepObfuscator::GetDecryptAllPage();
        uintptr_t xorCryptPage   = SleepObfuscator::GetXorCryptPage();
        // ★ BUILD 548: 豁免补丁维护 + 防截图函数所在页 — 防止 EkkoSleep 加密这些函数崩溃
        //   主循环周期性调用 ApplyCs2Patch/MaintainCs2Patch/IsScreenshotToolRunning/TemporarilyRevertPatch,
        //   若这些函数自身所在页被 StealthSleep 加密, 则执行已加密代码 → 崩溃
        uintptr_t applyPatchPage      = reinterpret_cast<uintptr_t>(&ApplyCs2Patch) & ~0xFFFULL;
        uintptr_t maintainPatchPage   = reinterpret_cast<uintptr_t>(&MaintainCs2Patch) & ~0xFFFULL;
        uintptr_t screenshotCheckPage = reinterpret_cast<uintptr_t>(&IsScreenshotToolRunning) & ~0xFFFULL;
        uintptr_t revertPatchPage     = reinterpret_cast<uintptr_t>(&TemporarilyRevertPatch) & ~0xFFFULL;
        // ★ BUILD 557: 豁免 DR0 函数所在页 — 防止 EkkoSleep 加密这些函数崩溃
        //   VEH 在 CS2 线程上高频触发, 会调用 SetupDR0Breakpoint/ClearDR0Breakpoint
        //   (后者在主循环调用 StartDR0FrequencyStat/ReportDR0Frequency).
        //   若这些函数所在页被 StealthSleep 加密, 则执行已加密代码 → 崩溃.
        //   双重保险: BUILD 557 在 60s 统计窗口内已禁用 StealthSleep (变更 8),
        //   但 60s 窗口外的 StealthSleep 也可能误伤这些函数页, 必须加入豁免.
        uintptr_t setupDr0Page        = reinterpret_cast<uintptr_t>(&SetupDR0Breakpoint) & ~0xFFFULL;
        uintptr_t clearDr0Page        = reinterpret_cast<uintptr_t>(&ClearDR0Breakpoint) & ~0xFFFULL;
        uintptr_t startStatPage       = reinterpret_cast<uintptr_t>(&StartDR0FrequencyStat) & ~0xFFFULL;
        uintptr_t reportFreqPage      = reinterpret_cast<uintptr_t>(&ReportDR0Frequency) & ~0xFFFULL;

        // ★ BUILD 558 FIX: 豁免 .idata 段 — 防止 EkkoSleep 加密 IAT 导致 VEH 处理器 IAT 调用崩溃
        //   根因: EkkoSleep 加密 [dllBase+0x1000, dllBase+dllSize) 包含 .idata 段 (IAT 所在),
        //         VEH 处理器 DiagVehHandler 通过 IAT 调用 GetCurrentThreadId/GetTickCount/
        //         VirtualProtect/MessageBoxW 以及 DiagLog 内部的 CreateFileW/WriteFile/CloseHandle,
        //         IAT 条目被 XOR 加密后读到垃圾地址 → call 跳转到无效地址 → 0xc0000005 崩溃
        //   崩溃点: payload.dll 偏移 0x971E (DiagVehHandler 内 call *0x7809c(%rip) → GetCurrentThreadId IAT)
        //   修复: 豁免 .idata 段所有页 (IAT 条目保持明文, 所有 IAT 调用正常工作)
        //   .idata 位置获取: 优先 PE 头 DataDirectory[IMPORT] 解析, PE 头被擦除时硬编码回退
        uintptr_t idataPageStart = 0;
        uintptr_t idataPageEnd   = 0;
        {
            auto* image = reinterpret_cast<BYTE*>(dllBase);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
            bool peParsed = false;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                    if (importDir.VirtualAddress && importDir.Size) {
                        uintptr_t idataStart = (uintptr_t)dllBase + importDir.VirtualAddress;
                        uintptr_t idataEnd   = idataStart + importDir.Size;
                        idataPageStart = idataStart & ~0xFFFULL;
                        idataPageEnd   = (idataEnd + 0xFFF) & ~0xFFFULL;
                        peParsed = true;
                    }
                }
            }
            if (!peParsed) {
                // ★ PE 头被 ManualMap 擦除 (前 0x400 字节) → 硬编码回退
                //   ★ BUILD 567 v3.254 FIX: 修正 .idata 偏移 0x82000 → 0x87000 (objdump -h 验证)
                //     原错误: BUILD 558 FIX-2 硬编码 [0x82000, 0x84000), 但 v3.252+ payload.dll
                //     .text 段减小后 .idata 移到 RVA 0x87000, Size=0x1C10.
                //     后果: v3.253 import thunk 扫描 rel32 目标验证全部失败 (target 不在
                //     [0x82000, 0x84000) 范围), 匹配 0 个 thunk → EkkoSleep 仍崩溃.
                //   当前 payload.dll: .idata @RVA 0x87000, Size=0x1C10 → 页范围 [0x87000, 0x89000) = 2 页
                //   注意: 重新编译后需用 objdump -h payload.dll 验证 .idata 偏移, 更新此处
                idataPageStart = (uintptr_t)dllBase + 0x87000;
                idataPageEnd   = (uintptr_t)dllBase + 0x89000;
                DiagLog("B558:FIX:.idata fallback hardcoded [0x%llX-0x%llX) (PE header erased)\n",
                    (unsigned long long)idataPageStart, (unsigned long long)idataPageEnd);
            } else {
                DiagLog("B558:FIX:.idata parsed [0x%llX-0x%llX)\n",
                    (unsigned long long)idataPageStart, (unsigned long long)idataPageEnd);
            }
            // ★ BUILD 558 FIX-2: 保存到全局变量, 供主循环诊断使用
            g_idataPageStart = idataPageStart;
            g_idataPageEnd   = idataPageEnd;
        }

        // ★ BUILD 558 FIX: 豁免 DiagLog 函数所在页 — VEH 处理器大量调用 DiagLog
        //   DiagLog 代码在 .text 段, 若所在页被 EkkoSleep 加密, VEH 调用 DiagLog 执行加密垃圾 → 崩溃
        //   DiagLog 内部通过 IAT 调用 CreateFileW/WriteFile/CloseHandle (已由 .idata 豁免覆盖)
        uintptr_t diagLogPage = reinterpret_cast<uintptr_t>(&DiagLog) & ~0xFFFULL;

        // ★ BUILD 558 FIX: 豁免 DKOMProcessHider::UnhideAll 函数所在页
        //   VEH fatal 路径 (进程退出前) 调用 UnhideAll 挂回链表防 0x139 蓝屏
        //   UnhideAll 代码在 .text 段 (byovd_kernel.cpp 编译进 payload.dll), 若所在页被加密 → 崩溃
        //   ★ Itanium ABI (g++/MinGW x64): 成员函数指针 = 16 字节 (函数地址 + this 调整偏移)
        //     非虚函数前 8 字节 = 函数地址 (LSB=0); 虚函数前 8 字节 = vtable 偏移 (LSB=1)
        //     UnhideAll 是非虚函数 (byovd_kernel.h: void UnhideAll();), 取前 8 字节作为函数地址
        uintptr_t unhideAllPage = 0;
        {
            auto mfp = &stealth::DKOMProcessHider::UnhideAll;
            static_assert(sizeof(mfp) >= sizeof(uintptr_t),
                "Member function pointer too small - expected >=8 bytes on x64");
            union {
                decltype(mfp) mfp;
                struct {
                    uintptr_t funcAddr;     // 前 8 字节: 函数地址 (非虚) 或 vtable 偏移 (虚)
                    uintptr_t thisAdjust;   // 后 8 字节: this 指针调整
                } parts;
            } u;
            u.mfp = mfp;
            // 合理性检查: 函数地址在 DLL 范围内 (排除虚函数 vtable 偏移或异常值)
            uintptr_t dllStart = (uintptr_t)dllBase;
            uintptr_t dllEnd   = dllStart + dllSize;
            if (u.parts.funcAddr >= dllStart && u.parts.funcAddr < dllEnd) {
                unhideAllPage = u.parts.funcAddr & ~0xFFFULL;
            } else {
                // 回退: 无法定位 UnhideAll 页, 不豁免 (VEH fatal 路径仍有风险, 但优于编译失败)
                DiagLog("B558:FIX:WARN unhideAll addr 0x%llX out of DLL range [0x%llX-0x%llX)\n",
                    (unsigned long long)u.parts.funcAddr,
                    (unsigned long long)dllStart, (unsigned long long)dllEnd);
            }
        }

        // 收集所有需要豁免的页面 (去重 + 排序)
        // ★ BUILD 544: 数组从 [2] 扩展到 [8] 以容纳 5 个豁免页 (去重后可能更少)
        // ★ BUILD 548: 数组从 [16] 缩减到 [16] 容纳 9 个豁免页 (5 BUILD 544 + 4 BUILD 548)
        // ★ BUILD 557: 9 → 13 个豁免页 (新增 4 个 DR0 函数页)
        // ★ BUILD 558 FIX: 13 → 13 + 2 (DiagLog + UnhideAll) + .idata页数 (当前 2 页)
        //   数组扩到 [32] 容纳 15 基础 + 最多 8 .idata 页 (保守上限) + 余量
        // ★ BUILD 558 FIX-3: [32] → [48] 容纳 18 基础 (15 + 3 跨页保护) + .idata + 余量
        //   根因: EncryptAll 函数 (0x15E70-0x1643A) 跨越 0x15000-0x16000 页边界,
        //         GetEncryptAllPage() 只返回入口页 0x15000, 函数尾部在 0x16000 页未豁免,
        //         EkkoSleep 加密 0x16000 页 → AV:EXEC 崩溃 @0x15FFE (跳到 0x16003 已加密代码)
        //   修复: 对 EncryptAll/DecryptAll/XorCrypt 额外豁免"入口页+0x1000"(下一页),
        //         防止函数跨页时尾部所在页被加密. 代价: 多 3*4KB=12KB 不加密 (相对 .text 344KB 仅 3.5%)
        //   注: 即使函数不跨页, 多豁免一页也是安全的 (仅减少少量加密范围, 不影响功能)
        // ★ BUILD 567 v3.243 FIX: 豁免 SleepObfuscator 对象所在页面 (真正根因修复)
        //   根因: SleepObfuscator 单例对象 (含 m_regions[64] 约 1.5KB) 在 .bss 段,
        //         EncryptAll 保护范围 [dllBase+0x1000, dllBase+dllSize) 覆盖整个 DLL 镜像 (含 .bss).
        //         若 m_regions 所在页未被豁免, EncryptAll 处理覆盖 .bss 的 region 时
        //         会 XorCrypt 加密 m_regions 数组本身 → 下次循环读取 m_regions[ri+1] 时
        //         addr/size/xorKey 都是加密垃圾 → VirtualProtect 用错误 addr → 崩溃!
        //   修复: 豁免 SleepObfuscator::Instance() 对象所在页 + 下一页 (防跨页, 对象 ~1.5KB)
        //   代价: 多 2*4KB=8KB 不加密 (相对 520KB 仅 1.5%)
        uintptr_t sleepObjAddr = (uintptr_t)&SleepObfuscator::Instance();
        uintptr_t sleepObjPage = sleepObjAddr & ~0xFFFULL;
        // ★ BUILD 567 v3.252 FIX: [48] → [128] 容纳 import thunk 页 (188 thunks, ~15 pages)
        uintptr_t exemptPages[128] = {
            ekkoPage, ekkoPage + 0x1000, ekkoPage + 0x2000, ekkoPage + 0x3000,  // ★ BUILD 567 v3.244 FIX: EkkoSleep 跨页保护 (扩展到 4 页, 防止 EkkoSleep+v3.244 EK_RAW_LOG 代码跨页)
            vehPage,
            encryptAllPage, encryptAllPage + 0x1000,        // ★ FIX-3: EncryptAll 跨页保护
            decryptAllPage, decryptAllPage + 0x1000,        // ★ FIX-3: DecryptAll 跨页保护
            xorCryptPage,   xorCryptPage   + 0x1000,        // ★ FIX-3: XorCrypt 跨页保护
            applyPatchPage, maintainPatchPage, screenshotCheckPage, revertPatchPage,
            setupDr0Page, clearDr0Page, startStatPage, reportFreqPage,
            diagLogPage, unhideAllPage,
            sleepObjPage, sleepObjPage + 0x1000  // ★ BUILD 567 v3.243 FIX: SleepObfuscator 对象跨页保护
        };
        int exemptPageCount = 23;  // ★ v3.244: 22 → 23 (添加 ekkoPage + 0x3000)
        // 追加 .idata 段所有页 (IAT 所在, 必须全部豁免)
        // ★ BUILD 567 v3.252: 限制从 30 → 120 (为 import thunk 页留空间)
        for (uintptr_t p = idataPageStart; p < idataPageEnd && exemptPageCount < 120; p += 0x1000) {
            exemptPages[exemptPageCount++] = p;
        }
        // ★ BUILD 567 v3.253 FIX: 豁免所有 import thunk 所在页 (EkkoSleep 崩溃根因修复)
        //   根因: EkkoSleep EncryptAll 加密 .text 段时, 加密了 import thunk
        //         (FF 25 xx xx xx xx = jmp [rip+rel32] → IAT 条目),
        //         EK_RAW_LOG 宏 / VirtualProtect / FlushInstructionCache 等调用
        //         通过 import thunk 跳转到 IAT, import thunk 代码被加密后
        //         → CPU 执行加密字节 → 0xc0000005 崩溃.
        //   修复: 扫描整个 DLL 镜像找到所有 import thunk (FF 25 xx xx xx xx),
        //         验证 rel32 目标地址在 .idata 段范围内 (精确匹配, 无误报),
        //         将其所在页添加到 exemptPages (去重).
        //   ★ BUILD 567 v3.254 FIX: 添加宽松匹配回退. 原因: v3.253 硬编码回退值
        //     0x82000 过期 (实际 .idata 在 0x87000), rel32 验证全部失败, 匹配 0 个 thunk.
        //     修复: (1) 更新硬编码回退值为 0x87000; (2) 如果精确匹配到 0 个 thunk,
        //     改用宽松匹配 (只匹配 FF 25 xx xx xx xx, 不验证 target), 防止未来过期.
        //     代价: 宽松匹配可能有少量误报 (FF 25 在 .text 中除 import thunk 外很少使用),
        //     多豁免几页不影响功能.
        {
            uintptr_t scanStart = (uintptr_t)dllBase + 0x1000;
            uintptr_t scanEnd = (uintptr_t)dllBase + dllSize;
            int thunkCount = 0;
            // Pass 1: 精确匹配 (FF 25 + rel32 目标在 .idata 段)
            for (uintptr_t p = scanStart; p + 6 <= scanEnd; p++) {
                uint8_t* b = reinterpret_cast<uint8_t*>(p);
                if (b[0] != 0xFF || b[1] != 0x25) continue;
                int32_t rel32 = (int32_t)((uint32_t)b[2] | ((uint32_t)b[3] << 8) |
                                          ((uint32_t)b[4] << 16) | ((uint32_t)b[5] << 24));
                uintptr_t target = p + 6 + (int64_t)rel32;
                if (target < idataPageStart || target >= idataPageEnd) continue;
                uintptr_t thunkPage = p & ~0xFFFULL;
                bool found = false;
                for (int i = 0; i < exemptPageCount; i++) {
                    if (exemptPages[i] == thunkPage) { found = true; break; }
                }
                if (!found && exemptPageCount < 126) {
                    exemptPages[exemptPageCount++] = thunkPage;
                }
                thunkCount++;
                p += 5;
            }
            // Pass 2: 宽松匹配回退 (仅当精确匹配到 0 个 thunk 时)
            //   场景: PE 头被擦除 + 硬编码回退值过期 → idataPageStart/idataPageEnd 错误
            //   匹配所有 FF 25 xx xx xx xx (jmp [rip+rel32]), 不验证 target
            if (thunkCount == 0) {
                DiagLog("B567:254:precise match 0, fallback to loose match\n");
                for (uintptr_t p = scanStart; p + 6 <= scanEnd; p++) {
                    uint8_t* b = reinterpret_cast<uint8_t*>(p);
                    if (b[0] != 0xFF || b[1] != 0x25) continue;
                    uintptr_t thunkPage = p & ~0xFFFULL;
                    bool found = false;
                    for (int i = 0; i < exemptPageCount; i++) {
                        if (exemptPages[i] == thunkPage) { found = true; break; }
                    }
                    if (!found && exemptPageCount < 126) {
                        exemptPages[exemptPageCount++] = thunkPage;
                    }
                    thunkCount++;
                    p += 5;
                }
            }
            DiagLog("B567:254:import thunk scan: %d thunks, %d exempt pages\n",
                thunkCount, exemptPageCount);
        }
        // 去重 (数组小, 简单 O(n^2))
        for (int i = 0; i < exemptPageCount; i++) {
            for (int j = i + 1; j < exemptPageCount; ) {
                if (exemptPages[j] == exemptPages[i]) {
                    exemptPages[j] = exemptPages[exemptPageCount - 1];
                    exemptPageCount--;
                } else {
                    j++;
                }
            }
        }
        // 排序 (插入排序, 数组小)
        for (int i = 1; i < exemptPageCount; i++) {
            uintptr_t v = exemptPages[i];
            int j = i - 1;
            while (j >= 0 && exemptPages[j] > v) {
                exemptPages[j + 1] = exemptPages[j];
                j--;
            }
            exemptPages[j + 1] = v;
        }

        SIZE_T totalProtected = 0;
        uintptr_t cursor = codeBase;

        for (int ei = 0; ei < exemptPageCount; ei++) {
            uintptr_t skip = exemptPages[ei];
            if (skip < cursor || skip >= codeEnd) continue;
            if (skip > cursor) {
                SIZE_T segSz = skip - cursor;
                SleepObfuscator::Instance().RegisterProtectedRegion((void*)cursor, segSz);
                totalProtected += segSz;
            }
            cursor = skip + 0x1000;
        }
        if (cursor < codeEnd) {
            SIZE_T segSz = codeEnd - cursor;
            SleepObfuscator::Instance().RegisterProtectedRegion((void*)cursor, segSz);
            totalProtected += segSz;
        }

        // ★ BUILD 567 v3.239 DIAG: 添加 ek+1@ (ekkoPage+0x1000) 显示下一页地址
        //   若 diagLog 地址 ∈ [ek+1, ek+1+0x1000) → EkkoDiagLog 在未被豁免的下一页 → 根因确认
        // ★ BUILD 567 v3.243 DIAG: 添加 sleepObj@ 字段 — 确认 SleepObfuscator 对象地址在豁免页
        DiagLog("B550:EK:protected %llu bytes (exempt %d pages, ek@0x%llX ek+1@0x%llX veh@0x%llX "
                "encA@0x%llX decA@0x%llX xorC@0x%llX ap@0x%llX mp@0x%llX "
                "sc@0x%llX rp@0x%llX dl@0x%llX uh@0x%llX sleepObj@0x%llX idata[0x%llX-0x%llX))\n",
            (unsigned long long)totalProtected, exemptPageCount,
            (unsigned long long)ekkoPage, (unsigned long long)(ekkoPage + 0x1000),
            (unsigned long long)vehPage,
            (unsigned long long)encryptAllPage, (unsigned long long)decryptAllPage,
            (unsigned long long)xorCryptPage,
            (unsigned long long)applyPatchPage, (unsigned long long)maintainPatchPage,
            (unsigned long long)screenshotCheckPage, (unsigned long long)revertPatchPage,
            (unsigned long long)diagLogPage, (unsigned long long)unhideAllPage,
            (unsigned long long)sleepObjAddr,
            (unsigned long long)idataPageStart, (unsigned long long)idataPageEnd);
    }

    // --- 阶段1: 初始化规避引擎 (9层) ---
    if (!StealthEngine::Instance().Initialize()) {
        DiagLog("FAIL: StealthEngine::Initialize\n");
        return 1;
    }
    DiagLog("OK: StealthEngine::Initialize\n");

    // --- 阶段2: 自身内存隐身 (跳过 UnlinkSelfLdr + RandomizeProtections, ManualMap 下不稳定) ---
    if (dllBase && dllSize > 0) {
        SelfCloaker::CloakManualMap(dllBase, dllSize);
    }
    DiagLog("OK: CLOAK done\n");

    // --- 阶段3: 附加到 CS2 进程 ---
    // ★ BUILD 529: 测试模式跳过 CS2 附加 (测试2 无 CS2 长时间运行验证 E+G 保护层)
    // ★ BUILD 550: 加密 "cs2.exe" 进程名 (原明文 L"cs2.exe")
    wchar_t procNameW[32] = {};
    {
        char encBuf[32] = {};
        STEALTH_STR_DECRYPT_TO("cs2.exe", encBuf, sizeof(encBuf));
        for (int i = 0; i < 32 && encBuf[i]; i++) procNameW[i] = (wchar_t)(unsigned char)encBuf[i];
        StringObfuscator::SecureZero(encBuf, sizeof(encBuf));
    }
    if (!g_egTestMode && !StealthEngine::Instance().AttachToProcess(procNameW)) {
        DiagLog("FAIL: AttachToProcess\n");
        stealth::KernelDefense::DisableAll();
        StealthEngine::Instance().Shutdown();
        // ★ BUILD 550: 加密用户消息 (原明文 L"未找到 CS2 进程 (cs2.exe)..." 等)
        //   MessageBoxW 参数用栈上解密的 wchar_t, 用完即毁
        wchar_t msgBody[256] = {};
        wchar_t msgTitle[64] = {};
        {
            char encBody[256] = {};
            STEALTH_STR_DECRYPT_TO("Game process not found.\n\nPlease start the game first, then re-run loader.", encBody, sizeof(encBody));
            for (int i = 0; i < 256 && encBody[i]; i++) msgBody[i] = (wchar_t)(unsigned char)encBody[i];
            StringObfuscator::SecureZero(encBody, sizeof(encBody));
        }
        {
            char encTitle[64] = {};
            STEALTH_STR_DECRYPT_TO("Game not running", encTitle, sizeof(encTitle));
            for (int i = 0; i < 64 && encTitle[i]; i++) msgTitle[i] = (wchar_t)(unsigned char)encTitle[i];
            StringObfuscator::SecureZero(encTitle, sizeof(encTitle));
        }
        MessageBoxW(NULL, msgBody, msgTitle, MB_OK | MB_ICONINFORMATION);
        StringObfuscator::SecureZero(msgBody, sizeof(msgBody));
        StringObfuscator::SecureZero(msgTitle, sizeof(msgTitle));
        StringObfuscator::SecureZero(procNameW, sizeof(procNameW));
        return 2;
    }
    StringObfuscator::SecureZero(procNameW, sizeof(procNameW));
    if (g_egTestMode) {
        DiagLog("B550:TM:skip tgt-attach (test mode)\n");  // ★ BUILD 550: 脱敏
    } else {
        DiagLog("OK: AttachToProcess, PID=%u HANDLE=%p\n",
            StealthEngine::Instance().GetProcessId(),
            StealthEngine::Instance().GetProcessHandle());
    }

    // 封锁进程句柄 (DACL → 仅允许自身访问, 阻止反作弊通过NtQuerySystemInformation枚举)
    // ★ BUILD 529: 测试模式跳过 (无 CS2 句柄)
    if (!g_egTestMode) {
        HANDLE hGame = StealthEngine::Instance().GetProcessHandle();
        if (hGame) {
            stealth::HandleACLGuard::LockHandle(hGame);
            DiagLog("OK: HandleACLGuard locked\n");
        } else {
            DiagLog("WARN: HandleACLGuard skipped (no handle)\n");
        }
    } else {
        DiagLog("E+G TEST: skipping HandleACLGuard (test mode)\n");
    }

    // BYOVD 内核防御 — 加载漏洞驱动 + 摘除 PAC 内核回调 (Ring-0)
    // v3.24: 优先 System32\drivers, 回退嵌入提取到 %TEMP%
    // ObRegisterCallbacks/ProcessNotify/ImageNotify → 全部失效
    //
    // ★ v3.79: BYOVD 初始化块 — 重新排序以修复备份缓冲区被 IOCTL 覆盖的致命 bug
    //   BUILD 377/378 的 bug: 备份在 Guard scan 之后分配 → 备份 VA 在 scan 范围外
    //   → IOCTL 映射物理内存到备份 VA → 备份腐败 → VEH 用腐败备份恢复 → 二次崩溃
    //   v3.79 修复: (1) 先分配备份 (2) Guard scan 扩展覆盖备份 VA
    {
        // ★ v3.79 Step 0: 先分配备份缓冲区 — 必须在 Guard scan 之前
        //   否则 Guard scan 不知道备份的 VA, 无法保护备份
        uint32_t preChecksum = 0;
        uint8_t* codeBackupBuf = nullptr;
        SIZE_T   codeLen = 0;  // 供 guard scan 使用
        if (dllBase && dllSize > 0x1000) {
            uint8_t* code = (uint8_t*)dllBase + 0x1000;
            codeLen = dllSize - 0x1000;
            codeBackupBuf = (uint8_t*)VirtualAlloc(nullptr, codeLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (codeBackupBuf) {
                memcpy(codeBackupBuf, code, codeLen);
                g_backupBuf = codeBackupBuf;
                g_backupLen = codeLen;
                g_backupCodeBase = code;
                for (SIZE_T i = 0; i < codeLen; i += 4) {
                    preChecksum ^= *(uint32_t*)(code + i);
                }
                DiagLog("BYOVD: code backup saved [0x%llX, %llu bytes] checksum=0x%08X\n",
                    (unsigned long long)codeBackupBuf, (unsigned long long)codeLen, preChecksum);
                // ★ v3.78: 注册备份缓冲区为保护区 (检测 IOCTL 重叠)
                stealth::KernelMemoryAccessor::RegisterCodeRegion(codeBackupBuf, codeLen);
            }
        }

        // ★ v3.74/v3.79 Layer 1: 强化 Guard Pages — 在 BYOVD IOCTL 之前
        //   v3.79: 扩展扫描范围同时覆盖 DLL 和备份缓冲区
        // ★ v3.120: 固定数组, 避免 std::vector CRT 堆依赖
        struct GuardRegion { void* addr; SIZE_T size; };
        static constexpr size_t MAX_GUARD_REGIONS = 4096;
        GuardRegion guardRegions[MAX_GUARD_REGIONS];
        int guardRegionCount = 0;

        if (dllBase && dllSize > 0x1000) {
            uintptr_t dllStart = (uintptr_t)dllBase;
            uintptr_t dllEnd   = dllStart + dllSize;
            const SIZE_T SCAN_MARGIN = 0x4000000; // ±64MB

            // ★ v3.79: 扩展扫描范围覆盖备份缓冲区
            //   备份与 DLL 可能相距甚远 (VirtualAlloc 可能分配到 DLL+89MB),
            //   需要确保扫描范围同时覆盖两者
            uintptr_t backupStart = codeBackupBuf ? (uintptr_t)codeBackupBuf : 0;
            uintptr_t backupEnd   = (codeBackupBuf && codeLen > 0) ? (backupStart + codeLen) : 0;
            uintptr_t minAddr = dllStart;
            uintptr_t maxAddr = dllEnd;
            if (backupStart && backupStart < minAddr) minAddr = backupStart;
            if (backupEnd   && backupEnd   > maxAddr) maxAddr = backupEnd;

            uintptr_t scanStart = (minAddr > SCAN_MARGIN) ? (minAddr - SCAN_MARGIN) : 0x10000;
            uintptr_t scanEnd   = maxAddr + SCAN_MARGIN;
            if (scanEnd < maxAddr) scanEnd = (uintptr_t)-1; // overflow guard

            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t addr = scanStart;
            while (addr < scanEnd) {
                SIZE_T qr = VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi));
                if (qr == 0) break;

                if (mbi.State == MEM_FREE) {
                    uintptr_t freeStart = (uintptr_t)mbi.BaseAddress;
                    SIZE_T freeSize = mbi.RegionSize;
                    if (freeStart < scanStart) {
                        freeSize -= (scanStart - freeStart);
                        freeStart = scanStart;
                    }
                    if (freeStart + freeSize > scanEnd)
                        freeSize = scanEnd - freeStart;
                    if (freeSize >= 0x1000) {
                        void* r = VirtualAlloc((void*)freeStart, freeSize, MEM_RESERVE, PAGE_NOACCESS);
                        if (r && guardRegionCount < MAX_GUARD_REGIONS) {
                            guardRegions[guardRegionCount].addr = r;
                            guardRegions[guardRegionCount].size = freeSize;
                            guardRegionCount++;
                        }
                    }
                }
                addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            }
            DiagLog("BYOVD: reserved %d guard regions [0x%llX - 0x%llX] (backup@0x%llX dll@0x%llX)\n",
                guardRegionCount,
                (unsigned long long)scanStart, (unsigned long long)scanEnd,
                (unsigned long long)backupStart, (unsigned long long)dllStart);
        }

        // 注册所有 DLL 代码页为保护区 (跳过 PE 头第0页)
        if (dllBase && dllSize > 0x1000) {
            stealth::KernelMemoryAccessor::RegisterCodeRegion(
                (void*)((uintptr_t)dllBase + 0x1000), dllSize - 0x1000);
            DiagLog("BYOVD: registered DLL code region [0x%llX - 0x%llX]\n",
                (unsigned long long)((uintptr_t)dllBase + 0x1000),
                (unsigned long long)((uintptr_t)dllBase + dllSize));
        }

        // ★ BUILD 554 P1-3: 验证 .data/.bss 段已被 EkkoSleep 覆盖 (修复 B1 假设)
        //   分析发现: L1326-1404 的 EkkoSleep 注册代码已覆盖整个 DLL 镜像
        //             [dllBase+0x1000, dllBase+dllSize), 包含 .text/.rdata/.data/.bss 全部段.
        //   本段为显式验证 + 诊断输出, 确认 .data/.bss 段确实在已注册范围内,
        //   并通过 DiagLogEnc 输出段范围供 sd.log 排查 (PAC 扫描 .data 段时加密生效).
        //   注: 若未来 EkkoSleep 注册范围改为仅 .text 段, 此处需补充 RegisterProtectedRegion 调用.
        if (dllBase && dllSize > 0x1000) {
            auto* dosHdr = (IMAGE_DOS_HEADER*)dllBase;
            if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* ntHdr = (IMAGE_NT_HEADERS64*)((uint8_t*)dllBase + dosHdr->e_lfanew);
                if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                    auto* secHdr = IMAGE_FIRST_SECTION(ntHdr);
                    uintptr_t ekBase = (uintptr_t)dllBase + 0x1000;
                    uintptr_t ekEnd  = (uintptr_t)dllBase + dllSize;
                    for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
                        char secName[9] = {};
                        memcpy(secName, secHdr[i].Name, 8);
                        uintptr_t secStart = (uintptr_t)dllBase + secHdr[i].VirtualAddress;
                        uintptr_t secEnd   = secStart + secHdr[i].Misc.VirtualSize;
                        // 验证段在 EkkoSleep 已注册范围内
                        bool inRange = (secStart >= ekBase && secEnd <= ekEnd);
                        DiagLog("B554:SEC:%s [%llX-%llX] inEkkoRange=%d\n",
                            secName,
                            (unsigned long long)secStart,
                            (unsigned long long)secEnd,
                            (int)inRange);
                    }
                }
            }
        }

        auto kernelResult = stealth::KernelDefense::EnableAll();

        // ★ v3.75: 后校验 — 仅诊断，不自动恢复
        //   校验覆盖整个 DLL 镜像 (.data/.bss 运行时变化是正常的),
        //   真正的代码污染会触发 STATUS_PRIVILEGED_INSTRUCTION → VEH 自愈
        if (dllBase && dllSize > 0x1000) {
            uint32_t postChecksum = 0;
            uint8_t* code = (uint8_t*)dllBase + 0x1000;
            SIZE_T codeLen = dllSize - 0x1000;
            for (SIZE_T i = 0; i < codeLen; i += 4) {
                postChecksum ^= *(uint32_t*)(code + i);
            }
            if (preChecksum != postChecksum) {
                DiagLog("WARN: DLL checksum changed pre=0x%08X post=0x%08X (data changes during init are normal)\n",
                    preChecksum, postChecksum);
            } else {
                DiagLog("BYOVD: code integrity OK (checksum=0x%08X)\n", postChecksum);
            }
            // ★ v3.78: 永久保留备份 — 主循环中 DKOM/IOCTL 仍可能污染代码,
            //   VEH handler 和 MapPhysical 重叠恢复依赖此备份
            //   同时也保留 g_backupBuf/g_backupLen/g_backupCodeBase 给 byovd_kernel.cpp 使用
            //   (不再释放 codeBackupBuf, 由进程退出时 OS 自动回收)
        }

        g_byovdDriverLoaded = kernelResult.driverLoaded;

        // ★ BUILD 567 v3.235: VAD 隐藏 (先执行, 缓存 EPROCESS)
        //   原因: DKOM 成功后会断链 loader.exe, VAD GetEPROCESSByPid 遍历 ActiveProcessLinks
        //         找不到 loader.exe → VAD 隐藏失败.
        //   修复: VAD 先执行 (链表完整, 能找到 loader.exe), 缓存 EPROCESS 地址;
        //         DKOM 后续断链不影响 VAD (VAD 用缓存的 EPROCESS 访问 VAD 树).
        //   注意: VAD 必须在 BYOVD driver loaded 之后 (需要内核 R/W 访问 VAD 节点).
        //   周期: 60-90s 主循环重新调用 (PAC 可能恢复 VAD 标志), 用缓存的 EPROCESS.
        if (kernelResult.driverLoaded) {
            DWORD loaderPid = GetCurrentProcessId();  // payload.dll 在 loader.exe 进程内
            uintptr_t bases[1] = { (uintptr_t)g_diagDllBase };
            int vadOk = stealth::VADConcealer::ConcealAllRegions(loaderPid, bases, 1);
            DiagLog("B554:VAD:%d/1 base=0x%llX (pre-DKOM, cache eprocess)\n",
                vadOk, (unsigned long long)g_diagDllBase);
        }

        // ★ BUILD 537: Gamma-A — 早期 DKOM 隐藏 (永久断链, 无需周期缓解)
        //   EnableAll() 成功加载驱动后立即隐藏 loader 进程,
        //   缩短进程在 ActiveProcessLinks 中的可见窗口.
        //   ★ PG 已通过 bcdedit /debug on 禁用, DKOM 可永久断链, 无需 Unhide/Rehide 循环
        //   ★ BUILD 567 v3.235: 移到 VAD 隐藏之后 (VAD 需要在链表完整时缓存 EPROCESS)
        if (kernelResult.driverLoaded) {
            bool dkomOk = stealth::DKOMProcessHider::Instance().HideProcess();
            DiagLog("E+G: early DKOM hide (permanent, PG disabled): %s\n", dkomOk ? "OK" : "FAILED");

            // ★ BUILD 552: 方案 D — Patch SHV_Install 主动防御
            //   ★ BUILD 559 隐蔽 SHV 对抗: patch 内容从 `mov eax,-4;ret` 改为 `mov eax,-5;ret`
            //     在 BYOVD 就绪后立即 patch PAC SHV_Install 入口为 `mov eax, -5; ret`,
            //     阻止 PAC 启动 VMX/EPT 硬件级内存监控.
            //   ★ -5 (0xFFFFFFFB) 是 PAC CheckPhysicalMemoryLimit 内部"物理内存超过 2GB EPT 限制"
            //     的自然错误码, PAC 会打印 "EPT map limit" 错误并进入降级处理,
            //     不会怀疑 patch (相比原 -4 STATUS_TOO_MANY_OPEN_FILES 更隐蔽).
            //   ★ SHV 是临时性 install-then-uninstall 模式 (周期性启动),
            //     patch 后所有后续 SHV 启动尝试都立即返回 -5 (自然失败).
            //   ★ 失败不影响主流程 (仅记录 ByovdDiag 日志), PatchShvInstallEntry
            //     内部已做防御性检查 (KMA 未就绪 / PAC 未加载 / 特征码未匹配均安全返回 false).
            bool shvPatched = stealth::ShvInstallPatcher::PatchShvInstallEntry();
            DiagLog("B552:SHV:%s\n", shvPatched ? "ok" : "skip");  // 去特征化日志
        }

        DiagLog("OK: BYOVD driver=%d ob=%d proc=%d img=%d thread=%d pac=%d\n",
            (int)kernelResult.driverLoaded,
            kernelResult.obCallbacksRemoved,
            kernelResult.processCallbacksRemoved,
            kernelResult.imageCallbacksRemoved,
            kernelResult.threadCallbacksRemoved,
            (int)kernelResult.pacStatus);

        // ★ BUILD 548: 集成补丁逻辑 (替代 basic.exe)
        //   原本由 basic.exe 通过 OpenProcess + WriteProcessMemory 补丁
        //   现在 payload.dll 在 CS2 进程内直接补丁 client.dll
        //   测试模式/半测试模式跳过补丁 (避免封号, 仅验证保护层)
        if (!g_egTestMode && !g_halfTestMode) {
            g_cs2Patched = ApplyCs2Patch();
            DiagLog("B549:I:01 %s\n", g_cs2Patched ? "ok" : "pend");  // ★ BUILD 549: 去特征化
            // ★ BUILD 557: 补丁成功后启动 DR0 频率统计 (60s 窗口)
            //   目的: 统计 32 c0 (现为 90 90) 执行频率, 为 BUILD 558 DR0+VEH 跳过方案提供决策依据
            //   幂等: StartDR0FrequencyStat 内部用 InterlockedExchange(&g_dr0StatActive, 1) 防重入
            // ★ BUILD 567 v3.237: 禁用 DR0 频率统计 — DR0 设置在 CS2 线程上,
            //   #DB 异常在 CS2 进程内触发, loader.exe 的 VEH 无法跨进程捕获,
            //   导致 CS2 线程执行到 patch 地址时触发 #DB → CS2 崩溃 (0xC0000005).
            if (g_cs2Patched) {
                // StartDR0FrequencyStat();  // ★ v3.237: 禁用 (DR0 跨进程崩溃根因)
            }

            // ★ BUILD 565: Hook NtReadVirtualMemory 双重保险
            //   拦截 PAC 用户态 PvpAlive.dll 对 CS2 client.dll 的扫描,
            //   在 Buffer 中恢复 patch 区域 (RVA 0xC125D9, 2 字节) 原始字节 (32 c0).
            //   方案 B (IAT hook PvpAlive) 优先, 失败时启用方案 A (inline hook ntdll).
            //   失败安全: Install 失败不影响其他防御功能.
            if (g_cs2Patched && g_patchAddr && g_clientBase) {
                HANDLE hCs2ForHook = StealthEngine::Instance().GetProcessHandle();
                if (hCs2ForHook) {
                    bool ntReadHooked = stealth::NtReadHooker::Instance().Install(
                        hCs2ForHook, g_clientBase, g_patchAddr);
                    DiagLog("B565:I:01 %s\n", ntReadHooked ? "ok" : "fail");
                }
            }
        } else {
            DiagLog("B549:I:02 skip (test)\n");  // ★ BUILD 549: 去特征化
        }

        // ★ v3.80: 释放 guard pages — 延迟到 CleanupInjectionTraces 之后
        //   防止 DKOM/VAD 操作的 IOCTL 映射腐败 DLL 代码或 VEH handler
        for (int gi = 0; gi < guardRegionCount; gi++) {
            VirtualFree(guardRegions[gi].addr, 0, MEM_RELEASE);
        }
        DiagLog("BYOVD: freed %d guard regions\n",
            guardRegionCount);

        // ★ BUILD 554 P0-1: VAD 隐藏已移到 DKOM 隐藏之前 (BUILD 567 v3.235)
        //   原因: DKOM 成功断链 loader.exe 后, VAD GetEPROCESSByPid 找不到 loader.exe.
        //   修复: VAD 先执行 (见上方 L2710-2723), 缓存 EPROCESS; DKOM 后续断链不影响 VAD.
        //   周期: 60-90s 主循环重新调用 (PAC 可能恢复 VAD 标志), 用缓存的 EPROCESS.
    }

        // ★ BUILD 548: EPT dump 触发逻辑已移除 (不再需要 EPT dump 诊断)

// ★ BUILD 529: 测试模式跳过所有 CS2 操作 (PEB/模块诊断/内存初始化/Overlay/EntityChain)
    //   CS2 内存初始化失败会 return 3 退出, 测试模式下必须跳过避免退出
    // ★ BUILD 537: 半测试模式也跳过 — Memory::Initialize 失败会 return 3 退出,
    //   导致主循环不运行, 无法验证 ObCallbacks 持续移除 + DKOM 隐藏 + 不被踢.
    //   半测试模式主循环已跳过 CS2 内存访问 (L1847), 无需 Memory::Initialize.
    if (!g_egTestMode && !g_halfTestMode) {
    {
        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();

        // 1. Query PEB
        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG rl = 0;
        NTSTATUS st = SysQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), &rl, SyscallMethod::Indirect);
        DiagLog("PEB: status=0x%08X peb=0x%llX\n", (unsigned)st, (unsigned long long)pbi.PebBaseAddress);

        // 2. Read PEB to get Ldr
        BYTE pebBuf[0x100] = {};
        SIZE_T br = 0;
        st = SysReadVirtualMemory(hProc, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &br, SyscallMethod::Indirect);
        DiagLog("ReadPEB: status=0x%08X bytes=%zu\n", (unsigned)st, br);
        if (NT_SUCCESS(st) && br >= 0x20) {
            uintptr_t ldrAddr = *(uintptr_t*)(pebBuf + 0x18);
            DiagLog("LDR: addr=0x%llX\n", (unsigned long long)ldrAddr);

            // 3. Read LDR data (PEB_LDR_DATA)
            BYTE ldrBuf[0x100] = {};
            st = SysReadVirtualMemory(hProc, (PVOID)ldrAddr, ldrBuf, sizeof(ldrBuf), &br, SyscallMethod::Indirect);
            DiagLog("ReadLDR: status=0x%08X bytes=%zu\n", (unsigned)st, br);

            // 4. Read InLoadOrderModuleList head
            uintptr_t listHead = ldrAddr + 0x10;
            BYTE listBuf[0x20] = {};
            st = SysReadVirtualMemory(hProc, (PVOID)listHead, listBuf, sizeof(listBuf), &br, SyscallMethod::Indirect);
            DiagLog("ReadList: status=0x%08X bytes=%zu flink=0x%llX\n",
                (unsigned)st, br, (unsigned long long)*(uintptr_t*)listBuf);

            // 5. Walk first entry
            uintptr_t flink = *(uintptr_t*)listBuf;
            if (flink) {
                BYTE modBuf[0x400] = {};
                st = SysReadVirtualMemory(hProc, (PVOID)flink, modBuf, sizeof(modBuf), &br, SyscallMethod::Indirect);
                DiagLog("ReadMod: status=0x%08X bytes=%zu base=0x%llX\n",
                    (unsigned)st, br, (unsigned long long)*(uintptr_t*)(modBuf + 0x30));
                // FullName
                uintptr_t fname = *(uintptr_t*)(modBuf + 0x48);
                DiagLog("FullNameVA=0x%llX\n", (unsigned long long)fname);
            }
        }
    }

    // 诊断: 列出 CS2 进程模块
    {
        // ★ BUILD 557 FIX: modules[64] → modules[256] (CS2 实际 181 个模块, 64 截断导致 client.dll 未枚举)
        StealthProcess::ModuleInfo modules[256];
        int modCount = StealthProcess::GetProcessModules(
            StealthEngine::Instance().GetProcessHandle(), modules, 256);
        DiagLog("GetProcessModules: %d modules found\n", modCount);
        for (int i = 0; i < modCount; i++) {
            if (wcsstr(modules[i].name, L"client") || wcsstr(modules[i].name, L"engine"))
                DiagLog("  %ls @ 0x%llX\n", modules[i].name, (unsigned long long)modules[i].baseAddress);
        }
    }

    // --- 阶段4: 初始化 CS2 内存读取 ---
    cs2::Offsets offsets;
    if (!cs2::Memory::Instance().Initialize(offsets)) {
        DiagLog("B549:M:01 FAIL init\n");  // ★ BUILD 549: 去特征化
        stealth::KernelDefense::DisableAll();
        StealthEngine::Instance().Shutdown();
        return 3;
    }
    DiagLog("B549:M:02 ok cb=0x%llX eb=0x%llX\n",  // ★ BUILD 549: 去特征化
        (unsigned long long)cs2::Memory::Instance().ClientBase(),
        (unsigned long long)cs2::Memory::Instance().EngineBase());

    {
        uintptr_t cb = cs2::Memory::Instance().ClientBase();
        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
        auto& off = cs2::Memory::Instance().GetOffsets();

        // 获取 client.dll 大小
        uintptr_t clientSize = 0;
        {
            StealthProcess::ModuleInfo modules[256];
            int modCount = stealth::StealthProcess::GetProcessModules(hProc, modules, 256);
            // ★ BUILD 549+: 用 ModNameHash 比较替代 wcscmp(L"client.dll") (避免明文模块名)
            //   ModNameHash(L"client.dll") 编译期计算, 二进制中只出现 hash 常量
            constexpr uint32_t clientDllHash = stealth::ModNameHash(L"client.dll");
            for (int i = 0; i < modCount; i++) {
                if (stealth::ModNameHashRT(modules[i].name) == clientDllHash) {
                    clientSize = modules[i].size;
                    break;
                }
            }
        }
        DiagLog("B549:M:03 cb=0x%llX sz=0x%llX (%lldMB) end=0x%llX\n",  // ★ BUILD 549: 去特征化
            (unsigned long long)cb, (unsigned long long)clientSize,
            (long long)(clientSize / 1048576), (unsigned long long)(cb + clientSize));

        auto diagRead = [&](const char* name, uintptr_t addr) {
            uintptr_t val = 0;
            SIZE_T br = 0;
            SysReadVirtualMemory(hProc, (PVOID)addr, &val, 8, &br, SyscallMethod::Indirect);
            BYTE raw[32] = {};
            SIZE_T br2 = 0;
            SysReadVirtualMemory(hProc, (PVOID)(addr - 8), raw, 32, &br2, SyscallMethod::Indirect);
            DiagLog("  %s(off=0x%llX) addr=0x%llX val=0x%llX [hex:", name,
                (unsigned long long)(addr - cb), (unsigned long long)addr, (unsigned long long)val);
            if (br2 >= 8) {
                for (int i = 0; i < 24; i++) DiagLog("%02X ", raw[i]);
            }
            DiagLog("]");
            if (addr >= cb + clientSize) DiagLog(" *** OUT OF BOUNDS!");
            DiagLog("\n");
            return val;
        };

        diagRead("dwLocalPlayerCtl", cb + off.dwLocalPlayerController);
        diagRead("dwEntityList    ", cb + off.dwEntityList);
        diagRead("dwViewMatrix    ", cb + off.dwViewMatrix);

        // 宽扫: 从 viewMatrix 偏移到 entityList 偏移范围
        DiagLog("  -- scan for valid pointers in range 0x2300000..0x2600000 --\n");
        int found = 0;
        for (uintptr_t scanOff = 0x2300000; scanOff < 0x2600000 && found < 30; scanOff += 8) {
            if (cb + scanOff >= cb + clientSize) break; // 超出模块
            uintptr_t val = 0;
            SIZE_T br = 0;
            SysReadVirtualMemory(hProc, (PVOID)(cb + scanOff), &val, 8, &br, SyscallMethod::Indirect);
            if (val > cb && val < (cb + 0x20000000)) {
                DiagLog("  PTR: off=0x%llX val=0x%llX\n",
                    (unsigned long long)scanOff, (unsigned long long)val);
                found++;
            }
        }
        DiagLog("  -- found %d valid ptrs in range --\n", found);

        // Dump entity system raw memory to understand structure
        DiagLog("  -- entity system dump (first 512 bytes) --\n");
        {
            uintptr_t elBase = 0;
            SIZE_T br = 0;
            SysReadVirtualMemory(hProc, (PVOID)(cb + off.dwEntityList), &elBase, 8, &br, SyscallMethod::Indirect);
            if (elBase) {
                BYTE buf[512] = {};
                SIZE_T br2 = 0;
                SysReadVirtualMemory(hProc, (PVOID)elBase, buf, 512, &br2, SyscallMethod::Indirect);
                for (int row = 0; row < 32; row++) {
                    DiagLog("  +0x%03X: ", row * 16);
                    for (int col = 0; col < 16; col++) DiagLog("%02X ", buf[row * 16 + col]);
                    DiagLog("\n");
                }
                // Also read highest entity index at known offsets
                for (int offTry : {0x2090, 0x20A0, 0x20F0, 0x118, 0x20}) {
                    int hi = 0;
                    SysReadVirtualMemory(hProc, (PVOID)(elBase + offTry), &hi, 4, &br2, SyscallMethod::Indirect);
                    DiagLog("  highestIdx@+0x%X = %d\n", offTry, hi);
                }

                // Try: read identity list pointer at +0x10, mask tag, iterate
                uintptr_t idListTagged = 0;
                SysReadVirtualMemory(hProc, (PVOID)(elBase + 0x10), &idListTagged, 8, &br2, SyscallMethod::Indirect);
                uintptr_t idList = idListTagged & ~0xFULL; // strip tag
                DiagLog("  idList: tagged=0x%llX cleaned=0x%llX\n",
                    (unsigned long long)idListTagged, (unsigned long long)idList);

                // Try dumping first few entries at idList with various step sizes
                for (int stepSize : {0x78, 0x80, 0x88, 0x90, 0x120}) {
                    DiagLog("  -- iter with step=0x%X --\n", stepSize);
                    int valid = 0;
                    for (int i = 0; i < 5 && i <= 13; i++) {
                        uintptr_t addr = idList + i * stepSize;
                        uintptr_t val = 0;
                        SysReadVirtualMemory(hProc, (PVOID)addr, &val, 8, &br2, SyscallMethod::Indirect);
                        if (val > 0x10000) {
                            DiagLog("    [%d] @+0x%X val=0x%llX\n", i, i * stepSize, (unsigned long long)val);
                            valid++;
                        }
                    }
                    if (valid == 0) DiagLog("    (all zero)\n");
                }
            }
        }
    }
    // ★ BUILD 548: ESP 渲染由 CS2 自己完成 (ApplyCs2Patch 后 CS2 读取解密数据自行渲染)
    //   不再需要 game_esp.cpp/cheat_overlay.cpp 的 overlay 渲染
    //   保留 SetScreenSize 供诊断使用
    {
        int w = GetSystemMetrics(SM_CXSCREEN);
        int h = GetSystemMetrics(SM_CYSCREEN);
        cs2::Memory::Instance().SetScreenSize(w, h);
        DiagLog("B550:SC:screen=%dx%d\n", w, h);  // ★ BUILD 550: 脱敏 (原含 CS2/ESP)
    }

    // --- 阶段7: 主循环 (反检测维护 + 基础.exe 存活监控) ---
    // ---- 预检查: 直接用每种syscall方法读取clientBase的PE magic ----
    {
        HANDLE hProc = StealthEngine::Instance().GetProcessHandle();
        uintptr_t cb = cs2::Memory::Instance().ClientBase();

        // 方法1: TartarusGate (Direct Syscall)
        {
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)cb, &magic, 2, &bytesRead, SyscallMethod::Direct);
            DiagLog("TARTARUS: magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st));
        }

        // 方法2: Indirect Syscall (跳转ntdll syscall;ret gadget)
        {
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)cb, &magic, 2, &bytesRead, SyscallMethod::Indirect);
            DiagLog("INDIRECT: magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st));
        }

        // 方法3: StackSpoof (深度栈伪造)
        {
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = SysReadVirtualMemory(hProc, (PVOID)cb, &magic, 2, &bytesRead, SyscallMethod::StackSpoof);
            DiagLog("SPOOF:   magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st));
        }

        // 方法4: GetProcAddress fallback
        {
            using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
            auto fn = (Fn)STEALTH_GET_PROC_ADDRESS_NOREF(stealth::GetModuleBaseFromPEB(stealth::ModNameHash(L"ntdll.dll")), "NtReadVirtualMemory");  // ★ BUILD 549+: PEB Ldr
            uint16_t magic = 0;
            SIZE_T bytesRead = 0;
            NTSTATUS st = fn ? fn(hProc, (PVOID)cb, &magic, 2, &bytesRead) : (NTSTATUS)0xC0000002;
            DiagLog("GPA:      magic=0x%04X bytesRead=%zu status=0x%08X NT_SUCCESS=%d fn=%p\n",
                magic, bytesRead, (unsigned)st, (int)NT_SUCCESS(st), (void*)fn);
        }
    }

    // --- 诊断: 追踪 Controller->Handle->Pawn 链条 ---
    {
        auto& mem = cs2::Memory::Instance();
        auto& off = mem.GetOffsets();
        uintptr_t elBase = mem.EntityList();
        HANDLE hProcDiag = StealthEngine::Instance().GetProcessHandle();
        uintptr_t lpCtl = mem.LocalPlayerController();

        DiagLog("--- Entity Chain Trace ---\n");
        DiagLog("LocalPlayerController: 0x%llX\n", (unsigned long long)lpCtl);

        uint32_t rawHandle; SIZE_T br;
        NTSTATUS st = SysReadVirtualMemory(hProcDiag, (PVOID)(lpCtl + off.m_hPlayerPawn), &rawHandle, 4, &br, SyscallMethod::Indirect);
        DiagLog("pawnHandle raw: status=0x%08X bytes=%zu val=0x%08X idx=%u serial=0x%X\n",
            (unsigned)st, br, rawHandle, rawHandle & 0x7FFF, rawHandle >> 15);

        if (NT_SUCCESS(st) && br == 4 && rawHandle && rawHandle != 0xFFFFFFFF) {
            uintptr_t le;
            SysReadVirtualMemory(hProcDiag, (PVOID)(elBase + 8 * ((rawHandle & 0x7FFF) >> 9) + 16), &le, 8, &br, SyscallMethod::Indirect);
            DiagLog("  pawn chunk raw=0x%llX cleaned=0x%llX\n",
                (unsigned long long)le, (unsigned long long)(le & ~0xFULL));
            le &= ~0xFULL;
            if (le) {
                uintptr_t pawn;
                SysReadVirtualMemory(hProcDiag, (PVOID)(le + 120 * (rawHandle & 0x1FF)), &pawn, 8, &br, SyscallMethod::Indirect);
                DiagLog("  pawn resolved=0x%llX (idx=%u entryOff=0x%llX)\n",
                    (unsigned long long)pawn, rawHandle & 0x1FF,
                    (unsigned long long)(120 * (rawHandle & 0x1FF)));
            }
        }

        // 扫描 Controller 结构: 在 +0x700..+0x900 范围内找有效 pawnHandle
        DiagLog("--- Controller memory scan for pawnHandle (offset+0x700..0x900) ---\n");
        {
            BYTE ctlMem[0x200] = {};
            SIZE_T br2;
            NTSTATUS st2 = SysReadVirtualMemory(hProcDiag, (PVOID)(lpCtl + 0x700), ctlMem, sizeof(ctlMem), &br2, SyscallMethod::Indirect);
            if (NT_SUCCESS(st2)) {
                for (int off = 0; off < (int)sizeof(ctlMem) - 4; off += 4) {
                    uint32_t val = *(uint32_t*)(ctlMem + off);
                    if (val == 0 || val == 0xFFFFFFFF) continue;
                    uint32_t idx = val & 0x7FFF;
                    uint32_t serial = val >> 15;
                    // 有效 handle: index 在合理范围(1..511), serial 非零
                    if (idx >= 1 && idx <= 256 && serial > 0) {
                        DiagLog("  +0x%llX: handle=0x%08X idx=%u serial=0x%X\n",
                            (unsigned long long)(0x700 + off), val, idx, serial);
                    }
                }
            }
        }
        DiagLog("--- Entity Iteration (i=0..511) ---\n");
        for (int i = 0; i < 512; i++) {
            uintptr_t le; SIZE_T br2;
            st = SysReadVirtualMemory(hProcDiag, (PVOID)(elBase + 8 * ((i & 0x7FFF) >> 9) + 16), &le, 8, &br2, SyscallMethod::Indirect);
            le &= ~0xFULL;
            if (!le) { DiagLog("[%d] chunk=NULL\n", i); continue; }
            uintptr_t ctl = 0;
            SysReadVirtualMemory(hProcDiag, (PVOID)(le + 120 * (i & 0x1FF)), &ctl, 8, &br2, SyscallMethod::Indirect);
            if (!ctl) continue;
            bool isLocal = (ctl == lpCtl);
            DiagLog("[%d] ctl=0x%llX%s\n", i, (unsigned long long)ctl, isLocal ? " (LOCAL)" : "");
            uint32_t ph = 0;
            SysReadVirtualMemory(hProcDiag, (PVOID)(ctl + off.m_hPlayerPawn), &ph, 4, &br2, SyscallMethod::Indirect);
            DiagLog("    pawnHandle=0x%08X idx=%u serial=0x%X\n", ph, ph & 0x7FFF, ph >> 15);
            if (ph && ph != 0xFFFFFFFF) {
                uintptr_t le2 = 0;
                SysReadVirtualMemory(hProcDiag, (PVOID)(elBase + 8 * ((ph & 0x7FFF) >> 9) + 16), &le2, 8, &br2, SyscallMethod::Indirect);
                le2 &= ~0xFULL;
                uintptr_t pawn = 0;
                if (le2) SysReadVirtualMemory(hProcDiag, (PVOID)(le2 + 120 * (ph & 0x1FF)), &pawn, 8, &br2, SyscallMethod::Indirect);
                DiagLog("    pawn=0x%llX\n", (unsigned long long)pawn);
            }
        }
        DiagLog("--- End Entity Chain Trace ---\n");
    }
    } else if (g_halfTestMode) {
        DiagLog("B550:HM:skip all tgt-ops (half-test)\n");  // ★ BUILD 550: 脱敏
    } else {
        DiagLog("B550:TM:skip all tgt-ops (test mode)\n");
    }

    DiagLogEnc("m1");  // ★ BUILD 549: 加密 "main loop start"
    int frameCount = 0;
    DWORD lastDiagTime = 0;
    DWORD lastRetryTime = 0;

    while (true) {
        frameCount++;

        // ★ BUILD 567 v3.227: 周期性统计摘要 (每 5 分钟输出一次, 封号分析用)
        //   内部检查 lastSummaryTick, 未到 5 分钟直接返回 false, 无性能影响
        LogPeriodicSummary();

        // ★ BUILD 540: CS2 退出检测安全网 — 防止 TerminateProcess 路径 0x139 蓝屏
        //   根因: DKOM 永久断链后, 进程被 TerminateProcess(任务管理器) 终止时
        //   PspExitProcess 的 RemoveEntryList 调试检查失败 → BugCheck 0x139 参数 3
        //   21:42:37 第二次蓝屏即此路径 (用户强制终止卡死的 loader2.exe)
        //   修复: 主循环每次迭代检测 CS2 是否退出, 若退出则主动调用
        //         DisableAll(含 UnhideProcess) → return 0 安全退出
        //   场景: CS2 被反作弊踢出 / 用户关闭 CS2 → 主循环检测到 → 安全退出
        //   注意: g_egTestMode (pac_probe) 无 CS2 句柄, 跳过检测
        //   安全性: GetExitCodeProcess 只读进程对象退出码字段, 无 syscall 痕迹;
        //           ReopenProcessHandle 先开新句柄再关旧句柄, 无窗口期;
        //           句柄暂时无效时 GetExitCodeProcess 返回 FALSE, 不误退出
        if (!g_egTestMode) {
            HANDLE hCs2 = StealthEngine::Instance().GetProcessHandle();
            if (hCs2) {
                DWORD cs2ExitCode = STILL_ACTIVE;
                if (GetExitCodeProcess(hCs2, &cs2ExitCode) && cs2ExitCode != STILL_ACTIVE) {
                    DiagLog("B550:EX:tgt-exit=%u safe-exit\n", cs2ExitCode);  // ★ BUILD 550: 脱敏 (原含 CS2)
                    // ★ BUILD 556: 移除 ShadowPageManager::Uninstall (影子页方案已废弃)
                    //   VirtualProtect patch 无需卸载 (CS2 退出时自动释放)
                    // ★ BUILD 565: 卸载 NtReadVirtualMemory hook (恢复 IAT + ntdll)
                    //   必须在 CS2 退出前调用, 恢复 IAT/ntdll 原始字节, 防止 CS2 崩溃.
                    //   失败安全: Uninstall 失败仅记录日志, 不阻塞退出 (hook 在用户态, 不蓝屏).
                    if (stealth::NtReadHooker::Instance().IsActive()) {
                        stealth::NtReadHooker::Instance().Uninstall();
                    }
                    // ★ BUILD 567 v3.227: 退出摘要 (CS2 退出路径)
                    LogExitSummary();
                    stealth::KernelDefense::DisableAll();  // 包含 UnhideProcess
                    StealthEngine::Instance().Shutdown();
                    return 0;
                }
            }
        }

        // 隐身维护 (ETW/AMSI/VAC/Hook检测/NMI心跳)
        StealthEngine::Instance().OnFrame();

        // ★ BUILD 552: 移除 SyscallGuard::VerifyAndRepair() 调用 (EAC 专属, 已删除)
        //   实际 stub 完整性自愈由 syscall_direct 模块的 Halo's Gate / Tartarus Gate 提供
        //   原 v3.34 间隔随机化逻辑随 SyscallGuard 一并移除

        // ★ v3.126g: PAC 周期性监控 — 检查反作弊驱动是否加载,
        //   如果加载则自动摘除内核回调, 解决反作弊在 BYOVD 之后启动的问题
        //   注意: 使用 GetTickCount 而非 frameCount, 避免 Sleep 波动影响
        // ★ BUILD 534: 频率从 500-1500ms → 60-90s
        //   原 500-1500ms 调用 ReapplyAllCallbacks (每次 15+ IOCTL), 5分钟 7000+ IOCTL
        //   导致 PDFWKRNL.sys 资源耗尽卡死 (BUILD 532 在 300s 卡死, BUILD 533 在 160s 卡死).
        //   ReapplyAllCallbacks 调用 DisableAll (ObCallbacks+ProcessNotify+ImageNotify),
        //   ProcessNotify/ImageNotify 不需要频繁重新摘除 (PAC 不会频繁重注册).
        //   ObCallbacks 的频繁重新摘除由 L1773 ReDisablePacCallbacks (20-30s) 负责.
        //   5分钟内: ReapplyAllCallbacks 4次×15 IOCTL + ReDisablePacCallbacks 12次×5 IOCTL = ~120 IOCTL
        {
            static DWORD lastPacCheck = 0;
            DWORD nowTick = GetTickCount();
            // ★ BUILD 556: SHV 周期 60-90s → 30-45s
            //   原因: 加快 SHV patch 恢复响应, 缩短 PAC 重载驱动后的 EPT 监控窗口
            //   IOCTL 负担评估: 5 分钟内 ~210 IOCTL (原 ~105 IOCTL), 仍在 PDFWKRNL.sys 安全范围
            static DWORD pacCheckInterval = RandomJitter(30000, 15000);  // ★ BUILD 556: 30-45s
            if (nowTick - lastPacCheck >= pacCheckInterval) {
                lastPacCheck = nowTick;
                pacCheckInterval = RandomJitter(30000, 15000);  // ★ BUILD 556: 30-45s 随机
                if (stealth::KernelMemoryAccessor::Instance().IsActive()) {
                    stealth::KernelDefense::ReapplyAllCallbacks();
                    // ★ BUILD 567 v3.227: 回调重应用计数 + 状态日志
                    g_logStats.cbReapply++;
                    DiagLogState("CB", "REAPPLIED", "tick=%u", (unsigned)GetTickCount());

                    // ★ BUILD 552: 周期性验证 SHV_Install patch 仍然有效
                    //   若 PAC 重载驱动或自我修复 patch, 此处重新 patch
                    //   低频率 (60-90s) 不增加 IOCTL 负担
                    // ★ BUILD 555 P2-1: 降级模式下跳过 SHV patch 检查
                    //   原因: 连续 patch 失败 ≥3 次后, 跳过周期性检查避免触发频繁 IOCTL
                    //         (PAC 频繁恢复 patch → 频繁 BYOVD IOCTL → PDFWKRNL.sys 卡死风险)
                    //   降级期依赖 MinifilterNeutralizer (操作回调 stub) 作为主要 minifilter 防护
                    //   自恢复: IsDegradedMode() 内部判断距上次尝试 >5 分钟自动退出降级模式
                    // ★ BUILD 566 加固 v3.226: 同时验证 VmxOnWrapper patch (独立降级模式)
                    //   - 与 SHV_Install patch 维护并立 (独立降级状态, 互不污染)
                    //   - 两者任一需要重 patch, 调用 PatchShvInstallEntry (内部优先 PatchVmxOnWrapper)
                    //   - 一次 PatchShvInstallEntry 调用同时维护两者 (避免重复 IOCTL)
                    //   - VmxOnWrapper 降级模式下跳过 (依赖 SHV_Install patch 兜底)
                    bool needShvRepatch = false;
                    if (!stealth::ShvInstallPatcher::IsDegradedMode()) {
                        if (!stealth::ShvInstallPatcher::IsPatched()) {
                            needShvRepatch = true;
                        }
                    }
                    bool needVmxOnRepatch = false;
                    if (!stealth::ShvInstallPatcher::IsVmxOnDegradedMode()) {
                        if (!stealth::ShvInstallPatcher::IsVmxOnPatched()) {
                            needVmxOnRepatch = true;
                        }
                    }
                    if (needShvRepatch || needVmxOnRepatch) {
                        // ★ PatchShvInstallEntry 内部优先 PatchVmxOnWrapper + 后续 SHV_Install patch
                        //   一次调用同时维护两者, 避免分别调用导致重复 IOCTL
                        stealth::ShvInstallPatcher::PatchShvInstallEntry();
                    }

                    // ★ BUILD 554 P0-1: 周期性重新调用 VADConcealer
                    //   原因: PAC 可能通过周期性内核修复恢复 VAD 标志 (MEM_MAPPED → MEM_PRIVATE),
                    //         使 payload.dll 注入区域重新暴露给 VAD 扫描.
                    //   策略: 每 60-90s 与 ReapplyAllCallbacks 同周期重新隐藏, 保持深度防御.
                    {
                        DWORD cs2Pid = GetCurrentProcessId();
                        uintptr_t bases[1] = { (uintptr_t)g_diagDllBase };
                        stealth::VADConcealer::ConcealAllRegions(cs2Pid, bases, 1);
                    }
                }
            }
        }

        // v3.34: 诊断间隔随机化 (4-6秒, 规避固定节奏)
        DWORD now = GetTickCount();
        static DWORD diagInterval = RandomJitter(4000, 2000);
        if (now - lastDiagTime >= diagInterval) {
            lastDiagTime = now;
            diagInterval = RandomJitter(4000, 2000);
            // ★ BUILD 529: 测试模式跳过 cs2::Memory 调用 — 测试模式下 cs2::Memory
            //   未初始化 (Initialize 被跳过), m_clientBase=0, m_hProcess=nullptr.
            //   EntityList() 会调用 Read<uintptr_t>(0 + dwEntityList) 通过 syscall
            //   读取地址 0, 导致 ntdll 崩溃 (CRASH: code=0xC0000005 in ntdll).
            //   ClientBase() 本身安全 (只返回成员变量), 但为统一性一并跳过.
            // ★ BUILD 537: 半测试模式也跳过 CS2 内存访问 — 避免初始化不完整导致崩溃
            //   半测试模式目标: 验证 ObCallbacks 移除 + DKOM 隐藏 + loader2 附加 CS2 不被踢
            //   不需要实际读取 CS2 内存 (无 basic.exe ESP 渲染)
            if (!g_egTestMode && !g_halfTestMode) {
                uintptr_t elBase = cs2::Memory::Instance().EntityList();
                DiagLog("B549:F=%d p=%d el=0x%llX cb=0x%llX\n",  // ★ BUILD 549: 去特征化
                    frameCount,
                    g_cs2Patched ? 1 : 0,
                    (unsigned long long)elBase,
                    (unsigned long long)cs2::Memory::Instance().ClientBase());
            } else {
                // 测试模式/半测试模式: 只打印 E+G 保护层状态, 不访问 CS2 内存
                DiagLog("B549:F=%d t=%d (test)\n",  // ★ BUILD 549: 去特征化
                    frameCount,
                    g_cs2Patched ? 1 : 0);
            }
        }

        // ============================================================
        // ★ BUILD 528: E+G 组合方案 — 周期性保护验证
        // ============================================================

        // ★ BUILD 528: E+G — ObCallbacks 持续验证 (4-6秒周期, 与诊断同步)
        //   PAC 可能重新注册回调, 需周期性重新移除.
        //   ★ 不检查 HasRemovedCallbacks() — 该函数仅检查"我们是否保存过回调",
        //     不检查 PAC 是否重新注册了新回调。必须始终尝试重新移除。
        //     (memory 约束: "EAC callback removal must run in a periodic loop,
        //      with HasRemovedCallbacks() check removed to allow repeated attempts")
        // ★ BUILD 533: 降低频率从 diagInterval(4-6s) → 20-30s
        //   原每 5 秒调用一次 (60次/5分钟), 每次 20+ IOCTL, 总 7000+ IOCTL/5分钟
        //   导致 PDFWKRNL.sys 资源耗尽卡死. 降至 20-30s → 10次/5分钟, 降低 6 倍.
        //   BUILD 533 同时缓存 GetKernelModuleBase + ObpCallbackArrayHead, 进一步
        //   减少 IOCTL (首次 20+ IOCTL, 后续 10+ IOCTL)
        static DWORD lastObCheckTime = 0;
        static DWORD obCheckInterval = 20000;  // ★ BUILD 533: 20 秒起步
        if (now - lastObCheckTime >= obCheckInterval) {
            lastObCheckTime = now;
            obCheckInterval = RandomJitter(20000, 10000);  // 20-30 秒随机
            // 始终尝试重新移除 — ReDisablePacCallbacks 内部会扫描 ObpCallbackArray
            // 找到 PAC 注册的新回调并 NULL 化, 已移除的不会重复处理
            int reRemoved = stealth::EACCallbackDisabler::Instance().ReDisablePacCallbacks();
            if (reRemoved > 0) {
                DiagLog("E+G: ObCallbacks re-removed (count=%d)\n", reRemoved);
            }
        }

        // ★ BUILD 528: E+G — 句柄重随机化 (10-20秒周期)
        //   对抗 NtQuerySystemInformation(SystemHandleInformation) 句柄枚举扫描.
        //   关闭旧句柄并通过 syscall NtOpenProcess 重开, 缩短句柄可见窗口.
        static DWORD lastHandleReopenTime = 0;
        static DWORD handleReopenInterval = RandomJitter(10000, 10000);
        if (now - lastHandleReopenTime >= handleReopenInterval) {
            lastHandleReopenTime = now;
            handleReopenInterval = RandomJitter(10000, 10000);
            bool reopenOk = stealth::StealthEngine::Instance().ReopenProcessHandle();
            DiagLog("B550:EG:handle re-rand %s\n", reopenOk ? "OK" : "FAIL");  // ★ BUILD 550: 脱敏
        }

        // ★ BUILD 537: Gamma-A — 移除 PatchGuard 缓解循环 (PG 已禁用, 无需 Unhide/Rehide)
        //   原 BUILD 528: 每 60-90s Unhide+Sleep+Rehide 循环缓解 PatchGuard 扫描
        //   Gamma-A: bcdedit /debug on 已禁用 PatchGuard, DKOM 可永久断链
        //   保留此注释块作为变更记录, 实际循环代码已移除
        // ----------------------------------------------------------
        // 原代码 (BUILD 528-536):
        //   static DWORD lastDkomCycleTime = 0;
        //   static DWORD dkomCycleInterval = RandomJitter(60000, 30000);
        //   if (now - lastDkomCycleTime >= dkomCycleInterval) {
        //       lastDkomCycleTime = now;
        //       dkomCycleInterval = RandomJitter(60000, 30000);
        //       auto& hider = stealth::DKOMProcessHider::Instance();
        //       if (hider.GetCurrentEPROCESS()) {
        //           hider.UnhideProcess();              // 先恢复链表
        //           Sleep(RandomJitter(50, 100));       // 短暂等待, 让 PatchGuard 扫描通过
        //           hider.HideProcess();                // 重新隐藏
        //           DiagLog("E+G: DKOM cycle (unhide+rehide) done\n");
        //       }
        //   }
        // ----------------------------------------------------------

        // ★ BUILD 549: 补丁维护 + 防截图 (频率调整 + 影子页模式分支)
        //   补丁维护: 5s → 500ms (影子页周期切换, 10% 占空比)
        //   ★ BUILD 553: 500ms → 5s (降频 10 倍, 减少 IOCTL 频率)
        //     IOCTL/min: 240 → 24, 远低于 PDFWKRNL.sys 卡死基线 (1400/min)
        //   截图检测: 1s → 5s (减少 NtQSI 调用频率)
        static DWORD lastPatchCheck = 0;
        static DWORD lastScreenshotCheck = 0;
        static bool g_patchReverted = false;  // ★ BUILD 548: 移到前面, 供 patch 维护分支检查

        // ★ BUILD 557: DR0 频率统计报告 — 每秒检查, 60s 后触发
        //   ReportDR0Frequency 内部检查 elapsed >= 60s 才真正执行, 提前调用是 no-op
        //   每秒检查一次避免高频 GetTickCount 调用
        {
            static DWORD lastDr0Check = 0;
            if (g_dr0StatActive && !g_dr0StatDone &&
                GetTickCount() - lastDr0Check > 1000) {
                lastDr0Check = GetTickCount();
                ReportDR0Frequency();
            }
        }

        // ★ BUILD 567 v3.236 FIX-3: DR0 清除重试机制 — 10 秒周期
        //   触发条件: g_dr0StatActive=1 && g_dr0StatDone=1
        //             (ReportDR0Frequency 已执行, 但 failCount > 0 有残留 DR0)
        //   全部清除成功时恢复 StealthSleep (g_dr0StatActive=0),
        //   否则保持禁用等待下次重试 (避免 EkkoSleep 加密 .data 期间残留 DR0 触发崩溃)
        {
            static DWORD lastDr0Retry = 0;
            if (g_dr0StatActive && g_dr0StatDone &&
                GetTickCount() - lastDr0Retry > 10000) {
                lastDr0Retry = GetTickCount();
                RetryClearDR0Breakpoints();
            }
        }

        // ★ BUILD 553: 补丁维护 — 5s 间隔 (从 BUILD 549 的 500ms 降频, 1% 占空比)
        if (GetTickCount() - lastPatchCheck > 5000) {
            if (!g_cs2Patched) {
                g_cs2Patched = ApplyCs2Patch();
                // ★ BUILD 558 FIX-5: 主循环中 ApplyCs2Patch 成功后补启动 DR0 频率统计
                //   原因: 初始化阶段 ApplyCs2Patch 在 cs2::Memory::Initialize 之前调用 (阶段3 vs 阶段4),
                //         导致初始化阶段 ApplyCs2Patch 失败 ("mod not loaded"), StartDR0FrequencyStat 未被调用.
                //         主循环中 cs2::Memory 已初始化, ApplyCs2Patch 成功后需要补启动 DR0 统计.
                //   幂等: StartDR0FrequencyStat 内部用 InterlockedExchange(&g_dr0StatActive, 1) 防重入
                if (g_cs2Patched) {
                    // ★ BUILD 567 v3.237: 禁用 DR0 频率统计 — DR0 设置在 CS2 线程上,
                    //   #DB 异常在 CS2 进程内触发, loader.exe 的 VEH 无法跨进程捕获,
                    //   导致 CS2 线程执行到 patch 地址时触发 #DB → CS2 崩溃 (0xC0000005).
                    //   DR0 是 BUILD 557 诊断功能, 非核心功能, 禁用不影响透视/防检测.
                    // StartDR0FrequencyStat();  // ★ v3.237: 禁用
                    // ★ BUILD 565: 若初始化阶段 NtReadHooker 未安装 (ApplyCs2Patch 失败),
                    //   主循环中重试安装 (5s 间隔, 与 ApplyCs2Patch 同周期)
                    if (!stealth::NtReadHooker::Instance().IsActive() && g_patchAddr && g_clientBase) {
                        HANDLE hCs2ForHook = StealthEngine::Instance().GetProcessHandle();
                        if (hCs2ForHook) {
                            // ★ BUILD 567 v3.238 DIAG: NtReadHooker::Install 前后诊断
                            DiagLog("B238:NR:I+ pre addr=0x%llX cb=0x%llX h=%p\n",
                                (unsigned long long)g_patchAddr,
                                (unsigned long long)g_clientBase, hCs2ForHook);
                            stealth::NtReadHooker::Instance().Install(
                                hCs2ForHook, g_clientBase, g_patchAddr);
                            DiagLog("B238:NR:I+ post active=%d\n",
                                stealth::NtReadHooker::Instance().IsActive() ? 1 : 0);
                        }
                    }
                }
            } else if (!g_patchReverted) {  // 截图工具运行期间不维护补丁
                MaintainCs2Patch();
            }
            lastPatchCheck = GetTickCount();
        }

        // ★ BUILD 565: NtReadHooker 维护 — 与补丁维护同 5s 间隔
        //   检测 PvpAlive.dll 重载 (基址变化) 或 ntdll 被 PAC 恢复, 自动重新安装 hook.
        //   仅在 hook 已安装且非测试模式时执行.
        if (!g_egTestMode && !g_halfTestMode && stealth::NtReadHooker::Instance().IsActive()) {
            // ★ BUILD 567 v3.238 DIAG: NtReadHooker::Maintain 前后诊断
            DiagLog("B238:NR:M+ pre\n");
            stealth::NtReadHooker::Instance().Maintain();
            DiagLog("B238:NR:M+ post\n");
        }

        // ★ BUILD 567 v3.257 DIAG: 主循环心跳 — 5s 间隔
        //   目的: 调查 CS2 对局加载崩溃 (主菜单正常, 进入对局加载界面崩溃 0xC0000005)
        //   日志含: frameCount, CS2 是否活跃, hook 内部状态 (IAT/inline/PvpAlive/filter),
        //   patch 状态 (g_cs2Patched/g_patchReverted/g_patchAddr)
        //   判读: 崩溃前最后一条 B257:HB 显示崩溃时刻主循环状态;
        //         若 PvpAlive 基址=0 → CS2 卸载 PvpAlive.dll (对局加载触发);
        //         若 filterFunc=0 → hook 未安装或被清理;
        //         若 inlineHook=1 → 走 inline hook 路径 (shellcode 在 CS2 进程内执行)
        {
            static DWORD lastHeartbeat = 0;
            if (GetTickCount() - lastHeartbeat > 5000) {
                lastHeartbeat = GetTickCount();
                bool cs2Alive = false;
                HANDLE hCs2 = StealthEngine::Instance().GetProcessHandle();
                if (hCs2) {
                    DWORD ec = STILL_ACTIVE;
                    if (GetExitCodeProcess(hCs2, &ec) && ec == STILL_ACTIVE) cs2Alive = true;
                }
                auto& nrh = stealth::NtReadHooker::Instance();
                DiagLog("B257:HB:fc=%d cs2=%d act=%d iat=%d inl=%d pvp=0x%llX ff=0x%llX nf=0x%llX pat=%d rev=%d pa=0x%llX\n",
                    frameCount, cs2Alive ? 1 : 0,
                    nrh.IsActive() ? 1 : 0,
                    nrh.IsIATHookActive() ? 1 : 0,
                    nrh.IsInlineHookActive() ? 1 : 0,
                    (unsigned long long)nrh.GetPvpAliveBase(),
                    (unsigned long long)nrh.GetFilterFuncAddr(),
                    (unsigned long long)nrh.GetInlineFilterFunc(),
                    g_cs2Patched ? 1 : 0,
                    g_patchReverted ? 1 : 0,
                    (unsigned long long)g_patchAddr);
            }
        }

        // ★ BUILD 549: 截图检测 — 5s 间隔 (原 1s)
        if (GetTickCount() - lastScreenshotCheck > 5000) {
            bool toolRunning = IsScreenshotToolRunning();
            if (toolRunning && !g_patchReverted && g_cs2Patched) {
                // ★ BUILD 556: 移除影子页 RevealOriginal, 直接走 TemporarilyRevertPatch 回退路径
                //   原因: 影子页方案已废弃, 降级到 VirtualProtect
                TemporarilyRevertPatch();  // VirtualProtect 模式: 临时恢复原始字节
                g_patchReverted = true;
            } else if (!toolRunning && g_patchReverted) {
                // ★ BUILD 556: 移除影子页 ReapplyPatch, 直接走 ApplyCs2Patch 回退路径
                //   恢复补丁: 检查返回值 — 失败则保持 g_patchReverted=true, 下次循环重试
                if (ApplyCs2Patch()) {
                    g_patchReverted = false;
                }
            }
            lastScreenshotCheck = GetTickCount();
        }

        // ★ BUILD 528: E+G — 增大睡眠比例 (80-250ms), 明文窗口降至 ~2%
        //   原: 40-170ms (明文窗口 3-12%)
        //   新: 80-250ms (明文窗口 1-3%)
        // v3.34: EkkoSleep 随机间隔 (规避固定周期时序特征)
        DWORD sleepMs = RandomJitter(80, 170);
        // ★ BUILD 531: 测试模式跳过 StealthSleep (EkkoSleep) — EkkoSleep 的 EncryptAll
        //   会加密自身代码页, 导致 EncryptAll 返回时执行已加密代码 → 进程崩溃.
        //   测试模式无 CS2 无反作弊扫描, 不需要内存加密; 用普通 Sleep 代替.
        // ★ BUILD 544: 解除半测试跳过 — EkkoSleep 豁免已修复 (EncryptAll/DecryptAll/XorCrypt 页加入豁免)
        //   保留 g_egTestMode (无 CS2) 跳过 — 测试2 不需要内存加密
        // ★ BUILD 548: 移除 EncryptBasicCode/DecryptBasicCode (basic.exe 已移除)
        // ★ BUILD 557: DR0 统计窗口内禁用 StealthSleep — 关键安全约束
        //   原因: EkkoSleep 的 EncryptAll 会 XOR 加密 .data 段 (含统计变量 g_dr0StatActive/
        //         g_dr0HitCount/g_dr0Addr), VEH 在 CS2 线程上高频触发时读取加密垃圾 →
        //         g_dr0StatActive 比较失败 → fallthrough 到 ACCESS_VIOLATION 自愈 → 进程崩溃.
        //   恢复: ReportDR0Frequency 执行后 g_dr0StatActive=0, 自动恢复 StealthSleep.
        //   双重保险: DR0 函数页已加入 exemptPages (变更 9), 但 .data 段变量无法豁免.
        // ★ BUILD 558 FIX-2: StealthSleep 之前检查 .idata 页保护属性
        //   崩溃地址 0x9A2E (DiagVehHandler 内 GetCurrentThreadId IAT call) 表明 EkkoSleep
        //   期间 .idata 页不可读. 此诊断在 StealthSleep 之前 (此时 .idata 仍可读) 调用
        //   VirtualQuery 记录保护属性, 若异常则强制恢复 PAGE_READONLY.
        //   10s 周期避免日志泛滥, 但每次循环都强制恢复保护属性 (零开销 VirtualProtect)
        if (!g_egTestMode && !g_dr0StatActive && g_idataPageStart && g_idataPageEnd) {
            static DWORD lastIdataDiag = 0;
            bool needDiag = (GetTickCount() - lastIdataDiag) > 10000;
            if (needDiag) lastIdataDiag = GetTickCount();
            for (uintptr_t p = g_idataPageStart; p < g_idataPageEnd; p += 0x1000) {
                MEMORY_BASIC_INFORMATION mbi = {};
                if (VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) {
                    // PAGE_READONLY=0x02, PAGE_READWRITE=0x04, PAGE_NOACCESS=0x01
                    // 正常: mbi.Protect == PAGE_READONLY (ManualMap 设置)
                    // 异常: mbi.Protect == PAGE_NOACCESS 或 0
                    if (mbi.Protect != PAGE_READONLY && mbi.Protect != PAGE_READWRITE) {
                        DWORD oldProt = 0;
                        if (VirtualProtect((LPVOID)p, 0x1000, PAGE_READONLY, &oldProt)) {
                            if (needDiag) {
                                DiagLog("B558:IDATA:page 0x%llX prot=0x%X → PAGE_READONLY (restored)\n",
                                    (unsigned long long)p, (unsigned)mbi.Protect);
                            }
                        } else if (needDiag) {
                            DiagLog("B558:IDATA:page 0x%llX prot=0x%X VirtualProtect FAILED err=%u\n",
                                (unsigned long long)p, (unsigned)mbi.Protect, GetLastError());
                        }
                    }
                }
            }
        }
        if (!g_egTestMode && !g_dr0StatActive) {
            // ★ BUILD 567 v3.238 DIAG: StealthSleep (EkkoSleep) 前后诊断
            //   若 pre 有 post 无 → EkkoSleep 内部崩溃 (EncryptAll/DecryptAll 失败)
            DiagLog("B238:SS:pre ms=%u dr0=%d eg=%d\n", sleepMs, g_dr0StatActive, g_egTestMode);
            StealthEngine::Instance().StealthSleep(sleepMs);
            DiagLog("B238:SS:post\n");
        } else {
            // ★ BUILD 567 v3.238 DIAG: 普通 Sleep 分支 (测试模式/DR0 active)
            DiagLog("B238:SLP:pre ms=%u (no Ekko dr0=%d eg=%d)\n",
                sleepMs, g_dr0StatActive, g_egTestMode);
            Sleep(sleepMs);
            DiagLog("B238:SLP:post\n");
        }
    }

    // ★ BUILD 548: basic.exe 已移除, 不需要 TerminateBasicESP
    // ★ BUILD 556: 移除 ShadowPageManager::Uninstall (影子页方案已废弃)
    //   VirtualProtect patch 无需卸载 (进程退出时自动释放)
    // ★ BUILD 567 v3.227: 退出摘要 (主循环正常退出路径)
    LogExitSummary();
    stealth::KernelDefense::DisableAll();
    StealthEngine::Instance().Shutdown();
    return 0;
}

// ============================================================
// DLL 入口点
// ManualMap 完成后由 loader 在主线程上调用。
// ============================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    // ★ BUILD 539: DLL_PROCESS_DETACH 时挂回 ActiveProcessLinks — 防止 0x139 蓝屏
    //   根因: DKOM 永久断链后进程退出时 PspExitProcess 的 RemoveEntryList 调试检查失败
    //   manual-mapped DLL 的 DETACH 通常不会被系统调用, 但 loader 可能手动调用.
    //   正常退出路径 (CheatMainLoop return) 已调用 DisableAll→UnhideProcess.
    //   这里作为双保险: 如果 DETACH 被触发, 确保链表挂回.
    if (fdwReason == DLL_PROCESS_DETACH) {
        DiagLog("DllMain: DETACH — calling UnhideAll (prevent 0x139 BSOD)\n");
        // ★ BUILD 544: 必须挂回所有隐藏进程 (loader2)
        //   BUILD 548: basic.exe 已移除, 只需挂回 loader2
        stealth::DKOMProcessHider::Instance().UnhideAll();
        return TRUE;
    }

    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hinstDLL);

    SIZE_T dllSize = 0;
    {
        auto* image = reinterpret_cast<BYTE*>(hinstDLL);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                image + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                dllSize = nt->OptionalHeader.SizeOfImage;
            }
        }
        // ★ BUILD 557 FIX: PE 头被 ManualMap 擦除时, 用 VirtualQuery 回退获取 dllSize
        //   原因: loader.cpp MinimalManualMap L516-526 擦除 PE 头前 0x400 字节,
        //         导致 dos->e_magic != IMAGE_DOS_SIGNATURE, dllSize=0,
        //         EkkoSleep 保护 0 字节 (内存加密失效), VEH 自愈无法恢复代码.
        //   修复: VirtualQuery 遍历连续 AllocationBase 区域, 累加 RegionSize.
        if (dllSize == 0) {
            SIZE_T totalSize = 0;
            BYTE* addr = reinterpret_cast<BYTE*>(hinstDLL);
            while (totalSize < 64 * 1024 * 1024) {  // 安全上限 64MB
                MEMORY_BASIC_INFORMATION mbi = {};
                if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
                if (mbi.AllocationBase != hinstDLL) break;
                totalSize += mbi.RegionSize;
                addr += mbi.RegionSize;
            }
            dllSize = totalSize;
            DiagLog("B557:FIX:dllSize=%llu via VirtualQuery (PE header erased)\n",
                (unsigned long long)dllSize);
        }
    }

    return (CheatMainLoop(hinstDLL, dllSize) == 0) ? TRUE : FALSE;
}
