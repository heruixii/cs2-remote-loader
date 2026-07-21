import os
# 分析 v3.295 所有防护层的代码状态
out = []
out.append('=== v3.295 防护层完整分析 ===')
out.append('')

# 1. 检查 NtReadHooker 是否正确启用
out.append('【1. NtReadHooker IAT hook (反用户态扫描)】')
import re
payload = open(r'D:\技术研发\tmp\payload.cpp', 'r', encoding='utf-8').read()
byovd = open(r'D:\技术研发\tmp\stealth_lib\byovd_kernel.cpp', 'r', encoding='utf-8').read()

# 检查初始化阶段
if 'if (false && g_cs2Patched' in payload:
    out.append('  初始化阶段: ❌ 仍然被 if(false) 禁用')
elif 'if (g_cs2Patched && g_patchAddr && g_clientBase)' in payload:
    out.append('  初始化阶段: ✅ 已启用 (IAT hook only)')
else:
    out.append('  初始化阶段: ? 未知状态')

# 检查主循环重试
if 'if (false && !stealth::NtReadHooker' in payload:
    out.append('  主循环重试: ❌ 仍然被 if(false) 禁用')
elif 'if (!stealth::NtReadHooker::Instance().IsActive()' in payload:
    out.append('  主循环重试: ✅ 已启用')
else:
    out.append('  主循环重试: ? 未知状态')

# 检查 Install 是否移除 inline hook 回退
if 'InstallInlineHook(cs2Process, ntReadAddr' in byovd and 'fallback to inline' in byovd:
    out.append('  Install inline 回退: ❌ 仍然存在')
elif 'inline disabled' in byovd:
    out.append('  Install inline 回退: ✅ 已移除')
else:
    out.append('  Install inline 回退: ? 未知')

# 检查 Uninstall 调用
if 'stealth::NtReadHooker::Instance().Uninstall()' in payload:
    out.append('  Uninstall 调用: ✅ 已添加')
else:
    out.append('  Uninstall 调用: ❌ 缺失')

out.append('')
out.append('【2. CS2 patch 字节隐蔽性】')
if 'patchBytes[2] = { 0x66, 0x90 }' in payload:
    out.append('  patch 字节: ✅ 66 90 (Intel 标准 2字节 NOP)')
elif 'patchBytes[2] = { 0x90, 0x90 }' in payload:
    out.append('  patch 字节: ❌ 90 90 (显眼的 NOP NOP)')
else:
    out.append('  patch 字节: ? 未知')

out.append('')
out.append('【3. PvpAlivePatcher (内核 patch 检测函数)】')
if 'GetProcessCR3' in byovd and 'PCID' in byovd:
    out.append('  GetCR3 PCID 修复: ✅ v3.294 已修复')
else:
    out.append('  GetCR3 PCID 修复: ❌ 缺失')

if 'g_patchRet[]' in byovd and 'xor eax,eax; ret' in byovd:
    out.append('  patch 字节: ✅ 31 C0 C3 (xor eax,eax; ret)')
else:
    out.append('  patch 字节: ? 未知')

if 'PvpAlivePatcher::Instance().Uninstall()' in payload:
    out.append('  Uninstall 调用: ✅ 已添加')
else:
    out.append('  Uninstall 调用: ❌ 缺失')

out.append('')
out.append('【4. PsLoadedModuleHider (驱动隐藏)】')
if 'StateLog("B564", "HideFail"' in byovd:
    out.append('  诊断日志: ✅ 已添加 StateLog')
else:
    out.append('  诊断日志: ❌ 缺失')

out.append('')
out.append('【5. BYOVD 回调禁用】')
if 'PostDisableOb' in byovd and 'PostDisableProc' in byovd:
    out.append('  回调禁用: ✅ Ob/Proc/Img/Thread 回调禁用')
else:
    out.append('  回调禁用: ❌ 缺失')

out.append('')
out.append('【6. MinifilterNeutralizer (MessageTransfer 中和)】')
if 'NeutralizeMessageTransfer' in byovd:
    out.append('  minifilter 中和: ✅ 存在')
else:
    out.append('  minifilter 中和: ❌ 缺失')

out.append('')
out.append('【7. DKOM 进程隐藏】')
if 'DKOMProcessHider' in byovd and 'HideProcessByPid' in byovd:
    out.append('  DKOM 隐藏: ✅ 存在')
else:
    out.append('  DKOM 隐藏: ❌ 缺失')

out.append('')
out.append('【8. VAD 隐藏】')
if 'FindAndModifyVadNode' in byovd:
    out.append('  VAD 隐藏: ✅ 存在')
else:
    out.append('  VAD 隐藏: ❌ 缺失')

out.append('')
out.append('【9. SHV/Vmx patch】')
if 'PatchShvInstallEntry' in byovd and 'PatchVmxOnWrapper' in byovd:
    out.append('  SHV/Vmx patch: ✅ 存在 (仅 PAC 已安装时)')
else:
    out.append('  SHV/Vmx patch: ❌ 缺失')

out.append('')
out.append('【10. EkkoSleep (内存加密)】')
if 'EkkoSleep' in payload or 'SleepObfuscator' in payload:
    out.append('  EkkoSleep: ✅ 存在')
else:
    out.append('  EkkoSleep: ❌ 缺失')

out.append('')
out.append('=== PAC 检测路径分析 ===')
out.append('')
out.append('PAC 检测手段 → 防护状态:')
out.append('  1. PvpAlive.dll NtReadVirtualMemory 扫描 client.dll')
out.append('     → IAT hook 拦截, 返回原始字节 32 c0 ✅')
out.append('     → PvpAlive.dll 4 个检测函数被 patch 返回 0 ✅')
out.append('     → 双重防护: 即使 IAT hook 失败, PvpAlive 函数也被 patch')
out.append('')
out.append('  2. MessageTransfer.sys minifilter 内核扫描')
out.append('     → MinifilterNeutralizer 中和回调 ✅')
out.append('     → 回调返回 FLT_PREOP_SUCCESS_NO_CALLBACK ✅')
out.append('')
out.append('  3. ObRegisterCallbacks 监控')
out.append('     → BYOVD 禁用 Ob/Proc/Img/Thread 回调 ✅')
out.append('')
out.append('  4. PsLoadedModuleList 驱动枚举')
out.append('     → PsLoadedModuleHider DKOM 断链 (v3.295 加诊断) ⚠️')
out.append('     → 风险: v3.293 日志显示 ok=0 (失败), 需测试 v3.295 诊断')
out.append('')
out.append('  5. SCM 服务枚举')
out.append('     → RegDeleteTreeW 删除服务键 ✅')
out.append('')
out.append('  6. CS2 ntdll 完整性自检')
out.append('     → IAT hook 不碰 ntdll ✅')
out.append('     → inline hook 已移除 ✅')
out.append('')
out.append('  7. SHV/EPT 虚拟化检测')
out.append('     → PatchShvInstallEntry + PatchVmxOnWrapper ✅')
out.append('     → 仅 PAC 已安装时执行 ✅')
out.append('')
out.append('=== 潜在风险点 ===')
out.append('')
out.append('1. ⚠️ PsLoadedModuleHider 失败 (v3.293 ok=0)')
out.append('   - v3.295 添加了 StateLog 诊断, 需测试确认失败原因')
out.append('   - 若失败, PAC 可枚举 PsLoadedModuleList 发现 PDFWKRNL.sys')
out.append('   - 但 PDFWKRNL.sys 是随机化名称, PAC 可能不识别')
out.append('')
out.append('2. ⚠️ IAT hook shellcode 内存 (PAGE_EXECUTE_READWRITE)')
out.append('   - VirtualAllocEx 分配的可执行内存可能被扫描')
out.append('   - 但 shellcode 在 CS2 进程内, PvpAlive.dll IAT 已被 hook')
out.append('   - PvpAlive.dll 调用 NtReadVirtualMemory 时被拦截, 无法扫描')
out.append('')
out.append('3. ⚠️ PvpAlive.dll IAT 完整性自检')
out.append('   - 若 PvpAlive.dll 检查自己的 IAT 是否被修改')
out.append('   - 风险: IAT hook 会被发现')
out.append('   - 缓解: PvpAlive.dll 4 个检测函数已被 patch, 无法执行检测逻辑')
out.append('')
out.append('4. ⚠️ 物理内存 patch 检测')
out.append('   - PvpAlivePatcher 用 driver 物理内存写入 patch')
out.append('   - 若 PAC 检查 PvpAlive.dll 代码段完整性')
out.append('   - 风险: 4 个函数入口被改为 31 C0 C3')
out.append('   - 缓解: MessageTransfer.sys 回调已中和, 无法扫描')

open(r'D:\技术研发\v295_analysis.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')
