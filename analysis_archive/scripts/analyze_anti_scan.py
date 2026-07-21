import os
p = r'D:\技术研发\sd_dump.txt'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

out = []
# 搜索 NtReadHooker / B565 / IAT hook / inline hook 相关
out.append('=== NtReadHooker / B565 (anti-scan) ===')
for line in lines:
    if any(k in line for k in ['B565', 'NtRead', 'IAT hook', 'inline hook', 'InstallIAT', 'InstallInline', 'PvpAlive', 'FilterShellcode', 'B565:I', 'B565:M', 'B565:U']):
        out.append(line)

# 搜索 SHV / Vmx 相关
out.append('')
out.append('=== SHV / Vmx (BUILD 566) ===')
for line in lines:
    if any(k in line for k in ['B552:', 'B553:', 'SHV', 'Vmx', 'B566', 'ShvInstall', 'VmxOn']):
        out.append(line)

# 搜索 Minifilter / PAC 相关
out.append('')
out.append('=== Minifilter / PAC (BUILD 563) ===')
for line in lines:
    if any(k in line for k in ['B563', 'Minifilter', 'MessageTransfer', 'FltGlobals', 'PAC', 'pac=']):
        out.append(line)

# 搜索所有 B5xx 和 B2xx 日志摘要
out.append('')
out.append('=== All B5xx/B2xx summary lines ===')
for line in lines:
    if any(k in line for k in ['B549:F=', 'B257:HB:', 'B289:', 'B558:MP:', 'B558:AP:', 'B552:', 'B554:', 'B565:', 'OK: BYOVD']):
        out.append(line)

open(r'D:\技术研发\detection_anti_scan.txt', 'w', encoding='utf-8').write('\n'.join(out))
print(f'done, {len(lines)} lines, output {len(out)} lines')
