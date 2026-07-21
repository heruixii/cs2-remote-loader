import os
p = r'D:\技术研发\sd_dump.txt'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

out = []

# 1. CS2 patch 详细信息 - 找 patch 地址、原始字节、patch 字节
out.append('=== CS2 PATCH DETAILS ===')
for line in lines:
    if any(k in line for k in ['B549:', 'B558:', 'pat=', 'pa=0x', 'patched', 'B257:HB', 'B550:TM', 'orig', 'restor', 'CS2', 'client.dll']):
        out.append(line)

# 2. 驱动隐藏状态
out.append('')
out.append('=== DRIVER HIDE STATUS ===')
for line in lines:
    if any(k in line for k in ['HideDriver', 'PreHide', 'PostHide', 'PsLoaded', 'DKOM', 'hide', 'Hide']):
        out.append(line)

# 3. 回调禁用详情
out.append('')
out.append('=== CALLBACK DISABLE DETAILS ===')
for line in lines:
    if any(k in line for k in ['DisableOb', 'DisableProc', 'DisableImg', 'DisableThread', 'PreDisable', 'PostDisable', 'ob=', 'proc=', 'img=', 'thread=']):
        out.append(line)

# 4. VEH/SHV/Vmx 状态
out.append('')
out.append('=== VEH/SHV/VMX STATUS ===')
for line in lines:
    if any(k in line for k in ['VEH', 'SHV', 'Vmx', 'B552:', 'B553:', 'B555:']):
        out.append(line)

# 5. 日志最后 100 行（看退出状态）
out.append('')
out.append('=== LAST 100 LINES ===')
out.extend(lines[-100:])

open(r'D:\技术研发\detection_detail.txt', 'w', encoding='utf-8').write('\n'.join(out))
print(f'done, {len(lines)} lines')
