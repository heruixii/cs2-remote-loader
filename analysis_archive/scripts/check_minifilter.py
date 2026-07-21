import os
p = r'D:\技术研发\sd_dump.txt'
if not os.path.exists(p):
    print('sd_dump.txt not found')
    exit()
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

out = []
# 搜索 MinifilterNeutralizer 相关日志
out.append('=== MinifilterNeutralizer 状态 ===')
for line in lines:
    if any(k in line for k in ['FLT:', 'NTRL', 'minifilter', 'MessageTransfer', 'B550:NT', 'B553:GP', 'NeutralizeMessageTransfer', 'IsMessageTransferNeutralized']):
        out.append(line)

# 搜索 PAC 状态
out.append('')
out.append('=== PAC 状态 ===')
for line in lines:
    if any(k in line for k in ['PAC', 'pac=', 'pacStatus', 'NotInstalled', 'PacStatus', 'SHV']):
        out.append(line)

# 搜索 OK: BYOVD 行
out.append('')
out.append('=== BYOVD 启动状态 ===')
for line in lines:
    if 'OK: BYOVD' in line:
        out.append(line)

open(r'D:\技术研发\minifilter_status.txt', 'w', encoding='utf-8').write('\n'.join(out))
print(f'done, {len(out)} lines')
