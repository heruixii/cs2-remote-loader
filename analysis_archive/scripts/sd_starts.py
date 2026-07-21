import os
p = r'C:\Users\29066\AppData\Local\Temp\sd.log'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

# 找所有 BUILD 567 v3. 启动摘要 (新 loader 启动会写这个)
starts = []
for i, line in enumerate(lines):
    if 'BUILD 567 v3.' in line and '启动摘要' in line:
        starts.append((i, line.strip()))

# 找所有 HostPID
pids = []
for i, line in enumerate(lines):
    if 'HostPID:' in line:
        pids.append((i, line.strip()))

out = [f'Found {len(starts)} 启动摘要:']
for s in starts:
    out.append(f'  {s}')
out.append('')
out.append(f'Found {len(pids)} HostPID lines:')
for p in pids:
    out.append(f'  {p}')

open(r'D:\技术研发\sd_starts.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')
