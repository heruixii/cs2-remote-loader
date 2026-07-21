import os
p = r'C:\Users\29066\AppData\Local\Temp\sd.log'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

starts = []
for i, line in enumerate(lines):
    if 'BUILD 567 v3.' in line:
        starts.append((i, line.strip()))

out = [f'Found {len(starts)} sessions:']
for idx, (ln, txt) in enumerate(starts):
    out.append(f'  session {idx}: line {ln} -- {txt}')

# 看第二个 session 的前 50 行和关键 PVP 事件
if len(starts) >= 2:
    s2_start = starts[1][0]
    out.append('')
    out.append(f'=== session 2 first 50 lines (from line {s2_start}) ===')
    for line in lines[s2_start:s2_start+50]:
        out.append(line)
    out.append('')
    out.append('=== session 2 PVP events ===')
    for line in lines[s2_start:]:
        if 'STATE:PVP' in line or 'InstallFail' in line or 'CR3Fail' in line or 'FE_Fail' in line:
            out.append(line)

open(r'D:\技术研发\sd_sessions.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')
