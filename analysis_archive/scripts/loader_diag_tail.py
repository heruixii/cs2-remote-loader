import os
p = r'C:\Users\29066\AppData\Local\Temp\loader_diag.log'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

# 找最后一次 v3.292 启动
last_start = -1
for i, line in enumerate(lines):
    if 'LOADER v3.292' in line:
        last_start = i

out = [f'last v3.292 session from line {last_start}']
if last_start >= 0:
    for line in lines[last_start:last_start+30]:
        out.append(line)

open(r'D:\技术研发\loader_diag_tail.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')
