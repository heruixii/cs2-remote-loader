import os, datetime
p = r'C:\Users\29066\AppData\Local\Temp\sd.log'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

# 找最后一次启动
last_start = -1
for i, line in enumerate(lines):
    if 'BUILD 567 v3.' in line:
        last_start = i

# 看最后 30 行
out = [f'last session from line {last_start}, total {len(lines)} lines']
out.append('=== last 30 lines ===')
for line in lines[-30:]:
    out.append(line)

open(r'D:\技术研发\sd_tail.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('\n'.join(out))
