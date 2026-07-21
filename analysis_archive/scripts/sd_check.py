import os, datetime
p = r'C:\Users\29066\AppData\Local\Temp\sd.log'
if not os.path.exists(p):
    print('sd.log NOT FOUND')
    exit()
mtime = datetime.datetime.fromtimestamp(os.path.getmtime(p))
size = os.path.getsize(p)
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

out = [f'### sd.log mtime={mtime} size={size}']
out.append(f'### total lines: {len(lines)}')
out.append('')

# 找最后一次启动 (BUILD 567 v3.)
last_start = -1
for i, line in enumerate(lines):
    if 'BUILD 567 v3.' in line:
        last_start = i

out.append(f'=== last session (from line {last_start}) ===')
for line in lines[last_start:]:
    out.append(line)

open(r'D:\技术研发\sd_dump.txt', 'w', encoding='utf-8').write('\n'.join(out))
print(f'done, last_start={last_start}, total={len(lines)}')
