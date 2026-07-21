import os
# 读取之前保存的 sd_dump.txt (v3.293 完整日志的第一部分)
p = r'D:\技术研发\sd_dump.txt'
if not os.path.exists(p):
    print('sd_dump.txt not found')
    exit()
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')

out = []
# 找 CS2 补丁相关日志
out.append('=== CS2 patch related ===')
for line in lines:
    if any(k in line for k in ['B549:', 'pat=', 'patch', 'ApplyCs2Patch', 'client.dll', '90 90', '32 c0', '0x90', 'patAddr', 'B558:MP']):
        out.append(line)

# 找 BYOVD driver 相关
out.append('')
out.append('=== BYOVD driver related ===')
for line in lines:
    if any(k in line for k in ['BYOVD:', 'PDFWKRNL', 'RTCore', 'driver', 'IOCTL', 'STATE:BYOVD']):
        out.append(line)

# 找 VAD/DKOM 相关
out.append('')
out.append('=== VAD/DKOM related ===')
for line in lines:
    if any(k in line for k in ['B554:', 'DKOM', 'VAD', 'E+G:', 'SHV']):
        out.append(line)

# 找回调相关
out.append('')
out.append('=== Callbacks related ===')
for line in lines:
    if any(k in line for k in ['ob=', 'proc=', 'img=', 'thread=', 'callback', '回调']):
        out.append(line)

open(r'D:\技术研发\detection_analysis.txt', 'w', encoding='utf-8').write('\n'.join(out))
print(f'done, {len(lines)} lines analyzed')
