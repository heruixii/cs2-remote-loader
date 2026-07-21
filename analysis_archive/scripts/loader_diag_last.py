import os
p = r'C:\Users\29066\AppData\Local\Temp\loader_diag.log'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')
lines = text.split('\n')
out = [f'total {len(lines)} lines', '=== last 20 lines ===']
for line in lines[-20:]:
    out.append(line)
open(r'D:\技术研发\loader_diag_last.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')
