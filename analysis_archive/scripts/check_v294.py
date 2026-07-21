import os
out = []
p = r'C:\Users\29066\AppData\Local\Temp\sd.log'
data = open(p, 'rb').read()
text = data.decode('utf-8', errors='replace')

if 'v3.294' in text:
    out.append('v3.294 found in sd.log')
    idx = text.find('v3.294')
    start = max(0, idx - 200)
    end = min(len(text), idx + 500)
    out.append(text[start:end])
else:
    out.append('v3.294 NOT found in sd.log -- user is still running v3.293')

p2 = r'C:\Users\29066\AppData\Local\Temp\loader_diag.log'
if os.path.exists(p2):
    data2 = open(p2, 'rb').read()
    text2 = data2.decode('utf-8', errors='replace')
    idx = text2.rfind('LOADER v3.')
    if idx >= 0:
        end = text2.find('\n', idx)
        out.append(f'Last loader version: {text2[idx:end]}')
    # 也找 v3.292
    if 'v3.292' in text2:
        out.append('v3.292 found in loader_diag.log')
    else:
        out.append('v3.292 NOT found in loader_diag.log -- user did not run v3.292 loader')

open(r'D:\技术研发\check_v294.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')

