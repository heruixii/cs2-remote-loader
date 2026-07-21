import os, datetime
out = []
# 检查常见位置
for d in [r'C:\Users\29066\Desktop', r'D:\', r'D:\技术研发\run', r'C:\Users\29066\Downloads']:
    if not os.path.isdir(d): continue
    try:
        for f in os.listdir(d):
            if f.lower() in ('loader.exe', 'payload.dat', 'loader2.exe'):
                p = os.path.join(d, f)
                sz = os.path.getsize(p)
                mt = datetime.datetime.fromtimestamp(os.path.getmtime(p))
                out.append(f'{p}  size={sz}  mtime={mt}')
    except Exception as e:
        out.append(f'ERROR reading {d}: {e}')

if not out:
    out.append('No loader.exe/payload.dat found in common locations')

open(r'D:\技术研发\find_loader_files.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')
