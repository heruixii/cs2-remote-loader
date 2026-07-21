import os, glob
# 查找所有 loader.exe
candidates = []
for root in [r'C:\Users\29066\Desktop', r'C:\Users\29066\Downloads',
             r'D:\技术研发\run', r'D:\技术研发\tmp', r'D:\技术研发']:
    for f in glob.glob(os.path.join(root, 'loader.exe')):
        try:
            st = os.stat(f)
            candidates.append((f, st.st_size, st.st_mtime))
        except: pass

import datetime
for f, sz, mt in candidates:
    t = datetime.datetime.fromtimestamp(mt)
    print(f'{f}  size={sz}  mtime={t}')
