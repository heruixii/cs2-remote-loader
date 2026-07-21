import os, glob, datetime, traceback
try:
    patterns = [
        r'C:\Users\29066\AppData\Local\Temp\sd.log',
        r'C:\Users\29066\AppData\Local\Temp\loader_diag.log',
        r'C:\Windows\Temp\sd.log',
        r'C:\Windows\Temp\loader_diag.log',
        r'D:\sd.log',
        r'D:\loader_diag.log',
        r'C:\Users\29066\Desktop\sd.log',
        r'C:\Users\29066\Desktop\loader_diag.log',
        r'C:\sd.log',
        r'C:\loader_diag.log',
    ]
    found = []
    for p in patterns:
        if os.path.exists(p):
            sz = os.path.getsize(p)
            mt = datetime.datetime.fromtimestamp(os.path.getmtime(p))
            found.append((p, sz, mt))

    for p in glob.glob(r'D:\技术研发\run\*.log'):
        sz = os.path.getsize(p)
        mt = datetime.datetime.fromtimestamp(os.path.getmtime(p))
        found.append((p, sz, mt))

    for p in glob.glob(r'C:\Users\29066\AppData\Local\Temp\sd*'):
        found.append((p, os.path.getsize(p), datetime.datetime.fromtimestamp(os.path.getmtime(p))))
    for p in glob.glob(r'C:\Users\29066\AppData\Local\Temp\loader*'):
        found.append((p, os.path.getsize(p), datetime.datetime.fromtimestamp(os.path.getmtime(p))))

    out = []
    if found:
        for p, sz, mt in found:
            out.append(f'{p}  size={sz}  mtime={mt}')
    else:
        out.append('NO log files found anywhere')
    open(r'D:\技术研发\find_logs.txt', 'w', encoding='utf-8').write('\n'.join(out))
    print('done')
except Exception as e:
    open(r'D:\技术研发\find_logs_err.txt', 'w').write(traceback.format_exc())
    print('ERROR:', e)

