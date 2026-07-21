import re
data = open(r'D:\技术研发\tmp\payload.dll', 'rb').read()
# CR3 全链路诊断关键字
cr3_keys = [
    b'EO_Cached', b'EO_PreResolve', b'EO_PreReadSys', b'EO_ScanStart', b'EO_OK', b'EO_Fail',
    b'FE_Fail', b'FE_Start', b'FE_OK',
    b'CR3PreReadOff', b'CR3PostReadOff', b'CR3PreVaToPa', b'CR3PostVaToPa',
    b'CR3ScanProg', b'CR3ScanHit', b'CR3OK', b'CR3Fail', b'CR3Step',
    b'InstallStart', b'InstallStep', b'InstallFail', b'InstallDone',
    b'PatchOK', b'PatchFail',
    b'FindBaseFail',
]
found = []
missing = []
for k in cr3_keys:
    if k in data:
        found.append(k.decode())
    else:
        missing.append(k.decode())
print(f'Found ({len(found)}): {found}')
print(f'Missing ({len(missing)}): {missing}')
