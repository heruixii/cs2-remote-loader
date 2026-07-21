import ctypes
from ctypes import wintypes

# 用 EnumProcesses + GetModuleBaseName 找 loader.exe
PSAPI = ctypes.WinDLL('psapi.dll')
KERNEL32 = ctypes.WinDLL('kernel32.dll')

arr = (wintypes.DWORD * 1024)()
cb = ctypes.sizeof(arr)
lpcbNeeded = wintypes.DWORD()
PSAPI.EnumProcesses(ctypes.byref(arr), cb, ctypes.byref(lpcbNeeded))
count = lpcbNeeded.value // ctypes.sizeof(wintypes.DWORD)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

loader_pids = []
for i in range(count):
    pid = arr[i]
    if pid == 0: continue
    h = KERNEL32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h: continue
    name_buf = ctypes.create_unicode_buffer(260)
    PSAPI.GetModuleBaseNameW(h, None, name_buf, 260)
    if name_buf.value.lower() == 'loader.exe':
        loader_pids.append(pid)
    KERNEL32.CloseHandle(h)

if loader_pids:
    print(f'Found {len(loader_pids)} loader.exe process(es): PIDs = {loader_pids}')
    print('WARNING: Running a new loader will conflict with existing one!')
else:
    print('No loader.exe process found (safe to run new loader)')
