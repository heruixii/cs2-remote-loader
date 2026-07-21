import ctypes
import ctypes.wintypes as wt

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('cntUsage', wt.DWORD),
        ('th32ProcessID', wt.DWORD), ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
        ('th32ModuleID', wt.DWORD), ('cntThreads', wt.DWORD),
        ('th32ParentProcessID', wt.DWORD), ('pcPriClassBase', wt.LONG),
        ('dwFlags', wt.DWORD), ('szExeFile', wt.WCHAR * 260)]

snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
e = PROCESSENTRY32W(); e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
found = []
if kernel32.Process32FirstW(snap, ctypes.byref(e)):
    while True:
        if 'loader' in e.szExeFile.lower() or 'cs2' in e.szExeFile.lower() or '完美' in e.szExeFile:
            found.append((e.th32ProcessID, e.szExeFile, e.th32ParentProcessID))
        if not kernel32.Process32NextW(snap, ctypes.byref(e)):
            break
kernel32.CloseHandle(snap)

out = []
out.append('=== 相关进程 ===')
for pid, name, ppid in found:
    # 获取完整路径
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    path = 'N/A'
    if h:
        buf = ctypes.create_unicode_buffer(260)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(wt.DWORD(260))):
            path = buf.value
        kernel32.CloseHandle(h)
    out.append(f'  pid={pid} ppid={ppid} name={name} path={path}')

open(r'D:\技术研发\procs.txt', 'w', encoding='utf-8').write('\n'.join(out))
print(f'found {len(found)} processes')
