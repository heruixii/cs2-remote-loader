import struct
dll = r'D:\技术研发\tmp\payload.dll'
data = open(dll, 'rb').read()

# .idata: vaddr=0x8b000 vsize=0x1c8c rawptr=0x72e00 rawsize=0x1e00
idata_vaddr = 0x8b000
idata_rawptr = 0x72e00
idata_size = 0x1e00
idata_data = data[idata_rawptr:idata_rawptr+idata_size]

# 找目标函数名字符串
target_funcs = [b'AddVectoredExceptionHandler', b'DisableThreadLibraryCalls',
                b'Sleep', b'VirtualQuery', b'VirtualProtect', b'GetTickCount',
                b'GetCurrentProcess', b'TerminateProcess', b'ExitProcess',
                b'CreateFileW', b'WriteFile', b'CloseHandle', b'GetLastError',
                b'GetProcAddress', b'LoadLibraryA', b'VirtualAlloc']

print('=== Function name strings in .idata ===')
name_offsets = {}  # func_name -> file offset in .idata
for fn in target_funcs:
    # 函数名前有 2 字节 hint
    idx = idata_data.find(fn)
    while idx != -1:
        # 确认是完整字符串 (后面是 \0)
        end = idx + len(fn)
        if end < len(idata_data) and idata_data[end] == 0:
            # hint 在前 2 字节
            hint = struct.unpack_from('<H', idata_data, idx-2)[0]
            file_off = idata_rawptr + idx - 2
            rva = idata_vaddr + idx - 2
            name_offsets.setdefault(fn, []).append((file_off, rva, hint))
            print(f'  {fn.decode():35} hint={hint:3} file_off={file_off:#x} rva={rva:#x}')
        idx = idata_data.find(fn, idx+1)

# 现在找 IAT thunks (指向这些 name strings 的 QWORD)
# IAT thunks 在 .idata 中, 值 = name string 的 RVA
print()
print('=== IAT thunks (pointing to name strings) ===')
# 扫描整个 .idata 找 QWORD == name string RVA
all_thunks = {}  # func_name -> list of thunk RVA
for fn, offs in name_offsets.items():
    for file_off, name_rva, hint in offs:
        # 扫描 .idata 找 QWORD == name_rva
        for i in range(0, len(idata_data)-8, 8):
            val = struct.unpack_from('<Q', idata_data, i)[0]
            if val == name_rva:
                thunk_rva = idata_vaddr + i
                all_thunks.setdefault(fn, []).append(thunk_rva)
                print(f'  {fn.decode():35} thunk_rva={thunk_rva:#x}  (name_rva={name_rva:#x})')
                break  # 通常只有一个

# 也扫描 .text 和其他段 (IAT 可能在 .idata 之外)
print()
print('=== Search whole file for thunks ===')
for fn, offs in name_offsets.items():
    for file_off, name_rva, hint in offs:
        # 扫描整个文件
        for sec_name, sec_vaddr, sec_vsize, sec_rawptr, sec_rawsize in [
            ('.text', 0x1000, 0x5b9c0, 0x400, 0x5ba00),
            ('.data', 0x5d000, 0xb80, 0x5be00, 0xc00),
            ('.rdata', 0x5e000, 0x11118, 0x5ca00, 0x11200),
            ('.idata', 0x8b000, 0x1c8c, 0x72e00, 0x1e00),
        ]:
            sec_data = data[sec_rawptr:sec_rawptr+sec_rawsize]
            for i in range(0, len(sec_data)-8, 8):
                val = struct.unpack_from('<Q', sec_data, i)[0]
                if val == name_rva:
                    thunk_rva = sec_vaddr + i
                    if fn not in all_thunks:
                        all_thunks[fn] = []
                        all_thunks[fn].append(thunk_rva)
                        print(f'  {fn.decode():35} thunk_rva={thunk_rva:#x}  in {sec_name} (name_rva={name_rva:#x})')
                        break

print()
print('=== Summary: loader hardcoded vs actual ===')
hardcoded = {
    'AddVectoredExceptionHandler': 0x8a720,
    'DisableThreadLibraryCalls': 0x8a7b0,
    'Sleep': 0x8a9e8,
    'VirtualQuery': 0x8aa58,
}
for fn, hrva in hardcoded.items():
    actual = all_thunks.get(fn.encode(), [])
    match = '✓' if hrva in actual else '✗ MISMATCH'
    print(f'  {fn:35} hardcoded={hrva:#x} actual={actual}  {match}')
