import struct
dll = r'D:\技术研发\tmp\payload.dll'
data = open(dll, 'rb').read()

# PE 解析
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
nt = e_lfanew
nsec = struct.unpack_from('<H', data, nt+6)[0]
opt_size = struct.unpack_from('<H', data, nt+20)[0]
opt_off = nt + 24
magic = struct.unpack_from('<H', data, opt_off)[0]

# Section table
sec_off = opt_off + opt_size
sections = []
for i in range(nsec):
    s = sec_off + i*40
    name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s+8)
    sections.append((name, vaddr, vsize, rawptr, rawsize))

def rva_to_off(rva):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None

# 找 .idata section
idata = None
for name, vaddr, vsize, rawptr, rawsize in sections:
    if name == '.idata':
        idata = (vaddr, vsize, rawptr, rawsize)
        break

if not idata:
    print('NO .idata section!')
    exit()

idata_vaddr, idata_size, idata_rawptr, idata_rawsize = idata
idata_data = data[idata_rawptr:idata_rawptr+idata_rawsize]

target_funcs = [b'AddVectoredExceptionHandler', b'DisableThreadLibraryCalls',
                b'Sleep', b'VirtualQuery']

print('=== Function name strings in .idata ===')
name_offsets = {}
for fn in target_funcs:
    idx = idata_data.find(fn)
    while idx != -1:
        end = idx + len(fn)
        if end < len(idata_data) and idata_data[end] == 0:
            hint = struct.unpack_from('<H', idata_data, idx-2)[0]
            name_rva = idata_vaddr + idx - 2
            name_offsets.setdefault(fn, []).append(name_rva)
        idx = idata_data.find(fn, idx+1)

print('=== IAT thunks ===')
all_thunks = {}
for fn, offs in name_offsets.items():
    for name_rva in offs:
        for i in range(0, len(idata_data)-8, 8):
            val = struct.unpack_from('<Q', idata_data, i)[0]
            if val == name_rva:
                thunk_rva = idata_vaddr + i
                all_thunks.setdefault(fn, []).append(thunk_rva)
                break

print('=== loader hardcoded vs actual ===')
hardcoded = {
    'AddVectoredExceptionHandler': 0x8b0f8,
    'DisableThreadLibraryCalls': 0x8b188,
    'Sleep': 0x8b3b8,
    'VirtualQuery': 0x8b428,
}
for fn, hrva in hardcoded.items():
    actual = all_thunks.get(fn.encode(), [])
    match = 'OK' if hrva in actual else 'MISMATCH'
    print(f'  {fn:35} hardcoded={hrva:#x} actual={[hex(a) for a in actual]}  {match}')
