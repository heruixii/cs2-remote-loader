import struct
dll = r'D:\技术研发\tmp\payload.dll'
data = open(dll, 'rb').read()

# PE 解析
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
nt = e_lfanew
sig = struct.unpack_from('<I', data, nt)[0]
assert sig == 0x4550, f'bad sig {sig:#x}'
# COFF header
nsec = struct.unpack_from('<H', data, nt+6)[0]
opt_size = struct.unpack_from('<H', data, nt+20)[0]
opt_off = nt + 24
magic = struct.unpack_from('<H', data, opt_off)[0]
print(f'PE magic={magic:#x} nsec={nsec} opt_size={opt_size}')
# Optional header
if magic == 0x20b:  # PE32+
    image_base = struct.unpack_from('<Q', data, opt_off+24)[0]
    ndir_off = opt_off + 112  # NumberOfRvaAndSizes
else:
    image_base = struct.unpack_from('<I', data, opt_off+28)[0]
    ndir_off = opt_off + 96
ndir = struct.unpack_from('<I', data, ndir_off)[0]
print(f'ImageBase={image_base:#x} NumberOfRvaAndSizes={ndir}')
# Data dirs
dir_off = ndir_off + 4
# IAT is dir index 12
iat_rva, iat_size = struct.unpack_from('<II', data, dir_off + 12*8)
print(f'IAT dir: rva={iat_rva:#x} size={iat_size:#x}')

# Section table
sec_off = opt_off + opt_size
sections = []
for i in range(nsec):
    s = sec_off + i*40
    name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s+8)
    sections.append((name, vaddr, vsize, rawptr, rawsize))
    print(f'  sec[{i}] {name:8} vaddr={vaddr:#x} vsize={vsize:#x} rawptr={rawptr:#x} rawsize={rawsize:#x}')

def rva_to_off(rva):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None

# Import dir is index 1
imp_rva, imp_size = struct.unpack_from('<II', data, dir_off + 1*8)
print(f'Import dir: rva={imp_rva:#x} size={imp_size:#x}')

# Walk import descriptors
imp_off = rva_to_off(imp_rva)
print(f'Import desc file offset: {imp_off:#x}')
target_funcs = [b'AddVectoredExceptionHandler', b'DisableThreadLibraryCalls',
                b'Sleep', b'VirtualQuery', b'VirtualProtect', b'GetTickCount']
found = {}
i = 0
while True:
    desc = imp_off + i*20
    ilt_rva, tdate, fchain, name_rva, fta_rva = struct.unpack_from('<IIIII', data, desc)
    if ilt_rva == 0 and name_rva == 0:
        break
    name_off = rva_to_off(name_rva)
    dll_name = data[name_off:].split(b'\x00')[0].decode('ascii', errors='replace')
    # ILT (Import Lookup Table)
    ilt_off = rva_to_off(ilt_rva)
    fta_off = rva_to_off(fta_rva) if fta_rva else None
    j = 0
    while True:
        ent = struct.unpack_from('<Q', data, ilt_off + j*8)[0]
        if ent == 0: break
        if ent & 0x8000000000000000:
            # ordinal
            j += 1
            continue
        hint_name_rva = ent & 0x7FFFFFFF
        hn_off = rva_to_off(hint_name_rva)
        hint = struct.unpack_from('<H', data, hn_off)[0]
        fname = data[hn_off+2:].split(b'\x00')[0].decode('ascii', errors='replace')
        # IAT entry RVA = fta_rva + j*8
        iat_entry_rva = fta_rva + j*8 if fta_rva else ilt_rva + j*8
        for tf in target_funcs:
            if fname == tf.decode():
                found[fname] = (dll_name, iat_entry_rva, hint)
        j += 1
    i += 1

print()
print('=== Target IAT entries ===')
for fn in [f.decode() for f in target_funcs]:
    if fn in found:
        d, rva, hint = found[fn]
        print(f'  {fn:35} dll={d:20} IAT_RVA={rva:#x}  hint={hint}')
    else:
        print(f'  {fn:35} NOT FOUND')
