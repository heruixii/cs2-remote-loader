import struct, re

with open(r'd:\技术研发\tmp\stealth_lib\rtcore64_embed.h', 'r') as f:
    content = f.read()
hex_bytes = re.findall(r'0x([0-9A-Fa-f]{2})', content)
data = bytes(int(b, 16) for b in hex_bytes)

pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
section_start = pe_offset + 24 + opt_header_size

sections = {}
for i in range(num_sections):
    off = section_start + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    sections[name] = {
        'vaddr': struct.unpack_from('<I', data, off + 12)[0],
        'vsize': struct.unpack_from('<I', data, off + 8)[0],
        'raw_off': struct.unpack_from('<I', data, off + 20)[0],
        'raw_size': struct.unpack_from('<I', data, off + 16)[0],
    }
    print(f'[{name}] VA=0x{sections[name]["vaddr"]:04X} RawOff=0x{sections[name]["raw_off"]:X} RawSize=0x{sections[name]["raw_size"]:X}')

# INIT section (DriverEntry)
init = sections['INIT']
init_data = data[init['raw_off']:init['raw_off']+init['raw_size']]
print(f'\n=== INIT section (DriverEntry) ===')
for j in range(0, min(512, len(init_data)), 16):
    hex_str = ' '.join(f'{b:02X}' for b in init_data[j:j+16])
    print(f'  +0x{j:04X}: {hex_str}')

# .rdata section
rdata = sections['.rdata']
rdata_data = data[rdata['raw_off']:rdata['raw_off']+rdata['raw_size']]
print(f'\n=== .rdata section ===')
for j in range(0, min(256, len(rdata_data)), 16):
    hex_str = ' '.join(f'{b:02X}' for b in rdata_data[j:j+16])
    print(f'  +0x{j:04X}: {hex_str}')

# .data section
data_sec = sections['.data']
data_data = data[data_sec['raw_off']:data_sec['raw_off']+data_sec['raw_size']]
print(f'\n=== .data section ===')
for j in range(0, min(256, len(data_data)), 16):
    hex_str = ' '.join(f'{b:02X}' for b in data_data[j:j+16])
    print(f'  +0x{j:04X}: {hex_str}')

# .text section
text = sections['.text']
text_data = data[text['raw_off']:text['raw_off']+text['raw_size']]
print(f'\n=== .text section (full) ===')
for j in range(0, len(text_data), 16):
    hex_str = ' '.join(f'{b:02X}' for b in text_data[j:j+16])
    print(f'  +0x{j:04X} (VA 0x{text["vaddr"]+j:04X}): {hex_str}')