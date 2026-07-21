import re
dll_data = open(r'D:\技术研发\tmp\payload.dll', 'rb').read()
# 查找所有 90 90 出现位置
positions = []
for i in range(len(dll_data) - 1):
    if dll_data[i] == 0x90 and dll_data[i+1] == 0x90:
        positions.append(i)
print(f'Total 90 90 occurrences: {len(positions)}')
# 显示前 10 个位置的上下文
for p in positions[:10]:
    ctx = dll_data[max(0,p-4):p+6].hex()
    print(f'  offset 0x{p:06X}: ...{ctx}...')
# 查找 66 90 出现位置
positions66 = []
for i in range(len(dll_data) - 1):
    if dll_data[i] == 0x66 and dll_data[i+1] == 0x90:
        positions66.append(i)
print(f'\nTotal 66 90 occurrences: {len(positions66)}')
for p in positions66[:5]:
    ctx = dll_data[max(0,p-4):p+6].hex()
    print(f'  offset 0x{p:06X}: ...{ctx}...')
