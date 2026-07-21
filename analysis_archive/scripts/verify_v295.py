import re, os, hashlib, datetime
out = []
# 验证 payload.dll 版本
dll_data = open(r'D:\技术研发\tmp\payload.dll', 'rb').read()
matches = re.findall(rb'v3\.\d+', dll_data)
out.append(f'payload.dll version: {set(m.decode() for m in matches)}')
out.append(f'payload.dll size: {len(dll_data)} bytes')
out.append(f'payload.dll MD5: {hashlib.md5(dll_data).hexdigest()}')

# 验证 payload.dat
dat_data = open(r'D:\技术研发\tmp\payload.dat', 'rb').read()
out.append(f'payload.dat size: {len(dat_data)} bytes')
out.append(f'payload.dat MD5: {hashlib.md5(dat_data).hexdigest()}')

# 验证 loader.exe
loader_data = open(r'D:\技术研发\tmp\loader.exe', 'rb').read()
loader_matches = re.findall(rb'LOADER v3\.\d+', loader_data)
out.append(f'loader.exe version: {set(m.decode() for m in loader_matches)}')
out.append(f'loader.exe size: {len(loader_data)} bytes')
out.append(f'loader.exe MD5: {hashlib.md5(loader_data).hexdigest()}')

# 检查 66 90 patch 字节是否在 payload.dll 中 (XOR 加密后)
# PAT_ENC 加密: 0x32^0x5A=0x68, 0xc0^0x5A=0x9A
# patchBytes 0x66 0x90 是明文, 应该出现在 payload.dll 中
out.append(f'')
out.append(f'Patch bytes check:')
out.append(f'  0x66 0x90 in payload.dll: {bytes([0x66, 0x90]) in dll_data}')
out.append(f'  0x90 0x90 in payload.dll: {bytes([0x90, 0x90]) in dll_data} (should be rare)')

# 复制到 run 目录
import shutil
run_dir = r'D:\技术研发\run'
os.makedirs(run_dir, exist_ok=True)
shutil.copy2(r'D:\技术研发\tmp\payload.dat', os.path.join(run_dir, 'payload.dat'))
shutil.copy2(r'D:\技术研发\tmp\loader.exe', os.path.join(run_dir, 'loader.exe'))
out.append(f'')
out.append(f'Copied to run directory:')
out.append(f'  {run_dir}\\payload.dat ({os.path.getsize(os.path.join(run_dir, "payload.dat"))} bytes)')
out.append(f'  {run_dir}\\loader.exe ({os.path.getsize(os.path.join(run_dir, "loader.exe"))} bytes)')

open(r'D:\技术研发\verify_v295.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('done')
