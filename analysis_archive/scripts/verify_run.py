import re
# 验证 loader.exe 版本
data = open(r'D:\技术研发\run\loader.exe', 'rb').read()
matches = re.findall(rb'LOADER v3\.\d+', data)
print('loader.exe:', set(m.decode() for m in matches))

# 验证 payload.dat 版本 (加密的, 但版本字符串在加密前的 payload.dll 中)
# payload.dat 是加密的, 无法直接读取版本字符串
# 但可以用大小判断: v3.294 payload.dat = 482308 bytes
import os
sz = os.path.getsize(r'D:\技术研发\run\payload.dat')
print(f'payload.dat size: {sz} bytes (v3.294 = 482308)')

# 解密 payload.dat 验证版本
# 加密工具用 XTEA, 但我们不知道密钥. 改用 payload.dll 验证
dll_data = open(r'D:\技术研发\tmp\payload.dll', 'rb').read()
matches2 = re.findall(rb'v3\.\d+', dll_data)
print('payload.dll (source of payload.dat):', set(m.decode() for m in matches2))
