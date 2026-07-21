import re
data = open(r'D:\技术研发\tmp\loader.exe', 'rb').read()
# 找 v3.xxx 字符串
matches = re.findall(rb'v3\.\d+', data)
print('v3 strings in loader.exe:', set(m.decode() for m in matches))
# 找 BUILD xxx
matches2 = re.findall(rb'BUILD \d+', data)
print('BUILD strings:', set(m.decode() for m in matches2))
# 找 LOADER v3
matches3 = re.findall(rb'LOADER v3\.\d+', data)
print('LOADER v3 strings:', set(m.decode() for m in matches3))
