import re
data = open(r'D:\技术研发\tmp\payload.dll', 'rb').read()
matches = re.findall(rb'v3\.\d+', data)
print('v3 strings in payload.dll:', set(m.decode() for m in matches))
matches2 = re.findall(rb'BUILD \d+', data)
print('BUILD strings:', set(m.decode() for m in matches2))
# 检查关键 StateLog 字符串
for key in [b'PreDisableOb', b'PostDisableOb', b'PostDisableThread', b'PreCleanTraces', b'PostCleanTraces', b'PreHideDriver', b'PostHideDriver', b'PreDelSCM', b'PostDelSCM', b'EnableAll_DONE']:
    if key in data:
        print(f'  StateLog key found: {key.decode()}')
    else:
        print(f'  *** MISSING: {key.decode()}')
