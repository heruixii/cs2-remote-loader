import subprocess, os
dll = r'D:\技术研发\tmp\payload.dll'
out = r'D:\技术研发\tmp\payload_objdump.txt'
# objdump 不支持中文路径, 先 copy 到 ASCII 路径
import shutil
tmp = r'D:\技术研发\tmp\payload_tmp.dll'
shutil.copy(dll, tmp)
r = subprocess.run([r'C:\msys64\ucrt64\bin\objdump.exe', '-p', tmp],
                   capture_output=True, text=True, timeout=30)
open(out, 'w', encoding='utf-8', errors='replace').write(r.stdout + r.stderr)
os.remove(tmp)
print('exit', r.returncode, 'size', len(r.stdout))
