#!/usr/bin/env python3
"""embed_basic_loader.py — 将基础.exe 转换为 C++ 嵌入字节数组供 loader.cpp 使用"""
import sys, os

def embed_exe(exe_path):
    if not os.path.exists(exe_path):
        print(f"[ERROR] 文件不存在: {exe_path}")
        return False
    with open(exe_path, 'rb') as f:
        data = f.read()
    size = len(data)
    print(f"[INFO] 读取: {size} bytes ({size/1024:.1f} KB)")

    lines = [
        "// Auto-generated — embedded basic ESP for loader.cpp",
        f"// Source: {os.path.basename(exe_path)} ({size} bytes)",
        "#pragma once",
        "#include <cstdint>",
        "",
        f"static const uint8_t EMBEDDED_BASIC_EXE[] = {{",
    ]
    for i in range(0, size, 16):
        chunk = data[i:i+16]
        hex_str = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_str}," if i + 16 < size else f"    {hex_str}")
    lines.append(f"}};")
    lines.append(f"static constexpr size_t EMBEDDED_BASIC_EXE_SIZE = {size};")

    output_path = os.path.join(os.path.dirname(os.path.abspath(exe_path)), "embedded_basic_loader.h")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"[OK] 生成: {output_path}")
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python embed_basic_loader.py <基础.exe路径>")
        sys.exit(1)
    embed_exe(sys.argv[1])
