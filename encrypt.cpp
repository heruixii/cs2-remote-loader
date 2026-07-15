// ============================================================
// encrypt.cpp — XTEA CBC 加密 payload.dll → payload.dat
// 格式: [4字节 originalSize] [XTEA CBC 加密的 DLL 数据]
// ============================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <stdexcept>

static constexpr uint32_t XTEA_DELTA = 0x9E3779B9;
static constexpr uint32_t XTEA_KEY[4] = {
    0x7B2E1A4F, 0xC9D83560, 0x4A1F93E7, 0xE8056B2C
};

static void XteaEncryptBlock(uint32_t& v0, uint32_t& v1) {
    uint32_t sum = 0;
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + XTEA_KEY[sum & 3]);
        sum += XTEA_DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + XTEA_KEY[(sum >> 11) & 3]);
    }
}

static void XteaEncryptCBC(uint8_t* data, size_t size) {
    uint32_t iv0 = 0xDEADBEEF;
    uint32_t iv1 = 0xCAFEBABE;

    auto* blocks = reinterpret_cast<uint32_t*>(data);
    size_t numBlocks = size / 4;

    for (size_t i = 0; i < numBlocks; i += 2) {
        blocks[i]   ^= iv0;
        blocks[i+1] ^= iv1;

        XteaEncryptBlock(blocks[i], blocks[i+1]);

        iv0 = blocks[i];
        iv1 = blocks[i+1];
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: encrypt.exe <input.dll> <output.dat>\n");
        return 1;
    }

    // 读取输入
    FILE* fin = fopen(argv[1], "rb");
    if (!fin) { fprintf(stderr, "Cannot open %s\n", argv[1]); return 1; }
    fseek(fin, 0, SEEK_END);
    size_t size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, fin);
    fclose(fin);

    // 补齐到 8 字节对齐
    size_t padded = (size + 7) & ~7;
    data.resize(padded, 0);

    // XTEA CBC 加密
    XteaEncryptCBC(data.data(), padded);

    // 写入: [originalSize(4)] [encrypted]
    FILE* fout = fopen(argv[2], "wb");
    if (!fout) { fprintf(stderr, "Cannot create %s\n", argv[2]); return 1; }
    uint32_t origSize = (uint32_t)size;
    fwrite(&origSize, 1, 4, fout);
    fwrite(data.data(), 1, padded, fout);
    fclose(fout);

    printf("Encrypted: %zu -> %zu bytes\n", size, 4 + padded);
    return 0;
}
