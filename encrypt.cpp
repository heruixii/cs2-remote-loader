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

// ============================================================
// ★ BUILD 551: XTEA 密钥分段混淆 (与 loader.cpp 同策略)
//   原因: encrypt.cpp 源码在 GitHub 上暴露, 明文密钥可被 PAC 团队直接提取
//   策略: 密钥拆分 OBF/MASK, 运行时 volatile XOR 重组, noinline 阻止常量折叠
//   注意: encrypt.exe 是构建时工具, 不进入运行时 loader.exe 二进制,
//         此处混淆纯粹防止源码泄露导致的密钥暴露
// ============================================================
static constexpr uint32_t XTEA_KEY_OBF[4] = {
    0x211264DE, 0x3939E7A3, 0x5135A8AB, 0x778B1640
};
static constexpr uint32_t XTEA_KEY_MASK[4] = {
    0x5A3C7E91, 0xF0E1D2C3, 0x1B2A3B4C, 0x9F8E7D6C
};

__attribute__((noinline)) static void GetXteaKey(uint32_t outKey[4]) {
    volatile uint32_t obf0 = XTEA_KEY_OBF[0];
    volatile uint32_t obf1 = XTEA_KEY_OBF[1];
    volatile uint32_t obf2 = XTEA_KEY_OBF[2];
    volatile uint32_t obf3 = XTEA_KEY_OBF[3];
    volatile uint32_t mask0 = XTEA_KEY_MASK[0];
    volatile uint32_t mask1 = XTEA_KEY_MASK[1];
    volatile uint32_t mask2 = XTEA_KEY_MASK[2];
    volatile uint32_t mask3 = XTEA_KEY_MASK[3];

    outKey[0] = obf0 ^ mask0;
    outKey[1] = obf1 ^ mask1;
    outKey[2] = obf2 ^ mask2;
    outKey[3] = obf3 ^ mask3;
}

static void XteaEncryptBlock(uint32_t& v0, uint32_t& v1) {
    uint32_t key[4];
    GetXteaKey(key);
    uint32_t sum = 0;
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += XTEA_DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    key[0] = key[1] = key[2] = key[3] = 0;
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
