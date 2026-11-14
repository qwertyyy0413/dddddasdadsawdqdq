#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "blz.h"
#include "blz_config.h"

#define FOOTER_SIZE   33
#define NOISE_MIN     BLZ_NOISE_MIN
#define NOISE_MAX     BLZ_NOISE_MAX

static inline uint32_t rotl32(uint32_t x, int k) {
    return (x << k) | (x >> (32 - k));
}

typedef struct { uint32_t s[4]; } xoshi_t;

static uint32_t xoshi_next(xoshi_t *x) {
    uint32_t result = rotl32(x->s[0] + x->s[3], 7) + x->s[0];
    uint32_t t = x->s[1] << 9;
    x->s[2] ^= x->s[0];
    x->s[3] ^= x->s[1];
    x->s[1] ^= x->s[2];
    x->s[0] ^= x->s[3];
    x->s[2] ^= t;
    x->s[3] = rotl32(x->s[3], 11);
    return result;
}

static void xoshi_seed(xoshi_t *x, const uint8_t seed[16]) {
    memcpy(x->s, seed, 16);
    for (int i = 0; i < 4; i++)
        x->s[i] ^= BLZ_XOSHI_INIT_XOR;
    if (x->s[0] == 0 && x->s[1] == 0 && x->s[2] == 0 && x->s[3] == 0)
        x->s[0] = BLZ_SEED_FALLBACK;
}

static void xoshi_xor_stream(char *data, int len, const uint8_t seed[16]) {
    xoshi_t st;
    xoshi_seed(&st, seed);
    int i = 0;
    while (i < len) {
        uint32_t r = xoshi_next(&st);
        for (int j = 0; j < 4 && i < len; j++, i++)
            data[i] ^= (r >> (j * 8)) & 0xFF;
    }
}

static void block_transpose(char *data, int len, const uint8_t seed[16]) {
    int nblocks = len / 8;
    if (nblocks < 2) return;

    xoshi_t st;
    xoshi_seed(&st, seed);
    for (int i = 0; i < nblocks; i++) xoshi_next(&st);

    char tmp[8];
    for (int i = nblocks - 1; i > 0; i--) {
        uint32_t r = xoshi_next(&st);
        int j = r % (i + 1);
        if (i != j) {
            memcpy(tmp, data + i * 8, 8);
            memcpy(data + i * 8, data + j * 8, 8);
            memcpy(data + j * 8, tmp, 8);
        }
    }
}

static void delta_encode(char *data, int len) {
    uint32_t prev = 0;
    for (int i = 0; i + 3 < len; i += 4) {
        uint32_t val;
        memcpy(&val, data + i, 4);
        uint32_t delta = val - prev;
        prev = val;
        memcpy(data + i, &delta, 4);
    }
}

static void byte_remap(char *data, int len) {
    for (int i = 0; i < len; i++)
        data[i] = (char)BLZ_SBOX[(uint8_t)data[i]];
}

static uint64_t compute_hmac(const uint8_t seed[16],
                             uint32_t comp_sz, uint32_t decomp_sz) {
    uint64_t h = 0;
    for (int i = 0; i < 16; i++)
        h = (h * BLZ_HMAC_BASE) + seed[i];
    h ^= (uint64_t)comp_sz;
    h = (h << BLZ_HMAC_ROT) | (h >> (64 - BLZ_HMAC_ROT));
    h ^= (uint64_t)decomp_sz;
    h *= BLZ_HMAC_MUL;
    h ^= h >> 32;
    h ^= BLZ_VERIFY_MAGIC;
    return h;
}

static void derive_footer_key(const uint8_t seed[16], uint8_t key[8]) {
    for (int i = 0; i < 8; i++)
        key[i] = seed[i] ^ seed[i + 8] ^ (uint8_t)(i * BLZ_KD_MUL + BLZ_KD_ADD);
}

static void encrypt_footer_data(uint8_t *data, int len,
                                const uint8_t seed[16]) {
    uint8_t key[8];
    derive_footer_key(seed, key);
    for (int i = 0; i < len; i++)
        data[i] ^= key[i % 8];
}

static int fill_random(uint8_t *buf, int len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    int ok = (int)fread(buf, 1, (size_t)len, f);
    fclose(f);
    return ok == len ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    FILE *fin = fopen(argv[1], "rb");
    if (!fin) { perror("fopen input"); return 2; }

    fseek(fin, 0, SEEK_END);
    long src_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (src_size <= 0) {
        fprintf(stderr, "Empty input\n");
        fclose(fin);
        return 3;
    }

    char *src_buf = malloc((size_t)src_size);
    if (!src_buf || fread(src_buf, 1, (size_t)src_size, fin) != (size_t)src_size) {
        perror("read");
        free(src_buf);
        fclose(fin);
        return 4;
    }
    fclose(fin);

    delta_encode(src_buf, (int)src_size);
    byte_remap(src_buf, (int)src_size);

    int max_dst = blz_pack_bound((int)src_size);
    char *dst_buf = malloc((size_t)max_dst);
    if (!dst_buf) {
        perror("malloc dst");
        free(src_buf);
        return 5;
    }

    int comp_size = blz_pack(src_buf, dst_buf, (int)src_size, max_dst);
    free(src_buf);
    if (comp_size <= 0) {
        fprintf(stderr, "Compression failed\n");
        free(dst_buf);
        return 6;
    }

    printf("[Compressor] %ld -> %d bytes (%.2f%%)\n",
           src_size, comp_size, (float)comp_size / src_size * 100.0f);

    uint8_t seed[16];
    if (fill_random(seed, 16) != 0) {
        fprintf(stderr, "Failed to get random seed\n");
        free(dst_buf);
        return 7;
    }

    xoshi_xor_stream(dst_buf, comp_size, seed);
    block_transpose(dst_buf, comp_size, seed);

    printf("[Compressor] Obfuscation applied (seed=");
    for (int i = 0; i < 16; i++) printf("%02X", seed[i]);
    printf(")\n");

    uint8_t noise_len_byte;
    fill_random(&noise_len_byte, 1);
    int noise_len = NOISE_MIN + (noise_len_byte % (NOISE_MAX - NOISE_MIN + 1));

    uint8_t *noise = malloc((size_t)noise_len);
    if (!noise) { free(dst_buf); return 8; }
    fill_random(noise, noise_len);

    uint8_t footer[FOOTER_SIZE];
    memcpy(footer, seed, 16);

    uint8_t enc_data[8];
    uint32_t c32 = (uint32_t)comp_size;
    uint32_t d32 = (uint32_t)src_size;
    memcpy(enc_data, &c32, 4);
    memcpy(enc_data + 4, &d32, 4);
    encrypt_footer_data(enc_data, 8, seed);
    memcpy(footer + 16, enc_data, 8);

    uint64_t hmac = compute_hmac(seed, (uint32_t)comp_size, (uint32_t)src_size);
    memcpy(footer + 24, &hmac, 8);

    footer[32] = (uint8_t)noise_len;

    FILE *fout = fopen(argv[2], "wb");
    if (!fout) {
        perror("fopen output");
        free(dst_buf);
        free(noise);
        return 9;
    }

    fwrite(dst_buf, 1, (size_t)comp_size, fout);
    fwrite(noise, 1, (size_t)noise_len, fout);
    fwrite(footer, 1, FOOTER_SIZE, fout);

    fclose(fout);
    free(dst_buf);
    free(noise);

    printf("[Compressor] Packed payload (%d + %d + %d = %d bytes)\n",
           comp_size, noise_len, FOOTER_SIZE,
           comp_size + noise_len + FOOTER_SIZE);
    return 0;
}
