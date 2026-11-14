#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static void read_random(uint8_t *buf, int n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        exit(1);
    }
    if (read(fd, buf, (size_t)n) != n) {
        perror("read /dev/urandom");
        exit(1);
    }
    close(fd);
}

static uint32_t xs_s[4];

static uint32_t rotl32(uint32_t x, int k) {
    return (x << k) | (x >> (32 - k));
}

static uint32_t xs_next(void) {
    uint32_t r = rotl32(xs_s[0] + xs_s[3], 7) + xs_s[0];
    uint32_t t = xs_s[1] << 9;
    xs_s[2] ^= xs_s[0];
    xs_s[3] ^= xs_s[1];
    xs_s[1] ^= xs_s[2];
    xs_s[0] ^= xs_s[3];
    xs_s[2] ^= t;
    xs_s[3] = rotl32(xs_s[3], 11);
    return r;
}

static void xs_seed(const uint8_t seed[16]) {
    memcpy(xs_s, seed, 16);
    if (!xs_s[0] && !xs_s[1] && !xs_s[2] && !xs_s[3])
        xs_s[0] = 1;
    for (int i = 0; i < 16; i++) xs_next();
}

static uint32_t rand_range(uint32_t lo, uint32_t hi) {
    /* hi inclusive */
    uint32_t range = hi - lo + 1;
    return lo + (xs_next() % range);
}

static uint32_t rand_odd32(void) {
    uint32_t v;
    do { v = xs_next(); } while (v < 0x80000000U);
    return v | 1;
}

static uint64_t rand_odd64(void) {
    uint64_t hi = (uint64_t)xs_next() << 32 | xs_next();
    uint64_t lo_mask = 0x8000000000000000ULL;
    if (hi < lo_mask) hi |= lo_mask;
    return hi | 1;
}

static void gen_sbox(uint8_t sbox[256], uint8_t inv[256]) {
    for (int i = 0; i < 256; i++) sbox[i] = (uint8_t)i;
    for (int i = 255; i > 0; i--) {
        int j = (int)(xs_next() % (uint32_t)(i + 1));
        uint8_t tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    for (int i = 0; i < 256; i++) inv[sbox[i]] = (uint8_t)i;
}

static void write_array(FILE *f, const char *name, const uint8_t arr[256]) {
    fprintf(f, "static const unsigned char %s[256] = {\n", name);
    for (int i = 0; i < 256; i += 16) {
        fprintf(f, "    ");
        for (int j = 0; j < 16; j++) {
            int idx = i + j;
            if (idx < 255)
                fprintf(f, "0x%02X, ", arr[idx]);
            else
                fprintf(f, "0x%02X", arr[idx]);
        }
        fprintf(f, "\n");
    }
    fprintf(f, "};\n\n");
}

int main(int argc, char **argv) {
    const char *out_path = (argc > 1) ? argv[1] : "blz_config.h";

    uint8_t seed[16];
    read_random(seed, 16);
    xs_seed(seed);

    int    ml_bits   = 5;
    int    minmatch  = (int)rand_range(3, 4);
    int    overflow  = (int)rand_range(200, 254);
    uint32_t hp32    = rand_odd32();
    uint64_t hp64    = rand_odd64();
    uint32_t off_xor = rand_range(0x0100, 0xFFFE);
    uint32_t verify  = rand_range(0x10000000U, 0xFFFFFFFFU);
    uint32_t str_key = rand_range(0x10, 0xFE);
    uint32_t xoshi_xor = rand_range(0x10000000U, 0xFFFFFFFFU);

    uint64_t hmac_mul   = rand_odd64();
    uint32_t hmac_base  = rand_range(127, 251);
    uint32_t hmac_rot   = rand_range(7, 25);
    uint32_t kd_mul     = rand_range(0x10, 0xFE);
    uint32_t kd_add     = rand_range(0x10, 0xFE);
    uint32_t seed_fb    = rand_range(0x10000000U, 0xFFFFFFFFU);
    uint32_t noise_min  = rand_range(16, 48);
    uint32_t noise_max  = rand_range(noise_min + 32, 200);

    uint8_t sbox[256], inv[256];
    gen_sbox(sbox, inv);

    FILE *f = fopen(out_path, "w");
    if (!f) { perror("fopen output"); return 1; }

    fprintf(f, "#ifndef BLZ_CONFIG_H\n#define BLZ_CONFIG_H\n\n");
    fprintf(f, "#define BLZ_ML_BITS          %d\n",   ml_bits);
    fprintf(f, "#define BLZ_MINMATCH         %d\n",   minmatch);
    fprintf(f, "#define BLZ_OVERFLOW_BYTE    0x%02X\n", overflow);
    fprintf(f, "#define BLZ_HASH_PRIME32     0x%08XU\n", hp32);
    fprintf(f, "#define BLZ_HASH_PRIME64     0x%016llXULL\n", (unsigned long long)hp64);
    fprintf(f, "#define BLZ_OFFSET_XOR       0x%04X\n", off_xor);
    fprintf(f, "#define BLZ_VERIFY_MAGIC     0x%08XU\n", verify);
    fprintf(f, "#define BLZ_STR_KEY          0x%02X\n", str_key);
    fprintf(f, "#define BLZ_XOSHI_INIT_XOR   0x%08XU\n", xoshi_xor);
    fprintf(f, "#define BLZ_HMAC_MUL         0x%016llXULL\n", (unsigned long long)hmac_mul);
    fprintf(f, "#define BLZ_HMAC_BASE        %uU\n", hmac_base);
    fprintf(f, "#define BLZ_HMAC_ROT         %u\n", hmac_rot);
    fprintf(f, "#define BLZ_KD_MUL           0x%02X\n", kd_mul);
    fprintf(f, "#define BLZ_KD_ADD           0x%02X\n", kd_add);
    fprintf(f, "#define BLZ_SEED_FALLBACK    0x%08XU\n", seed_fb);
    fprintf(f, "#define BLZ_NOISE_MIN        %u\n", noise_min);
    fprintf(f, "#define BLZ_NOISE_MAX        %u\n\n", noise_max);

    write_array(f, "BLZ_SBOX",     sbox);
    write_array(f, "BLZ_INV_SBOX", inv);

    fprintf(f, "#endif\n");
    fclose(f);

    fprintf(stderr, "[gen_config] %s: ML=%d MM=%d OV=0x%02X H32=0x%08X OXOR=0x%04X\n",
            out_path, ml_bits, minmatch, overflow, hp32, off_xor);
    return 0;
}
