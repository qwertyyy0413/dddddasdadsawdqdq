#include "headers/ascon.h"
#include <string.h>
#include <stdint.h>

static uint64_t load64(const uint8_t* bytes) {
    return ((uint64_t)bytes[0] << 56) |
           ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) |
           ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) |
           ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8)  |
           ((uint64_t)bytes[7]);
}

static void store64(uint8_t* bytes, uint64_t x) {
    bytes[0] = (x >> 56) & 0xFF;
    bytes[1] = (x >> 48) & 0xFF;
    bytes[2] = (x >> 40) & 0xFF;
    bytes[3] = (x >> 32) & 0xFF;
    bytes[4] = (x >> 24) & 0xFF;
    bytes[5] = (x >> 16) & 0xFF;
    bytes[6] = (x >> 8) & 0xFF;
    bytes[7] = x & 0xFF;
}

typedef struct {
    uint64_t x0, x1, x2, x3, x4;
} ascon_state_t;

static uint64_t ROTR64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static void ascon_round(ascon_state_t* s, uint8_t c) {
    s->x2 ^= c;
    s->x0 ^= s->x4; s->x4 ^= s->x3; s->x2 ^= s->x1;
    uint64_t t0 = s->x0 & (~s->x1);
    uint64_t t1 = s->x1 & (~s->x2);
    uint64_t t2 = s->x2 & (~s->x3);
    uint64_t t3 = s->x3 & (~s->x4);
    uint64_t t4 = s->x4 & (~s->x0);
    s->x0 ^= t1; s->x1 ^= t2; s->x2 ^= t3; s->x3 ^= t4; s->x4 ^= t0;
    s->x1 ^= s->x0; s->x0 ^= s->x4; s->x3 ^= s->x2; s->x2 = ~s->x2;
    s->x0 ^= ROTR64(s->x0, 19) ^ ROTR64(s->x0, 28);
    s->x1 ^= ROTR64(s->x1, 61) ^ ROTR64(s->x1, 39);
    s->x2 ^= ROTR64(s->x2,  1) ^ ROTR64(s->x2,  6);
    s->x3 ^= ROTR64(s->x3, 10) ^ ROTR64(s->x3, 17);
    s->x4 ^= ROTR64(s->x4,  7) ^ ROTR64(s->x4, 41);
}

static void ascon_permutation(ascon_state_t* s, int rounds) {
    static const uint8_t constants[12] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
    };
    int start = 12 - rounds;
    for (int i = start; i < 12; i++) {
        ascon_round(s, constants[i]);
    }
}

static void ascon_init(ascon_state_t* s, const uint8_t* key, const uint8_t* nonce) {
    s->x0 = 0x80400c0600000000ULL;
    s->x1 = load64(key);
    s->x2 = load64(key + 8);
    s->x3 = load64(nonce);
    s->x4 = load64(nonce + 8);
    ascon_permutation(s, 12);
    s->x3 ^= load64(key);
    s->x4 ^= load64(key + 8);
}

static void ascon_absorb_ad(ascon_state_t* s, const uint8_t* ad, size_t ad_len) {
    if (ad_len == 0) {
        s->x4 ^= 1;
        return;
    }
    while (ad_len >= 8) {
        s->x0 ^= load64(ad);
        ascon_permutation(s, 6);
        ad += 8;
        ad_len -= 8;
    }
    uint8_t padded[8] = {0};
    memcpy(padded, ad, ad_len);
    padded[ad_len] = 0x80;
    s->x0 ^= load64(padded);
    ascon_permutation(s, 6);
    s->x4 ^= 1;
}

static void ascon_encrypt(ascon_state_t* s, uint8_t* c, const uint8_t* m, size_t m_len) {
    while (m_len >= 8) {
        s->x0 ^= load64(m);
        store64(c, s->x0);
        ascon_permutation(s, 6);
        m += 8;
        c += 8;
        m_len -= 8;
    }
    if (m_len > 0) {
        uint8_t padded[8] = {0};
        memcpy(padded, m, m_len);
        padded[m_len] = 0x80;
        s->x0 ^= load64(padded);
        uint8_t out[8];
        store64(out, s->x0);
        memcpy(c, out, m_len);
    }
}

static void ascon_decrypt(ascon_state_t* s, uint8_t* m, const uint8_t* c, size_t c_len) {
    while (c_len >= 8) {
        uint64_t cx = load64(c);
        store64(m, s->x0 ^ cx);
        s->x0 = cx;
        ascon_permutation(s, 6);
        c += 8;
        m += 8;
        c_len -= 8;
    }
    if (c_len > 0 && c_len < 8) {
        uint8_t out[8];
        store64(out, s->x0);
        for (size_t i = 0; i < c_len; i++) {
            m[i] = out[i] ^ c[i];
            out[i] = c[i];
        }
        out[c_len] ^= 0x80;
        s->x0 = load64(out);
    }
}

static void ascon_finalize(ascon_state_t* s, uint8_t* tag, const uint8_t* key) {
    s->x1 ^= load64(key);
    s->x2 ^= load64(key + 8);
    ascon_permutation(s, 12);
    s->x3 ^= load64(key);
    s->x4 ^= load64(key + 8);
    store64(tag, s->x3);
    store64(tag + 8, s->x4);
}

int ascon128_aead_encrypt(uint8_t *ciphertext, size_t *ciphertext_len, const uint8_t *plaintext, size_t plaintext_len, const uint8_t *associated_data, size_t ad_len, const uint8_t *nonce, const uint8_t *key) {
    if (!ciphertext || !ciphertext_len || !nonce || !key) return -1;
    ascon_state_t state;
    ascon_init(&state, key, nonce);
    ascon_absorb_ad(&state, associated_data, ad_len);
    ascon_encrypt(&state, ciphertext, plaintext, plaintext_len);
    ascon_finalize(&state, ciphertext + plaintext_len, key);
    *ciphertext_len = plaintext_len + ASCON_TAG_LEN;
    return 0;
}

int ascon128_aead_decrypt(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *associated_data, size_t ad_len, const uint8_t *nonce, const uint8_t *key) {
    if (!plaintext || !plaintext_len || !ciphertext || !nonce || !key) return -1;
    if (ciphertext_len < ASCON_TAG_LEN) return -1;
    size_t msg_len = ciphertext_len - ASCON_TAG_LEN;
    ascon_state_t state;
    uint8_t computed_tag[ASCON_TAG_LEN];
    ascon_init(&state, key, nonce);
    ascon_absorb_ad(&state, associated_data, ad_len);
    ascon_decrypt(&state, plaintext, ciphertext, msg_len);
    ascon_finalize(&state, computed_tag, key);
    int diff = 0;
    for (int i = 0; i < ASCON_TAG_LEN; i++) {
        diff |= computed_tag[i] ^ ciphertext[msg_len + i];
    }
    if (diff != 0) {
        memset(plaintext, 0, msg_len);
        return -1;
    }
    *plaintext_len = msg_len;
    return 0;
}
