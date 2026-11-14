#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>

#include "headers/crypto.h"
#include "headers/ascon.h"
#include "headers/rand.h"
#include "headers/keyguard.h"
#include "headers/table.h"

#define MODULE_TAG "crypto"
#include "headers/debug.h"

static int crypto_initialized = 0;
static volatile uint32_t nonce_counter = 0;
static int urandom_fd = -1;

static void encode_epoch_ad(uint8_t ad[4], uint32_t epoch) {
    ad[0] = (epoch >> 24) & 0xFF;
    ad[1] = (epoch >> 16) & 0xFF;
    ad[2] = (epoch >> 8) & 0xFF;
    ad[3] = epoch & 0xFF;
}

void crypto_init(void) {
    if (!crypto_initialized) {
        init_rand();
        keyguard_init();
        nonce_counter = (uint32_t)(time(NULL) & 0xFFFFFFFF);
        urandom_fd = open("/dev/urandom", O_RDONLY);
        crypto_initialized = 1;
        DEBUG_PRINT("Crypto initialized with keyguard");
    }
}

void crypto_cleanup(void) {
    if (crypto_initialized) {
        if (urandom_fd >= 0) {
            close(urandom_fd);
            urandom_fd = -1;
        }
        keyguard_cleanup();
        crypto_initialized = 0;
    }
}

static int generate_hybrid_nonce(uint8_t *nonce) {
    uint32_t ctr = __sync_fetch_and_add(&nonce_counter, 1);
    nonce[0] = (ctr >> 24) & 0xFF;
    nonce[1] = (ctr >> 16) & 0xFF;
    nonce[2] = (ctr >> 8) & 0xFF;
    nonce[3] = ctr & 0xFF;

#ifdef SYS_getrandom
    ssize_t ret = getrandom(nonce + 4, ASCON_NONCE_LEN - 4, 0);
    if (ret == ASCON_NONCE_LEN - 4) {
        return 0;
    }
#endif

    if (urandom_fd >= 0) {
        ssize_t bytes_read = read(urandom_fd, nonce + 4, ASCON_NONCE_LEN - 4);
        if (bytes_read == ASCON_NONCE_LEN - 4) {
            return 0;
        }
    }

    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t bytes_read = read(fd, nonce + 4, ASCON_NONCE_LEN - 4);
            close(fd);
            if (bytes_read == ASCON_NONCE_LEN - 4) {
                return 0;
            }
        }
    }

    for (size_t i = 0; i < (ASCON_NONCE_LEN - 4); i += 4) {
        uint32_t r = rand_next();
        size_t to_copy = (i + 4 <= ASCON_NONCE_LEN - 4) ? 4 : (ASCON_NONCE_LEN - 4 - i);
        memcpy(nonce + 4 + i, &r, to_copy);
    }
    return 0;
}

int crypto_encrypt(const uint8_t *plaintext, size_t plaintext_len, uint8_t *output, size_t *output_len) {
    uint8_t nonce[ASCON_NONCE_LEN];
    uint8_t active_key[ASCON_KEY_LEN];
    uint8_t epoch_ad[4];
    
    if (generate_hybrid_nonce(nonce) != 0) return -1;

    uint32_t epoch = keyguard_get_key(active_key);
    encode_epoch_ad(epoch_ad, epoch);
    DEBUG_PRINT("Encrypting with epoch %u", epoch);
    
    uint16_t frame_len = (uint16_t)(ASCON_NONCE_LEN + plaintext_len + ASCON_TAG_LEN);
    output[0] = (frame_len >> 8) & 0xFF;
    output[1] = frame_len & 0xFF;
    
    memcpy(output + 2, nonce, ASCON_NONCE_LEN);
    
    size_t ciphertext_len;
    int ret = ascon128_aead_encrypt(
        output + 2 + ASCON_NONCE_LEN,
        &ciphertext_len,
        plaintext,
        plaintext_len,
        epoch_ad,
        sizeof(epoch_ad),
        nonce,
        active_key
    );
    
    secure_memzero(active_key, ASCON_KEY_LEN);
    
    if (ret != 0) return -1;
    
    *output_len = 2 + ASCON_NONCE_LEN + ciphertext_len;
    return 0;
}

static int try_decrypt_with_epoch(const uint8_t *input, size_t input_len, uint8_t *plaintext, size_t *plaintext_len, const uint8_t *key, uint32_t epoch) {
    const uint8_t *nonce = input + 2;
    const uint8_t *ciphertext = input + 2 + ASCON_NONCE_LEN;
    size_t ciphertext_len = input_len - 2 - ASCON_NONCE_LEN;
    
    uint8_t epoch_ad[4];
    encode_epoch_ad(epoch_ad, epoch);
    
    return ascon128_aead_decrypt(
        plaintext,
        plaintext_len,
        ciphertext,
        ciphertext_len,
        epoch_ad,
        sizeof(epoch_ad),
        nonce,
        key
    );
}

int crypto_decrypt(const uint8_t *input, size_t input_len, uint8_t *plaintext, size_t *plaintext_len) {
    if (input_len < 2 + ASCON_NONCE_LEN + ASCON_TAG_LEN) {
        return -1;
    }
    
    uint8_t key[ASCON_KEY_LEN];
    uint32_t current_epoch = keyguard_current_epoch();
    
    keyguard_get_key_for_epoch(key, current_epoch);
    if (try_decrypt_with_epoch(input, input_len, plaintext, plaintext_len, key, current_epoch) == 0) {
        DEBUG_PRINT("Decrypted with current epoch %u", current_epoch);
        secure_memzero(key, ASCON_KEY_LEN);
        return 0;
    }
    
    if (current_epoch > 0) {
        keyguard_get_key_for_epoch(key, current_epoch - 1);
        if (try_decrypt_with_epoch(input, input_len, plaintext, plaintext_len, key, current_epoch - 1) == 0) {
            DEBUG_PRINT("Decrypted with previous epoch %u", current_epoch - 1);
            secure_memzero(key, ASCON_KEY_LEN);
            return 0;
        }
    }
    
    keyguard_get_key_for_epoch(key, current_epoch + 1);
    if (try_decrypt_with_epoch(input, input_len, plaintext, plaintext_len, key, current_epoch + 1) == 0) {
        DEBUG_PRINT("Decrypted with next epoch %u", current_epoch + 1);
        secure_memzero(key, ASCON_KEY_LEN);
        return 0;
    }
    
    secure_memzero(key, ASCON_KEY_LEN);
    DEBUG_PRINT("Decryption failed - no valid epoch");
    return -1;
}

ssize_t crypto_send(int sockfd, const uint8_t *data, size_t len) {
    uint8_t buffer[4096 + CRYPTO_OVERHEAD];
    size_t encrypted_len;
    
    if (len > 4096) {
        len = 4096;
    }
    
    if (crypto_encrypt(data, len, buffer, &encrypted_len) != 0) {
        return -1;
    }
    
    size_t total_sent = 0;
    while (total_sent < encrypted_len) {
        ssize_t sent = send(sockfd, buffer + total_sent, encrypted_len - total_sent, MSG_NOSIGNAL);
        if (sent <= 0) return -1;
        total_sent += sent;
    }
    
    return (ssize_t)len;
}

ssize_t crypto_recv(int sockfd, uint8_t *buffer, size_t max_len) {
    uint8_t header[2];
    ssize_t n = recv(sockfd, header, 2, MSG_WAITALL);
    if (n != 2) {
        DEBUG_PRINT("crypto_recv: recv(header) got %zd (need 2), errno=%d %s", n, errno, n < 0 ? strerror(errno) : "EOF");
        return -1;
    }

    uint16_t frame_len = ((uint16_t)header[0] << 8) | header[1];

    if (frame_len < ASCON_NONCE_LEN + ASCON_TAG_LEN) {
        DEBUG_PRINT("crypto_recv: invalid frame_len %u (too small)", (unsigned)frame_len);
        return -1;
    }

    if (frame_len > 4096 + ASCON_NONCE_LEN + ASCON_TAG_LEN) {
        DEBUG_PRINT("crypto_recv: invalid frame_len %u (too large)", (unsigned)frame_len);
        return -1;
    }

    size_t max_plaintext_len = frame_len - ASCON_NONCE_LEN - ASCON_TAG_LEN;
    if (max_plaintext_len > max_len) {
        DEBUG_PRINT("crypto_recv: frame too large for buffer (need %zu, have %zu)", max_plaintext_len, max_len);
        return -1;
    }

    uint8_t frame[4096 + ASCON_NONCE_LEN + ASCON_TAG_LEN];
    frame[0] = header[0];
    frame[1] = header[1];

    n = recv(sockfd, frame + 2, frame_len, MSG_WAITALL);
    if (n != (ssize_t)frame_len) {
        DEBUG_PRINT("crypto_recv: recv(frame) got %zd (need %zu), errno=%d %s", n, (size_t)frame_len, errno, n < 0 ? strerror(errno) : "EOF");
        return -1;
    }

    size_t plaintext_len;
    if (crypto_decrypt(frame, 2 + frame_len, buffer, &plaintext_len) != 0) {
        DEBUG_PRINT("crypto_recv: decrypt failed (epoch mismatch or corrupt data)");
        return -1;
    }

    return (ssize_t)plaintext_len;
}
