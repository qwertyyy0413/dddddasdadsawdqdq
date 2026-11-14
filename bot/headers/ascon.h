#pragma once

#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stddef.h>

#define ASCON_KEY_LEN    16
#define ASCON_NONCE_LEN  16
#define ASCON_TAG_LEN    16

int ascon128_aead_encrypt(
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *associated_data,
    size_t ad_len,
    const uint8_t *nonce,
    const uint8_t *key
);

int ascon128_aead_decrypt(
    uint8_t *plaintext,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *associated_data,
    size_t ad_len,
    const uint8_t *nonce,
    const uint8_t *key
);

#endif
