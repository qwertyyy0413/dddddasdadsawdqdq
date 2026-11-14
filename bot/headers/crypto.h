#pragma once

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define CRYPTO_OVERHEAD 34

void crypto_init(void);
void crypto_cleanup(void);

int crypto_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *output,
    size_t *output_len
);

int crypto_decrypt(
    const uint8_t *input,
    size_t input_len,
    uint8_t *plaintext,
    size_t *plaintext_len
);

ssize_t crypto_send(int sockfd, const uint8_t *data, size_t len);
ssize_t crypto_recv(int sockfd, uint8_t *buffer, size_t max_len);

#endif
