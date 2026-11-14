#pragma once

#ifndef KEYGUARD_H
#define KEYGUARD_H

#include <stdint.h>
#include <stddef.h>

#define KEYGUARD_KEY_LEN      16

#ifndef KEYGUARD_EPOCH_SECS
#define KEYGUARD_EPOCH_SECS   600
#endif

#define KEYGUARD_NUM_SHARES   3
#define KEYGUARD_NUM_DECOYS   8

void keyguard_init(void);
uint32_t keyguard_get_key(uint8_t *key_out);
void keyguard_get_key_for_epoch(uint8_t *key_out, uint32_t epoch);
uint32_t keyguard_current_epoch(void);
void keyguard_reobfuscate(void);
void keyguard_cleanup(void);
#endif
