#pragma once

#ifndef ATTACK_PARAMS_H
#define ATTACK_PARAMS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct attack_option {
    uint8_t type;
    uint16_t len;
    uint8_t* data;
    struct attack_option* next;
} attack_option;

typedef struct {
    struct sockaddr_in target_addr;
    uint32_t duration;
    volatile uint32_t active;
    attack_option* options;
} attack_params;

static inline attack_option* find_option(attack_params* params, uint8_t type) {
    if (!params) return NULL;
    attack_option* opt = params->options;
    while (opt) {
        if (opt->type == type) return opt;
        opt = opt->next;
    }
    return NULL;
}

static inline uint8_t get_option_u8(attack_option* opt) {
    if (!opt || !opt->data || opt->len < 1) return 0;
    return opt->data[0];
}

static inline uint16_t get_option_u16(attack_option* opt) {
    if (!opt || !opt->data || opt->len < 2) return 0;
    uint16_t val;
    memcpy(&val, opt->data, sizeof(val));
    return ntohs(val);
}

static inline uint32_t get_option_u32(attack_option* opt) {
    if (!opt || !opt->data || opt->len < 4) return 0;
    uint32_t val;
    memcpy(&val, opt->data, sizeof(val));
    return ntohl(val);
}

static inline void free_options(attack_option* head) {
    while (head) {
        attack_option* next = head->next;
        if (head->data) free(head->data);
        free(head);
        head = next;
    }
}

static inline attack_option* create_option(uint8_t type, uint16_t len, uint8_t* data) {
    attack_option* opt = (attack_option*)malloc(sizeof(attack_option));
    if (!opt) return NULL;
    
    opt->type = type;
    opt->len = len;
    opt->next = NULL;
    
    if (len > 0 && data) {
        opt->data = (uint8_t*)malloc(len);
        if (!opt->data) {
            free(opt);
            return NULL;
        }
        memcpy(opt->data, data, len);
    } else {
        opt->data = NULL;
    }
    
    return opt;
}

static inline attack_option* clone_options(attack_option* src) {
    if (!src) return NULL;
    
    attack_option* head = NULL;
    attack_option* tail = NULL;
    
    while (src) {
        attack_option* clone = create_option(src->type, src->len, src->data);
        if (!clone) {
            free_options(head);
            return NULL;
        }
        
        if (!head) {
            head = clone;
            tail = clone;
        } else {
            tail->next = clone;
            tail = clone;
        }
        
        src = src->next;
    }
    
    return head;
}

static inline void free_attack_params(attack_params* params) {
    if (!params) return;
    free_options(params->options);
    free(params);
}

#endif // ATTACK_PARAMS_H
