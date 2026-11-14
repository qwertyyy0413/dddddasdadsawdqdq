#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include "headers/rand.h"

static uint32_t x, y, z, w;
static pthread_mutex_t rand_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t rand_next_unlocked(void) {
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

uint32_t rand_next(void) {
    pthread_mutex_lock(&rand_mutex);
    uint32_t result = rand_next_unlocked();
    pthread_mutex_unlock(&rand_mutex);
    return result;
}

void init_rand(void) {
    pthread_mutex_lock(&rand_mutex);
    uintptr_t addr = (uintptr_t)&x;
    uint32_t seed = (uint32_t)time(NULL) ^ (uint32_t)addr ^ (uint32_t)(addr >> 16);
    x = seed;
    y = seed << 13;
    z = (seed >> 9) ^ 0xA5A5A5A5;
    w = seed ^ 0x12345678;
    pthread_mutex_unlock(&rand_mutex);
}
