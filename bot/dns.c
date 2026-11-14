#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>

#include "headers/dns.h"
#include "headers/rand.h"

#define DNS_PORT 53
#define DNS_TIMEOUT 5
#define DNS_TYPE_A 1
#define DNS_CLASS_IN 1

static const char* dns_servers[] = {
    "8.8.8.8",
    "1.1.1.1",
    "8.8.4.4",
    "1.0.0.1"
};
#define DNS_SERVER_COUNT 4

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_header;

static int encode_domain(const char* domain, uint8_t* buffer, size_t buf_size) {
    int pos = 0;
    const char* start = domain;
    const char* dot;

    while ((dot = strchr(start, '.')) != NULL) {
        int len = dot - start;
        if ((size_t)(pos + 1 + len) >= buf_size) return -1;
        buffer[pos++] = len;
        memcpy(buffer + pos, start, len);
        pos += len;
        start = dot + 1;
    }

    int len = strlen(start);
    if (len > 0) {
        if ((size_t)(pos + 1 + len) >= buf_size) return -1;
        buffer[pos++] = len;
        memcpy(buffer + pos, start, len);
        pos += len;
    }

    if ((size_t)(pos + 1) > buf_size) return -1;
    buffer[pos++] = 0;
    return pos;
}

static uint32_t parse_response(uint8_t* buffer, int len) {
    if (len < (int)sizeof(dns_header)) return 0;

    dns_header* header = (dns_header*)buffer;
    int ancount = ntohs(header->ancount);
    if (ancount == 0) return 0;

    uint8_t* ptr = buffer + sizeof(dns_header);
    uint8_t* end = buffer + len;

    while (ptr < end && *ptr != 0) {
        if ((*ptr & 0xC0) == 0xC0) {
            ptr += 2;
            break;
        }
        if (ptr + *ptr + 1 > end) return 0;
        ptr += *ptr + 1;
    }

    if (ptr >= end) return 0;
    if (*ptr == 0) ptr++;

    if (ptr + 4 > end) return 0;
    ptr += 4;

    for (int i = 0; i < ancount && ptr + 12 <= end; i++) {
        if ((*ptr & 0xC0) == 0xC0) {
            ptr += 2;
        } else {
            while (ptr < end && *ptr != 0) {
                ptr += *ptr + 1;
            }
            if (ptr >= end) return 0;
            ptr++;
        }

        if (ptr + 10 > end) break;
        uint16_t rtype_net;
        memcpy(&rtype_net, ptr, sizeof(rtype_net));
        uint16_t rtype = ntohs(rtype_net);
        ptr += 2;
        ptr += 2;
        ptr += 4;
        
        uint16_t rdlen_net;
        memcpy(&rdlen_net, ptr, sizeof(rdlen_net));
        uint16_t rdlen = ntohs(rdlen_net);
        ptr += 2;

        if (rtype == DNS_TYPE_A && rdlen == 4 && ptr + 4 <= end) {
            uint32_t ip;
            memcpy(&ip, ptr, 4);
            return ip;
        }

        ptr += rdlen;
    }

    return 0;
}

static uint32_t query_dns_server(const char* server, const char* domain) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) return 0;

    struct timeval tv;
    tv.tv_sec = DNS_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    dns_addr.sin_addr.s_addr = inet_addr(server);

    uint8_t query[512];
    memset(query, 0, sizeof(query));

    dns_header* header = (dns_header*)query;
    header->id = htons(rand_next() & 0xFFFF);
    header->flags = htons(0x0100);
    header->qdcount = htons(1);

    int qname_len = encode_domain(domain, query + sizeof(dns_header), sizeof(query) - sizeof(dns_header));
    if (qname_len < 0) {
        close(sockfd);
        return 0;
    }
    uint8_t* qtype_ptr = query + sizeof(dns_header) + qname_len;
    uint16_t qtype_val = htons(DNS_TYPE_A);
    uint16_t qclass_val = htons(DNS_CLASS_IN);
    memcpy(qtype_ptr, &qtype_val, sizeof(qtype_val));
    memcpy(qtype_ptr + 2, &qclass_val, sizeof(qclass_val));

    int query_len = sizeof(dns_header) + qname_len + 4;

    if (sendto(sockfd, query, query_len, 0, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        close(sockfd);
        return 0;
    }

    uint8_t response[512];
    ssize_t resp_len = recv(sockfd, response, sizeof(response), 0);
    close(sockfd);

    if (resp_len <= 0) return 0;

    return parse_response(response, resp_len);
}

uint32_t dns_resolve(const char* domain) {
    if (!domain || strlen(domain) == 0) return 0;

    struct in_addr addr;
    if (inet_pton(AF_INET, domain, &addr) == 1) {
        return addr.s_addr;
    }

    for (int i = 0; i < DNS_SERVER_COUNT; i++) {
        uint32_t ip = query_dns_server(dns_servers[i], domain);
        if (ip != 0) return ip;
    }

    return 0;
}
