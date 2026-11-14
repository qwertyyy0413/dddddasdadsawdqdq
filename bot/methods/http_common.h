#pragma once

#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

#include <stddef.h>

extern const char* const HTTP_USER_AGENTS[];
extern const size_t HTTP_NUM_USER_AGENTS;

extern const char* const HTTP_ACCEPT_HEADERS[];
extern const size_t HTTP_NUM_ACCEPT_HEADERS;

extern const char* const HTTP_ACCEPT_LANGUAGES[];
extern const size_t HTTP_NUM_ACCEPT_LANGUAGES;

extern const char* const HTTP_SEC_CH_UA[];
extern const size_t HTTP_NUM_SEC_CH_UA;

typedef struct {
    const char *user_agent;
    const char *sec_ch_ua;       /* NULL for Firefox/Safari (don't send sec-ch-ua headers) */
    const char *sec_ch_platform; /* NULL for Firefox/Safari */
} browser_identity_t;

const char* http_get_random_user_agent(void);

/* Returns a correlated identity where UA, sec-ch-ua, and platform always match */
const browser_identity_t* http_get_random_identity(void);

void http_generate_random_string(char* buf, int len);

void http_set_nonblocking(int fd);

/* Returns 1 if host is a dotted-quad IPv4 address, 0 otherwise */
int http_is_ip_address(const char *host);

#endif /* HTTP_COMMON_H */
