#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <limits.h>
#include <time.h>

#include "headers/killer.h"
#include "headers/lifecycle.h"

#define SUSPICION_THRESHOLD 3
#define HIGH_CPU_THRESHOLD 20000000

#define CACHE_SIZE 256
#define CACHE_EXPIRE_SECS 30

static pthread_t killer_tid;
static int killer_started = 0;

static pid_t safe_pids[CACHE_SIZE];
static int safe_count = 0;
static time_t cache_time = 0;

static pid_t killed_pids[CACHE_SIZE];
static int killed_count = 0;

static pid_t my_pid = 0;

static const char *whitelisted_paths[] = {
    "/bin/",
    "/usr/bin/",
    "/sbin/",
    "/usr/sbin/",
    "/lib/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/",
    "/opt/",
    "/etc/init.d/",
    NULL
};

static void cache_init(void) {
    memset(safe_pids, 0, sizeof(safe_pids));
    memset(killed_pids, 0, sizeof(killed_pids));
    safe_count = 0;
    killed_count = 0;
    cache_time = time(NULL);
    my_pid = getpid();
}

static void cache_refresh_if_expired(void) {
    time_t now = time(NULL);
    if (now - cache_time >= CACHE_EXPIRE_SECS) {
        memset(safe_pids, 0, sizeof(safe_pids));
        safe_count = 0;
        cache_time = now;
    }
}

static int is_cached_safe(pid_t pid) {
    for (int i = 0; i < safe_count; i++) {
        if (safe_pids[i] == pid) return 1;
    }
    return 0;
}

static void add_to_safe_cache(pid_t pid) {
    if (safe_count < CACHE_SIZE) {
        safe_pids[safe_count++] = pid;
    }
}

static int is_already_killed(pid_t pid) {
    for (int i = 0; i < killed_count; i++) {
        if (killed_pids[i] == pid) return 1;
    }
    return 0;
}

static void add_to_killed(pid_t pid) {
    if (killed_count < CACHE_SIZE) {
        killed_pids[killed_count++] = pid;
    } else {
        memmove(killed_pids, killed_pids + 1, (CACHE_SIZE - 1) * sizeof(pid_t));
        killed_pids[CACHE_SIZE - 1] = pid;
    }
}

static int is_whitelisted(const char *exe) {
    if (!exe) return 0;
    for (int i = 0; whitelisted_paths[i] != NULL; i++) {
        if (strncmp(exe, whitelisted_paths[i], strlen(whitelisted_paths[i])) == 0) {
            return 1; 
        }
    }
    return 0;
}

static int is_system_path(const char *exe) {
    if (!exe) return 1;

    if (strncmp(exe, "/usr", 4) == 0) return 1;
    if (strncmp(exe, "/bin", 4) == 0) return 1;
    if (strncmp(exe, "/sbin", 5) == 0) return 1;
    if (strncmp(exe, "/lib", 4) == 0) return 1;
    if (strncmp(exe, "/lib64", 6) == 0) return 1;
    if (strncmp(exe, "/opt", 4) == 0) return 1;

    if (strncmp(exe, "/sbin/init", 10) == 0) return 1;
    if (strstr(exe, "/systemd")) return 1;

    return 0;  
}

static int read_exe_path(pid_t pid, char *out, size_t n) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/exe", pid);
    ssize_t r = readlink(p, out, n-1);
    if (r < 0) {
        out[0] = 0;
        return 0;
    }
    out[r] = 0;
    return 1;
}

static int is_temp_path(const char *p) {
    return strstr(p, "/tmp") || strstr(p, "/dev/shm") || strstr(p, "/var/tmp") || strstr(p, "/run/");
}

static int suspicious_name(const char *exe, const char *cmd) {
    if (!exe || !cmd) return 0;
    if (strstr(cmd, "systemd") || strstr(cmd, "kthreadd") || strstr(cmd, "init"))
        if (!strstr(exe, "systemd") && !strstr(exe, "init"))
            return 1;
    return 0;
}

static int check_deleted(const char *p) {
    return strstr(p, "(deleted)") != NULL;
}

static int check_packed(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char buf[8] = {0};
    size_t n = fread(buf, 1, 7, f);
    fclose(f);
    if (n < 3) return 0;
    if (strstr(buf, "UPX")) return 1;
    return 0;
}

static int check_ld_preload(pid_t pid) {
    char p[256];
    snprintf(p, sizeof(p), "/proc/%d/environ", pid);
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);
    if (n == 0) return 0;
    return memmem(buf, n, "LD_PRELOAD=", 11) != NULL;
}

static int check_perms(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (st.st_mode & S_IWOTH) return 1;
    if (!S_ISREG(st.st_mode)) return 1;
    return 0;
}

static int high_cpu(pid_t pid) {
    char p[256];
    snprintf(p, sizeof(p), "/proc/%d/stat", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    long ut = 0, st = 0;
    char buf[2048];
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);
    
    char *after_comm = strrchr(buf, ')');
    if (!after_comm) return 0;
    after_comm++;
    int field = 0;
    char *ptr = after_comm;
    while (*ptr && field < 13) {
        while (*ptr == ' ') ptr++;
        if (!*ptr) break;
        field++;
        if (field == 12) ut = atol(ptr);
        if (field == 13) st = atol(ptr);
        while (*ptr && *ptr != ' ') ptr++;
    }
    return (ut + st) > HIGH_CPU_THRESHOLD;
}

static int check_suspicious_socket(pid_t pid) {
    char fd_path[128];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
    DIR *d = opendir(fd_path);
    if (!d) return 0;

    struct dirent *e;
    char buf[256];
    int suspicious = 0;

    while ((e = readdir(d)) && !suspicious) {
        if (e->d_name[0] == '.') continue;
        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", fd_path, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(full)) continue;

        ssize_t len = readlink(full, buf, sizeof(buf)-1);
        if (len <= 0) continue;
        buf[len] = 0;

        if (strstr(buf, "socket:[")) {
            if (strstr(buf, "raw") || strstr(buf, "packet:"))
                suspicious = 1;
        }
    }
    closedir(d);
    return suspicious;
}

static int check_namespace(pid_t pid) {
    char p[128];
    struct stat st1, st2;

    snprintf(p, sizeof(p), "/proc/1/ns/pid");
    if (stat(p, &st1) != 0) return 0;

    snprintf(p, sizeof(p), "/proc/%d/ns/pid", pid);
    if (stat(p, &st2) != 0) return 0;

    return st1.st_ino != st2.st_ino;
}

static int check_hidden(pid_t pid) {
    char p[128];
    snprintf(p, sizeof(p), "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 1;
    char line[128];
    int count = 0;
    while (fgets(line, sizeof(line), f))
        count++;
    fclose(f);
    return count == 0;
}

static int check_ptrace(pid_t pid) {
    char p[128], line[256];
    snprintf(p, sizeof(p), "/proc/%d/status", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int x = atoi(line + 10);
            fclose(f);
            return x != 0;
        }
    }
    fclose(f);
    return 0;
}

static int system_ld_preload_exists(void) {
    struct stat st;
    return (stat("/etc/ld.so.preload", &st) == 0);
}

static pid_t get_ppid(pid_t pid) {
    char p[128], buf[1024];
    snprintf(p, sizeof(p), "/proc/%d/stat", pid);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);
    char *after_comm = strrchr(buf, ')');
    if (!after_comm) return 0;
    after_comm++;
    pid_t ppid = 0;
    /* Fields after comm: state(3) ppid(4) -- ppid is 2nd token after ')' */
    if (sscanf(after_comm, " %*c %d", &ppid) != 1)
        return 0;
    return ppid;
}

static int check_memfd(const char *exe) {
    if (!exe) return 0;
    return strstr(exe, "/memfd:") != NULL || strstr(exe, "memfd:") != NULL;
}

static int check_random_name(const char *cmd) {
    if (!cmd || strlen(cmd) < 2) return 0;
    
    int len = 0;
    int consonants = 0;
    int digits = 0;
    
    for (int i = 0; cmd[i] && i < 16; i++) {
        char c = cmd[i];
        if (c == ' ' || c == '/') break;
        len++;
        
        if (isdigit(c)) {
            digits++;
        } else if (isalpha(c)) {
            c = tolower(c);
            if (c != 'a' && c != 'e' && c != 'i' && c != 'o' && c != 'u')
                consonants++;
        }
    }
    
    if (len >= 6 && consonants >= 5) return 1;
    if (len >= 4 && digits >= len - 1) return 1;
    
    return 0;
}

static int check_interpreter_abuse(const char *exe, const char *cmdline) {
    if (!exe || !cmdline) return 0;
    
    if (strstr(exe, "/sh") || strstr(exe, "/bash") || strstr(exe, "/dash") || strstr(exe, "busybox")) {
        if (strstr(cmdline, "/tmp/") || strstr(cmdline, "/dev/shm/") || strstr(cmdline, "/var/tmp/") || strstr(cmdline, "/run/"))
            return 1;
    }
    return 0;
}

static int check_cron_spawn(pid_t ppid, const char *exe) {
    if (!exe) return 0;
    
    char parent_exe[256] = {0};
    if (!read_exe_path(ppid, parent_exe, sizeof(parent_exe))) return 0;
    
    if (strstr(parent_exe, "cron")) {
        if (is_temp_path(exe)) return 1;
    }
    return 0;
}

static int check_young_process(pid_t pid, const char *exe) {
    if (!exe || !is_temp_path(exe)) return 0;
    
    char path[128];
    struct stat st;
    snprintf(path, sizeof(path), "/proc/%d", pid);
    if (stat(path, &st) != 0) return 0;
    
    return (time(NULL) - st.st_ctime) < 3;
}

static int check_symlink_abuse(const char *exe) {
    if (!exe) return 0;
    
    struct stat st;
    if (lstat(exe, &st) != 0) return 0;
    
    if (S_ISLNK(st.st_mode)) {
        char target[PATH_MAX];
        ssize_t len = readlink(exe, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = 0;
            if (is_temp_path(target)) return 1;
        }
    }
    return 0;
}

static int inspect_pid(pid_t pid) {
    if (pid == my_pid) return 0;
    
    if (is_already_killed(pid)) return 0;
    
    if (is_cached_safe(pid)) return 0;

    char exe[PATH_MAX] = {0};
    int have_exe = read_exe_path(pid, exe, sizeof(exe));

    char cmdp[256];
    snprintf(cmdp, sizeof(cmdp), "/proc/%d/cmdline", pid);
    FILE *f = fopen(cmdp, "r");
    char cl[1024] = {0};
    if (f) {
        size_t n = fread(cl, 1, sizeof(cl)-1, f);
        fclose(f);
        for (size_t i = 0; i < n; i++)
            if (cl[i] == 0) cl[i] = ' ';
    }

    char sp[256];
    snprintf(sp, sizeof(sp), "/proc/%d", pid);
    struct stat st;
    if (stat(sp, &st) != 0) return 0;
    uid_t u = st.st_uid;
    uid_t me = getuid();
    if (u != me && me != 0) {
        add_to_safe_cache(pid);
        return 0;
    }

    if (have_exe) {
        if (is_whitelisted(exe) || is_system_path(exe)) {
            add_to_safe_cache(pid);
            return 0;
        }
    }

    int score = 0;

    if (have_exe) {
        if (check_deleted(exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
        if (is_temp_path(exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
        if (check_perms(exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
        if (check_packed(exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
        if (check_memfd(exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
        if (check_symlink_abuse(exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    } else {
        if (++score >= SUSPICION_THRESHOLD) return 1;
    }

    if (suspicious_name(exe, cl)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_random_name(cl)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_interpreter_abuse(exe, cl)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_ld_preload(pid)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (high_cpu(pid)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_suspicious_socket(pid)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_namespace(pid)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_hidden(pid)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_ptrace(pid)) { if (++score >= SUSPICION_THRESHOLD) return 1; }

    pid_t ppid = get_ppid(pid);
    if (ppid == 1 && !strstr(cl, "systemd")) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_cron_spawn(ppid, exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }
    if (check_young_process(pid, exe)) { if (++score >= SUSPICION_THRESHOLD) return 1; }

    if (score < SUSPICION_THRESHOLD) {
        add_to_safe_cache(pid);
    }

    return score >= SUSPICION_THRESHOLD;
}

void *killer_thread(void *arg) {
    (void)arg;
    cache_init();
    
    int threats_found = 0;
    
    while (running) {
        cache_refresh_if_expired();
        threats_found = 0;
        
        DIR *d = opendir("/proc");
        if (!d) {
            sleep(1);
            continue;
        }

        struct dirent *e;
        while ((e = readdir(d))) {
            if (!running) break;
            if (!isdigit(e->d_name[0])) continue;
            
            pid_t pid = atoi(e->d_name);
            if (pid <= 1) continue;
            
            if (inspect_pid(pid)) {
                kill(pid, SIGKILL);
                add_to_killed(pid);
                threats_found++;
            }
        }
        closedir(d);
        
        if (threats_found > 0) {
            usleep(500000);
        } else {
            sleep(3);
        }
    }
    return NULL;
}

int start_killer(void) {
    if (pthread_create(&killer_tid, NULL, killer_thread, NULL) != 0) {
        return -1;
    }
    killer_started = 1;
    return 0;
}

void stop_killer(void) {
    if (!killer_started) return;
    pthread_join(killer_tid, NULL);
    killer_started = 0;
}
