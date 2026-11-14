#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "headers/sysinfo.h"
#include "headers/protocol.h"

#define MODULE_TAG "sysinfo"
#include "headers/debug.h"

uint16_t get_cpu_count(void) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 1) nprocs = 1;
    return (uint16_t)nprocs;
}

uint32_t get_total_ram_mb(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) return 0;
    return (uint32_t)((uint64_t)si.totalram * si.mem_unit / (1024 * 1024));
}

uint32_t get_free_ram_mb(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) return 0;
    return (uint32_t)((uint64_t)(si.freeram + si.bufferram) * si.mem_unit / (1024 * 1024));
}

uint32_t get_system_uptime(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) return 0;
    return (uint32_t)si.uptime;
}

uint8_t is_running_as_root(void) {
    return (getuid() == 0) ? 1 : 0;
}

void get_load_average(uint16_t* load1, uint16_t* load5, uint16_t* load15) {
    double loadavg[3];
    if (getloadavg(loadavg, 3) != -1) {
        *load1 = (uint16_t)(loadavg[0] * 100);
        *load5 = (uint16_t)(loadavg[1] * 100);
        *load15 = (uint16_t)(loadavg[2] * 100);
    } else {
        *load1 = 0;
        *load5 = 0;
        *load15 = 0;
    }
}

uint8_t get_net_interface_count(void) {
    DIR* dir = opendir("/sys/class/net");
    if (!dir) return 0;
    
    uint8_t count = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] != '.') {
            count++;
        }
    }
    closedir(dir);
    return count;
}

uint16_t get_process_count(void) {
    DIR* dir = opendir("/proc");
    if (!dir) return 0;
    
    uint16_t count = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        char* p = ent->d_name;
        int is_pid = 1;
        while (*p) {
            if (*p < '0' || *p > '9') {
                is_pid = 0;
                break;
            }
            p++;
        }
        if (is_pid && ent->d_name[0] != '\0') {
            count++;
        }
    }
    closedir(dir);
    return count;
}

uint16_t get_listening_ports(void) {
    uint16_t count = 0;
    char line[256];
    const char* tcp_files[] = {"/proc/net/tcp", "/proc/net/tcp6", NULL};

    for (int i = 0; tcp_files[i]; i++) {
        FILE* fp = fopen(tcp_files[i], "r");
        if (!fp) continue;

        /* Skip header */
        if (fgets(line, sizeof(line), fp) == NULL) {
            fclose(fp);
            continue;
        }

        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, " 0A ") || strstr(line, " 0a ")) {
                count++;
            }
        }
        fclose(fp);
    }
    return count;
}

void get_device_type(char* buf, size_t len) {
    if (access("/etc/openwrt_release", F_OK) == 0 ||
        access("/etc/openwrt_version", F_OK) == 0) {
        strncpy(buf, "Router", len);
        buf[len - 1] = '\0';
        return;
    }
    
    if (access("/usr/bin/dvr", F_OK) == 0 ||
        access("/mnt/mtd/Config", F_OK) == 0) {
        strncpy(buf, "DVR", len);
        buf[len - 1] = '\0';
        return;
    }
    
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Raspberry") || strstr(line, "BCM")) {
                fclose(fp);
                strncpy(buf, "RaspberryPi", len);
                buf[len - 1] = '\0';
                return;
            }
        }
        fclose(fp);
    }
    
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        uint64_t ram_mb = (uint64_t)si.totalram * si.mem_unit / (1024 * 1024);
        if (ram_mb < 128) {
            strncpy(buf, "Embedded", len);
            buf[len - 1] = '\0';
            return;
        }
    }
    
    strncpy(buf, "Server", len);
    buf[len - 1] = '\0';
}

void get_os_name(char* buf, size_t len) {
    FILE* fp = fopen("/etc/os-release", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char* start = strchr(line, '"');
                if (start) {
                    start++;
                    char* end = strchr(start, '"');
                    if (end) *end = '\0';
                    strncpy(buf, start, len);
                    buf[len - 1] = '\0';
                    fclose(fp);
                    return;
                }
            }
        }
        fclose(fp);
    }
    
    fp = fopen("/etc/openwrt_version", "r");
    if (fp) {
        char version[64] = {0};
        if (fgets(version, sizeof(version), fp)) {
            version[strcspn(version, "\n")] = 0;
            snprintf(buf, len, "OpenWrt %s", version);
        }
        fclose(fp);
        return;
    }
    
    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(buf, len, "%s", uts.sysname);
    } else {
        strncpy(buf, "Linux", len);
        buf[len - 1] = '\0';
    }
}

void get_kernel_version(char* buf, size_t len) {
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(buf, uts.release, len);
    } else {
        strncpy(buf, "unknown", len);
    }
    buf[len - 1] = '\0';
}

void get_cpu_model(char* buf, size_t len) {
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        strncpy(buf, "unknown", len);
        buf[len - 1] = '\0';
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "model name", 10) == 0 ||
            strncmp(line, "Hardware", 8) == 0) {
            char* val = strchr(line, ':');
            if (val) {
                val++;
                while (*val == ' ' || *val == '\t') val++;
                val[strcspn(val, "\n\r")] = '\0';
                strncpy(buf, val, len);
                buf[len - 1] = '\0';
                fclose(fp);
                return;
            }
        }
    }
    fclose(fp);
    strncpy(buf, "unknown", len);
    buf[len - 1] = '\0';
}

void get_disk_usage(uint32_t* total_mb, uint32_t* free_mb) {
    struct statvfs sv;
    if (statvfs("/", &sv) == 0) {
        *total_mb = (uint32_t)((uint64_t)sv.f_blocks * sv.f_frsize / (1024 * 1024));
        *free_mb  = (uint32_t)((uint64_t)sv.f_bavail * sv.f_frsize / (1024 * 1024));
    } else {
        *total_mb = 0;
        *free_mb  = 0;
    }
}

void get_ip_address(char* buf, size_t len) {
    struct ifaddrs *ifaddr, *ifa;
    buf[0] = '\0';

    if (getifaddrs(&ifaddr) == -1) return;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &sa->sin_addr, buf, len);
        break;
    }
    freeifaddrs(ifaddr);
}

void get_mac_address(char* buf, size_t len) {
    DIR* dir = opendir("/sys/class/net");
    buf[0] = '\0';
    if (!dir) return;

    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.' || strcmp(ent->d_name, "lo") == 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", ent->d_name);
        FILE* fp = fopen(path, "r");
        if (fp) {
            if (fgets(buf, (int)len, fp)) {
                buf[strcspn(buf, "\n\r")] = '\0';
            }
            fclose(fp);
            if (strcmp(buf, "00:00:00:00:00:00") != 0) break;
            buf[0] = '\0';
        }
    }
    closedir(dir);
}

void get_hostname_info(char* buf, size_t len) {
    if (gethostname(buf, len) != 0) {
        strncpy(buf, "unknown", len);
    }
    buf[len - 1] = '\0';
}

void get_arch_name(char* buf, size_t len) {
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(buf, uts.machine, len);
    } else {
        strncpy(buf, "unknown", len);
    }
    buf[len - 1] = '\0';
}

uint32_t get_swap_total_mb(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) return 0;
    return (uint32_t)((uint64_t)si.totalswap * si.mem_unit / (1024 * 1024));
}

uint16_t get_open_fd_count(void) {
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return 0;

    uint16_t count = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] != '.') count++;
    }
    closedir(dir);
    return count > 0 ? count - 1 : 0;
}

void gather_sysinfo(sysinfo_t* info) {
    memset(info, 0, sizeof(sysinfo_t));
    
    info->cpu_cores = get_cpu_count();
    info->total_ram_mb = get_total_ram_mb();
    info->free_ram_mb = get_free_ram_mb();
    info->uptime_seconds = get_system_uptime();
    info->is_root = is_running_as_root();
    get_load_average(&info->load_avg_1, &info->load_avg_5, &info->load_avg_15);
    info->net_interfaces = get_net_interface_count();
    info->process_count = get_process_count();
    info->open_ports = get_listening_ports();
    get_device_type(info->device_type, sizeof(info->device_type));
    get_os_name(info->os_name, sizeof(info->os_name));
    get_kernel_version(info->kernel, sizeof(info->kernel));

    get_cpu_model(info->cpu_model, sizeof(info->cpu_model));
    get_disk_usage(&info->total_disk_mb, &info->free_disk_mb);
    get_ip_address(info->ip_address, sizeof(info->ip_address));
    get_mac_address(info->mac_address, sizeof(info->mac_address));
    get_hostname_info(info->hostname, sizeof(info->hostname));
    get_arch_name(info->arch_name, sizeof(info->arch_name));
    info->swap_total_mb = get_swap_total_mb();
    info->open_fd_count = get_open_fd_count();
    
    DEBUG_PRINT("Gathered sysinfo: cpu=%u, ram=%u/%uMB, uptime=%us, root=%u", info->cpu_cores, info->free_ram_mb, info->total_ram_mb, info->uptime_seconds, info->is_root);
    DEBUG_PRINT("Device: %s, OS: %s, Kernel: %s", info->device_type, info->os_name, info->kernel);
    DEBUG_PRINT("CPU Model: %s, Disk: %u/%uMB, IP: %s, Host: %s", info->cpu_model, info->free_disk_mb, info->total_disk_mb, info->ip_address, info->hostname);
}

static size_t put_u16(uint8_t* buf, uint16_t v) {
    uint16_t be = htons(v);
    memcpy(buf, &be, 2);
    return 2;
}

static size_t put_u32(uint8_t* buf, uint32_t v) {
    uint32_t be = htonl(v);
    memcpy(buf, &be, 4);
    return 4;
}

static size_t put_str(uint8_t* buf, const char* s, uint8_t max_len) {
    size_t slen = strlen(s);
    if (slen > max_len) slen = max_len;
    buf[0] = (uint8_t)slen;
    memcpy(buf + 1, s, slen);
    return 1 + slen;
}

int build_sysinfo_response(uint8_t* buffer, size_t max_len) {
    sysinfo_t info;
    gather_sysinfo(&info);
    
    if (max_len < 400) {
        DEBUG_PRINT("Buffer too small for sysinfo response");
        return -1;
    }
    
    size_t off = 0;
    
    buffer[off++] = CMD_SYSINFO_RESP;
    
    off += put_u16(buffer + off, info.cpu_cores);
    off += put_u32(buffer + off, info.total_ram_mb);
    off += put_u32(buffer + off, info.free_ram_mb);
    off += put_u32(buffer + off, info.uptime_seconds);
    buffer[off++] = info.is_root;
    off += put_u16(buffer + off, info.load_avg_1);
    off += put_u16(buffer + off, info.load_avg_5);
    buffer[off++] = info.net_interfaces;
    off += put_u16(buffer + off, info.process_count);
    off += put_u16(buffer + off, info.open_ports);
    
    off += put_str(buffer + off, info.device_type, 31);
    off += put_str(buffer + off, info.os_name, 63);
    off += put_str(buffer + off, info.kernel, 63);
    
    off += put_str(buffer + off, info.cpu_model, 47);
    off += put_u32(buffer + off, info.total_disk_mb);
    off += put_u32(buffer + off, info.free_disk_mb);
    off += put_str(buffer + off, info.ip_address, 15);
    off += put_str(buffer + off, info.mac_address, 17);
    off += put_str(buffer + off, info.hostname, 31);
    off += put_str(buffer + off, info.arch_name, 15);
    off += put_u32(buffer + off, info.swap_total_mb);
    off += put_u16(buffer + off, info.load_avg_15);
    off += put_u16(buffer + off, info.open_fd_count);
    
    DEBUG_PRINT("Built sysinfo response: %zu bytes", off);
    return (int)off;
}
