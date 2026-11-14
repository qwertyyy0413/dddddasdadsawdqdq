#pragma once

#ifndef SYSINFO_H
#define SYSINFO_H

#include <stdint.h>

typedef struct {
    uint16_t cpu_cores;
    uint32_t total_ram_mb;
    uint32_t free_ram_mb;
    uint32_t uptime_seconds;
    uint8_t  is_root;
    uint16_t load_avg_1;
    uint16_t load_avg_5;
    uint8_t  net_interfaces;
    uint16_t process_count;
    uint16_t open_ports;
    char     device_type[32];
    char     os_name[64];
    char     kernel[64];
    /* New fields */
    char     cpu_model[48];
    uint32_t total_disk_mb;
    uint32_t free_disk_mb;
    char     ip_address[16];
    char     mac_address[18];
    char     hostname[32];
    char     arch_name[16];
    uint32_t swap_total_mb;
    uint16_t load_avg_15;
    uint16_t open_fd_count;
} sysinfo_t;

void gather_sysinfo(sysinfo_t* info);

uint16_t get_cpu_count(void);
uint32_t get_total_ram_mb(void);
uint32_t get_free_ram_mb(void);
uint32_t get_system_uptime(void);
uint8_t  is_running_as_root(void);
void     get_load_average(uint16_t* load1, uint16_t* load5, uint16_t* load15);
uint8_t  get_net_interface_count(void);
uint16_t get_process_count(void);
uint16_t get_listening_ports(void);
void     get_device_type(char* buf, size_t len);
void     get_os_name(char* buf, size_t len);
void     get_kernel_version(char* buf, size_t len);
void     get_cpu_model(char* buf, size_t len);
void     get_disk_usage(uint32_t* total_mb, uint32_t* free_mb);
void     get_ip_address(char* buf, size_t len);
void     get_mac_address(char* buf, size_t len);
void     get_hostname_info(char* buf, size_t len);
void     get_arch_name(char* buf, size_t len);
uint32_t get_swap_total_mb(void);
uint16_t get_open_fd_count(void);

int build_sysinfo_response(uint8_t* buffer, size_t max_len);

#endif // SYSINFO_H
