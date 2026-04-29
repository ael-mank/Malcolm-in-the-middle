#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct mac {
    uint8_t bytes[6];
} mac;

typedef struct arp_frame {
    struct ethhdr   ether;
    struct arphdr   arp;
    uint8_t         sender_mac[6];
    uint8_t         sender_ip[4];
    uint8_t         target_mac[6];
    uint8_t         target_ip[4];
}   arp_frame;

typedef struct data {
    char            iface[IFNAMSIZ];
    int             ifaceIdx;
    int             sockfd;
    t_mac           src_mac;
    t_mac           tgt_mac;
    uint8_t         src_ip[4];
    uint8_t         tgt_ip[4];
} data;