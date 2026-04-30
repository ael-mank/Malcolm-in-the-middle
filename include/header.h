#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <net/if.h>

typedef struct s_mac {
    uint8_t bytes[6];
} t_mac;

typedef struct s_arp_frame {
    struct ethhdr   ether;
    struct arphdr   arp;
    uint8_t         sender_mac[6];
    uint8_t         sender_ip[4];
    uint8_t         target_mac[6];
    uint8_t         target_ip[4];
}   t_arp_frame;

typedef struct s_data {
    char            iface[IFNAMSIZ];
    int             ifaceIdx;
    int             sockfd;
    t_mac           src_mac;
    t_mac           tgt_mac;
    uint8_t         src_ip[4];
    uint8_t         tgt_ip[4];
} t_data;