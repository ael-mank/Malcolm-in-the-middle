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
    {
        printf("Usage: \n./ft_malcom <src ip> <src mac address> <target ip> <target mac address>\n");
        return 1;
    }
    else if (verify_ip_adress(argv[1]) == 1 || verify_ip_adress(argv[3]) == 1)
    {
        printf("Invalid IP address format \n");
        return 1;
    }
    else if (verify_mac_adress(argv[2]) == 1 || verify_mac_adress(argv[4]) == 1)
    {
        printf("Invalid MAC address format \n");
        return 1;
    }
    printf("looks good\n");
    return 0;
}

int find_interface(const char *target_ip_str)
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
            printf("Found available interface: %s\n", ifa->ifa_name);
            freeifaddrs(ifas);
            return 0;
        }
    }
    fprintf(stderr, "ft_malcolm: no interface found on the same subnet as target\n");
    freeifaddrs(ifas);
    return -1;
}

int main(int argc, char **argv)
{
    if (parse_args(argc, argv) == 1)
        return 1;
    if (find_interface(argv[3]) < 0)
        return 1;
    return 0;
}