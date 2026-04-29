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
    int err;
    char hexa[]  = "0123456789abcdef";

    idx = 0;
    err = 0;
    if (ft_strlen(mac_addr) != 17)
        err = 1;
    while (idx < 17)
    {
        if ((idx + 1) % 3 == 0 && idx + 1 != '\0')
        {
            if (mac_addr[idx] != ':')
                err = 1;
        }
        else
        {
            char c = ft_tolower(mac_addr[idx]);
            int j = 0;
            int found = 0;

            while (hexa[j])
            {
                if (c == hexa[j])
                {
                    found = 1;
                    break;
                }
                j++;
            }
            if (!found)
                err = 1;
        }
        idx++;
    }
    return err;
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
        printf("Invalid IP address format");
        return 1;
    }
    else if (verify_mac_adress(argv[2]) == 1 || verify_mac_adress(argv[4]) == 1)
    {
        printf("Invalid MAC address format");
        return 1;
    }
    printf("looks good");
    return 0;
}


int main(int argc, char **argv)
{
    if (parse_args(argc, argv) == 1)
        return 1;
    return 0;
}