bool verify_number_args(int argc)
{
    if (argc != 4)
    {
        printf("Usage: \n./ft_malcom <src ip> <src mac address> <target ip> <target mac address>\n");
        return 1;
    }
}

bool verify_ip_adress(const char *str) // str is ip address src or targ
{
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) // inet_pton rempli la struct addr 
        return 1;
    // printf("Ip %s is valid", str);
}

bool verify_mac_adress()
{
    
}