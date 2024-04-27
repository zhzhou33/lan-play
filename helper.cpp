#include "helper.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>

int get_mac_address(pcap_if_t *d, pcap_t *p, u_char mac_addr[6])
{
    int fd = pcap_fileno(p);
    struct ifreq buffer;
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, d->name);
    int result = ioctl(fd, SIOCGIFHWADDR, &buffer);
    if (result < 0)
    {
        fprintf(stderr, "%s %d\n", strerror(errno), fd);
        exit(1);
    }
    memcpy(mac_addr, buffer.ifr_hwaddr.sa_data, 6);
    return result;
}

int get_mac_address(const char *name, u_char mac_addr[6])
{
    struct ifreq buffer;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    memset(&buffer, 0, sizeof(buffer));
    strncpy(buffer.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &buffer) < 0)
    {
        perror("ioctl SIOCGIFHWADDR failed");
        return 1;
    }
    memcpy(mac_addr, buffer.ifr_hwaddr.sa_data, 6);
    return 0;
}