#pragma once
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <pcap.h>

#define SERVER_IP "10.13.37.1"
#define SUBNET_NET "10.13.0.0"
#define SUBNET_MASK "255.255.0.0"

#define READ_NET8(packet, offset) (*(uint8_t *)((uint8_t *)packet + offset))
#define READ_NET16(packet, offset) ntohs(*(uint16_t *)((uint8_t *)packet + offset))
#define WRITE_NET8(packet, offset, v) (*(uint8_t *)((uint8_t *)packet + offset) = v)
#define WRITE_NET16(packet, offset, v) (*(uint16_t *)((uint8_t *)packet + offset) = htons(v))

#define CPY_MAC(mac1, mac2) (memcpy(mac1, mac2, 6))
#define CPY_IPV4(ip1, ip2) (memcpy(ip1, ip2, 4))
#define CMP_MAC(mac1, mac2) (memcmp(mac1, mac2, 4) == 0)
#define CMP_IPV4(ip1, ip2) (memcmp(ip1, ip2, 4) == 0)

#define IS_SUBNET(ip, net, mask) (((*(uint32_t *)ip) & (*(uint32_t *)mask)) == *(uint32_t *)net)

inline void *str2ip(const char *ip)
{
    static uint8_t bin[4];
    int p[4];
    int i;
    sscanf(ip, "%d.%d.%d.%d", &p[0], &p[1], &p[2], &p[3]);
    for (i = 0; i < 4; i++)
    {
        bin[i] = p[i];
    }
    return bin;
}

int get_mac_address(const char *name, u_char mac_addr[6]);
