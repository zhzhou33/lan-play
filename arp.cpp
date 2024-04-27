#include "arp.h"
#include <cstdint>

uint8_t NONE_IP[4] = {0, 0, 0, 0};
uint8_t NONE_MAC[6] = {0, 0, 0, 0, 0, 0};
uint8_t BROADCASE_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

Arp_Helper::Arp_Helper(void *pcap)
{
    m_lruCache = new LRUCache();

    m_etherHelper = new Ether_Helper(pcap);
}

int Arp_Helper::process_arp(packet_ctx *arg, const ether_frame *ether)
{
    arp arp;
    parse_arp(ether, &arp);

    if (arp.hardware_type != ARP_HARDTYPE_ETHER
        || arp.protocol_type != ETHER_TYPE_IPV4
        || arp.hardware_size != 6
        || arp.protocol_size != 4)
    {
        std::cout << "Unknown hardware or protocol" << std::endl;
        return -1;
    }

    arp_set(arp.sender_mac, arp.sender_ip);

    switch (arp.opcode)
    {
    case ARP_OPCODE_REQUEST:
        return arp_request(arg, &arp);
    case ARP_OPCODE_REPLY:
        return arp_reply(arg, &arp);
    }

    return -1;
}

void Arp_Helper::parse_arp(const ether_frame *ether, arp *arp)
{
    const u_char *packet = ether->payload;
    arp->hardware_type = READ_NET16(packet, ARP_OFF_HARDWARE);
    arp->protocol_type = READ_NET16(packet, ARP_OFF_PROTOCOL);
    arp->hardware_size = READ_NET8(packet, ARP_OFF_HARDWARE_SIZE);
    arp->protocol_size = READ_NET8(packet, ARP_OFF_PROTOCOL_SIZE);
    arp->opcode = READ_NET16(packet, ARP_OFF_OPCODE);

    CPY_MAC(arp->sender_mac, packet + ARP_OFF_SENDER_MAC);
    CPY_IPV4(arp->sender_ip, packet + ARP_OFF_SENDER_IP);
    CPY_MAC(arp->target_mac, packet + ARP_OFF_TARGET_MAC);
    CPY_IPV4(arp->target_ip, packet + ARP_OFF_TARGET_IP);

    arp->payload = NULL;
}

void Arp_Helper::arp_set(uint8_t *mac, uint8_t *ip)
{
    m_lruCache->put(ip, mac);
}

int Arp_Helper::arp_request(packet_ctx *arg, const arp *arp)
{
    if (IS_SUBNET(arp->target_ip, arg->subnet_net, arg->subnet_mask))
    {
        if (CMP_IPV4(arp->target_ip, arp->sender_ip))
            return 0;
        if (CMP_IPV4(arp->sender_ip, NONE_IP))
            return 0;
        if (arp_lru_has_ip(const_cast<struct arp *>(arp)->target_ip))
            return 0;
        return send_arp(arg,
                        ARP_OPCODE_REPLY,
                        arg->mac,
                        arp->target_ip,
                        arp->sender_mac,
                        arp->sender_ip);
    }
    return 0;
}

int Arp_Helper::arp_reply(packet_ctx *arg, const arp *arp)
{
    return 0;
}

bool Arp_Helper::arp_lru_has_ip(uint8_t *ip)
{
    return m_lruCache->get(ip);
}

int Arp_Helper::send_arp(packet_ctx *self,
                         uint8_t opcode,
                         const void *sender_mac,
                         const void *sender_ip,
                         const void *target_mac,
                         const void *target_ip)
{
    uint8_t buffer[ARP_LEN];
    struct payload part;

    WRITE_NET16(buffer, ARP_OFF_HARDWARE, ARP_HARDTYPE_ETHER);
    WRITE_NET16(buffer, ARP_OFF_PROTOCOL, ETHER_TYPE_IPV4);
    WRITE_NET8(buffer, ARP_OFF_HARDWARE_SIZE, 6);
    WRITE_NET8(buffer, ARP_OFF_PROTOCOL_SIZE, 4);
    WRITE_NET16(buffer, ARP_OFF_OPCODE, opcode);

    CPY_MAC(buffer + ARP_OFF_SENDER_MAC, sender_mac);
    CPY_IPV4(buffer + ARP_OFF_SENDER_IP, sender_ip);
    CPY_MAC(buffer + ARP_OFF_TARGET_MAC, target_mac);
    CPY_IPV4(buffer + ARP_OFF_TARGET_IP, target_ip);

    part.ptr = buffer;
    part.len = ARP_LEN;
    part.next = NULL;

    return m_etherHelper->send_ether(
        self,
        sender_mac,
        target_mac,
        ETHER_TYPE_ARP,
        &part);
}
