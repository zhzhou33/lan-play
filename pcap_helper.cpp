#include "pcap_helper.h"
#include "arp.h"
#include "packet.h"
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <sys/types.h>

bool Pcap_Helper::init(const char *pcapFile)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = nullptr;
    if (strlen(pcapFile) != 0)
        handle = pcap_open_offline(pcapFile, errbuf);
    else
        handle = pcap_open_live("eth0", BUFSIZ, 1, 0, errbuf);
    if (!handle)
    {
        fprintf(stderr, "error in pcap_open_offline: %s \n", errbuf);
        return false;
    }
    m_stPcapResult.pcap_handle = handle;

    m_arpHelper = new Arp_Helper((void *)handle);

    m_pktCtx = new packet_ctx();

    memset(m_pktCtx, 0, sizeof(*m_pktCtx));

    // CPY_IPV4(m_pktCtx->ip, str2ip(SERVER_IP));
    // CPY_IPV4(m_pktCtx->subnet_net, str2ip(SUBNET_NET));
    // CPY_IPV4(m_pktCtx->subnet_mask, str2ip(SUBNET_MASK));
    m_pktCtx->mac = AnyMac;
    m_pktCtx->arp_ttl = 30;
    m_pktCtx->buffer = SEND_BUFFER;
    m_pktCtx->buffer_len = sizeof(SEND_BUFFER);
    uint8_t curMac[6];
    get_mac_address("eth0", curMac);
    m_pktCtx->mac = curMac;

    return true;
}

Pcap_Helper::~Pcap_Helper()
{
    pcap_close((pcap_t *)m_stPcapResult.pcap_handle);
}

void Pcap_Helper::handlePcapLoop()
{
    // 不能传类的非静态成员函数的原因是,有this指针存在,而静态成员函数则没有
    // pcap_loop((pcap_t *)res->pcap_handle, 0, pcapCallBack, (u_char *)res);
    // c 语言的方法不支持 this 指针的捕获
    pcap_loop((pcap_t *)m_stPcapResult.pcap_handle, 0, [](u_char *user_data, const struct pcap_pkthdr *pkt_info, const u_char *packet)
              { Pcap_Helper::getInstance()->pcapCallBack(user_data, pkt_info, packet); },
              /* (u_char *)&m_stPcapResult */ NULL);
}

void Pcap_Helper::pcapCallBack(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    /*     // pcap_result *res = (pcap_result *)userData;
        m_stPcapResult.ether_count++;

        if (pkthdr->caplen != pkthdr->len)
            return;
        pacp_packet pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ether_len = pkthdr->caplen;
        pkt.ether_packet = (struct ether_header *)packet;

        unsigned char *src_mac = pkt.ether_packet->ether_shost;
        unsigned char *dst_mac = pkt.ether_packet->ether_dhost;
        printf("src_mac:%x:%x:%x:%x:%x:%x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        printf("dst_mac:%x:%x:%x:%x:%x:%x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
        // printf("ether_type:%u\n",ethernet->ether_type);

        switch (ntohs(pkt.ether_packet->ether_type))
        {
        case ETHERTYPE_IP:
            pkt.ip_len = pkt.ether_len - sizeof(*pkt.ether_packet);
            pkt.ip_packet = (struct iphdr *)((u_char *)pkt.ether_packet + sizeof(*pkt.ether_packet));
            handlePacketIP(&pkt);
            break;
        case ETHERTYPE_ARP:
            handlePacketARP(&pkt);
            break;
        default:
            break;
        } */
    if (pkthdr->caplen != pkthdr->len)
        return;
    process_ether(m_pktCtx, packet, pkthdr->len);
}

int Pcap_Helper::process_ether(packet_ctx *arg, const u_char *packet, uint16_t len)
{
    struct ether_frame ether;
    parse_ether(packet, len, &ether);
    // 报文的src_ip 是本机ip
    if (CMP_MAC(ether.src, arg->mac))
    {
        return 0;
    }

    switch (ether.type)
    {
    case ETHER_TYPE_ARP:
        return m_arpHelper->process_arp(arg, &ether);
    case ETHER_TYPE_IPV4:
        return process_ipv4(arg, &ether);
    default:
        return 0; // just ignore them
    }
}

int Pcap_Helper::process_ipv4(packet_ctx *arg, const ether_frame *ether)
{
    return 0;
}

void Pcap_Helper::parse_ether(const u_char *packet, uint16_t len, ether_frame *ether)
{
    CPY_MAC(ether->dst, packet + ETHER_OFF_DST);
    CPY_MAC(ether->src, packet + ETHER_OFF_SRC);
    ether->raw = packet;
    ether->raw_len = len;
    ether->type = READ_NET16(packet, ETHER_OFF_TYPE);
    ether->payload = packet + ETHER_OFF_END;
}

void Pcap_Helper::parse_arp(const ether_frame *ether, arp *arp)
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

void Pcap_Helper::parse_ipv4(const ether_frame *ether, ipv4 *ipv4)
{
    const u_char *packet = ether->payload;
    uint8_t t;
    uint16_t tt;

    ipv4->ether = ether;
    t = READ_NET8(packet, IPV4_OFF_VER_LEN);
    ipv4->version = t >> 4;
    ipv4->header_len = (t & 0xF) * 4;
    t = READ_NET8(packet, IPV4_OFF_DSCP_ECN);
    ipv4->dscp = t >> 2;
    ipv4->ecn = t & 3; // 0b11
    ipv4->total_len = READ_NET16(packet, IPV4_OFF_TOTAL_LEN);
    ipv4->identification = READ_NET16(packet, IPV4_OFF_ID);
    tt = READ_NET16(packet, IPV4_OFF_FLAGS_FRAG_OFFSET);
    ipv4->flags = tt >> 13;
    ipv4->fragment_offset = tt & 0x1fff;
    ipv4->ttl = READ_NET8(packet, IPV4_OFF_TTL);
    ipv4->protocol = READ_NET8(packet, IPV4_OFF_PROTOCOL);
    ipv4->checksum = READ_NET16(packet, IPV4_OFF_PROTOCOL);
    CPY_IPV4(ipv4->src, packet + IPV4_OFF_SRC);
    CPY_IPV4(ipv4->dst, packet + IPV4_OFF_DST);
    ipv4->payload = packet + ipv4->header_len;
}

// void Pcap_Helper::handlePacketIP(pacp_packet *pkt)
// {
//     m_stPcapResult.ip_count++;
//     if (pkt->ip_packet->version != 4)
//     {
//         return;
//     }

//     int ip_hdr_len = pkt->ip_packet->ihl << 2; // 单位是4B
//     // |前导字段|帧起始定界符|目的地址|源地址|类型|负载|填充|帧校验CRC
//     //     7        1         6     6     2  46~1500     4
//     // |<--  被MAC滤除  -->|<--    用于计算FCS      -->|  FCS
//     int ip_total_len = ntohs(pkt->ip_packet->tot_len);
//     // 判断片偏移是否为0(是否分片的首个ip包)
//     if ((ntohs(pkt->ip_packet->frag_off) & IP_OFFMASK) != 0)
//     {
//         return;
//     }

//     unsigned char *saddr = (unsigned char *)&pkt->ip_packet->saddr; // 网络字节序转换成主机字节序
//     unsigned char *daddr = (unsigned char *)&pkt->ip_packet->daddr;

//     // printf("eth_len:%u  ip_len:%u  tcp_len:%u  udp_len:%u\n", eth_len, ip_len, tcp_len, udp_len);
//     printf("src_ip:%d.%d.%d.%d\n", saddr[0], saddr[1], saddr[2], saddr[3] /*InttoIpv4str(saddr)*/); // 源IP地址
//     printf("dst_ip:%d.%d.%d.%d\n", daddr[0], daddr[1], daddr[2], daddr[3] /*InttoIpv4str(daddr)*/); // 目的IP地址

//     switch (pkt->ip_packet->protocol)
//     {
//     case IPPROTO_TCP:
//         pkt->tcp_len = ip_total_len - ip_hdr_len;
//         if (pkt->tcp_len <= 0)
//             return;
//         pkt->tcp_packet = (struct tcphdr *)((u_char *)pkt->ip_packet + ip_hdr_len);
//         handlePacketTCP(pkt);
//         break;
//     case IPPROTO_UDP:
//         break;
//     case IPPROTO_ICMP:
//         break;
//     default:
//         break;
//     }
// }

// void Pcap_Helper::handlePacketTCP(pacp_packet *pkt)
// {
//     m_stPcapResult.tcp_count++;
//     int tcp_hdr_len = pkt->tcp_packet->th_off * 4;
//     printf("tcp_sport = %u\n", ntohs(pkt->tcp_packet->th_sport));
//     printf("tcp_dport = %u\n", ntohs(pkt->tcp_packet->th_dport));
//     printf("tcp_header_len = %u\n", tcp_hdr_len);
//     pkt->payload_len = pkt->tcp_len - tcp_hdr_len;
//     pkt->payload = (u_char *)pkt->tcp_packet + tcp_hdr_len;

//     printf("============================================\n");
// }

// void Pcap_Helper::handlePacketARP(pacp_packet *pkt)
// {
// }
