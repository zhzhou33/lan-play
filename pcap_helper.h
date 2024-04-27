#pragma once
#include <cstdint>
#include <pcap/pcap.h>

#include "packet.h"

class Arp_Helper;

typedef struct pcap_result_st
{
    void *pcap_handle;
    unsigned int ether_count;
    unsigned int ip_count;
    unsigned int tcp_count;
    unsigned int udp_count;
    unsigned int arp_count;
    pcap_result_st() :
        pcap_handle(nullptr), ether_count(0), ip_count(0), tcp_count(0), udp_count(0), arp_count(0)
    {
    }
} pcap_result;

typedef struct pacp_packet_st
{
} pacp_packet;

class Pcap_Helper
{
public:
    static Pcap_Helper *getInstance()
    {
        static Pcap_Helper *m_pInstance = new Pcap_Helper();
        return m_pInstance;
    }

    void pcapCallBack(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

    bool init(const char *pcapFile);

    void handlePcapLoop();

    ~Pcap_Helper();

private:
    Pcap_Helper() {}

    Pcap_Helper(const Pcap_Helper &) = delete;

    Pcap_Helper &operator=(const Pcap_Helper &) = delete;

    int process_ether(packet_ctx *arg, const u_char *packet, uint16_t len);

    int process_arp(packet_ctx *arg, const ether_frame *ether);

    int process_ipv4(packet_ctx *arg, const ether_frame *ether);

    void parse_ether(const u_char *packet, uint16_t len, ether_frame *ether);

    void parse_arp(const ether_frame *ether, arp *arp);

    void parse_ipv4(const ether_frame *ether, ipv4 *ipv4);

    void handlePacketIP(pacp_packet *pkt);

    void handlePacketARP(pacp_packet *pkt);

    void handlePacketTCP(pacp_packet *pkt);

private:
    pcap_result m_stPcapResult;

    Arp_Helper *m_arpHelper;

    packet_ctx *m_pktCtx;
};