#pragma once
#include "packet.h"
#include <pcap/pcap.h>
class Ether_Helper
{
public:
    Ether_Helper(void *pcap) :
        m_pPcap((pcap_t *)pcap) {}

    int send_ether(
        packet_ctx *arg,
        const void *src,
        const void *dst,
        uint16_t type,
        const payload *payload);

private:
    int send_payloads(
        struct packet_ctx *self,
        const struct payload *payload);

private:
    pcap_t *m_pPcap;
};