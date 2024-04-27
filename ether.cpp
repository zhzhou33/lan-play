#include "ether.h"
#include "helper.h"
#include "packet.h"
#include <cassert>
#include <cstdint>
#include <cstdio>

int Ether_Helper::send_ether(
    packet_ctx *arg,
    const void *src,
    const void *dst,
    uint16_t type,
    const payload *payload)
{
    uint8_t buffer[ETHER_HEADER_LEN];
    struct payload part;

    part.ptr = buffer;
    part.len = ETHER_HEADER_LEN;
    part.next = payload;

    CPY_MAC(buffer + ETHER_OFF_DST, dst);
    CPY_MAC(buffer + ETHER_OFF_SRC, src);
    WRITE_NET16(buffer, ETHER_OFF_TYPE, type);

    return send_payloads(arg, &part);
}

int Ether_Helper::send_payloads(
    struct packet_ctx *self,
    const struct payload *payload)
{
    uint8_t *buf = (uint8_t *)self->buffer;
    const struct payload *part = payload;
    uint16_t total_len = 0;
    while (part)
    {
        if (buf - (uint8_t *)self->buffer + part->len >= self->buffer_len)
        {
            assert(0);
            return -1;
        }
        memcpy(buf, part->ptr, part->len);
        for (int i = 0; i < part->len; i++)
        {
            printf("%02x ", buf[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
        buf += part->len;
        total_len += part->len;

        part = part->next;
    }

    self->upload_packet++;
    self->upload_byte += total_len;

    printf("total len %d B\n", total_len);

    return pcap_sendpacket(m_pPcap, (const u_char *)self->buffer, total_len);
}