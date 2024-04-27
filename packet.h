#pragma once

#include <cstdint>
#include <sys/types.h>
#define ETHER_OFF_DST 0
#define ETHER_OFF_SRC 6
#define ETHER_OFF_TYPE 12
#define ETHER_OFF_END 14
#define ETHER_OFF_ARP 14
#define ETHER_OFF_IPV4 14
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_IPV4 0x0800
#define ETHER_HEADER_LEN 14

#define IPV4_PROTOCOL_ICMP 1
#define IPV4_PROTOCOL_TCP 6
#define IPV4_PROTOCOL_UDP 17
#define IPV4_HEADER_LEN 20

#define IPV4_OFF_VER_LEN 0
#define IPV4_OFF_DSCP_ECN 1
#define IPV4_OFF_TOTAL_LEN 2
#define IPV4_OFF_ID 4
#define IPV4_OFF_FLAGS_FRAG_OFFSET 6
#define IPV4_OFF_TTL 8
#define IPV4_OFF_PROTOCOL 9
#define IPV4_OFF_CHECKSUM 10
#define IPV4_OFF_SRC 12
#define IPV4_OFF_DST 16
#define IPV4_OFF_END 20

#define IPV4P_OFF_SRC 0
#define IPV4P_OFF_DST 4
#define IPV4P_OFF_ZERO 8
#define IPV4P_OFF_PROTOCOL 9
#define IPV4P_OFF_LENGTH 10
#define IPV4P_OFF_END 12

#define UDP_OFF_SRCPORT 0
#define UDP_OFF_DSTPORT 2
#define UDP_OFF_LENGTH 4
#define UDP_OFF_CHECKSUM 6
#define UDP_OFF_END 8

#define ARP_OFF_HARDWARE 0
#define ARP_OFF_PROTOCOL 2
#define ARP_OFF_HARDWARE_SIZE 4
#define ARP_OFF_PROTOCOL_SIZE 5
#define ARP_OFF_OPCODE 6
#define ARP_OFF_SENDER_MAC 8
#define ARP_OFF_SENDER_IP 14
#define ARP_OFF_TARGET_MAC 18
#define ARP_OFF_TARGET_IP 24
#define ARP_OFF_END 28
#define ARP_LEN 28
#define ARP_HARDTYPE_ETHER 1
#define ARP_OPCODE_REQUEST 1
#define ARP_OPCODE_REPLY 2

static u_char AnyMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t SEND_BUFFER[2048];
struct packet_ctx
{
    // struct lan_play *arg;
    void *buffer;           // data send
    size_t buffer_len;      // length
    uint8_t ip[4];          // "10.13.37.1"
    uint8_t subnet_net[4];  // "10.13.0.0"
    uint8_t subnet_mask[4]; // "255.255.0.0"
    const uint8_t *mac;     // local mac
    uint16_t identification;
    // struct arp_item arp_list[ARP_CACHE_LEN];
    time_t arp_ttl;

    uint64_t upload_byte;
    uint64_t download_byte;
    uint64_t upload_packet;
    uint64_t download_packet;
};

struct ether_frame
{
    const u_char *raw;
    uint16_t raw_len;
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
    const u_char *payload;
};

struct ipv4
{
    const struct ether_frame *ether;
    uint8_t version;
    // unit: byte
    uint8_t header_len;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_len;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src[4];
    uint8_t dst[4];
    const u_char *payload;
};

struct udp
{
    const struct ipv4 *ipv4;
    uint16_t srcport;
    uint16_t dstport;
    uint16_t length;
    uint16_t checksum;
    const u_char *payload;
};

struct arp
{
    const struct ether_frame *ether;
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
    const u_char *payload;
};

struct icmp
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
    uint64_t timestamp;
    const u_char *payload;
};

struct payload
{
    const u_char *ptr;          // cur header
    uint16_t len;               // cur header len
    const struct payload *next; // payload
};