#pragma once
#include "ether.h"
#include "helper.h"
#include <cstddef>
#include <cstdint>
#include <unordered_map>

#define ARP_CACHE_LEN 100
#define ARP_TIME_EXPIRE 30 // 30s

class LRUCache;

class Arp_Helper
{
public:
    Arp_Helper(void *pcap);

    int process_arp(packet_ctx *arg, const ether_frame *ether);

private:
    void parse_arp(const ether_frame *ether, arp *arp);

    void arp_set(uint8_t *mac, uint8_t *ip);

    int arp_request(struct packet_ctx *self, const struct arp *arp);

    int arp_reply(packet_ctx *arg, const arp *arp);

    bool arp_lru_has_ip(uint8_t *ip);

    int send_arp(packet_ctx *self,
                 uint8_t opcode,
                 const void *sender_mac,
                 const void *sender_ip,
                 const void *target_mac,
                 const void *target_ip);

private:
    LRUCache *m_lruCache;
    Ether_Helper *m_etherHelper;
};

// 自定义哈希函数，用于 uint8_t[4] 类型
struct ArrayHasher
{
    std::size_t operator()(const uint8_t *key) const
    { // 自定义哈希算法，可以根据具体需求来实现
        std::size_t hashValue = 0;
        for (int i = 0; i < 4; ++i)
        {
            hashValue ^= std::hash<uint8_t>()(key[i]) + 0x9e3779b9 + (hashValue << 6) + (hashValue >> 2);
        }
        return hashValue;
    }
};

class LRUCache
{
public:
private:
    struct Node
    {
        uint8_t ip[4];  // key
        uint8_t mac[6]; // value<mac expire>
        time_t expireTime;
        Node *pre, *next;
        Node(uint8_t curIp[4], uint8_t curMac[6]) :
            pre(nullptr), next(nullptr)
        {
            if (!curIp || !curMac)
                return;
            CPY_IPV4(ip, curIp);
            CPY_MAC(mac, curMac);
            expireTime = time(NULL) + ARP_TIME_EXPIRE;
        }
    };
    std::unordered_map<uint8_t *, Node *, ArrayHasher> hashTable;
    Node *head, *tail;

private:
    void remove(Node *node, bool needDelete = false)
    {
        Node *pre = node->pre;
        Node *next = node->next;
        pre->next = next;
        next->pre = pre;
        if (needDelete)
            hashTable.erase(node->ip);
    }

    // insert new node
    void insert(uint8_t curIp[4], uint8_t curMac[6])
    {
        Node *pre = tail->pre;
        Node *next = tail;
        Node *newNode = new Node(curIp, curMac);

        pre->next = newNode;
        newNode->next = next;
        next->pre = newNode;
        newNode->pre = pre;

        hashTable[newNode->ip] = newNode;
    }

    void insert(Node *node)
    {
        // cur
        node->next = tail;
        node->pre = tail->pre;

        node->pre->next = node;
        tail->pre = node;

        node->expireTime = time(NULL) + ARP_TIME_EXPIRE;
    }

public:
    LRUCache()
    {
        head = new Node(nullptr, nullptr);
        tail = new Node(nullptr, nullptr);
        head->next = tail;
        tail->pre = head;
    }

    uint8_t *get(uint8_t curIp[4])
    {
        if (hashTable.count(curIp))
        {
            Node *node = hashTable[curIp];
            remove(node);
            insert(node);
            return node->mac;
        }
        return nullptr;
    }

    void put(uint8_t curIp[4], uint8_t curMac[6])
    {
        if (hashTable.count(curIp))
        {
            Node *node = hashTable[curIp];
            remove(node);
            CPY_MAC(node->mac, curMac);
            insert(node);
            return;
        }
        if (hashTable.size() == ARP_CACHE_LEN)
        {
            Node *node = head->next;
            remove(node, true);
            insert(curIp, curMac);
            return;
        }
        // 缓存未满
        insert(curIp, curMac);
        return;
    }
};