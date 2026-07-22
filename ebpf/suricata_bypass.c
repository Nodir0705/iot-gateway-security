/**
 * suricata_bypass.c — Suricata eBPF flow bypass filter (BTF map style)
 *
 * Compatible with libbpf v1.0+ (uses BTF-defined maps instead of legacy).
 * Matches Suricata 7.0's expected interface: section "filter", maps
 * "flow_table_v4" and "flow_table_v6".
 *
 * Build:
 *   clang -O2 -target bpf -c suricata_bypass.c -o suricata_bypass.bpf \
 *         -I/usr/include -I/usr/include/bpf
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VLAN_TRACKING 1

struct flowv4_keys {
    __u32 src;
    __u32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct flowv6_keys {
    __u32 src[4];
    __u32 dst[4];
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct pair {
    __u64 packets;
    __u64 bytes;
};

/* BTF-defined maps (libbpf v1.0+ compatible) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct flowv4_keys);
    __type(value, struct pair);
    __uint(max_entries, 32768);
} flow_table_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct flowv6_keys);
    __type(value, struct pair);
    __uint(max_entries, 32768);
} flow_table_v6 SEC(".maps");

struct vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

static __always_inline int ipv4_filter(struct __sk_buff *skb, __u16 vlan0, __u16 vlan1)
{
    void *data = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    __u32 nhoff = skb->cb[0];

    /* Bounds check for IP header */
    if (data + nhoff + sizeof(struct iphdr) > data_end)
        return -1;

    struct iphdr *iph = data + nhoff;

    struct flowv4_keys tuple = {};
    tuple.src = iph->saddr;
    tuple.dst = iph->daddr;
    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            tuple.ip_proto = 1;
            break;
        case IPPROTO_UDP:
            tuple.ip_proto = 0;
            break;
        default:
            return -1;
    }

    /* Fixed 20-byte IP header for verifier compatibility */
    __u32 port_off = nhoff + 20;
    if (data + port_off + 4 > data_end)
        return -1;

    __u32 *ports = data + port_off;
    tuple.ports = *ports;
    /* Swap ports: Suricata stores dst:src order */
    __u16 port = tuple.port16[1];
    tuple.port16[1] = tuple.port16[0];
    tuple.port16[0] = port;

    struct pair *value = bpf_map_lookup_elem(&flow_table_v4, &tuple);
    if (value) {
        value->packets++;
        value->bytes += skb->len;
        return 0;
    }
    return -1;
}

static __always_inline int ipv6_filter(struct __sk_buff *skb, __u16 vlan0, __u16 vlan1)
{
    void *data = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    __u32 nhoff = skb->cb[0];

    if (data + nhoff + 40 > data_end)
        return -1;

    struct ipv6hdr *ip6h = data + nhoff;

    struct flowv6_keys tuple = {};
    __builtin_memcpy(tuple.src, &ip6h->saddr, 16);
    __builtin_memcpy(tuple.dst, &ip6h->daddr, 16);
    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    switch (ip6h->nexthdr) {
        case IPPROTO_TCP:
            tuple.ip_proto = 1;
            break;
        case IPPROTO_UDP:
            tuple.ip_proto = 0;
            break;
        default:
            return -1;
    }

    __u32 port_off = nhoff + 40;
    if (data + port_off + 4 > data_end)
        return -1;

    __u32 *ports = data + port_off;
    tuple.ports = *ports;
    __u16 port = tuple.port16[1];
    tuple.port16[1] = tuple.port16[0];
    tuple.port16[0] = port;

    struct pair *value = bpf_map_lookup_elem(&flow_table_v6, &tuple);
    if (value) {
        value->packets++;
        value->bytes += skb->len;
        return 0;
    }
    return -1;
}

SEC("filter")
int hashfilter(struct __sk_buff *skb)
{
    void *data = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    __u32 nhoff = ETH_HLEN;

    if (data + nhoff > data_end)
        return -1;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 proto = bpf_ntohs(eth->h_proto);
    __u16 vlan0 = skb->vlan_tci & 0x0fff;
    __u16 vlan1 = 0;

    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {
        if (data + nhoff + sizeof(struct vlan_hdr) > data_end)
            return -1;
        struct vlan_hdr *vhdr = data + nhoff;
        proto = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
#if VLAN_TRACKING
        vlan1 = bpf_ntohs(vhdr->h_vlan_TCI) & 0x0fff;
#endif
        nhoff += sizeof(struct vlan_hdr);
    }

    skb->cb[0] = nhoff;

    switch (proto) {
        case ETH_P_IP:
            return ipv4_filter(skb, vlan0, vlan1);
        case ETH_P_IPV6:
            return ipv6_filter(skb, vlan0, vlan1);
        default:
            break;
    }
    return -1;
}

char __license[] SEC("license") = "GPL";
