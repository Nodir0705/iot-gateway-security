// XDP IoT Security Gateway — Combined Filter
// Pipeline: Blacklist check → Rate limit → Bypass classification
// This is the production XDP program

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// === MAPS ===

// IP Blacklist (C2, botnet, attackers)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u32);
} blacklist SEC(".maps");

// IP Whitelist (trusted services)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u32);
} whitelist SEC(".maps");

// Rate limiting per source IP
struct rate_entry {
    __u64 count;
    __u64 last_reset;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_entry);
} ip_rate SEC(".maps");

// Config: 0=SYN limit, 1=UDP limit, 2=window_ns
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} config SEC(".maps");

// Stats: 0=total, 1=passed, 2=blacklist_drop, 3=ratelimit_drop, 4=bypassed, 5=to_inspect
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} gw_stats SEC(".maps");

// Flow metadata export (for Part 4 Flow Extractor)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_table SEC(".maps");

// === HELPERS ===

static __always_inline void inc_stat(__u32 key)
{
    __u64 *val = bpf_map_lookup_elem(&gw_stats, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline __u64 get_config(__u32 key, __u64 default_val)
{
    __u64 *val = bpf_map_lookup_elem(&config, &key);
    return (val && *val > 0) ? *val : default_val;
}

// === MAIN XDP PROGRAM ===

SEC("xdp")
int xdp_gateway_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    inc_stat(0); // total

    // --- Parse headers ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 pkt_len = bpf_ntohs(ip->tot_len);

    // --- STAGE 1: Blacklist check ---
    if (bpf_map_lookup_elem(&blacklist, &src_ip) ||
        bpf_map_lookup_elem(&blacklist, &dst_ip)) {
        inc_stat(2); // blacklist drop
        return XDP_DROP;
    }

    // --- Parse L4 ---
    __u16 src_port = 0, dst_port = 0;
    int is_syn = 0, is_udp = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        is_syn = (tcp->syn && !tcp->ack) ? 1 : 0;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
        is_udp = 1;
    }

    // --- STAGE 2: Rate limiting (SYN + UDP only) ---
    if (is_syn || is_udp) {
        __u64 limit = is_syn ?
            get_config(0, 100) :
            get_config(1, 500);
        __u64 window = get_config(2, 1000000000ULL);

        struct rate_entry *entry = bpf_map_lookup_elem(&ip_rate, &src_ip);
        if (entry) {
            if (now - entry->last_reset > window) {
                entry->count = 1;
                entry->last_reset = now;
            } else {
                entry->count++;
                if (entry->count > limit) {
                    inc_stat(3); // rate limit drop
                    return XDP_DROP;
                }
            }
        } else {
            struct rate_entry new_entry = { .count = 1, .last_reset = now };
            bpf_map_update_elem(&ip_rate, &src_ip, &new_entry, BPF_ANY);
        }
    }

    // --- STAGE 3: Flow tracking (metadata for NPU — Part 4/5) ---
    struct flow_key fkey = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = ip->protocol,
    };

    struct flow_value *fval = bpf_map_lookup_elem(&flow_table, &fkey);
    if (fval) {
        __sync_fetch_and_add(&fval->packets, 1);
        __sync_fetch_and_add(&fval->bytes, pkt_len);
        fval->last_seen = now;
    } else {
        struct flow_value new_flow = {
            .packets = 1,
            .bytes = pkt_len,
            .first_seen = now,
            .last_seen = now,
        };
        bpf_map_update_elem(&flow_table, &fkey, &new_flow, BPF_ANY);
    }

    // --- STAGE 4: Whitelist bypass ---
    if (bpf_map_lookup_elem(&whitelist, &src_ip) ||
        bpf_map_lookup_elem(&whitelist, &dst_ip)) {
        inc_stat(4); // bypassed
        return XDP_PASS;
    }

    inc_stat(5); // needs Suricata inspection
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
