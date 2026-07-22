/**
 * xdp_filter.c — XDP L4 pre-filter for RK3588 IoT Security Gateway
 *
 * Runs at the earliest possible point in the network stack (before sk_buff
 * allocation). Provides:
 *   1. Known-good IP/port instant passthrough (whitelist)
 *   2. Known-bad IP instant drop (blacklist)
 *   3. Rate limiting per source IP (anti-DDoS)
 *
 * This dramatically reduces CPU load by filtering traffic before it reaches
 * Suricata or the kernel network stack.
 *
 * Build:
 *   clang -O2 -target bpf -c xdp_filter.c -o xdp_filter.bpf \
 *         -I/usr/include -I/usr/include/bpf
 *
 * Load:
 *   ip link set dev eth0 xdp obj xdp_filter.bpf sec xdp
 *
 * Unload:
 *   ip link set dev eth0 xdp off
 *
 * Manage maps (add/remove IPs):
 *   bpftool map update pinned /sys/fs/bpf/xdp_whitelist_ips \
 *     key 0xC0 0xA8 0x03 0x01  value 0x01 0x00 0x00 0x00
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ─── Maps ───────────────────────────────────────────────────────────── */

/* Whitelist: trusted IPs that bypass all inspection.
 * Key: __u32 (IPv4 addr, network byte order)
 * Value: __u32 (1 = whitelist active) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_whitelist_ips SEC(".maps");

/* Whitelist: trusted destination ports (e.g., 443 for HTTPS streaming).
 * Key: __u16 (port, host byte order)
 * Value: __u32 (1 = whitelist active) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_whitelist_ports SEC(".maps");

/* Blacklist: known malicious IPs — drop immediately.
 * Key: __u32 (IPv4 addr, network byte order)
 * Value: __u64 (drop counter) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_blacklist_ips SEC(".maps");

/* Rate limiter: per-source-IP packet counter with timestamp.
 * Used for basic DDoS mitigation. */
struct rate_entry {
    __u64 packet_count;
    __u64 window_start;  /* nanoseconds */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct rate_entry);
    __uint(max_entries, 8192);
} xdp_rate_limit SEC(".maps");

/* Stats counters: 0=passed, 1=dropped(blacklist), 2=dropped(ratelimit), 3=whitelisted */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} xdp_stats SEC(".maps");

/* ─── Constants ──────────────────────────────────────────────────────── */

#define RATE_WINDOW_NS  1000000000ULL  /* 1 second */
#define RATE_LIMIT_PPS  5000           /* packets per second per source IP */

/* ─── Helpers ────────────────────────────────────────────────────────── */

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&xdp_stats, &idx);
    if (val)
        (*val)++;
}

/* ─── XDP Program ────────────────────────────────────────────────────── */

SEC("xdp")
int xdp_iot_filter(struct xdp_md *ctx) {
    void *data = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;

    /* ── 1. Blacklist check (drop known malicious) ─────────────────── */
    __u64 *bl = bpf_map_lookup_elem(&xdp_blacklist_ips, &src_ip);
    if (bl) {
        __sync_fetch_and_add(bl, 1);
        inc_stat(1);
        return XDP_DROP;
    }

    /* ── 2. Whitelist IP check (bypass inspection) ─────────────────── */
    __u32 *wl = bpf_map_lookup_elem(&xdp_whitelist_ips, &dst_ip);
    if (wl) {
        inc_stat(3);
        return XDP_PASS;  /* fast path — no inspection needed */
    }

    /* Also check source IP whitelist (for return traffic) */
    wl = bpf_map_lookup_elem(&xdp_whitelist_ips, &src_ip);
    if (wl) {
        inc_stat(3);
        return XDP_PASS;
    }

    /* ── 3. Whitelist port check (streaming traffic bypass) ────────── */
    /* Use fixed 20-byte IP header offset for BPF verifier compatibility.
     * IP options are extremely rare in practice (<0.01% of traffic). */
    __u16 dst_port = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(eth + 1) + 20;
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(eth + 1) + 20;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        dst_port = bpf_ntohs(udph->dest);
    }

    if (dst_port > 0) {
        __u32 *pwl = bpf_map_lookup_elem(&xdp_whitelist_ports, &dst_port);
        if (pwl) {
            inc_stat(3);
            return XDP_PASS;
        }
    }

    /* ── 4. Rate limiting per source IP ────────────────────────────── */
    __u64 now = bpf_ktime_get_ns();
    struct rate_entry *rate = bpf_map_lookup_elem(&xdp_rate_limit, &src_ip);
    if (rate) {
        if (now - rate->window_start > RATE_WINDOW_NS) {
            /* New window */
            rate->packet_count = 1;
            rate->window_start = now;
        } else {
            rate->packet_count++;
            if (rate->packet_count > RATE_LIMIT_PPS) {
                inc_stat(2);
                return XDP_DROP;  /* rate exceeded — drop */
            }
        }
    } else {
        struct rate_entry new_entry = {
            .packet_count = 1,
            .window_start = now,
        };
        bpf_map_update_elem(&xdp_rate_limit, &src_ip, &new_entry, BPF_ANY);
    }

    /* ── 5. Default: pass to kernel / Suricata ─────────────────────── */
    inc_stat(0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
