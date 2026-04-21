#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Week 3 Milestone: BPF Maps and Structs
#define WINDOW_NS 1000000000ULL      // 1-second rate limit window
#define BLOCK_TIME_NS 30000000000ULL // 30-second temporary block

struct rate_tracker {
    __u64 count;
    __u64 window_start;
};

// Blocklist: Key = Source IP, Value = Expiration Timestamp
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} blocklist SEC(".maps");

// Rate limit trackers per protocol
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_tracker);
} syn_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_tracker);
} icmp_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_tracker);
} udp_tracker SEC(".maps");

// Helper function to check and update rate limits
static __always_inline int check_rate_limit(void *tracker_map, __u32 ip, __u64 now, __u64 threshold) {
    struct rate_tracker *tracker = bpf_map_lookup_elem(tracker_map, &ip);
    
    if (!tracker) {
        struct rate_tracker new_tracker = { .count = 1, .window_start = now };
        bpf_map_update_elem(tracker_map, &ip, &new_tracker, BPF_ANY);
        return 0; // Not blocked
    }

    if (now - tracker->window_start > WINDOW_NS) {
        // Window expired, reset counter
        tracker->count = 1;
        tracker->window_start = now;
    } else {
        tracker->count++;
        if (tracker->count > threshold) {
            return 1; // Threshold exceeded, trigger block
        }
    }
    return 0;
}

SEC("xdp")
int xdp_ips_main(struct xdp_md *ctx) {
    // Week 1 & 2 Milestone: Packet Parsing & Bounds Checking
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 now      = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;

    // Week 4 Milestone: Blocklist Enforcement
    __u64 *expiry_time = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (expiry_time) {
        if (now < *expiry_time) {
            // SLIDING WINDOW: The attacker is still sending packets.
            // Reset their 30-second expiration clock.
            *expiry_time = now + BLOCK_TIME_NS; 
            
            return XDP_DROP;
        } else {
            // The 30 seconds have passed with zero traffic.
            // Block expired, clean it up.
            bpf_map_delete_elem(&blocklist, &src_ip);
        }
    }

    // Week 3 Milestone: Detection Rules
    int trigger_block = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;

        // SYN Flood Rule: 100 pkts/s threshold
        if (tcph->syn && !tcph->ack) {
            if (check_rate_limit(&syn_tracker, src_ip, now, 100)) {
                trigger_block = 1;
                bpf_printk("SYN flood detected. Blocking IP.\n");
            }
        }
    } 
    else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
        if ((void *)(icmph + 1) > data_end) return XDP_PASS;

        // ICMP Flood Rule: 50 pkts/s threshold
        if (icmph->type == ICMP_ECHO) {
            if (check_rate_limit(&icmp_tracker, src_ip, now, 50)) {
                trigger_block = 1;
                bpf_printk("ICMP flood detected. Blocking IP.\n");
            }
        }
    }
    else if (iph->protocol == IPPROTO_UDP) {
        // UDP Flood Rule: 200 pkts/s threshold
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end) return XDP_PASS;

        if (check_rate_limit(&udp_tracker, src_ip, now, 200)) {
            trigger_block = 1;
            bpf_printk("UDP flood detected. Blocking IP.\n");
        }
    }

    // Apply the block if any rule was triggered
    if (trigger_block) {
        __u64 block_until = now + BLOCK_TIME_NS;
        bpf_map_update_elem(&blocklist, &src_ip, &block_until, BPF_ANY);
        return XDP_DROP;
    }

    return XDP_PASS;
}