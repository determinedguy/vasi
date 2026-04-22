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

// Define block reasons
#define REASON_SYN 1
#define REASON_ICMP 2
#define REASON_UDP 3
#define REASON_MANUAL 4

struct rate_tracker {
    __u64 count;
    __u64 window_start;
};

// Struct to hold both the expiration time and the reason
struct block_info {
    __u64 expiry;
    __u32 reason;
};

// Blocklist: Key = Source IP, Value = Expiration Timestamp + Reason
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct block_info);
} blocklist SEC(".maps");

// Rate limit trackers
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, struct rate_tracker); } syn_tracker SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, struct rate_tracker); } icmp_tracker SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, struct rate_tracker); } udp_tracker SEC(".maps");

static __always_inline int check_rate_limit(void *tracker_map, __u32 ip, __u64 now, __u64 threshold) {
    struct rate_tracker *tracker = bpf_map_lookup_elem(tracker_map, &ip);
    if (!tracker) {
        struct rate_tracker new_tracker = { .count = 1, .window_start = now };
        bpf_map_update_elem(tracker_map, &ip, &new_tracker, BPF_ANY);
        return 0;
    }
    if (now - tracker->window_start > WINDOW_NS) {
        tracker->count = 1;
        tracker->window_start = now;
    } else {
        tracker->count++;
        if (tracker->count > threshold) return 1;
    }
    return 0;
}

SEC("xdp")
int xdp_ips_main(struct xdp_md *ctx) {
    // Week 1-2 Milestone: Packet Parsing & Bounds Checking
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 now      = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;
    // Cast the 32-bit IP into an array of 4 individual bytes for logging
    __u8 *ip = (__u8 *)&src_ip;

    // Week 4 Milestone: Blocklist Enforcement
    struct block_info *info = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (info) {
        if (now < info->expiry) {
            // SLIDING WINDOW: The attacker is still sending packets.
            // Reset their 30-second expiration clock as a penalty (for temporary blocks).
            // Manual blocks (reason 4) keep their infinite timestamp.
            if (info->reason != 4) {
                info->expiry = now + BLOCK_TIME_NS;
            }
            return XDP_DROP; 
        } else {
            // The 30 seconds have passed with zero traffic.
            // Clean up the block and log the unblocking.
            bpf_map_delete_elem(&blocklist, &src_ip);
            bpf_printk("IP %d.%d.%d.%d unblocked. 30s block window expired.\n", ip[0], ip[1], ip[2], ip[3]);
        }
    }

    // Week 3 Milestone: Detection Rules
    int trigger_block = 0;
    __u32 block_reason = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;

        // Additional: Malformed Packet Drops (Instant Death, No Tracking Needed)
        
        // 1. NULL Scan (No flags set)
        if (!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) {
            bpf_printk("NULL Scan detected from IP: %d.%d.%d.%d. Dropping.\n", ip[0], ip[1], ip[2], ip[3]);
            return XDP_DROP;
        }

        // 2. XMAS Scan (FIN, PSH, and URG set simultaneously)
        if (tcph->fin && tcph->psh && tcph->urg) {
            bpf_printk("XMAS Scan detected from IP: %d.%d.%d.%d. Dropping.\n", ip[0], ip[1], ip[2], ip[3]);
            return XDP_DROP;
        }

        // 3. FIN Scan (FIN set, but ACK not set - illegal state)
        if (tcph->fin && !tcph->ack) {
            bpf_printk("FIN Scan detected from IP: %d.%d.%d.%d. Dropping.\n", ip[0], ip[1], ip[2], ip[3]);
            return XDP_DROP;
        }

        // SYN Flood Check: 100 pkts/s threshold imitating a typical SYN flood attack.
        // This is rate-limited because SYN packets are normally legal, but excessive rates indicate an attack.
        if (tcph->syn && !tcph->ack) {
            if (check_rate_limit(&syn_tracker, src_ip, now, 100)) {
                trigger_block = 1;
                block_reason = REASON_SYN;
                // Print the 4 octets using %d.%d.%d.%d
                bpf_printk("SYN flood from IP: %d.%d.%d.%d. Blocking.\n", ip[0], ip[1], ip[2], ip[3]);
            }
        }
    } 
    else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
        if ((void *)(icmph + 1) > data_end) return XDP_PASS;

        if (icmph->type == ICMP_ECHO) {
            if (check_rate_limit(&icmp_tracker, src_ip, now, 50)) {
                trigger_block = 1;
                block_reason = REASON_ICMP;
                bpf_printk("ICMP flood from IP: %d.%d.%d.%d. Blocking.\n", ip[0], ip[1], ip[2], ip[3]);
            }
        }
    }
    else if (iph->protocol == IPPROTO_UDP) {
        // UDP Flood Rule: 200 pkts/s threshold
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end) return XDP_PASS;

        if (check_rate_limit(&udp_tracker, src_ip, now, 200)) {
            trigger_block = 1;
            block_reason = REASON_UDP;
            bpf_printk("UDP flood from IP: %d.%d.%d.%d. Blocking.\n", ip[0], ip[1], ip[2], ip[3]);
        }
    }

    // Apply the block if any rule was triggered
    if (trigger_block) {
        struct block_info new_block = {
            .expiry = now + BLOCK_TIME_NS,
            .reason = block_reason
        };
        bpf_map_update_elem(&blocklist, &src_ip, &new_block, BPF_ANY);
        return XDP_DROP;
    }

    return XDP_PASS;
}