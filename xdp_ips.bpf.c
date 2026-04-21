#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_drop_all(struct xdp_md *ctx) {
    // Week 1 Milestone: Drop all incoming packets
    // Use bpf_printk to log to /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("Packet received and dropped via XDP.\n");
    
    return XDP_DROP;
}