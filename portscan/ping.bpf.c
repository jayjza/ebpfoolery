#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

static __always_inline unsigned short is_icmp_ping_request(void *data,
                                                           void *data_end) {
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return 0;

    if (iph->protocol != IPPROTO_ICMP)
        // We're only interested in ICMP packets
        return 0;

    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
        return 0;

    return (icmp->type == 8);
}

int xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (is_icmp_ping_request(data, data_end)) {
        bpf_trace_printk("Got ping packet");
        return XDP_DROP;
    }

    return XDP_PASS;
}
