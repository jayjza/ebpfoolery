#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <linux/tcp.h>

#define DEFAULT_ACTION XDP_PASS

#define TCP_CWR 0x80
#define TCP_ECE 0x40
#define TCP_URG 0x20
#define TCP_ACK 0x10
#define TCP_PSH 0x08
#define TCP_RST 0x04
#define TCP_SYN 0x02
#define TCP_FIN 0x01

#define IP_DF 0x4000

// T2-T6 Options = 03030a01 02040109 080affff ffff0000 00000402
#define TCP_NMAP_T2_T6_PROBES_1 0x010a0303
#define TCP_NMAP_T2_T6_PROBES_2 0x09010402
#define TCP_NMAP_T2_T6_PROBES_3 0xffff0a08
#define TCP_NMAP_T2_T6_PROBES_4 0x0000ffff
#define TCP_NMAP_T2_T6_PROBES_5 0x02040000

static __always_inline unsigned short compare_payload(
    char *target, __u32 target_len,
    unsigned char *tcp_payload, __u32 tcp_payload_len,
    void *data_end)
{
    if (tcp_payload_len < target_len) {
        return 0;
    }

    if (((void *)tcp_payload + target_len) > data_end) {
        return 0;
    }

    for (int i = 0; i < target_len; i++) {
        if (tcp_payload[i] != target[i])
            return 0;
    }

    return 1;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return DEFAULT_ACTION;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return DEFAULT_ACTION;

    struct iphdr *ip_header = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return DEFAULT_ACTION;

    if (ip_header->protocol != IPPROTO_TCP)
        return DEFAULT_ACTION;

    struct tcphdr *tcp_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return DEFAULT_ACTION;

    __u16 tcp_flags = bpf_ntohs(tcp_flag_word(tcp_header)) & 0x00FF;

    // Nmap Null scan (-sN): Does not set any bits (TCP flag header is 0)
    if (tcp_flags == 0x00) {
        bpf_printk("Nmap Null scan");
    }

    // Nmap FIN scan (-sF): Sets just the TCP FIN bit.
    if (tcp_flags == TCP_FIN) {
        bpf_printk("Nmap FIN scan");
    }

    // Nmap Xmas scan (-sX): Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
    if (tcp_flags == (TCP_FIN | TCP_PSH | TCP_URG)) {
        bpf_printk("Nmap Xmas scan");
    }

    __u32 tcp_header_len = tcp_header->doff * 4;
    __u32 tcp_options_len = tcp_header_len - sizeof(struct tcphdr);

    void *tcp_options = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    if (tcp_options > data_end)
        return DEFAULT_ACTION;

    // Nmap T3 prove has an tcp options length of 20
    if (tcp_options_len == 20) {
        // bpf_printk("tcp_options_len is 20");
        if ((tcp_options + 20) > data_end) {
            // bpf_printk("tcp_options_len too long");
            return DEFAULT_ACTION;
        }
        if ((*(__u32 *)(tcp_options)      == TCP_NMAP_T2_T6_PROBES_1) &&
            (*(__u32 *)(tcp_options + 4)  == TCP_NMAP_T2_T6_PROBES_2) &&
            (*(__u32 *)(tcp_options + 8)  == TCP_NMAP_T2_T6_PROBES_3) &&
            (*(__u32 *)(tcp_options + 12) == TCP_NMAP_T2_T6_PROBES_4) &&
            (*(__u32 *)(tcp_options + 16) == TCP_NMAP_T2_T6_PROBES_5) )
        {
            // Nmap T3 Scan (-sT -T3)
            if ((tcp_flags == (TCP_SYN | TCP_FIN | TCP_PSH | TCP_URG)) &&
                (bpf_ntohs(tcp_header->window) == 256) &&
                ((bpf_ntohs(ip_header->frag_off) & IP_DF) == 0))
            {
                bpf_printk("Nmap T3 scan");
            }
        }
    }

    unsigned char *tcp_payload = (void *)tcp_header + tcp_header_len;
    if ((void *)tcp_payload > data_end)
            return DEFAULT_ACTION;

    __u32 tcp_payload_len = data_end - (void *)tcp_payload;

    char honeydet_ssh[] = "SSH-1111-OpenSSH_9.0";
    __u32 honeydet_ssh_len = sizeof(honeydet_ssh) - 1; // Ignore nul char
    if (compare_payload(honeydet_ssh, honeydet_ssh_len, tcp_payload, tcp_payload_len, data_end)) {
        bpf_printk("Honeydet Scanner: cowrie");
    }

    char honeydet_redis[] = "[[,[[";
    __u32 honeydet_redis_len = sizeof(honeydet_redis) - 1; // Ignore nul char
    if (compare_payload(honeydet_redis, honeydet_redis_len, tcp_payload, tcp_payload_len, data_end)) {
        bpf_printk("Honeydet Scanner: opencanary-redis");
    }

    return DEFAULT_ACTION;
}

char _license[] SEC("license") = "GPL";