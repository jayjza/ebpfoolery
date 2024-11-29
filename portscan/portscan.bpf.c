#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

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

int xdp(struct xdp_md *ctx) {
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

    u_int16_t tcp_flags = ntohs(tcp_flag_word(tcp_header)) & 0x00FF;

    // Nmap Null scan (-sN): Does not set any bits (TCP flag header is 0)
    if (tcp_flags == 0x00) {
        bpf_trace_printk("Nmap Null scan");
    }

    // Nmap FIN scan (-sF): Sets just the TCP FIN bit.
    if (tcp_flags == TCP_FIN) {
        bpf_trace_printk("Nmap FIN scan");
    }

    // Nmap Xmas scan (-sX): Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
    if (tcp_flags == (TCP_FIN | TCP_PSH | TCP_URG)) {
        bpf_trace_printk("Nmap Xmas scan");
    }

    u_int32_t tcp_header_len = tcp_header->doff * 4;
    u_int32_t tcp_options_len = tcp_header_len - sizeof(struct tcphdr);
    // if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_options_len  > data_end)
    //     bpf_trace_printk("Error: options past end");
    //     return DEFAULT_ACTION;

    void *tcp_options = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    if (tcp_options_len == 20) {
        if (tcp_options + 20 > data_end) {
            return DEFAULT_ACTION;
        }
        if ((*(u_int32_t *)(tcp_options)      == TCP_NMAP_T2_T6_PROBES_1) &&
            (*(u_int32_t *)(tcp_options + 4)  == TCP_NMAP_T2_T6_PROBES_2) &&
            (*(u_int32_t *)(tcp_options + 8)  == TCP_NMAP_T2_T6_PROBES_3) &&
            (*(u_int32_t *)(tcp_options + 12) == TCP_NMAP_T2_T6_PROBES_4) &&
            (*(u_int32_t *)(tcp_options + 16) == TCP_NMAP_T2_T6_PROBES_5) )
        {
            // Nmap T3 Scan (-sT -T3)
            if ((tcp_flags == (TCP_SYN | TCP_FIN | TCP_PSH | TCP_URG)) &&
                (ntohs(tcp_header->window) == 256) &&
                ((ntohs(ip_header->frag_off) & IP_DF) == 0))
            {
                bpf_trace_printk("Nmap T3 scan");
            }
        }
    }
    else if (tcp_options_len == 16) {
        if (tcp_options + 16 > data_end) {
            return DEFAULT_ACTION;
        }

    }

    return DEFAULT_ACTION;
}
