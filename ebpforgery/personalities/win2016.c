#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <net/ip.h>

#define DEFAULT_ACTION XDP_PASS
// #define DEBUG 1

BPF_TABLE(MAPTYPE, uint32_t, long, dropcnt, 256);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ( (void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

static inline void swap_mac(uint8_t *src_mac, uint8_t *dst_mac)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        uint8_t tmp_src;
        tmp_src = *(src_mac + i);
        *(src_mac + i) = *(dst_mac + i);
        *(dst_mac + i) = tmp_src;
    }
}

// Update IP checksum for IP header, as specified in RFC 1071
// The checksum_location is passed as a pointer. At this location 16 bits need to be set to 0.
static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location)
{
    uint32_t accumulator = 0;
    int i;
    for (i = 0; i < len; i += 2)
    {
        uint16_t val;
        // If we are currently at the checksum_location, set to zero
        if (data + i == checksum_location)
        {
            val = 0;
        }
        else
        {
            // Else we load two bytes of data into val
            val = *(uint16_t *)(data + i);
        }
        accumulator += val;
    }

    // Add 16 bits overflow back to accumulator (if necessary)
    uint16_t overflow = accumulator >> 16;
    accumulator &= 0x00FFFF;
    accumulator += overflow;

    // If this resulted in an overflow again, do the same (if necessary)
    accumulator += (accumulator >> 16);
    accumulator &= 0x00FFFF;

    // Invert bits and set the checksum at checksum_location
    uint16_t chk = accumulator ^ 0xFFFF;

#ifdef DEBUG
    bpf_printk("Checksum: %u", chk);
#endif

    *checksum_location = chk;
}


int xdp_prog1(struct CTXTYPE *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    int rc = DEFAULT_ACTION;
    uint16_t h_proto;           //! Protocol value inside the ethernet header

#ifdef DEBUG
    bpf_trace_printk("Running XDP program");
#endif

    // Boundary check: check if packet is larger than a full ethernet + ip header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        bpf_trace_printk("Invalid size for an IP packet");
        return DEFAULT_ACTION;
    }

    struct ethhdr *eth = data;

    h_proto = eth->h_proto;

    // Ignore packet if ethernet protocol is not IP-based
    if (h_proto != bpf_htons(ETH_P_IP)) // || h_proto != bpf_htons(ETH_P_IPV6))  // Not handling IPv6 right now 
    {
#ifdef DEBUG
        bpf_trace_printk("Not a IPv4 Packet");
#endif        
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);

    // Check for ICMP traffic
    if (ip->protocol == IPPROTO_ICMP)
    {
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
        {
            bpf_trace_printk("ICMP packet exceeding size of buffer");
            return DEFAULT_ACTION;
        }

        // If ICMP echo request
        bpf_trace_printk("Processing ICMP packet");
        struct icmphdr *icmp = data + sizeof(*eth) + sizeof(*ip);

        // Build ICMP echo reply
        icmp->code = 0;
        icmp->type = 0;
        // Update checksum
        icmp->checksum = 0;

        update_ip_checksum(icmp, sizeof(struct icmphdr), &icmp->checksum);

        // Clear don't fragement
        if (ip->frag_off & ntohs(IP_DF))
            ip->frag_off = ip->frag_off ^ ntohs(IP_DF);

        // Set TTL to 128
        ip->ttl = 128;

        // Swap src/dst IP
        uint32_t src_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = src_ip;

        swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);

        // Recalculate IP checksum
        update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

        return XDP_TX;
    }
#ifdef DEBUG
    bpf_trace_printk("Not a ICMP Packet");
#endif
    return rc;
}
