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

// TCP FLAGS
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// TCP OPTIONS
#define TCPOPT_NOP 1
#define TCPOPT_MAXSEG 2
#define TCPOPT_WINDOW_SCALE 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOPT_TIMESTAMP 8

// TCP OPTIONS CONSTANTS
#define TCPOLEN_NOP 1
#define TCPOLEN_MAXSEG 4
#define TCPOLEN_WINDOW 3
#define TCPOLEN_SACK_PERMITTED 2
#define TCPOLEN_TIMESTAMP 10

#ifndef TH_WIN
#define TH_WIN window
#endif

#define TCP_MAX_OPTION_LEN 40

#define TCP_NMAP_SEQ_PROBE_P1_1 0x010a0303              // 10a0303
#define TCP_NMAP_SEQ_PROBE_P1_2 0xb4050402
#define TCP_NMAP_SEQ_PROBE_P1_3 0xffff0a08
#define TCP_NMAP_SEQ_PROBE_P1_4 0x0000ffff
#define TCP_NMAP_SEQ_PROBE_P1_5 0x02050000


// task=b'<idle>', pid=0, msg=b'NMap options part 10a0303'
// task=b'<idle>', pid=0, msg=b'NMap options part b4050402'
// task=b'<idle>', pid=0, msg=b'NMap options part ffff0a08'
// task=b'<idle>', pid=0, msg=b'NMap options part ffff'
// task=b'<idle>', pid=0, msg=b'NMap options part 2050000'



BPF_TABLE(MAPTYPE, uint32_t, long, dropcnt, 256);

#define MAX_BUFFER_SIZE 512
u8 buffer[MAX_BUFFER_SIZE];                 //!< A temporary buffer where we can store some data when processing.

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

// Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted. The window field is 1.
// Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL. The window field is 63.
// Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640). The window field is 4.
// Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 4.
// Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 16.
// Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). The window field is 512.


// The htonl() function converts the unsigned integer hostlong from host byte order to network byte order.
// The htons() function converts the unsigned short integer hostshort from host byte order to network byte order.
// The ntohl() function converts the unsigned integer netlong from network byte order to host byte order.
// The ntohs() function converts the unsigned short integer netshort from network byte order to host byte order.

static inline void check_flags(struct tcphdr* tcp) {
    // Check TCP flags
    // XMAS: ALL URG,PSH,SYN,FIN
    if (tcp->syn && tcp->urg && tcp->psh && tcp->fin) {
        bpf_trace_printk("NMAP Xmas scan");
    }
    // if (tcp->syn) {
    //     // TCP SYN flag is set
    //     bpf_trace_printk("TCP SYN flag is set");
    // }

    // if (tcp->ack) {
    //     // TCP ACK flag is set
    //     bpf_trace_printk("TCP ACK flag is set");
    // }
    // Add more checks for other TCP flags as needed
}

static inline void check_options(struct tcphdr* tcp) {
    // Check TCP options
    // Assuming options start right after the TCP header
    unsigned char* options = (unsigned char*)(tcp) + sizeof(struct tcphdr);
    int is_probe_1_mss = 0;
    int is_probe_1_sack = 0;
    int is_probe_1_win_scale = 0;
    int is_probe_1_timestamp = 0;
    // Loop through TCP options
    while ((options - (unsigned char*)(tcp)) < ((tcp->doff * 4) - sizeof(struct tcphdr))) {
        // Extract the option kind
        unsigned char optionKind = *options;

        // Process the option kind as needed
        switch (optionKind) {
            case TCPOPT_NOP:
                // No-operation option
                break;

            case TCPOPT_MAXSEG: {
                // Maximum Segment Size option
                unsigned char optionLength = *(options + 1);
                if (optionLength == TCPOLEN_MAXSEG) {
                    uint16_t maxSegmentSize = ntohs(*(uint16_t*)(options + 2));
                    // bpf_trace_printk("Maximum Segment Size: " << maxSegmentSize << " bytes.");
                    if (maxSegmentSize == 1460) {
                        is_probe_1_mss = 1;
                    }
                }
                break;
            }

            case TCPOPT_WINDOW_SCALE: {
                // Window Scale option
                unsigned char optionLength = *(options + 1);
                if (optionLength == TCPOLEN_WINDOW) {
                    uint8_t windowScale = *(uint8_t*)(options + 2);
                    // std::cout << "Window Scale: " << static_cast<int>(windowScale) << "\n";
                    if ((int)(windowScale) == 10) {
                        is_probe_1_win_scale = 1;
                    }
                }
                break;
            }

            case TCPOPT_SACK_PERMITTED: {
                // Sack Permitted option
                is_probe_1_sack = 1;
            }

            case TCPOPT_TIMESTAMP: {
                // Timestamp option
                unsigned char optionLength = *(options + 1);
                if (optionLength == TCPOLEN_TIMESTAMP) {
                    uint32_t timestampValue = ntohl(*(uint32_t*)(options + 2));
                    uint32_t timestampEchoReply = ntohl(*(uint32_t*)(options + 6));
                    if (timestampValue == (uint32_t)0xFFFFFFFF) {
                        is_probe_1_timestamp = 1;
                    }
                    // is_probe_1_timestamp = true;
                }
            }

            default:
                // Handle unknown or unsupported options
                break;
        }

        // Move to the next option
        options += (options[1] > 0) ? options[1] : 1;
    }

    // if (is_probe_1_timestamp && is_probe_1_sack && is_probe_1_win_scale && is_probe_1_mss) {
    //     bpf_trace_printk("FOUND PACKET 1 of the firt probe");
    // }
}

static inline void check_options2(struct tcphdr* tcp, void* data_end) {
    u_int32_t options_len = tcp->doff*4 - sizeof(struct tcphdr);

    bpf_trace_printk("TCP Options length is %d and hdr %d", options_len, sizeof(struct tcphdr));

    void *blah = (void *)tcp + sizeof(struct tcphdr) + options_len;
    bpf_trace_printk("tcp start = %p, data_end = %p (%d))", blah, data_end, data_end - (void *) tcp);

    if ((void *)tcp + sizeof(struct tcphdr) + options_len > data_end)
    {
        bpf_trace_printk("TCP Options length is greater than the packet size");
        return;
    }

    void *options_start = (void *) tcp + sizeof(struct tcphdr);

    void * cursor = options_start;
    uint16_t i;

    for (i = 0; i < TCP_MAX_OPTION_LEN; i++)
    {
        bpf_trace_printk("Running i = %d", i);
        if (i >= options_len)
        {
            bpf_trace_printk("Reached end of TCP Options");
            break;
        }
        if (cursor + 1 > data_end)
        {
            bpf_trace_printk("Error: boundary exceeded while parsing TCP Options");
            break;
        }

        if (*(u8 *)(cursor) == TCPOPT_MAXSEG)
        {
            bpf_trace_printk("TCP Option Maximum Segment Size");
            if (cursor + 4 > data_end)
            {
                bpf_trace_printk("Error: boundary exceeded while parsing TCP Option MSS");
            }
            else
            {
                u_int16_t mss = htons(*(uint16_t *)(cursor + 2));
                bpf_trace_printk("MSS is = %d", mss);
            }
        }

        cursor++;
    }

    // for (int i = 0; i < options_len; i++)
    // {
    //     bpf_trace_printk("TCP Options value %x", options + i);

    //     if (options + i > data_end)
    //         break;

    //     u8 value = *((u8 *)(options + i));
        
    //     switch (value)
    //     {
    //         case TCPOPT_NOP:
    //             break;
    //     //     case TCPOPT_MAXSEG:
    //     //         bpf_trace_printk("TCP Option Maximum Segment Size");
    //     //         break;
    //     //     case TCPOPT_WINDOW_SCALE:
    //     //         bpf_trace_printk("TCP Option Window Scale");
    //     //         break;
    //     //     case TCPOPT_SACK_PERMITTED:
    //     //         bpf_trace_printk("TCP Option SACK Allowed");
    //     //         break;
    //     //     case TCPOPT_TIMESTAMP:
    //     //         bpf_trace_printk("TCP Option Timestamp");
    //     //         break;
    //         default:
    //             bpf_trace_printk("TCP Option Unknown");
    //             break;
    //     }

    //     if (i > 2)
    //         break;
    //     // if (options + i > data_end)
    //     // {
    //     //     bpf_trace_printk("Invalid option positioon");
    //     //     break;
    //     // }
    //     // u_int8_t val = *(options + i);
    //     // bpf_trace_printk("TCP Options value %d", val);
    //     // if (*(options + i) == 2)
    //     //     bpf_trace_printk("Found MSS value");

    // }

}



static inline void detect_nmap_probes(void* data_end, struct tcphdr* tcp) {
    u_int32_t options_len = tcp->doff*4 - sizeof(struct tcphdr);

#ifdef DEBUG
    bpf_trace_printk("TCP Options length is %d and hdr %d", options_len, sizeof(struct tcphdr));
#endif

    void *blah = (void *)tcp + sizeof(struct tcphdr) + options_len;
#ifdef DEBUG
    bpf_trace_printk("tcp start = %p, data_end = %p (%d))", blah, data_end, data_end - (void *) tcp);
#endif

    if ((void *)tcp + sizeof(struct tcphdr) + options_len > data_end)
    {
        bpf_trace_printk("TCP Options length is greater than the packet size");
        return;
    }

    void *options_start = (void *) tcp + sizeof(struct tcphdr);

    void * cursor = options_start;
    uint16_t i;
    // The nmap probe TCP options is either 16 or 20 bytes
    if (options_len == 20) {
        // bpf_trace_printk("TCP Options length is %d and hdr %d", options_len, sizeof(struct tcphdr));
        if (cursor + 20 > data_end)
        {
            bpf_trace_printk("Error: boundary exceeded while parsing TCP Options");
            return;
        }
        u_int32_t value = (*(u_int32_t *)(cursor));

        bpf_trace_printk("NMap options part %x, %x", (*(u_int32_t *)(cursor)), (*(u_int32_t *)(cursor)) == TCP_NMAP_SEQ_PROBE_P1_1);
        bpf_trace_printk("NMap options part %x", (*(u_int32_t *)(cursor + 4)) == TCP_NMAP_SEQ_PROBE_P1_2 );
        bpf_trace_printk("NMap options part %x", (*(u_int32_t *)(cursor + 8)) == TCP_NMAP_SEQ_PROBE_P1_3);
        bpf_trace_printk("NMap options part %x", (*(u_int32_t *)(cursor + 12)) == TCP_NMAP_SEQ_PROBE_P1_4);
        bpf_trace_printk("NMap options part %x", (*(u_int32_t *)(cursor + 16)) == TCP_NMAP_SEQ_PROBE_P1_5);

        if ((*(u_int32_t *)(cursor) == TCP_NMAP_SEQ_PROBE_P1_1) &&
             (*(u_int32_t *)(cursor + 4) == TCP_NMAP_SEQ_PROBE_P1_2) &&
             (*(u_int32_t *)(cursor + 8) == TCP_NMAP_SEQ_PROBE_P1_3) &&
             (*(u_int32_t *)(cursor + 12) == TCP_NMAP_SEQ_PROBE_P1_4) &&
             (*(u_int32_t *)(cursor + 16) == TCP_NMAP_SEQ_PROBE_P1_5))
            {
                bpf_trace_printk("NMap TCP probe packet 1 detected");
                return;
            }
    }
    else if (options_len == 16) {
        // bpf_trace_printk("TCP Options length is %d and hdr %d", options_len, sizeof(struct tcphdr));
        if (cursor + 16 > data_end)
        {
            bpf_trace_printk("Error: boundary exceeded while parsing TCP Options");
            return;
        }
    }
    return;
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

    h_proto = bpf_htons(eth->h_proto);


    // Ignore packet if ethernet protocol is not IP-based
    if (h_proto != ETH_P_IP) // || h_proto != ETH_P_IPV6)  // Not handling IPv6 right now
    {
#ifdef DEBUG
        bpf_trace_printk("Not a IPv4 Packet");
#endif        
        return XDP_PASS;
    }
#ifdef DEBUG
    bpf_trace_printk("Ether Proto: 0x%x", h_proto);
#endif

    struct iphdr *ip = data + sizeof(*eth);

#ifdef DEBUG
    bpf_trace_printk("IP Proto: %d", ip->protocol);
#endif
    if (ip->protocol == IPPROTO_TCP)
    {
        // bpf_trace_printk("Processing TCP packet");

        struct tcphdr *tcp = (void *)ip + (ip->ihl << 2);
        if ((void *)(tcp + 1) > data_end) {
            return rc;
        }

#ifdef DEBUG
        bpf_trace_printk("TCP connection from %d to %d", ntohs(tcp->source), ntohs(tcp->dest));
#endif

        check_flags(tcp);
        // check_options2(tcp, data_end);
        detect_nmap_probes(data_end, tcp);


        // Access the window size field
        uint16_t windowSize = ntohs(tcp->TH_WIN);
    // printf("Window Size: %d bytes.\n", windowSize);
    }

    // Handle UDP traffic
    else if (ip->protocol == IPPROTO_UDP)
    {
        /*
            udp_unreach {
                reply yes;
                df no;
                ttl 128;
                max-len 356;
                tos 0;

                mangle-original {
                    ip-len 328;
                    ip-id same;ip
                    ip-csum same;
                    udp-len 308;
                    udp-csum same;
                    udp-data same;
                }
            }
        */
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        {
            bpf_trace_printk("ICMP packet exceeding size of buffer");
            return DEFAULT_ACTION;
        }
        struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);

        // TODO check if this port is open before doing this.
        // We probably need to use a BPF map to do this

#ifdef DEBUG
        bpf_trace_printk("Traffic for port %d", ntohs(udp->dest));
        bpf_trace_printk("ip length was %d", ntohs(ip->tot_len));
        bpf_trace_printk("Start = %p, end = %p (%d)", ctx->data, ctx->data_end, ctx->data_end - ctx->data);
#endif

        size_t new_header_size = sizeof(struct iphdr) +  sizeof(struct icmphdr);

        if (bpf_xdp_adjust_head(ctx, 0 - new_header_size))
        {
            bpf_trace_printk("Unable to allocate space for ICMP response");
            return DEFAULT_ACTION;
        }
#ifdef DEBUG
        bpf_trace_printk("Packet is now bigger %d", new_header_size);
#endif
        data = (void*)(long)ctx->data;
        data_end = (void*)(long)ctx->data_end;

#ifdef DEBUG
        bpf_trace_printk("Start = %p, end = %p, (%d)", ctx->data, ctx->data_end, ctx->data_end - ctx->data);
#endif

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
        {
            bpf_trace_printk("Resized packet is too small1");
            return DEFAULT_ACTION;
        }

        // Copy Ethernet header
        eth = data;
        void *old_eth_location = data + new_header_size;

#ifdef DEBUG
        bpf_trace_printk("Copying ethernet from old = %p, new = %p, (%d)", old_eth_location, eth, 0);
#endif

        // Copy the existing Ethernet Header
        for (int i = 0; i < sizeof(struct ethhdr); i++)
        {
            *((u_int8_t *) eth + i) = *((u_int8_t *) old_eth_location + i);
        }

        // Copy the IP header
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + new_header_size > data_end)
        {
            bpf_trace_printk("Resized packet is too small2");
            return DEFAULT_ACTION;
        }
        void *old_ip_header =  data + new_header_size + sizeof(struct ethhdr);

        ip = data + sizeof(struct ethhdr);
        for (int i = 0; i < sizeof(struct iphdr); i++)
        {
            *((u_int8_t *) ip + i) = *((u_int8_t *) old_ip_header + i);
        }

#ifdef DEBUG
        bpf_trace_printk("ethernet header is %d", sizeof(struct ethhdr));
#endif

        // Insert ICMP header
        struct icmphdr *icmp = data + sizeof(*eth) + sizeof(*ip);
        icmp->type = ICMP_DEST_UNREACH;
        icmp->code = ICMP_PORT_UNREACH;
        icmp->checksum = 0;
        icmp->un.gateway = 0;
        update_ip_checksum(icmp, sizeof(struct icmphdr), &icmp->checksum);

        // Update the existing IP header
        ip->protocol = IPPROTO_ICMP;
        ip->tot_len = htons(ntohs(ip->tot_len) + new_header_size);

#ifdef DEBUG
        bpf_trace_printk("ip length is %d", ntohs(ip->tot_len));
#endif

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

    // Check for ICMP traffic
    else if (ip->protocol == IPPROTO_ICMP)
    {
        /*
            icmp {
                reply yes;
                df none;
                ttl 128;
                cd zerocd;
            }
        */
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
