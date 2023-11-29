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

#define TCP_NMAP_T1_P1 0x11 // nmap_test1_probe1
#define TCP_NMAP_T1_P2 0x12 // nmap_test1_probe2
#define TCP_NMAP_T1_P3 0x13 // nmap_test1_probe3
#define TCP_NMAP_T1_P4 0x14 // nmap_test1_probe4
#define TCP_NMAP_T1_P5 0x15 // nmap_test1_probe5
#define TCP_NMAP_T1_P6 0x16 // nmap_test1_probe6
#define TCP_NMAP_T2_P1 0x21 // nmap_test2_probe1
#define TCP_NMAP_T3_P1 0x31 // nmap_test3_probe1
#define TCP_NMAP_T4_P1 0x41 // nmap_test4_probe1
#define TCP_NMAP_T5_P1 0x51 // nmap_test5_probe1
#define TCP_NMAP_T6_P1 0x61 // nmap_test6_probe1
#define TCP_NMAP_T7_P1 0x71 // nmap_test7_probe1
#define TCP_NMAP_NONE  0x00 // nmap detected none
#define TCP_NMAP_ERROR 0xFF // nmap detection error

// TCP NMAP probe values as captured by wireshark and the byte order reversed to network order
// Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted. The window field is 1.
#define TCP_NMAP_SEQ_PROBE_P1_1 0x010a0303              // 10a0303
#define TCP_NMAP_SEQ_PROBE_P1_2 0xb4050402
#define TCP_NMAP_SEQ_PROBE_P1_3 0xffff0a08
#define TCP_NMAP_SEQ_PROBE_P1_4 0x0000ffff
#define TCP_NMAP_SEQ_PROBE_P1_5 0x02040000

// Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL. The window field is 63.
#define TCP_NMAP_SEQ_PROBE_P2_1 0x78050402
#define TCP_NMAP_SEQ_PROBE_P2_2 0x04000303
#define TCP_NMAP_SEQ_PROBE_P2_3 0xff0a0802
#define TCP_NMAP_SEQ_PROBE_P2_4 0x00ffffff
#define TCP_NMAP_SEQ_PROBE_P2_5 0x00000000

// Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640). The window field is 4.
// TCP SEQ Probe P3 080affffffff0000000001010303050102040280
#define TCP_NMAP_SEQ_PROBE_P3_1 0xffff0a08
#define TCP_NMAP_SEQ_PROBE_P3_2 0x0000ffff
#define TCP_NMAP_SEQ_PROBE_P3_3 0x01010000
#define TCP_NMAP_SEQ_PROBE_P3_4 0x01050303
#define TCP_NMAP_SEQ_PROBE_P3_5 0x80020402

// Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 4.
// TCP SEQ Probe P4 0402080affffffff0000000003030a00
#define TCP_NMAP_SEQ_PROBE_P4_1 0x0a080204
#define TCP_NMAP_SEQ_PROBE_P4_2 0xffffffff
#define TCP_NMAP_SEQ_PROBE_P4_3 0x00000000
#define TCP_NMAP_SEQ_PROBE_P4_4 0x000a0303

// Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 16.
// TCP SEQ Probe P5 020402180402080affffffff0000000003030a00
#define TCP_NMAP_SEQ_PROBE_P5_1 0x18020402
#define TCP_NMAP_SEQ_PROBE_P5_2 0x0a080204
#define TCP_NMAP_SEQ_PROBE_P5_3 0xffffffff
#define TCP_NMAP_SEQ_PROBE_P5_4 0x00000000
#define TCP_NMAP_SEQ_PROBE_P5_5 0x000a0303

// Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). The window field is 512.
// TCP SEQ Probe P6 020401090402080affffffff00000000
#define TCP_NMAP_SEQ_PROBE_P6_1 0x09010402
#define TCP_NMAP_SEQ_PROBE_P6_2 0x0a080204
#define TCP_NMAP_SEQ_PROBE_P6_3 0xffffffff
#define TCP_NMAP_SEQ_PROBE_P6_4 0x00000000

// T2-T6 Options = 03030a01 02040109 080affff ffff0000 00000402
#define TCP_NMAP_T2_T7_PROBES_1 0x010a0303
#define TCP_NMAP_T2_T7_PROBES_2 0x09010402
#define TCP_NMAP_T2_T7_PROBES_3 0xffff0a08
#define TCP_NMAP_T2_T7_PROBES_4 0x0000ffff
#define TCP_NMAP_T2_T7_PROBES_5 0x02040000

// T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port. The IP DF bit is not set.
// T7 Options = 03030f01 02040109 080affff ffff0000 00000402


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

static inline uint8_t detect_nmap_probes(void* data_end, struct tcphdr* tcp, struct iphdr *ip) {
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
        return TCP_NMAP_NONE;
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
            return TCP_NMAP_NONE;
        }
        u_int32_t value = (*(u_int32_t *)(cursor));

#ifdef DEBUG
        bpf_trace_printk("NMap options part %x, %x, %x", (*(u_int32_t *)(cursor))     , TCP_NMAP_T2_T7_PROBES_1, (*(u_int32_t *)(cursor)) == TCP_NMAP_T2_T7_PROBES_1);
        bpf_trace_printk("NMap options part %x, %x, %x", (*(u_int32_t *)(cursor + 4)) , TCP_NMAP_T2_T7_PROBES_2, (*(u_int32_t *)(cursor + 4)) == TCP_NMAP_T2_T7_PROBES_2 );
        bpf_trace_printk("NMap options part %x, %x, %x", (*(u_int32_t *)(cursor + 8)) , TCP_NMAP_T2_T7_PROBES_3, (*(u_int32_t *)(cursor + 8)) == TCP_NMAP_T2_T7_PROBES_3);
        bpf_trace_printk("NMap options part %x, %x, %x", (*(u_int32_t *)(cursor + 12)), TCP_NMAP_T2_T7_PROBES_4, (*(u_int32_t *)(cursor + 12)) == TCP_NMAP_T2_T7_PROBES_4);
        bpf_trace_printk("NMap options part %x, %x, %x", (*(u_int32_t *)(cursor + 16)), TCP_NMAP_T2_T7_PROBES_5, (*(u_int32_t *)(cursor + 16)) == TCP_NMAP_T2_T7_PROBES_5);
#endif

        if ((*(u_int32_t *)(cursor) == TCP_NMAP_SEQ_PROBE_P1_1) &&
             (*(u_int32_t *)(cursor + 4) == TCP_NMAP_SEQ_PROBE_P1_2) &&
             (*(u_int32_t *)(cursor + 8) == TCP_NMAP_SEQ_PROBE_P1_3) &&
             (*(u_int32_t *)(cursor + 12) == TCP_NMAP_SEQ_PROBE_P1_4) &&
             (*(u_int32_t *)(cursor + 16) == TCP_NMAP_SEQ_PROBE_P1_5) &&
             (ntohs(tcp->window) == 1))
            {
                // bpf_trace_printk("NMap TCP probe packet 1 detected");
                return TCP_NMAP_T1_P1;
            }
        else if ((*(u_int32_t *)(cursor)      == TCP_NMAP_SEQ_PROBE_P2_1) &&
                 (*(u_int32_t *)(cursor + 4)  == TCP_NMAP_SEQ_PROBE_P2_2) &&
                 (*(u_int32_t *)(cursor + 8)  == TCP_NMAP_SEQ_PROBE_P2_3) &&
                 (*(u_int32_t *)(cursor + 12) == TCP_NMAP_SEQ_PROBE_P2_4) &&
                 (*(u_int32_t *)(cursor + 16) == TCP_NMAP_SEQ_PROBE_P2_5) &&
                 (ntohs(tcp->window) == 63))
        {
                // bpf_trace_printk("NMap TCP probe packet 2 detected");
                return TCP_NMAP_T1_P2;
        }
        else if ((*(u_int32_t *)(cursor)      == TCP_NMAP_SEQ_PROBE_P3_1) &&
                 (*(u_int32_t *)(cursor + 4)  == TCP_NMAP_SEQ_PROBE_P3_2) &&
                 (*(u_int32_t *)(cursor + 8)  == TCP_NMAP_SEQ_PROBE_P3_3) &&
                 (*(u_int32_t *)(cursor + 12) == TCP_NMAP_SEQ_PROBE_P3_4) &&
                 (*(u_int32_t *)(cursor + 16) == TCP_NMAP_SEQ_PROBE_P3_5) &&
                 (ntohs(tcp->window) == 4))
        {
                // bpf_trace_printk("NMap TCP probe packet 3 detected");
                return TCP_NMAP_T1_P3;
        }
        else if ((*(u_int32_t *)(cursor)      == TCP_NMAP_SEQ_PROBE_P5_1) &&
                 (*(u_int32_t *)(cursor + 4)  == TCP_NMAP_SEQ_PROBE_P5_2) &&
                 (*(u_int32_t *)(cursor + 8)  == TCP_NMAP_SEQ_PROBE_P5_3) &&
                 (*(u_int32_t *)(cursor + 12) == TCP_NMAP_SEQ_PROBE_P5_4) &&
                 (*(u_int32_t *)(cursor + 16) == TCP_NMAP_SEQ_PROBE_P5_5) &&
                 (ntohs(tcp->window) == 16))
        {
                // bpf_trace_printk("NMap TCP probe packet 5 detected");
                return TCP_NMAP_T1_P5;
        }
        else if ((*(u_int32_t *)(cursor)      == TCP_NMAP_T2_T7_PROBES_1) &&
                 (*(u_int32_t *)(cursor + 4)  == TCP_NMAP_T2_T7_PROBES_2) &&
                 (*(u_int32_t *)(cursor + 8)  == TCP_NMAP_T2_T7_PROBES_3) &&
                 (*(u_int32_t *)(cursor + 12) == TCP_NMAP_T2_T7_PROBES_4) &&
                 (*(u_int32_t *)(cursor + 16) == TCP_NMAP_T2_T7_PROBES_5) )
        {
            u_int16_t flags = ntohs(tcp_flag_word(tcp)) & 0x00FF;    // We only want a part of the word, and we only want the flag field
            // TODO: We need to check if the ports is open / closed, but we cannot determine that right now from XDP

            if ((flags == 0) &&
                (ntohs(tcp->window) == 128) &&
                (ntohs(ip->frag_off) & IP_DF))
            {
                bpf_trace_printk("NMap TCP probe T2 packet detected");
                return TCP_NMAP_T2_P1;
            }
            if ((flags == TCP_SYN | TCP_FIN | TCP_URG | TCP_PSH) &&
                (ntohs(tcp->window) == 256) &&
                (ntohs(ip->frag_off) & IP_DF) == 0)
            {
                bpf_trace_printk("NMap TCP probe T3 packet detected");
                return TCP_NMAP_T3_P1;
            }
            if ((flags = TCP_ACK) &&
                (ntohs(tcp->window) == 1024) &&
                (ntohs(ip->frag_off) & IP_DF))
            {
                bpf_trace_printk("NMap TCP probe T4 packet detected");
                return TCP_NMAP_T4_P1;
            }
            if ((flags = TCP_SYN) &&
                (ntohs(tcp->window) == 31337) &&
                (ntohs(ip->frag_off) & IP_DF) == 0)
            {
                bpf_trace_printk("NMap TCP probe T5 packet detected");
                return TCP_NMAP_T5_P1;
            }
            if ((flags = TCP_ACK) &&
                (ntohs(tcp->window) == 32768) &&
                (ntohs(ip->frag_off) & IP_DF))
            {
                bpf_trace_printk("NMap TCP probe T6 packet detected");
                return TCP_NMAP_T6_P1;
            }
        }

    }
    else if (options_len == 16) {
        // bpf_trace_printk("TCP Options length is %d and hdr %d", options_len, sizeof(struct tcphdr));
        if (cursor + 16 > data_end)
        {
            bpf_trace_printk("Error: boundary exceeded while parsing TCP Options");
            return TCP_NMAP_NONE;
        }
        if ((*(u_int32_t *)(cursor)      == TCP_NMAP_SEQ_PROBE_P4_1) &&
            (*(u_int32_t *)(cursor + 4)  == TCP_NMAP_SEQ_PROBE_P4_2) &&
            (*(u_int32_t *)(cursor + 8)  == TCP_NMAP_SEQ_PROBE_P4_3) &&
            (*(u_int32_t *)(cursor + 12) == TCP_NMAP_SEQ_PROBE_P4_4) &&
            (ntohs(tcp->window) == 4))
            {
                // bpf_trace_printk("NMap TCP probe packet 4 detected");
                return TCP_NMAP_T1_P4;
            }
        else if ((*(u_int32_t *)(cursor)      == TCP_NMAP_SEQ_PROBE_P6_1) &&
                 (*(u_int32_t *)(cursor + 4)  == TCP_NMAP_SEQ_PROBE_P6_2) &&
                 (*(u_int32_t *)(cursor + 8)  == TCP_NMAP_SEQ_PROBE_P6_3) &&
                 (*(u_int32_t *)(cursor + 12) == TCP_NMAP_SEQ_PROBE_P6_4) &&
                 (ntohs(tcp->window) == 512))
        {
                // bpf_trace_printk("NMap TCP probe packet 6 detected");
                return TCP_NMAP_T1_P6;
        }
    }
    return TCP_NMAP_NONE;
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

// struct iphdr {
//     uint8_t  ihl_version;  // Internet Header Length (4 bits) + Version (4 bits)
//     uint8_t  tos;          // Type of Service
//     uint16_t tot_len;      // Total Length
//     uint16_t id;           // Identification
//     uint16_t frag_off;     // Fragment Offset + Flags
//     uint8_t  ttl;          // Time to Live
//     uint8_t  protocol;     // Protocol (e.g., TCP, UDP, ICMP)
//     uint16_t check;        // Header Checksum
//     uint32_t saddr;        // Source IP Address
//     uint32_t daddr;        // Destination IP Address
//     // Options and padding may be present
// };


// struct tcphdr {
// 	__be16	source;
// 	__be16	dest;
// 	__be32	seq;
// 	__be32	ack_seq;
// #if defined(__LITTLE_ENDIAN_BITFIELD)
// 	__u16	res1:4,
// 		doff:4,
// 		fin:1,
// 		syn:1,
// 		rst:1,
// 		psh:1,
// 		ack:1,
// 		urg:1,
// 		ece:1,
// 		cwr:1;
// #elif defined(__BIG_ENDIAN_BITFIELD)
// 	__u16	doff:4,
// 		res1:4,
// 		cwr:1,
// 		ece:1,
// 		urg:1,
// 		ack:1,
// 		psh:1,
// 		rst:1,
// 		syn:1,
// 		fin:1;
// #else
// #error	"Adjust your <asm/byteorder.h> defines"
// #endif
// 	__be16	window;
// 	__sum16	check;
// 	__be16	urg_ptr;
// };

        check_flags(tcp);
        // check_options2(tcp, data_end);
        u_int8_t nmap_result = detect_nmap_probes(data_end, tcp, ip);
        // bpf_trace_printk("detect_nmap_probes %d", nmap_result);
        switch(nmap_result) {
            case TCP_NMAP_T1_P1: {
                //     set(df, 1);
                //     set(ttl, 128);
                //     set(ack, this+1);
                //     set(flags, ack|syn);

                //     set(win, 8192);
                //     insert(mss,1460);
                //     insert(wscale,8);
                //     insert(sackOK);
                //     insert(timestamp);

                // Fix TCP header
                // Set Syn/Ack on the TCP header
                tcp->syn = 1;
                tcp->ack = 1;

                tcp->ack_seq = htonl(ntohl(tcp->seq) + 1);
                // TODO: We need some random sequence number for the return
                tcp->window = htons(8192);

                // Swap src/dst TCP
                uint16_t src_tcp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = src_tcp_port;

                // Set the TCP options
                u_int32_t options_len = 20;
                void *options_start = (void *) tcp + sizeof(struct tcphdr);
                void * cursor = options_start;
                if (cursor + 20 > data_end)
                {
                    bpf_trace_printk("Error: boundary exceeded while trying to set TCP Options");
                    return DEFAULT_ACTION;
                }
                else
                {
                    (*(u_int32_t *)(cursor +  0)) = htonl(0x020405b4);
                    (*(u_int32_t *)(cursor +  4)) = htonl(0x01030308);
                    (*(u_int32_t *)(cursor +  8)) = htonl(0x0402080a);
                    (*(u_int32_t *)(cursor + 12)) = htonl(0x00163244);
                    (*(u_int32_t *)(cursor + 16)) = htonl(0xffffffff);
                }

                update_ip_checksum(tcp, sizeof(struct tcphdr) + options_len, &tcp->check);

                // Update the IP packet
                // Set IP don't fragment
                ip->frag_off | ntohs(IP_DF);
                // Set TTL to 128
                ip->ttl = 128;

                // Swap src/dst IP
                uint32_t src_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = src_ip;
                // Recalculate IP checksum
                update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                // Update the ethernet packet
                swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);
                bpf_trace_printk("NMAP detection found probe 1 of test 1");
                return XDP_TX;
                // return rc;
            }
            case TCP_NMAP_T1_P2: {
                // Fix TCP header
                // Set Syn/Ack on the TCP header
                tcp->syn = 1;
                tcp->ack = 1;

                // TODO: We need some random sequence number for the return
                tcp->window = htons(8192);

                // Swap src/dst TCP
                uint16_t src_tcp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = src_tcp_port;

                // Set the TCP options
                u_int32_t options_len = 20;
                void *options_start = (void *) tcp + sizeof(struct tcphdr);
                void * cursor = options_start;
                if (cursor + 20 > data_end)
                {
                    bpf_trace_printk("Error: boundary exceeded while trying to set TCP Options");
                    return DEFAULT_ACTION;
                }
                else
                {
                    (*(u_int32_t *)(cursor +  0)) = htonl(0x020405b4);
                    (*(u_int32_t *)(cursor +  4)) = htonl(0x01030308);
                    (*(u_int32_t *)(cursor +  8)) = htonl(0x0402080a);
                    (*(u_int32_t *)(cursor + 12)) = htonl(0x00163244);
                    (*(u_int32_t *)(cursor + 16)) = htonl(0xffffffff);
                }

                update_ip_checksum(tcp, sizeof(struct tcphdr) + options_len, &tcp->check);

                // Update the IP packet
                // Swap src/dst IP
                uint32_t src_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = src_ip;
                // Recalculate IP checksum
                update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                // Update the ethernet packet
                swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);

                bpf_trace_printk("NMAP detection found probe 2 of test 1");
                return XDP_TX;
            }
            case TCP_NMAP_T1_P3: {
                // Fix TCP header
                // Set Syn/Ack on the TCP header
                tcp->syn = 1;
                tcp->ack = 1;

                // TODO: We need some random sequence number for the return
                tcp->window = htons(8192);

                // Swap src/dst TCP
                uint16_t src_tcp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = src_tcp_port;

                                // Set the TCP options
                u_int32_t options_len = 20;
                void *options_start = (void *) tcp + sizeof(struct tcphdr);
                void * cursor = options_start;
                if (cursor + 20 > data_end)
                {
                    bpf_trace_printk("Error: boundary exceeded while trying to set TCP Options");
                    return DEFAULT_ACTION;
                }
                else
                {
                    (*(u_int32_t *)(cursor +  0)) = htonl(0x020405b4);
                    (*(u_int32_t *)(cursor +  4)) = htonl(0x01030308);
                    (*(u_int32_t *)(cursor +  8)) = htonl(0x0101080a);
                    (*(u_int32_t *)(cursor + 12)) = htonl(0x00163316);
                    (*(u_int32_t *)(cursor + 16)) = htonl(0xffffffff);
                }

                update_ip_checksum(tcp, sizeof(struct tcphdr) + options_len, &tcp->check);

                // Update the IP packet
                // Swap src/dst IP
                uint32_t src_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = src_ip;
                // Recalculate IP checksum
                update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                // Update the ethernet packet
                swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);

                bpf_trace_printk("NMAP detection found probe 3 of test 1");
                return XDP_TX;
            }
            case TCP_NMAP_T1_P4: {
                // For probe4 we need to make the buffer slightly bigger
                if (bpf_xdp_adjust_tail(ctx, 4))
                {
                    bpf_trace_printk("Error: Failed to increase packet size");
                    return DEFAULT_ACTION;
                }
                data_end = (void*)(long)ctx->data_end;
                data = (void*)(long)ctx->data;

                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
                {
                    bpf_trace_printk("Invalid size for an IP packet");
                    return DEFAULT_ACTION;
                }
                struct ethhdr *eth = data;
                struct iphdr *ip = data + sizeof(*eth);
                struct tcphdr *tcp = (void *)ip + (ip->ihl << 2);
                if ((void *)(tcp + 1) > data_end) {
                    return DEFAULT_ACTION;
                }

                // Fix TCP header
                // Set Syn/Ack on the TCP header
                tcp->syn = 1;
                tcp->ack = 1;

                // TODO: We need some random sequence number for the return
                tcp->window = htons(8192);

                // Swap src/dst TCP
                uint16_t src_tcp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = src_tcp_port;

                // Set the TCP options
                u_int32_t options_len = 20;
                void *options_start = (void *) tcp + sizeof(struct tcphdr);
                void * cursor = options_start;

                if (cursor + 20 > data_end)
                {
                    bpf_trace_printk("Error: boundary exceeded while trying to set TCP Options");
                    return DEFAULT_ACTION;
                }
                else
                {
                    (*(u_int32_t *)(cursor +  0)) = htonl(0x020405b4);
                    (*(u_int32_t *)(cursor +  4)) = htonl(0x01030308);
                    (*(u_int32_t *)(cursor +  8)) = htonl(0x0402080a);
                    (*(u_int32_t *)(cursor + 12)) = htonl(0x0016337a);
                    (*(u_int32_t *)(cursor + 16)) = htonl(0xffffffff);
                }

                update_ip_checksum(tcp, sizeof(struct tcphdr) + options_len, &tcp->check);

                // Update the IP packet
                // Swap src/dst IP
                uint32_t src_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = src_ip;
                // Recalculate IP checksum
                update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                // Update the ethernet packet
                swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);

                bpf_trace_printk("NMAP detection found probe 4 of test 1");
                return XDP_TX;
            }
            case TCP_NMAP_T1_P5: {
                // set(flags, ack|syn);
                // set(win, 8192);
                // insert(mss,1460);
                // insert(wscale,8);
                // insert(sackOK);
                // insert(timestamp);

                // Fix TCP header
                // Set Syn/Ack on the TCP header
                tcp->syn = 1;
                tcp->ack = 1;

                // TODO: We need some random sequence number for the return
                tcp->window = htons(8192);

                // Swap src/dst TCP
                uint16_t src_tcp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = src_tcp_port;

                // Set the TCP options
                u_int32_t options_len = 20;
                void *options_start = (void *) tcp + sizeof(struct tcphdr);
                void * cursor = options_start;
                if (cursor + 20 > data_end)
                {
                    bpf_trace_printk("Error: boundary exceeded while trying to set TCP Options");
                    return DEFAULT_ACTION;
                }
                else
                {
                    (*(u_int32_t *)(cursor +  0)) = htonl(0x020405b4);
                    (*(u_int32_t *)(cursor +  4)) = htonl(0x01030308);
                    (*(u_int32_t *)(cursor +  8)) = htonl(0x0402080a);
                    (*(u_int32_t *)(cursor + 12)) = htonl(0x00163244);
                    (*(u_int32_t *)(cursor + 16)) = htonl(0xffffffff);
                }

                update_ip_checksum(tcp, sizeof(struct tcphdr) + options_len, &tcp->check);

                // Update the IP packet

                // Swap src/dst IP
                uint32_t src_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = src_ip;
                // Recalculate IP checksum
                update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                // Update the ethernet packet
                swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);
                bpf_trace_printk("NMAP detection found probe 5 of test 1");
                return XDP_TX;
            }
            case TCP_NMAP_T1_P6: {
                // /* SEQ6 */
                // if (option(mss) && option(timestamp))
                // {
                //     set(flags, ack|syn);
                //     set(win, 8192);
                //     insert(mss,1460);
                //     insert(sackOK);
                //     insert(timestamp);

                //     reply;
                // }

                // Fix TCP header
                // Set Syn/Ack on the TCP header
                tcp->syn = 1;
                tcp->ack = 1;

                // TODO: We need some random sequence number for the return
                tcp->window = htons(8192);

                // Swap src/dst TCP
                uint16_t src_tcp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = src_tcp_port;

                // Set the TCP options
                u_int32_t options_len = 16;
                void *options_start = (void *) tcp + sizeof(struct tcphdr);
                void * cursor = options_start;
                if (cursor + 16 > data_end)
                {
                    bpf_trace_printk("Error: boundary exceeded while trying to set TCP Options");
                    return DEFAULT_ACTION;
                }
                else
                {
                    (*(u_int32_t *)(cursor +  0)) = htonl(0x020405b4);
                    (*(u_int32_t *)(cursor +  4)) = htonl(0x0402080a);
                    (*(u_int32_t *)(cursor +  8)) = htonl(0x0016344c);
                }

                update_ip_checksum(tcp, sizeof(struct tcphdr) + options_len, &tcp->check);

                // Update the IP packet
                // Swap src/dst IP
                uint32_t src_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = src_ip;
                // Recalculate IP checksum
                update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                // Update the ethernet packet
                swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);

                bpf_trace_printk("NMAP detection found probe 6 of test 1");
                return XDP_TX;
            }
            case TCP_NMAP_T2_P1:
            case TCP_NMAP_T3_P1:
            case TCP_NMAP_T4_P1:
            case TCP_NMAP_T6_P1:
            case TCP_NMAP_T7_P1:
            {
                return XDP_DROP;
            }

            case TCP_NMAP_NONE: {
#ifdef DEBUG
                bpf_trace_printk("NMAP detection found nothing.");
#endif
                return XDP_PASS;
            }
        }


        // Access the window size field

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
