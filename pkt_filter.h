#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H
#include <pcap.h>
#include <netinet/in.h>

typedef struct ethernet {
	u_char preamble[7];
#define MAC_ADDR_LEN 6
	u_char dst_mac[MAC_ADDR_LEN];
	u_char src_mac[MAC_ADDR_LEN];
	u_short type;
	u_short crc;
} Ethernet;
#define SIZE_ETHERNET 14

typedef struct ip {
	u_char vhl; 
	u_char tos;
	u_short len;
	u_short id;
	u_short offset;  // includes offset, reserved bit, dont fragment bit, more fragment bit
	u_char ttl;
	u_char proto;
	u_short chsum;
	struct in_addr src_ip;
	struct in_addr dst_ip;
} IP;
#define RF 0x8000 // reserved bit
#define DF 0x4000 // don't fragment bit
#define MF 0x2000 // more fragment bit
#define get_ip_version(ip) (((ip)->vhl) >> 4)
#define get_ip_hdr_len(ip) (((ip)->vhl) & 0x0f)
#define get_ip_offset(ip) (((ip)->offset) & 0x1fff)
#define get_ip_reserved_bit(ip) ((((ip)->offset) >> 13) & RF)
#define get_ip_dont_frag_bit(ip) ((((ip)->offset) >> 13) & DF)
#define get_ip_more_frag_bit(ip) ((((ip)->offset) >> 13) & MF)
#define ip_ntohs(ip) { \
	ip->len = ntohs(ip->len); \
	ip->id = ntohs(ip->id); \
	ip->offset = ntohs(ip->offset); \
	ip->chsum = ntohs(ip->chsum); \
}

typedef struct tcp {
	u_short src_port;
	u_short dst_port;
	u_int seq;
	u_int ack;
	u_char offset;   // includes 4 most significant bits of reserved
	u_char flags;    // 2 least significant bits of reserved, URG, ACK, PSH, RST, SYN, FIN
	u_short win;
	u_short chsum;
	u_short urg_ptr;
} TCP;
#define URG 0x20
#define ACK 0x10
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01
#define get_tcp_offset(tcp) (((tcp)->offset & 0xf0) >> 4)
#define get_tcp_reserved(tcp) (((((tcp)->offset) & 0x0f) << 2) | (((tcp)->flags >> 6) & 0x03))
#define get_tcp_urg_bit(tcp) (((tcp)->flags) & URG)
#define get_tcp_ack_bit(tcp) (((tcp)->flags) & ACK)
#define get_tcp_psh_bit(tcp) (((tcp)->flags) & PSH)
#define get_tcp_rst_bit(tcp) (((tcp)->flags) & RST)
#define get_tcp_syn_bit(tcp) (((tcp)->flags) & SYN)
#define get_tcp_fin_bit(tcp) (((tcp)->flags) & FIN)

typedef struct udp {
	u_short src_port;
	u_short dst_port;
	u_short len;
	u_short chsum;
} UDP;
#define SIZE_UDP 8
#define udp_ntohs(udp) { \
	udp->src_port = ntohs(udp->src_port); \
	udp->dst_port = ntohs(udp->dst_port); \
	udp->len = ntohs(udp->len); \
	udp->chsum = ntohs(udp->chsum); \
}

typedef struct icmp {

} ICMP;

typedef struct arp {

} ARP;

typedef struct dns {

} DNS;

#endif
