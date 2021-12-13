#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H
#include <pcap.h>
#include <netinet/in.h>

#define __ntohs(pkt, field) \
	pkt->field = ntohs(pkt->field)

#define SIZE_ETHERNET 14
#define MAC_ADDR_LEN 6
typedef struct ethernet {
	u_char dst_mac[MAC_ADDR_LEN];
	u_char src_mac[MAC_ADDR_LEN];
	u_short type;
} Ethernet;
#define IPv4 0x0800
#define eth_ntohs(eth){ \
	__ntohs(eth, type); \
}
void eth_info_print(Ethernet *eth);

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
	__ntohs(ip, len); \
	__ntohs(ip, id); \
	__ntohs(ip, offset); \
	__ntohs(ip, chsum); \
}
void ip_handler(IP *ip);

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
#define tcp_ntohs(tcp){ \
	__ntohs(tcp, src_port); \
	__ntohs(tcp, dst_port); \
	__ntohs(tcp, win); \
	__ntohs(tcp, chsum); \
	__ntohs(tcp, urg_ptr); \
}
void tcp_handler(TCP *tcp);

typedef struct udp {
	u_short src_port;
	u_short dst_port;
	u_short len;
	u_short chsum;
} UDP;
#define SIZE_UDP 8
#define udp_ntohs(udp) { \
	__ntohs(udp, src_port); \
	__ntohs(udp, dst_port); \
	__ntohs(udp, len); \
	__ntohs(udp, chsum); \
}
void udp_handler(UDP *udp);

typedef struct dns {
	u_short id;
	u_short flags; // for QR, Opcode, AA, TC, RD, RA, Z, RCODE
	u_short qd_cnt;
	u_short an_cnt;
	u_short ns_cnt;
	u_short ar_cnt;
} DNS;
#define get_dns_qr_bit(dns) ((dns->flags) >> 15)
#define get_dns_opcode(dns) (((dns->flags) >> 11) & 0xf)
#define get_dns_aa_bit(dns) (((dns->flags) >> 10) & 0x1)
#define get_dns_tc_bit(dns) (((dns->flags) >> 9) & 0x1)
#define get_dns_rd_bit(dns) (((dns->flags) >> 8) & 0x1)
#define get_dns_ra_bit(dns) (((dns->flags) >> 7) & 0x1)
#define get_dns_z(dns)      (((dns->flags) >> 4) & 0x7)
#define get_dns_rcode(dns)  ((dns->flags) & 0xf)
#define dns_ntohs(dns) { \
	__ntohs(dns, id); \
	__ntohs(dns, flags); \
	__ntohs(dns, qd_cnt); \
	__ntohs(dns, an_cnt); \
	__ntohs(dns, ns_cnt); \
	__ntohs(dns, ar_cnt); \
}
void dns_handler(DNS *dns);
void dns_label2str(u_char **label, u_char *start);

#endif
