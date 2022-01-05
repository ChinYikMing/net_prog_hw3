#include <stdio.h>
#include <time.h>
#include <assert.h> 
#include <stdbool.h> 
#include <stdlib.h> 
#include <signal.h>
#include <pthread.h>
#include <string.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include "pkt_filter.h"
#include "basis.h"

#define LOOP_FOREVER -1
#define MAX_DEV_SIZE 64
#define MAX_EXPR_SIZE 512
#define MAX_WRITE_FILENAME 512
#define MAX_SNAPLEN 8192

// options flag
#define OP_FILE  0x1
#define OP_IF    0x2
#define OP_WRITE 0x4

#define err_exit(msg){ \
    fprintf(stderr, "%s\n", msg); \
    exit(1); \
}

// DNS RR type(RFC 1035)
static const char *dns_types[18] = {
	"UNKN",  /* Unsupported / Invalid type */
	"A",     /* Host Address */
	"NS",    /* Authorative Name Server */
	"MD",    /* Mail Destination (Obsolete) */
	"MF",    /* Mail Forwarder   (Obsolete) */
	"CNAME", /* Canonical Name */
	"SOA",   /* Start of Authority */
	"MB",    /* Mailbox (Experimental) */
	"MG",    /* Mail Group Member (Experimental) */
	"MR",    /* Mail Rename (Experimental) */
	"NULL",  /* Null Resource Record (Experimental) */
	"WKS",   /* Well Known Service */
	"PTR",   /* Domain Name Pointer */
	"HINFO", /* Host Information */
	"MINFO", /* Mailbox / Mail List Information */
	"MX",    /* Mail Exchange */
	"TXT",   /* Text Strings */
	"AAAA"   /* IPv6 Host Address (RFC 1886) */
};
size_t packet_cnt = 0;
int datalink;
pcap_t *handle;
char dev[MAX_DEV_SIZE];

void pcap_dev_handler(const char *dev, const char *expr, int op_flags);
void pcap_write_handler(const char *dev, const char *write_filename);
void pcap_show_timestamp(const struct timeval *ts);

void read_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void write_packet(u_char *handle, const struct pcap_pkthdr *header, const u_char *packet);

pcap_t *get_handle_by_dev(const char *dev, bpf_u_int32 *net, bpf_u_int32 *mask); // caller is responsible to close the handle

void sig_handler(int signum);
static void usage(const char *prog_name);

int main(int argc, char *argv[]){
	/*
    if(argc < 3)
        usage(argv[0]);
	*/

    int opt;
    char expr[MAX_EXPR_SIZE] = "";     // default empty expression means all packets
    char write_filename[MAX_WRITE_FILENAME];
    int op_flags = 0;
    while((opt = getopt(argc, argv, "hf:i:e:w:")) != -1){
	switch(opt){
		case 'h':
			usage(argv[0]);

		case 'f':
			if(op_flags & OP_IF)
				err_exit("file and interface option are mutual exclusion");
			op_flags |= OP_FILE;
			strcpy(dev, optarg);
			break;

		case 'i':
			if(op_flags & OP_FILE)
				err_exit("file and interface option are mutual exclusion");
			op_flags |= OP_IF;
			strcpy(dev, optarg);
			break;

		case 'e':
			strcpy(expr, optarg);
			break;

		case 'w':
			op_flags |= OP_WRITE;
			strcpy(write_filename, optarg);
			break;

		default: // invalid option => exit the program
			err_exit("use '-h' option to check all available options");
	}
    }

    // default select any available interface
    if(!(op_flags & OP_IF | op_flags & OP_FILE))
	    	op_flags |= OP_IF;

    if(op_flags & OP_WRITE){
	    if(!(op_flags & OP_IF))
		err_exit("write packets option only available when interface is specified");

	    pcap_write_handler(dev, write_filename);
    } else
	    pcap_dev_handler(dev, expr, op_flags);

    exit(0);
}

void write_packet(u_char *dumper, const struct pcap_pkthdr *header, const u_char *packet){
	printf("\rGot %zu packets", packet_cnt);
	fflush(stdout);
	pcap_dump(dumper, header, packet);
	packet_cnt++;
}

// simply ignore first argument since it is NULL
void read_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	Ethernet *eth;
	ARP *arp;
	IP *ip;
	TCP *tcp;
	UDP *udp;
	u_char *payload;
	u_int size_ip;

	// show sniff timestamp
	printf("Timestamp: ");
	pcap_show_timestamp(&header->ts);

	// determine Link Layer type
	switch(datalink){
		case DLT_NULL:
			printf("lo\n");
			break;

		case DLT_EN10MB:
			eth = (Ethernet *) packet;
			eth_ntohs(eth);

			// show MAC address (cmd("ip link") to check your interface MAC address) and type
			eth_info_print(eth);

			if(eth->type == ETHERTYPE_ARP){
				arp = (ARP *) (packet + SIZE_ETHERNET);
				arp_handler(arp);
				goto end;
			} else if(eth->type == ETHERTYPE_IP){ // unsupported Internet Layer protocols
				ip = (IP *) (packet + SIZE_ETHERNET);
			} else {
				printf("Unknown protocol in Internet Layer, please use IPv4 instead\n");
				goto end;
			}

			break;

		default:
			printf("Unknown protocol in Link Layer, please use Ethernet or Loopback instead\n");
			goto end;
	}

	size_ip = get_ip_hdr_len(ip) << 2; // multiple 4 to get the total bytes since it is 4-byte words
	if(size_ip < 20){
		fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
		goto end;
	}
	ip_ntohs(ip);
	ip_handler(ip);

	if(IPPROTO_UDP == ip->proto){
		udp = (UDP *) (packet + SIZE_ETHERNET + size_ip);
		udp_handler(udp);

		if(53 == udp->src_port || 53 == udp->dst_port){
			DNS *dns = (DNS *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
			dns_ntohs(dns);

			dns_handler(dns);
		} else { // unsupported Application Layer protocols
			printf("Unknown protocol in Application Layer, only supported DNS(rfc1035)\n");
			goto end;
		}
	} else if(IPPROTO_TCP == ip->proto){
		tcp = (TCP *) (packet + SIZE_ETHERNET + size_ip);
		tcp_handler(tcp);

		u_int size_tcp;
		size_tcp = get_tcp_offset(tcp) << 2;
		if(53 == tcp->src_port || 53 == tcp->dst_port){
			DNS *dns = (DNS *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
			dns_ntohs(dns);

			dns_handler(dns);
		} else { // unsupported Application Layer protocols
			printf("Unknown protocol in Application Layer, only supported DNS(rfc1035)\n");
			goto end;
		}
	} else {  // unsupported Transport Layer protocols
		printf("Unknown protocol in Transport Layer, please use TCP/UDP instead\n");
		goto end;
	}

end:
	printf("========================================================================================="
		"==================================================================================\n");
	return;
}

void tcp_handler(TCP *tcp){
	tcp_ntohs(tcp);
	u_int size_tcp;

	size_tcp = get_tcp_offset(tcp) << 2; // multiple 4 to get the total bytes since it is 4-byte words
	if(size_tcp < 20){
		fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("TCP (src port: %u, ", tcp->src_port);
	printf("dest port: %u)\n", tcp->dst_port);
	return;
}

void udp_handler(UDP *udp){
	udp_ntohs(udp);

	printf("UDP (src port: %u, ", udp->src_port);
	printf("dest port: %u, ", udp->dst_port);
	printf("data length: %u)\n", udp->len);
	return;
}

void ip_handler(IP *ip){
	char src_buf[INET_ADDRSTRLEN];
	char dst_buf[INET_ADDRSTRLEN];
	const char *src_ip;
	const char *dst_ip;
	src_ip = inet_ntop(AF_INET, (void *) &ip->src_ip, src_buf, INET_ADDRSTRLEN);
	dst_ip = inet_ntop(AF_INET, (void *) &ip->dst_ip, dst_buf, INET_ADDRSTRLEN);
	printf("IP (ttl: %u, proto: %u, src_ip: %s, dst_ip: %s, len: %u)\n", 
			ip->ttl, ip->proto, src_ip, dst_ip, ip->len);
	return;
}

void eth_info_print(Ethernet *eth){
	u_char *ptr = eth->src_mac;
	u_char tmp;
	printf("ETHERNET (src_MAC: ");
	for(size_t i = 0; i < MAC_ADDR_LEN; ++i){
		memcpy(&tmp, ptr, sizeof(u_char));
		if(tmp < 0xf) // we need to fill zero before the hex
			printf("0");
		if(MAC_ADDR_LEN - 1 == i){
			printf("%X", *ptr);
			break;
		}
		printf("%X.", *ptr);
		ptr++;
	}
	printf(", dst_MAC: ");
	ptr = eth->dst_mac;
	for(size_t i = 0; i < MAC_ADDR_LEN; ++i){
		memcpy(&tmp, ptr, sizeof(u_char));
		if(tmp < 0xf) // we need to fill zero before the hex
			printf("0");
		if(MAC_ADDR_LEN - 1 == i){
			printf("%X ", *ptr);
			break;
		}
		printf("%X.", *ptr);
		ptr++;
	}

	printf("type: ");
	if(eth->type & ETHERTYPE_IP)
		printf("IPv4");
	else
		printf("Unknown");
	printf(")\n");
	return;
}

void pcap_dev_handler(const char *dev,const char *expr, int op_flags){
    char err_buf[PCAP_ERRBUF_SIZE] = {0};
    int ret;

    if(op_flags & OP_FILE){
	handle = pcap_open_offline(dev, err_buf);
	if(!handle)
		err_exit(err_buf);
	goto sniff;
    } else if(op_flags & OP_IF){
        bpf_u_int32 net;
        bpf_u_int32 mask;

	handle = get_handle_by_dev(dev, &net, &mask);
	if(handle){
	    struct bpf_program filter;
	    ret = pcap_compile(handle, &filter, expr, 0, net);
	    if(ret == -1)
		goto err;

	    ret = pcap_setfilter(handle, &filter);
	    if(ret == -1)
		goto err;

	    goto sniff;
	}

	err_exit("interface not found");
    }

sniff:
    printf("Listening on %s, snapshot length %zu bytes\n", dev, MAX_SNAPLEN);

    datalink = pcap_datalink(handle);
    
    // handle ctrl-C signal
    signal(SIGINT, sig_handler);

    ret = pcap_loop(handle, LOOP_FOREVER, read_packet, NULL);
    if(ret == -1)
	goto err;

    pcap_close(handle);
    exit(0);

err:
    pcap_close(handle);
    err_exit(pcap_geterr(handle));
}

void pcap_write_handler(const char *dev, const char *write_filename){
	int ret;
        bpf_u_int32 net;
        bpf_u_int32 mask;
	pcap_t *handle = get_handle_by_dev(dev, &net, &mask);
	
        pcap_dumper_t *dumper;
	if(handle){
   	    printf("Listening on %s, snapshot length %zu bytes\n", dev, MAX_SNAPLEN);
	    
	    dumper = pcap_dump_open(handle, write_filename);
	    if(!dumper)
		    err_exit(pcap_geterr(handle));

	    ret = pcap_loop(handle, LOOP_FOREVER, write_packet, (u_char *) dumper);
	    if(ret == -1)
		    err_exit(pcap_geterr(handle));
	} else
		    err_exit("Invalid interface");

done:
	pcap_close(handle);
	pcap_dump_close(dumper);
	return;
}

pcap_t *get_handle_by_dev(const char *dev, bpf_u_int32 *net, bpf_u_int32 *mask){
    	pcap_if_t *dev_ptr, *tmp;
	int ret;
	char err_buf[PCAP_ERRBUF_SIZE];
    	pcap_t *handle;

    	if(pcap_findalldevs(&dev_ptr, err_buf) == PCAP_ERROR)
		err_exit(err_buf);
	tmp = dev_ptr;

	while(dev_ptr){
		if(dev_ptr->flags & PCAP_IF_RUNNING && strcmp(dev_ptr->name, dev) == 0){
		    ret = pcap_lookupnet(dev, net, mask, err_buf);
		    if(ret == -1){
			fprintf(stderr, "Can't get netmask for device %s\n", dev);
			*net = 0;
			*mask = 0;
		    }

		    handle = pcap_open_live(dev, MAX_SNAPLEN, 1, 1000, err_buf);
		    if(!handle)
			err_exit(err_buf);

		    pcap_freealldevs(dev_ptr);
		    return handle;
		}
		dev_ptr = dev_ptr->next;
	}

	// default select any available interface
	dev_ptr = tmp;
	while(dev_ptr){
		if((dev_ptr->flags & PCAP_IF_RUNNING)){
		    strcpy(dev, dev_ptr->name);

		    ret = pcap_lookupnet(dev_ptr->name, net, mask, err_buf);
		    if(ret == -1){
			fprintf(stderr, "Can't get netmask for device %s\n", dev);
			*net = 0;
			*mask = 0;
		    }

		    handle = pcap_open_live(dev_ptr->name, MAX_SNAPLEN, 1, 1000, err_buf);
		    if(!handle)
			err_exit(err_buf);

		    pcap_freealldevs(dev_ptr);
		    return handle;
		}
		dev_ptr = dev_ptr->next;
	}
	
	// no any interface are available
	return NULL;
}

void dns_handler(DNS *dns){
	u_short i, j;
	u_short id = dns->id;
	u_short flags = dns->flags;
	u_short qd_cnt = dns->qd_cnt;
	u_short an_cnt = dns->an_cnt;
	u_short ns_cnt = dns->ns_cnt;
	u_short ar_cnt = dns->ar_cnt;

	/*
	printf("qr: %x\n", get_dns_qr_bit(dns));
	printf("opcode: %x\n", get_dns_opcode(dns));
	printf("aa: %x\n", get_dns_aa_bit(dns));
	printf("tc: %x\n", get_dns_tc_bit(dns));
	printf("rd: %x\n", get_dns_rd_bit(dns));
	printf("ra: %x\n", get_dns_ra_bit(dns));
	printf("z: %x\n", get_dns_z(dns));
	printf("rcode: %x\n", get_dns_rcode(dns));
	*/

	printf("DNS (");
	printf("ID: %u, Flags: %x, Questions: %u, Answers: %u, Authority RRs: %u, Additional RRs: %u)\n",
			id, flags, qd_cnt, an_cnt, ns_cnt, ar_cnt);
	
	u_char *payload = ((u_char *) dns) + sizeof(DNS);
	
	// query
	u_short query_nr = 1;
	while(qd_cnt--){
		// parsing qname
		printf("Query #%u:\n", query_nr);
		printf("\tQName: ");
		dns_label2str(&payload, (u_char *) dns);

		// parsing qtype
		u_short qtype_idx = ntohs(*((u_short *) payload));
		printf("\tQType: ");

		if(qtype_idx == 0 || qtype_idx > 28){
			printf("Unknown\n");
			return;
		}

		if(qtype_idx == 28)
			qtype_idx= 17;

		const char *qtype_str = dns_types[qtype_idx];
		printf("%s\n", qtype_str);
		payload += 2;

		// parsing qclass
		printf("\tQClass: ");
		u_short qclass = ntohs(*((u_short *) payload));
		if(qclass == CLASS_IN){
			printf("IN");
		} else if(qclass == CLASS_CH){
		
		} else if(qclass == CLASS_HS){
		
		}
		printf("\n");
		payload += 2;

		query_nr++;
	}

	// answer
	u_short ans_nr = 1;
	while(an_cnt--){
		// parsing answers
		printf("Answer #%u:\n", ans_nr);
		printf("\tName: ");
		dns_label2str(&payload, (u_char *) dns);

		printf("\tType: ");
		u_short type_idx = ntohs(*((u_short *) payload));
		if(type_idx == 28)
			type_idx = 17;
		const char *qtype_str = dns_types[type_idx];
		printf("%s\n", qtype_str);
		payload += 2;
		
		// parsing class
		printf("\tQClass: ");
		u_short qclass = ntohs(*((u_short *) payload));
		if(qclass == CLASS_IN){
			printf("IN");
		} else if(qclass == CLASS_CH){
		
		} else if(qclass == CLASS_HS){
		
		}
		printf("\n");
		payload += 2;

		// parsing ttl
		printf("\tTTL: ");
		uint32_t ttl = ntohl(*((uint32_t *) payload));
		printf("%u\n", ttl);
		payload += 4;

		// parsing data length
		printf("\tdata length: ");
		u_short len = ntohs(*((u_short *) payload));
		printf("%u\n", len);
		payload += 2;

		const char *addr;
		if(0 == strcmp(qtype_str, "A")){
			char buf[INET_ADDRSTRLEN];
			addr = inet_ntop(AF_INET, (void *) payload, buf, INET_ADDRSTRLEN);
			printf("\tAddress: ");
			printf("%s\n", addr);

			payload += len;
		} else if(0 == strcmp(qtype_str, "CNAME")){
			printf("\tName server: ");
			dns_label2str(&payload, (u_char *) dns);
		} else if(0 == strcmp(qtype_str, "WKS")){
			printf("\tName server: ");
			dns_label2str(&payload, (u_char *) dns);

		} else if(0 == strcmp(qtype_str, "PTR")){
			printf("\tName server: ");
			dns_label2str(&payload, (u_char *) dns);
		} else if(0 == strcmp(qtype_str, "HINFO")){
			u_char cpu_len = *((u_short *) payload);
			payload += 1;
			printf("\tCPU: ");
			if(cpu_len){
				for(u_char i = 0; i < cpu_len; ++i){
					printf("%c", *payload);
					payload++;
				}
			} else {
				printf("\"\"");
			}
			printf("\n");

			u_char os_len = *((u_short *) payload);
			payload += 1;
			printf("\tOS: ");
			if(os_len){
				for(u_char i = 0; i < os_len; ++i){
					printf("%c", *payload);
					payload++;
				}
			} else {
				printf("\"\"");
			}
			printf("\n");
		} else if(0 == strcmp(qtype_str, "MX")){
			u_short preference = ntohs(*((u_short *) payload));
			printf("\tPreference: %u\n", preference);
			payload += 2;

			printf("\tMail exchange: ");
			dns_label2str(&payload, (u_char *) dns);
		} else if(0 == strcmp(qtype_str, "TXT")){
			printf("\ttext: ");
			for(u_short i = 0; i < len; ++i)
				printf("%c", *(payload +i));
			printf("\n");

			payload += len;
		} else if(0 == strcmp(qtype_str, "AAAA")){
			char buf[INET6_ADDRSTRLEN];
			addr = inet_ntop(AF_INET6, (void *) payload, buf, INET6_ADDRSTRLEN);
			printf("\tAddress: ");
			printf("%s\n", addr);

			payload += len;
		} else if(0 == strcmp(qtype_str, "NS")){
			printf("\tName server:");
			dns_label2str(&payload, (u_char *) dns);
		}

		ans_nr++;
	}

	// authoritative nameservers
	u_short ns_nr = 1;
	while(ns_cnt--){
		// parsing authoritative nameservers
		printf("Authoritative nameservers #%u:\n", ns_nr);
		printf("\tName: ");
		dns_label2str(&payload, (u_char *) dns);

		printf("\tType: ");
		u_short type_idx = ntohs(*((u_short *) payload));
		if(41 == type_idx)
			type_idx = 12;
		const char *qtype_str = dns_types[type_idx];
		printf("%s\n", qtype_str); payload += 2;
		
		// parsing class
		printf("\tQClass: ");
		u_short qclass = ntohs(*((u_short *) payload));
		if(qclass == CLASS_IN){
			printf("IN");
		} else if(qclass == CLASS_CH){
		
		} else if(qclass == CLASS_HS){
		
		}
		printf("\n");
		payload += 2;

		// parsing ttl
		printf("\tTTL: ");
		uint32_t ttl = ntohl(*((uint32_t *) payload));
		printf("%u\n", ttl);
		payload += 4;

		// parsing data length
		printf("\tdata length: ");
		u_short len = ntohs(*((u_short *) payload));
		printf("%u\n", len);
		payload += 2;

		if(0 == strcmp(qtype_str, "SOA")){
			// parsing primary name server
			printf("\tPrimary name server: ");
			dns_label2str(&payload, (u_char *) dns);
			
			// parsing responsible authority's mailbox
			printf("\tResponsible authority's mailbox: ");
			dns_label2str(&payload, (u_char *) dns);

			// parsing serial number
			printf("\tSerial number: ");
			uint32_t serial_nr = ntohl(*((uint32_t *) payload));
			printf("%u\n", serial_nr);
			payload += 4;

			// parsing refresh interval
			printf("\tRefresh interval: ");
			uint32_t refresh_int = ntohl(*((uint32_t *) payload));
			printf("%u\n", refresh_int);
			payload += 4;

			// parsing retry interval
			printf("\tRetry interval: ");
			uint32_t retry_int = ntohl(*((uint32_t *) payload));
			printf("%u\n", retry_int);
			payload += 4;

			// parsing expire limit
			printf("\tExpire limit: ");
			uint32_t expire_lim = ntohl(*((uint32_t *) payload));
			printf("%u\n", expire_lim);
			payload += 4;
			
			// parsing mininum ttl
			printf("\tMinimum TTL: ");
			uint32_t ttl_min = ntohl(*((uint32_t *) payload));
			printf("%u\n", ttl_min);
			payload += 4;
		} else { // NS
			// parsing name server
			printf("\tName server: ");
			dns_label2str(&payload, (u_char *) dns);
		}

		ns_nr++;
	}

	// todo: additional records
}

/*
 * since domain name label could be pointer due to message compression(RFC 1035 4.1.4)
 * we have to take care of it
 * if first 2 bits of octet are 00 -> normal
 * if first 2 bits of octet are 11 -> pointer
 * first 2 bits, 10 and 10 are reserved for future
 * */
void dns_label2str(u_char **label, u_char *start){
	u_char *label_ptr = *label;
	u_char **label_pptr = &label_ptr;
	u_char *tmp = NULL; // pointer to resume before function return if any pointer seen before
	u_char label_len;
	u_short offset = 0;

	// root
	if(!*label_ptr){
		printf("<Root>\n");
		*label = label_ptr + 1;  // skip the null
		return;
	}

	// non root
	while(*label_ptr){
		label_len = *label_ptr;

		if(label_len & 0xC0){ // pointer
			if(!tmp){
				tmp = *label_pptr + 2; 
			}
			offset = ((*label_ptr) & 0x3F) | *(label_ptr + 1);
			label_ptr = start + offset;
			goto next;
		} else {              // octet length
			label_ptr++;
			for(u_short i = 0; i < label_len; ++i){
				printf("%c", *label_ptr);
				label_ptr++;
			}

			if(*label_ptr)
				printf(".");
			else {
				printf("\n");
				break;
			}
		}
	next:;
	}
	label_ptr++; // skip null

	*label = tmp ? tmp : label_ptr; // update label
	return;
}

void pcap_show_timestamp(const struct timeval *ts){
	time_t t = ts->tv_sec + ts->tv_usec / 100000;
	struct tm *loc_time = localtime(&t);
	char time_str[BUFSIZ] = {0};
	strftime(time_str, BUFSIZ, "%y-%m-%d %H:%M:%S", loc_time);

	printf("%s\n", time_str);
}

void sig_handler(int signum){
	// show pcap statistics
	struct pcap_stat stat;

	putc('\n', stdout);
	if(pcap_stats(handle, &stat) < 0)
		err_exit(pcap_geterr(handle));
	printf("%d packets received by filter\n", stat.ps_recv);
	printf("%d packets dropped by kernel\n", stat.ps_drop);

	exit(0);
}

static void usage(const char *prog_name){
    fprintf(stderr, " Usage:\n");
    fprintf(stderr, " %s < -i "BHRED"interface"reset" [-w "BHRED"saved_filename"reset"] | -f "BHRED"pcap_filename"reset" > "
		    "[-e \""BHRED"expression"reset"\", default will sniff all packets]\n", prog_name);
    fprintf(stderr, " Supported expression:\n");
    fprintf(stderr, "     dst "BHRED"host"reset", dst host IP(IPv4 and IPv6)\n");
    fprintf(stderr, "     src "BHRED"host"reset", src host IP(IPv4 and IPv6)\n");
    fprintf(stderr, "     host "BHRED"host"reset", IP(IPv4 and IPv6), no matter src or dst host\n");
    fprintf(stderr, "     dst port "BHRED"port"reset", dest host port\n");
    fprintf(stderr, "     src port "BHRED"port"reset", src host port\n");
    fprintf(stderr, "     port "BHRED"port"reset", no matter src or dst port\n");
    fprintf(stderr, "     less "BHRED"length"reset", packet with less than or equal length\n");
    fprintf(stderr, "     greater "BHRED"length"reset", packet with greater than or equal length\n");
    fprintf(stderr, " Example of expression: \"host 140.123.26.27 && port 80\"\n");
    fprintf(stderr, " A lot more available expression in "
		    "\"https://www.tcpdump.org/manpages/pcap-filter.7.html\"\n");

    err_exit(" Please try again!");
}

void arp_handler(ARP *arp){
	arp_ntohs(arp);

	printf("ARP (");
	/*
	printf("hardware type: ");
	if(arp->hw & DLT_EN10MB)
		printf("Ethernet, ");
	else
		printf("Unknown, ");

	printf("protocol type: ");
	if(arp->proto & ETHERTYPE_IP)
		printf("IPv4, ");
	else
		printf("Unknown, ");

	printf("hardware size: %u, ", arp->hw_size);
	printf("protocol size: %u, ", arp->proto_size);
	*/

	printf("opcode: ");
	if(arp->opcode & ARP_REQ)
		printf("request, ");
	else if(arp->opcode & ARP_REPLY)
		printf("reply, ");
	else
		printf("invalid opcode, ");

	char send_buf[INET_ADDRSTRLEN];
	char tgt_buf[INET_ADDRSTRLEN];
	const char *send_ip;
	const char *tgt_ip;
	send_ip = inet_ntop(AF_INET, (void *) &arp->send_ip, send_buf, INET_ADDRSTRLEN);
	tgt_ip = inet_ntop(AF_INET, (void *) &arp->tgt_ip, tgt_buf, INET_ADDRSTRLEN);
	u_char *ptr = arp->send_mac;
	u_char tmp;
	printf("sender MAC address: ");
	for(size_t i = 0; i < MAC_ADDR_LEN; ++i){
		memcpy(&tmp, ptr, sizeof(u_char));
		if(tmp < 0xf) // we need to fill zero before the hex
			printf("0");
		if(MAC_ADDR_LEN - 1 == i){
			printf("%X", *ptr);
			break;
		}
		printf("%X.", *ptr);
		ptr++;
	}
	printf(", sender IP address: %s", send_ip);
	printf(", target MAC address: ");
	ptr = arp->tgt_mac;
	for(size_t i = 0; i < MAC_ADDR_LEN; ++i){
		memcpy(&tmp, ptr, sizeof(u_char));
		if(tmp < 0xf) // we need to fill zero before the hex
			printf("0");
		if(MAC_ADDR_LEN - 1 == i){
			printf("%X", *ptr);
			break;
		}
		printf("%X.", *ptr);
		ptr++;
	}
	printf(", target IP address: %s)\n", tgt_ip);
}
