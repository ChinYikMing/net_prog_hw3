#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "pkt_filter.h"
#include "basis.h"

#define LOOP_FOREVER -1
#define MAX_DEV_SIZE 512
#define MAX_EXPR_SIZE 512

#define err_exit(msg){ \
    fprintf(stderr, "%s\n", msg); \
    exit(1); \
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static void usage(char *prog_name){
    fprintf(stderr, " Usage:\n");
    fprintf(stderr, " %s < -i interface | -f pcap_filename > [-e \"expression\", default will sniff all packets]\n", prog_name);
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

int main(int argc, char *argv[]){
    if(argc != 5)
        usage(argv[0]);

    int opt;
    char dev[MAX_DEV_SIZE];
    char expr[MAX_EXPR_SIZE] = "";     // default empty expression means all packets
    _Bool has_file_opt = false;
    _Bool has_if_opt = false;
    while((opt = getopt(argc, argv, "hf:i:e:")) != -1){
	switch(opt){
		case 'h':
			usage(argv[0]);

		case 'f':
			if(has_if_opt)
				err_exit("file and interface option are mutual exclusion");
			has_file_opt = true;
			strcpy(dev, optarg);
			break;

		case 'i':
			if(has_file_opt)
				err_exit("file and interface option are mutual exclusion");
			has_if_opt = true;
			strcpy(dev, optarg);
			break;

		case 'e':
			strcpy(expr, optarg);
			break;

		default: // invalid option => exit the program
			err_exit("use '-h' option to check all available options");
	}
    }

    pcap_dev_handler(dev, expr, has_if_opt ? DEV_IF : DEV_FILE);
}

// simply ignore first argument since it is NULL
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	Ethernet *eth;
	IP *ip;
	TCP *tcp;
	UDP *udp;
	u_char *payload;
	u_int size_ip;

	eth = (Ethernet *) packet;
	eth_ntohs(eth);

	// show MAC address (cmd("ip link") to check your interface MAC address) and type
	eth_info_print(eth);

	ip = (IP *) (packet + SIZE_ETHERNET);
	size_ip = get_ip_hdr_len(ip) << 2; // multiple 4 to get the total bytes since it is 4-byte words
	if(size_ip < 20){
		fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	ip_ntohs(ip);

	// ip info
	char src_buf[INET_ADDRSTRLEN];
	char dst_buf[INET_ADDRSTRLEN];
	const char *src_ip;
	const char *dst_ip;
	src_ip = inet_ntop(AF_INET, (void *) &ip->src_ip, src_buf, INET_ADDRSTRLEN);
	dst_ip = inet_ntop(AF_INET, (void *) &ip->dst_ip, dst_buf, INET_ADDRSTRLEN);
	printf("IP (ttl: %u, proto: %u, src_ip: %s, dst_ip: %s, len: %u)\n", 
			ip->ttl, ip->proto, src_ip, dst_ip, ip->len);

	if(IPPROTO_UDP == ip->proto)
		udp_handler((UDP *) (packet + SIZE_ETHERNET + size_ip));
	else if(IPPROTO_TCP == ip->proto)
		tcp_handler((TCP *) (packet + SIZE_ETHERNET + size_ip));

	/* statistics of packets */
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
	printf("=============================\n");
}

void udp_handler(UDP *udp){
	udp_ntohs(udp);

	printf("UDP (src port: %u, ", udp->src_port);
	printf("dest port: %u)\n", udp->dst_port);
	printf("=============================\n");
}

void ip_handler(IP *ip){

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

	if(eth->type & IPv4)
		printf("type: IPv4)\n");
	return;
}

void pcap_dev_handler(char *dev, char *expr, DevType devtype){
    char err_buf[PCAP_ERRBUF_SIZE];
    int ret;
    pcap_t *handle;

    if(DEV_FILE == devtype){
	handle = pcap_open_offline(dev, err_buf);
	if(!handle)
		err_exit(err_buf);
	goto sniff;
    } else if(DEV_IF == devtype){
    	pcap_if_t *dev_ptr;
    	ret = pcap_findalldevs(&dev_ptr, err_buf);
    	if(ret == PCAP_ERROR)
		err_exit(err_buf);

	while(dev_ptr){
		if(dev_ptr->flags & PCAP_IF_UP && strcmp(dev_ptr->name, dev) == 0){
		    bpf_u_int32 mask;
		    bpf_u_int32 net;

		    ret = pcap_lookupnet(dev, &net, &mask, err_buf);
		    if(ret == -1){
			fprintf(stderr, "Can't get netmask for device %s\n", dev);
			net = 0;
			mask = 0;
		    }

		    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
		    if(!handle)
			err_exit(err_buf);

		    struct bpf_program filter;
		    ret = pcap_compile(handle, &filter, expr, 0, net);
		    if(ret == -1)
			goto err;

		    ret = pcap_setfilter(handle, &filter);
		    if(ret == -1)
			goto err;

		    goto sniff;
		}
		dev_ptr = dev_ptr->next;
	}
	err_exit("interface not found");
    }
sniff:
    ret = pcap_loop(handle, LOOP_FOREVER, got_packet, NULL);
    if(ret == -1)
	goto err;

    pcap_close(handle);
    exit(0);

err:
    pcap_close(handle);
    err_exit(pcap_geterr(handle));
}
