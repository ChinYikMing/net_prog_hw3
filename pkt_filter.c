#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
*/
#include <arpa/inet.h>
#include "pkt_filter.h"

#define LOOP_FOREVER -1

#define err_exit(msg){ \
    fprintf(stderr, "%s\n", msg); \
    exit(1); \
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static void usage(char *prog_name){
    printf("%s <desired interface>\n", prog_name);
    exit(1);
}

int main(int argc, char *argv[]){
    if(argc != 2)
        usage(argv[0]);

    char *dev_desired = argv[1];
    char err_buf[PCAP_ERRBUF_SIZE];
    int ret;

    pcap_if_t *dev_ptr;
    ret = pcap_findalldevs(&dev_ptr, err_buf);
    if(ret == PCAP_ERROR)
        err_exit(err_buf);

    while(dev_ptr){
        if(dev_ptr->flags & PCAP_IF_UP && strcmp(dev_ptr->name, dev_desired) == 0){
            bpf_u_int32 mask;
            bpf_u_int32 net;

            ret = pcap_lookupnet(dev_desired, &net, &mask, err_buf);
            if(ret == -1){
                fprintf(stderr, "Can't get netmask for device %s\n", dev_desired);
                net = 0;
                mask = 0;
            }

            pcap_t *handle;
            handle = pcap_open_live(dev_desired, BUFSIZ, 1, 1000, err_buf);
            if(!handle)
                err_exit(err_buf);

            struct bpf_program filter;
            char expr[] = "port 53";
            ret = pcap_compile(handle, &filter, expr, 0, net);
            if(ret == -1){
		pcap_close(handle);
                err_exit(pcap_geterr(handle));
	    }

            ret = pcap_setfilter(handle, &filter);
            if(ret == -1){
		pcap_close(handle);
                err_exit(pcap_geterr(handle));
	    }

	    // sniff packet
	    ret = pcap_loop(handle, LOOP_FOREVER, got_packet, NULL);
	    if(ret == -1){
		pcap_close(handle);
                err_exit(pcap_geterr(handle));
	    }

            pcap_close(handle);
            exit(0);
        }
        dev_ptr = dev_ptr->next;
    }

    // desired interface not found
    fprintf(stderr, "%s interface not found!\n", dev_desired);
    exit(1);
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
