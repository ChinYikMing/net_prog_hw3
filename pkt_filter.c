#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
	u_int size_tcp;
	u_int size_udp;

	eth = (Ethernet *) packet;

	ip = (IP *) (packet + SIZE_ETHERNET);
	size_ip = get_ip_hdr_len(ip) << 2; // multiple 4 to get the total bytes since it is 4-byte words
	if(size_ip < 20){
		fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	// resolve byte ordering
	ip_ntohs(ip);

	/*
	printf("ip len(bin): %x\n", ip->len);
	printf("ip len: %u\n", ip->len);
	printf("ip id: %u\n", ip->id);
	printf("=============================\n");
	*/

	// ttl no problem
	//printf("ip ttl: %u\n", ip->ttl);
	
	// protocol no problem
	//printf("ip ttl: %u\n", ip->proto);
	
	// ip size no problem
	//printf("ip size: %u\n", size_ip);

	/* ip no problem
	char buf[INET_ADDRSTRLEN];
	const char *ip_src;
	const char *ip_dst;
	ip_src = inet_ntop(AF_INET, (void *) &ip->src_ip, buf, INET_ADDRSTRLEN);
	printf("ip src: %s\n", ip_src);
	ip_dst = inet_ntop(AF_INET, (void *) &ip->dst_ip, buf, INET_ADDRSTRLEN);
	printf("ip dest: %s\n", ip_dst);
	*/

	udp = (UDP *) (packet + SIZE_ETHERNET + size_ip);
	udp_ntohs(udp);

	printf("src port: %u\n", udp->src_port);
	printf("dest port: %u\n", udp->dst_port);
	printf("payload len: %u\n", udp->len);
	printf("=============================\n");

	/*
	size_tcp = get_tcp_offset(tcp) << 2; // multiple 4 to get the total bytes since it is 4-byte words
	if(size_tcp < 20){
		fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	*/

	/*
	char buf[1024];
	payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
	snprintf(buf, 100, "%s", payload);
	printf("buf: %s\n", buf);
	*/
	return;
}
