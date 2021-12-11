all:
	gcc -g pkt_filter.c -lpcap -o pkt_filter

clean:
	rm -rf pkt_filter
