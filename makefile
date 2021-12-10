all:
	gcc -g pkt_filter.c -lpcap -o pkt_filter

clean:
	rm pkt_filter
