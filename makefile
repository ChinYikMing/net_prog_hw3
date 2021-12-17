all:
	gcc -g pkt_filter.c -lpcap -o pkt_filter -Wno-discarded-qualifiers

clean:
	rm -rf pkt_filter
