CC = gcc
PCAP = -lpcap
all:reader
reader:reader.c
	$(CC) reader.c -o reader $(PCAP)

clean:
	rm -f reader
