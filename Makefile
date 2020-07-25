all : pcap-test

pcap-test: main.o
	g++ -g -o pcap-test main.o -lpcap

main.o:
	g++ -g -c -o main.o main.c

clean:
	rm -f pcap-test
	rm -f *.o
