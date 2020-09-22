all: pcap-test

pcap-test: main.o
	g++ -o pcap-test main.o -lpcap

main1.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f pcap-test *.o