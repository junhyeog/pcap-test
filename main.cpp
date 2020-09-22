#include <libnet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap-test <interface>\n");
  printf("sample: pcap-test wlan0\n");
}

const uint16_t MAX_DATA_SIZE = 0x10;
const uint16_t WORD_SIZE = 0x4;

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];  // get network device
  char errbuf[PCAP_ERRBUF_SIZE];

  /* get device */
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "Couldn't open %s - %s\n", dev, errbuf);
    fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
    return -1;
  }

  /* get packet */
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;        // 패킷을 얻지 못함
    if (res == -1 || res == -2) {  // 패킷을 더이상 얻지 못하는 상태
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
      break;
    }
    // 패킷 얻음
    const auto ethernet = (libnet_ethernet_hdr*)packet;
    if (ntohs(ethernet->ether_type) == 0x0800) {  // IPv4
      const auto ip = (libnet_ipv4_hdr*)(ethernet + 1);
      if (ip->ip_p == 0x06) {  // TCP
        const auto tcp = (libnet_tcp_hdr*)(ip + 1);
        const auto payload = (u_char*)tcp + (uint16_t)tcp->th_off * WORD_SIZE;
        uint16_t data_size =
            ntohs(ip->ip_len) -
            ((uint16_t)ip->ip_hl + (uint16_t)tcp->th_off) * WORD_SIZE;
        data_size = data_size < MAX_DATA_SIZE ? data_size : MAX_DATA_SIZE;
        /* output */
        printf("\n");
        // 1. Ethernet Header의 src mac / dst mac
        printf("ethernet - src mac: %s\n",
               ether_ntoa((ether_addr*)ethernet->ether_shost));
        printf("ethernet - dst mac: %s\n",
               ether_ntoa((ether_addr*)ethernet->ether_dhost));
        // 2. IP Header의 src ip / dst ip
        printf("ip - src ip: %s\n", inet_ntoa(ip->ip_src));
        printf("ip - dst ip: %s\n", inet_ntoa(ip->ip_dst));
        // 3. TCP Header의 src port / dst port
        printf("tcp - src port: %hu\n", ntohs(tcp->th_sport));
        printf("tcp - dst port: %hu\n", ntohs(tcp->th_dport));
        // 4. Payload(Data)의 hexadecimal value(최대 16바이트까지만)
        printf("payload: ");
        if (data_size) {
          for (uint16_t i = 0; i < data_size; i++) printf("%c", payload[i]);
          printf("\n%02x ", payload[0]);
          for (uint16_t i = 1; i < data_size; i++) {
            printf("%02x ", payload[i]);
            if (!(i % 8)) printf(" ");
            if (!(i % 16)) printf("\n");
          }
        }
        printf("\n");
      }
    }
  }

  pcap_close(handle);
  return 0;
}