#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "gilgil.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_Mac(struct gilethernet * ethh)
{

    printf("eth.dmac : %02X:%02X:%02X:%02X:%02X:%02X\n", ethh->dmac[0], ethh->dmac[1], ethh->dmac[2],
                                                    ethh->dmac[3], ethh->dmac[4], ethh->dmac[5]);

    printf("eth.smac : %02X:%02X:%02X:%02X:%02X:%02X\n", ethh->smac[0], ethh->smac[1], ethh->smac[2],
                                                    ethh->smac[3], ethh->smac[4], ethh->smac[5]);
}

void print_IP(struct gilIP * IPh)
{

    printf("ip.sip : %u.%u.%u.%u\n", IPh->sip[0], IPh->sip[1], IPh->sip[2], IPh->sip[3]);

    printf("ip.dip : %u.%u.%u.%u\n", IPh->dip[0], IPh->dip[1], IPh->dip[2], IPh->dip[3]);
}
void print_TCP(struct gilTCP * TCPh)
{

    printf("tcp.sport : %u\n", ntohs(TCPh->sport)); //convert network to host

    printf("tcp.dport : %u\n", ntohs(TCPh->dport));
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  char track[] = "consulting";
  char name[] = "ban_soo_hwan";
  printf("[bob8][%s]pcap_test[%s]\n", track, name);
  while (true)
  {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct gilethernet * ethh = (struct gilethernet *)packet; //Ethernet packets starting point
    struct gilIP * IPh = (struct gilIP *)(packet + 14); //IP packets starting point
    uint8_t IPheaderLen = (IPh->IPlen & 0x0F) * 4; // IP header length = 4bits

    struct gilTCP * TCPh = (struct gilTCP *)(packet + 14 + IPheaderLen);
    uint8_t TCPheaderLen = ((TCPh->TCPlen & 0xF0) >> 4) * 4; // TCP header length = 4bits
    u_char *Pdata = (u_char *)(packet + 14 + IPheaderLen + TCPheaderLen); // Payload data starts at ethernetlen + IPlen + TCPlen

    int Pdatalen = ntohs(IPh->totallen) - (IPheaderLen + TCPheaderLen); //Payload data length = IPheader's totallen - (ipheaderlen + tcp headerlen)


    if (ethh->type == ntohs(0x0800) && IPh->protocol == 0x06) // 0x0800 = IP, 0x06 = TCP
{
        printf("\n----------------------------------------------------\n");
        print_Mac(ethh);
        print_IP(IPh);
        print_TCP(TCPh);
        //printf ("%u\n%u\n", IPheaderLen, TCPheaderLen); test
        if (Pdatalen==0){
            printf("data(max=10) : There is no data\n"); // no data packets like syn,ack etc...

        }
        else{printf("data(max=10) : ");
            for(int i=0;i<10;i++){                      // max (data length) is 10
                if(i<Pdatalen){
                    printf("%02X ", Pdata[i]);
                }
                else{break;}
            }
            printf("\n");
        }

        printf("%u bytes captured\n", header->caplen);


}











  }


  pcap_close(handle);
  return 0;
}
