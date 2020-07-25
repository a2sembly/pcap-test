#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <pcap.h>
#include "struct_header.h"

void Ethernet_Pirnt(uint8_t const* s_ether, uint8_t const* d_ether);
void IPv4_Print(in_addr s_ip, in_addr d_ip);
void Port_Print(uint16_t s_port, uint16_t d_port);
void Usage(void);

int main(int argc, char* argv[]) 
{
    const struct libnet_ethernet* ethernet;    //이더넷 헤더
    const struct libnet_ipv4* ip;                //ipv4 헤더
    const struct libnet_tcp* tcp;                //tcp 헤더
    const u_char* payload;                     // 패킷담을 변수

    uint32_t size_ip;
    uint32_t size_tcp;
    uint32_t size_payload;
	
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (argc != 2) 
    {
        Usage();
        return -1;
    }

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf); // 인터페이스를 못찾으면 종료
    return -1;
    }

    while (true) 
    {
        struct pcap_pkthdr* header; 
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) 
            continue;
        if (res == -1 || res == -2) // -1 = function error || -2 = EOF
            break;

        ethernet = (struct libnet_ethernet*)(packet);
        if (ntohs(ethernet->ether_type) != ETHER_TYPE) //8000이 IP Protocol
        {
            continue;
        }

        ip = (struct libnet_ipv4*)(packet + 0x0e); // size == 14(0x0e)
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) // IPHeader 길이 확인
        {
            continue;
        }
        
        if (ip->ip_p != TCP_P_ID) // ICMP는 1번, TCP는 6번, UDP는 17번 
        // https://mr-zero.tistory.com/38
        {
            continue;
        }

        tcp = (struct libnet_tcp*)(packet + 0x0e + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) 
        {
            continue;
        }

        printf("-----TCP Imformation-----\n");
        Ethernet_Pirnt(ethernet->ether_shost,ethernet->ether_dhost);
        IPv4_Print(ip->ip_dst, ip->ip_dst);
        Port_Print(tcp->th_sport,tcp->th_dport);
        
        size_payload = ntohs(ip->ip_len) - size_ip - size_tcp;
        if (size_payload == 0) 
        {
            printf("There is no payload\n\n");
        }
        else 
        {
            payload = (u_char*)(packet + 0x0e + size_ip + size_tcp);

            printf("Payload For Hex: ");
            for (int i = 0; i < 16; i++) 
            {
                printf("%02X ", payload[i]);

                if (i == (size_payload - 1)) 
                {
                    break;
                }
            }
            printf("\n-----END-----\n\n");
        }
    }

    pcap_close(handle);

    return 0;
}

void Ethernet_Pirnt(uint8_t const* s_ether, uint8_t const* d_ether) 
{
    printf("Src Mac : %02X:%02X:%02X:%02X:%02X:%02X\n", s_ether[0], s_ether[1], s_ether[2], s_ether[3], s_ether[4], s_ether[5]);
    printf("Dst Mac : %02X:%02X:%02X:%02X:%02X:%02X\n", d_ether[0], d_ether[1], d_ether[2], d_ether[3], d_ether[4], d_ether[5]);
}
void IPv4_Print(in_addr s_ip, in_addr d_ip) 
{
    printf("Src IP : %s\n",inet_ntoa(s_ip));
    printf("Dst IP : %s\n",inet_ntoa(d_ip));
}
void Port_Print(uint16_t s_port, uint16_t d_port) 
{
    printf("Src Port : %u\n", ntohs(s_port));
    printf("Dst Port : %u\n", ntohs(d_port));
}
void Usage(void) 
{
    printf("Usage: pcap_test <interface>\n");
}
