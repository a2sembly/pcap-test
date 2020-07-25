#include <stdint.h>
#include <netinet/in.h>
//http://fac-staff.seattleu.edu/zhuy/web/teaching/winter13/cpsc4560/Packetsniff.pptx

#define ETHER_ADDR_LEN 6 //6Byte
#define TCP_P_ID 6
#define ETHER_TYPE 0x0800

struct libnet_ethernet { 
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t ether_type; /* Protocol 2Byte */
};

struct libnet_ipv4 {
    uint8_t ip_vhl;         /* version << 4 | header length >> 2 */
    uint8_t ip_tos;         /* type of service */
    uint16_t ip_len;        /* total length */
    uint16_t ip_id;         /* identification */
    uint16_t ip_off;        /* RF, DF, MF, fragment offset */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t ip_sum;        /* header checksum */
    struct in_addr ip_src, ip_dst; /* source and dest ip address */
};
#define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)    (((ip)->ip_vhl) >> 4)

struct libnet_tcp {
    uint16_t th_sport;      /* source port */
    uint16_t th_dport;      /* dest port */
    uint32_t th_seq;        /* sequence number */
    uint32_t th_ack;        /* acknowledgement number */
    uint8_t th_offx2;       /* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t th_win;        /* window size */
    uint16_t th_sum;        /* check sum */
    uint16_t th_urp;        /* urgent pointer */
};
