#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2

int icmpCount = 0;
int tcpCount = 0;
int udpCount = 0;
int dnsCount = 0;
int synCount[PCAP_BUF_SIZE];
int synIdx = 0;
char synIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
int httpCount[PCAP_BUF_SIZE];
int httpIdx = 0;
char httpIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv) {

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    int i, maxCountSyn = 0, maxCountHttp = 0, maxIdxSyn = 0, maxIdxHttp = 0;

    if(argc != 2) {
        printf("usage: %s filename\n", argv[0]);
        return -1;
    }


    /*fp = pcap_open_offline_with_tstamp_precision(argv[0], PCAP_TSTAMP_PRECISION_NANO, errbuf);*/
    fp = pcap_open_offline(argv[1], errbuf);
    if (fp == NULL) {
	    fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
	    return 0;
    }


    if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        return 0;
    }

    for (i = 0; i < synIdx; i++) {
        if (maxCountSyn < synCount[i]) {
            maxCountSyn = synCount[i];
            maxIdxSyn = i;
        }
    }

    for (i = 0; i < httpIdx; i++) {
        if (maxCountHttp < httpCount[i]) {
            maxCountHttp = httpCount[i];
            maxIdxHttp = i;
        }
    }

    printf("Protocol Summary: %d ICMP packets, %d TCP packets, %d UDP packets\n", icmpCount, tcpCount, udpCount);
    printf("DNS Summary: %d packets.\n", dnsCount);
    printf("IP address sending most SYN packets: %s\n", synIP[maxIdxSyn]);
    printf("IP address that most HTTP/HTTPS traffic goes to (in terms of bandwidth, NOT packet count): %s\n", httpIP[maxIdxHttp]);
    return 0;

}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    u_char mac_dest[ETH_ALEN * 3],  mac_src[ETH_ALEN * 3];
    u_int16_t ether_type;
    char ether_type_str[10];
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    int i;

    /*get Ethernet Info*/
    ethernetHeader = (struct ether_header*)packet;
    ether_type = ntohs(ethernetHeader->ether_type);
    if (ether_type == ETHERTYPE_IP) {
        strcpy(ether_type_str, "IP");
    } else if (ether_type == ETHERTYPE_ARP){
        strcpy(ether_type_str, "ARP");
    } else {
        strcpy(ether_type_str, "UNKNOWN");
    }
    printf("ETHER: Packet size\t: %d bytes\nETHER: Destination\t: %s\nETHER: Source\t\t: %s\nETHER: Ethertype\t: 0%x (%s)\n",
           pkthdr->len,
           ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_dhost), mac_dest),
           ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_shost), mac_src),
           ether_type, ether_type_str);
    /*IP info*/
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
	printf("IP:  Version = %d\n"
                "IP:  Header length = %d bytes\n"
                "IP:  Type of service = %x\n"
                "IP:  Total length = %d octets\n"
                "IP:  Identification = %d\n"
                "IP:  Fragment offset = %d\n"
                "IP:  Time to live = %d seconds/hops\n"
                "IP:  Protocol = %d\n"
                "IP:  Header checksum = %d\n"
                "IP:  Source address = %s\n"
                "IP:  Destination address = %s\n",
               ipHeader->ip_v & 0x0F,
               ipHeader->ip_hl & 0x0F,
               ipHeader->ip_tos,
               ntohs(ipHeader->ip_len),
               ipHeader->ip_id,
               ipHeader->ip_off,
               ipHeader->ip_ttl,
               ipHeader->ip_p,
               ipHeader->ip_sum,
               sourceIP, destIP);
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpCount = tcpCount + 1;
            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            if (sourcePort == 80 || sourcePort == 443 || destPort == 80 || destPort == 443) {
                for (i = 0; i < httpIdx; i++) {
                    if (strcmp(destIP, httpIP[i]) == 0) {
                        httpCount[i] = httpCount[i] + dataLength;
                    }
                }
                strcpy(httpIP[httpIdx], destIP);
                httpCount[httpIdx] = dataLength;
                httpIdx = httpIdx + 1;
            }

            if (tcpHeader->th_flags & TH_SYN) {
                for (i = 0; i < synIdx; i++) {
                    if (strcmp(sourceIP, synIP[i]) == 0) {
                        synCount[i] = synCount[i] + 1;
                    }
                }
                strcpy(synIP[synIdx], sourceIP);
                synCount[synIdx] = 1;
                synIdx = synIdx + 1;
            }

        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpCount = udpCount + 1;
            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(udpHeader->source);
            destPort = ntohs(udpHeader->dest);
            if (sourcePort == 53 || destPort == 53) {
                dnsCount = dnsCount + 1;

            }
        } else if (ipHeader->ip_p == IPPROTO_ICMP) {
            icmpCount = icmpCount + 1;
        }
    }
}
