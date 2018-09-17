#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
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
 
#define BUFLEN 1024
#define PORT 8080


/*
 * parser program reference: http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c
 *
 */
void parsePacket(const u_char * packet, const int size);

int main(void)
{
    char buffer[BUFLEN];
    char packet[BUFLEN];
    struct sockaddr_in serverAddr, clientAddr;
    int serverSock;
    int recv_len;
    socklen_t slen = sizeof(clientAddr); 
     
    /*create socket*/
    if ((serverSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket failed\n");
    }
     
    memset(&serverAddr, 0, slen);
    memset(&clientAddr, 0, slen);
    
    /*addresses*/ 
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    /*socket binding*/ 
    if( bind(serverSock , (struct sockaddr*)&serverAddr, slen) < 0){
        perror("binding failed\n");
    }
     
    /*packet transfer*/
    while(1)
    {
        /*receive packet*/
        memset(buffer,'\0', BUFLEN);
        if ((recv_len = recvfrom(serverSock, buffer, BUFLEN, 0, (struct sockaddr *) &clientAddr, &slen)) == -1) {
            perror("receiving failed\n");
        } else {
            parsePacket(buffer, recv_len);
        }
    }
 
    close(serverSock);
    return 0;
}

void parsePacket(const u_char* packet, const int size)
{
    
    struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    u_char mac_dest[ETH_ALEN * 3],  mac_src[ETH_ALEN * 3];
    u_int16_t ether_type;
    char ether_type_str[10];
    char ether_address_type;
    char ether_saddress_glb[20];
    char ether_saddress_grp[20];
    char ether_daddress_glb[20];
    char ether_daddress_grp[20];
    char ip_protocol_str[5];
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
    /*source address type*/
    if (packet[0] & 0x02) {
        strcpy(ether_daddress_glb, "Local");
    } else {
        strcpy(ether_daddress_glb, "Global");
    }
    if (packet[0] & 0x01) {
        strcpy(ether_daddress_grp, "Group");
    } else {
        strcpy(ether_daddress_grp, "Individual");
    }
    /*dest address type*/
    if (packet[6] & 0x02) {
        strcpy(ether_saddress_glb, "Local");
    } else {
        strcpy(ether_saddress_glb, "Global");
    }
    if (packet[6] & 0x01) {
        strcpy(ether_saddress_grp, "Group");
    } else {
        strcpy(ether_saddress_grp, "Individual");
    }
    printf("ETHER:   -----ETHER HEADER-----\nETHER: Packet size\t: %d bytes\nETHER: Destination\t: %s  Type: %s %s\nETHER: Source\t\t: %s  Type: %s %s\nETHER: Ethertype\t: 0%x (%s)\n",
           size,
           ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_dhost), mac_dest),
           ether_daddress_grp, ether_daddress_glb,
           ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_shost), mac_src),
           ether_saddress_grp, ether_daddress_glb,
           ether_type, ether_type_str);
    fflush(stdout);
    /*IP info*/
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
        if (ipHeader->ip_p == 6) {
            strcpy(ip_protocol_str, "TCP");
        } else if (ipHeader->ip_p == 17) {
            strcpy(ip_protocol_str, "UDP");
        } else { 
            strcpy(ip_protocol_str, "");
        }
        printf("IP:   -----IP HEADER-----\nIP:  Version = %d\n"
                "IP:  Header length = %d bytes\n"
                "IP:  Type of service = 0x%02x\n"
                "IP:     xxx. .... = %d (precedence)\n"
                "IP:     ...%c .... = normal delay\n"
                "IP:     .... %c... = normal throughput\n"
                "IP:     .... .%c.. = normal reliability\n"
                "IP:  Total length = %d octets\n"
                "IP:  Identification = %d\n"
                "IP:  Flags = 0x%02x%02x\n"
                "IP:    .%c.. .... = do not fragment\n"
                "IP:    ..%c. .... = last fragment\n"
                "IP:  Fragment offset = %d\n"
                "IP:  Time to live = %d seconds/hops\n"
                "IP:  Protocol = %d (%s)\n"
                "IP:  Header checksum = %x\n"
                "IP:  Source address = %s\n"
                "IP:  Destination address = %s\n"
                "IP:  %s options\n",
               ipHeader->ip_v & 0x0F,
               (ipHeader->ip_hl & 0x0F) * 4,
               ipHeader->ip_tos,
               packet[15] >> 5,
               (packet[15] & 0x10 ? '1' : '0'),
               (packet[15] & 0x08 ? '1' : '0'),
               (packet[15] & 0x04 ? '1' : '0'),
               ntohs(ipHeader->ip_len),
               ipHeader->ip_id,
               packet[20],packet[21],
               (packet[20] & 0x40 ? '1' : '0'), (packet[20] & 0x20 ? '1' : '0'),
               ipHeader->ip_off,
               ipHeader->ip_ttl,
               ipHeader->ip_p, ip_protocol_str,
               ipHeader->ip_sum,
               sourceIP, destIP,
               ((ipHeader->ip_hl & 0x0F) * 4  == 20? "No" : "Has"));
        fflush(stdout);

        /*print data*/
        int i = 0;
        char letters[16];
        for (i = 0; i < size; i++) {
            /*print line number*/
            if (i%16 == 0) {
                 printf("%03d0  ", i / 16);
            } 
            printf("%02x  ", packet[i]);
            if(((i+1)%16 == 0 && i != 0) || i == size-1) { 
                /*add padding*/
                if (i == size-1 && (i+1)%16 != 0) {
                    int j = 16;
                    while((i+1)%16 != 0){
                        printf("    ");
                        i++;
                    }
                }
                /*print letters*/
                int k = (i+1) - 16 ;
                while (k <= i && k < size) {
                    if (isprint(packet[k])) {
                        printf("%c", packet[k]);
                    } else {
                        printf(".");
                    } 
                    k++;
                }
                printf("\n");
            }
        } 
        printf("\n");
    } else {
        printf("Not IP header\n\n");
    }
}
