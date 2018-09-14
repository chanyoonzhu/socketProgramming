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
        perror("socket failed");
    }
     
    memset(&serverAddr, 0, slen);
    memset(&clientAddr, 0, slen);
    
    /*addresses*/ 
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    /*socket binding*/ 
    if( bind(serverSock , (struct sockaddr*)&serverAddr, slen) < 0){
        perror("binding failed");
    }
     
    /*packet transfer*/
    while(1)
    {
        printf("Waiting for data...");
        fflush(stdout);
      
        /*receive packet*/
        memset(buffer,'\0', BUFLEN);
        if ((recv_len = recvfrom(serverSock, buffer, BUFLEN, 0, (struct sockaddr *) &clientAddr, &slen)) == -1) {
            perror("receiving failed");
        } else {
            printf("Received packet from %s:%d\nReceived length: %d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), recv_len);
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
           size,
           ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_dhost), mac_dest),
           ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_shost), mac_src),
           ether_type, ether_type_str);
    fflush(stdout);
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
        fflush(stdout);

        /*print data*/
        int i = 0;
        char letters[16];
        for (i = 0; i < size; i++) { 
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
                int k = i - 16;
                while (k < i && k < size) {
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
    }
}
