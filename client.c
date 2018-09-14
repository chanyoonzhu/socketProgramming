#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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

#define CLIENTPORT     8080 
#define BUFLEN 1024 

int main(int argc, char **argv) { 
    
    pcap_t *pp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char buffer[BUFLEN]; 
    const unsigned char *packet;
    struct sockaddr_in serverAddr; 
    struct pcap_pkthdr header;
    int serverSock;
    socklen_t slen = sizeof(serverAddr);
 
    /*socket creation*/
    if ((serverSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    }

    memset(&serverAddr, 0, sizeof(serverAddr)); 
 
    /*address*/
    serverAddr.sin_family = AF_INET; 
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    serverAddr.sin_port = htons(CLIENTPORT); 

    /*check arguments*/
    if(argc != 2) {
        printf("usage: %s filename\n", argv[0]);
        return 0;
    }

    /*open pcap file*/
    pp = pcap_open_offline(argv[1], errbuf);
    if (pp == NULL) {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        return 0;
    }

    while ((packet = pcap_next(pp, &header)) != NULL) {
        
        int i = 0;

        /*send packet*/
        /*for(i = 0;i < header.len;i++) { 
            printf("%02x  ", packet[i]);
            if (isprint(packet[i])) {
                printf("%c", packet[i]);    
            } else {
                printf(".");
            }
            if((i%16 == 0 && i != 0) || i == header.len-1) { 
                printf("\n"); 
            }
        }*/
        if (sendto(serverSock, packet, header.len, 
            MSG_CONFIRM, (const struct sockaddr *) &serverAddr,  
            slen) < 0) {
            perror("send error");
        } else {
            printf("message sent: %d.\n", header.len);
        } 
    }

    close(serverSock); 
    return 0;
}
