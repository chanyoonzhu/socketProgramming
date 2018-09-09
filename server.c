#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
            printf("Received packet from %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
            printf("Data: %s\n" , buffer);
        }
    }
 
    close(serverSock);
    return 0;
}
