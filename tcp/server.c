#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
 
#define BUFLEN 1024
#define PORT 8080
int main(void)
{
    char buffer[BUFLEN];
    //char packet[BUFLEN];
    struct sockaddr_in serverAddr, clientAddr;
    int serverSock;
    int fd;
    int recv_len;
    int queue_limit = 10;
    socklen_t slen = sizeof(clientAddr); 
     
    /*create socket*/
    if ((serverSock=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
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

    // socket listen
    if (listen(serverSock, queue_limit) < 0 ){
        perror("listening failed\n");
    }

    
    while(1)
    {
        // socket accept
        if ((fd = accept(serverSock, (struct sockaddr*)&clientAddr, &slen)) < 0){
            perror("accept failed\n");
        }
        /*receive packet*/
        memset(buffer,'\0', BUFLEN);
        if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
            perror("receiving failed\n");
        } else {
            //parsePacket(buffer, recv_len);
            printf("%s\n", buffer);
        }
    }
 
    close(serverSock);
    return 0;
}


