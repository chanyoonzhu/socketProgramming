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
#define FILENAMELEN 30

int main(void)
{
    char buffer[BUFLEN];
    char filename[FILENAMELEN];
    struct sockaddr_in serverAddr, clientAddr;
    int serverSock;
    int fd;
    FILE *fptr;
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

    // socket accept
    if ((fd = accept(serverSock, (struct sockaddr*)&clientAddr, &slen)) < 0){
        perror("accept failed\n");
    }
    
    while(1)
    {
        memset(buffer,'\0', BUFLEN);
        // TODO: timeout
        if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
            perror("receiving failed\n");
        } else {
            if(send(fd, "Success\0", 8, 0) != 8) {
                perror("success/fail acknowledge failed\n");
                exit(1);
            }
            printf("writing file: %s\n", buffer);
            if ((fptr = fopen(buffer, "w+")) == NULL) {
                perror("can't create file\n");
                exit(1);
            }

            memset(buffer, '\0', BUFLEN);
            if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
                perror("receiving data failed\n");
            }
            while (strcmp(buffer, "DONE!\n") != 0) {
                printf("writing data %s\n", buffer);
                fputs(buffer, fptr);
                memset(buffer, '\0', BUFLEN);
                if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
                    perror("receiving data failed\n");
                }
            }
            if ((send(fd, "THANK YOU! FILE CLOSED\0", BUFLEN, 0)) != BUFLEN) {
                perror("file close acknowledge not sent\n");
            } else {
                printf("file close ack sent\n");
            } 
            fclose(fptr);
            printf("done writing file\n");
       }
    }
 
    close(serverSock);
    return 0;
}


