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
#include <poll.h>
 
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
    struct pollfd pfd;
    int ret;
    int timedout;

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
        pfd.fd = fd;
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, 30000); // 10 seconds timeout
        switch (ret) {
            case -1:
                perror("timeout error\n");
                break;
            case 0:
                timedout = 1;
                break;
            default:
                timedout = 0;         
        } 
        if (timedout == 1) {
            if(send(fd, "Failed\0", 8, 0) != 8) {
                perror("success/fail acknowledge failed\n");
                exit(1);
            }
            timedout = 0;
            continue;
        } else {
            if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
                perror("receiving failed\n");
            } else {
                if (strcmp(buffer, "FINISHED!\n") == 0) {
                    printf("%s", buffer);
                    memset(buffer, '\0', BUFLEN);
                    if (send(fd, "THANK YOU CLOSE CONNECTION!\0", BUFLEN, 0) != BUFLEN) {
                        perror("finish ack not sent\n");
                    } else { 
                        memset(buffer,'\0', BUFLEN);
                        if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
                            perror("finish ack not received\n");
                        } else {
                            if (strcmp(buffer, "AGREED!\n") == 0) {
                                printf("%s", buffer);
                                break;
                            }
                        }
                    } 
                } else if (strcmp(buffer+strlen(buffer)-4, ".txt") == 0) {
                    if(send(fd, "Success\0", 8, 0) != 8) {
                        perror("success/fail acknowledge failed\n");
                        exit(1);
                    }
                    printf("writing file: %s\n", buffer);
                    if ((fptr = fopen(buffer, "a")) == NULL) {
                        perror("can't create file\n");
                        exit(1);
                    }
        
                    memset(buffer, '\0', BUFLEN);
                    if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
                        perror("receiving data failed\n");
                    }
                    while (strcmp(buffer, "DONE!\n") != 0) {
                        printf("writing data %s", buffer);
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
                        if ((recv_len = recv(fd, buffer, BUFLEN, 0)) < 0) {
                            perror("client ack not received\n");
                        }
                    } 
                    fclose(fptr);
                    printf("file closed.\n");
                } else {
                    send(fd, "\0", BUFLEN, 0);
                }
            }
        }
    }
 
    close(serverSock);
    printf("server connection closed.\n");
    return 0;
}


