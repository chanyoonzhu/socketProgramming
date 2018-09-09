#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define CLIENTPORT     8080 
#define BUFLEN 1024 
  
// Driver code 
int main() { 
    char buffer[BUFLEN]; 
    struct sockaddr_in serverAddr; 
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

    while (1) {
        /*send packet*/
        printf("enter message");
        memset(buffer, '\0', BUFLEN);
        read(STDIN_FILENO, buffer, BUFLEN);
        if (sendto(serverSock, buffer, strlen(buffer), 
            MSG_CONFIRM, (const struct sockaddr *) &serverAddr,  
            slen) < 0) {
            perror("send error");
        } else {
            printf("message sent.\n");
        } 
    }
    close(serverSock); 
    return 0; 
} 
