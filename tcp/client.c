#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define CLIENTPORT     8080 
#define BUFLEN 1024 
#define FILENAMELEN 30

int readFilenames(char* file, char** filenames);

int main(int argc, char **argv) { 
    
    char buffer[BUFLEN]; 
    const unsigned char *packet;
    struct sockaddr_in serverAddr; 
    int serverSock;
    socklen_t slen = sizeof(serverAddr);
    char** filenames;
    int filecount;
    /*socket creation*/
    if ((serverSock = socket(PF_INET, SOCK_STREAM, 0)) < 0) { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    }

    memset(&serverAddr, 0, sizeof(serverAddr)); 
 
    /*address*/
    serverAddr.sin_family = AF_INET; 
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    serverAddr.sin_port = htons(CLIENTPORT); 

    // client connect
    if (connect(serverSock, (struct sockaddr*)&serverAddr, slen) < 0) {
        perror("connect failed\n");
    }

    /*check arguments*/
    if(argc != 2) {
        printf("usage: %s filename\n", argv[0]);
        return 0;
    }

    // read file
    if ((filecount = readFilenames(argv[1], filenames)) < 0) {
        perror("can't read file.\n");
        exit(1);
    }

    for (int i = 0; i < filecount; i++) {
        // send filenames
        if (send(serverSock, "Hi", FILENAMELEN, 0) != FILENAMELEN) {
            perror("filename sent error\n");
        } else {
            // server replys 1. success 0. failure
            printf("success\n");  
        }
    }

    // sends more until finished
    // recv server ack
    // acknowledge ack

    /*
    // open pcap file
    pp = pcap_open_offline(argv[1], errbuf);
    if (pp == NULL) {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        return 0;
    }
    
    
    while ((packet = pcap_next(pp, &header)) != NULL) {
        
        int i = 0;

        if (sendto(serverSock, packet, header.len, 
            MSG_CONFIRM, (const struct sockaddr *) &serverAddr,  
            slen) < 0) {
            perror("send error\n");
        } else {
            printf("packet sent\n");
        } 
    }
    */
    close(serverSock); 
    return 0;
}


int readFilenames(char* file, char** filenames)
{
    FILE *fp;
    int count = 0;
    char c;
    char buffer[FILENAMELEN];

    if ((fp = fopen(file, "r")) == NULL) {
        perror("Can't open file\n");
        return -1;
    }

    for (c = getc(fp); c != EOF; c = getc(fp)) {
        if (c == '\n') {
            count++;
        }
    }
    // point to file beginning 
    fseek(fp, 0, SEEK_SET);
    filenames = malloc(sizeof(char*) * count);      
    for (int i = 0; i < count; i++) {
        memset(buffer, 0, sizeof(buffer));
        fscanf(fp, "%s\n", buffer);
        filenames[i] = malloc(sizeof(buffer));
        strcpy(filenames[i], buffer);
    }

    return count; 
}
