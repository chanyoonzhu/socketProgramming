#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
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

#define CLIENTPORT     4767 
#define BUFLEN 1024 

struct host {
    short port;
    long ip_address;
    long real_ip;
    int total_neighbors;
    char packet_file[BUFLEN];
    struct host** neighbors;
};

void readConfigFile (char* filename, struct host* machine);
void *createClient(void * arg);
void *createServer(void * arg);
void *createClientSocket(void * arg);

int main(int argc, char **argv) { 
    
    pthread_t threads[2];
    int status;
    void *exit_value; 

    /*check arguments*/
    if(argc != 3) {
        printf("usage: %s config_file packet_file\n", argv[0]);
        return 0;
    }

    struct host *machine = malloc(sizeof(struct host));
    if (machine == NULL) {
        printf("Cannot create server\n");
        exit(EXIT_FAILURE);
    }
    
    strcpy(machine->packet_file, argv[2]);

    readConfigFile(argv[1], machine);

    status = pthread_create(&threads[0], NULL, createClient, machine);
    status = pthread_create(&threads[1], NULL, createServer, machine);

    status = pthread_join(threads[0], &exit_value);
    status = pthread_join(threads[1], &exit_value);
    
    return 0;
}

void readConfigFile (char* filename, struct host* machine)
{
    FILE *config_file;
    char buffer[16];
    char ip[16];
    struct host** neighborptr;

    // test for file not existing
    if ((config_file = fopen(filename, "r")) == NULL) {
        printf("Error. Cannot open file.\n");
        exit(-1);
    }

    /*read info for this machine*/
    fscanf(config_file, "%s\n\n%hu\n\n%d\n\n", buffer, &machine->port, &machine->total_neighbors);
    printf("from text file: %s\n", buffer);

    /* read neighbors info*/
    machine->neighbors = malloc(sizeof(struct host*) * machine->total_neighbors); 
    neighborptr = machine->neighbors;
    for (int i = 0; i < machine->total_neighbors; i++) {
        *neighborptr = malloc(sizeof(struct host));
        memset(buffer, 0, sizeof buffer);
        memset(ip, 0, sizeof ip);
        fscanf(config_file, "%s %s %hu\n\n", buffer, ip, &(*neighborptr)->port);
        (*neighborptr)->ip_address = inet_addr(buffer);
        (*neighborptr)->real_ip = inet_addr(ip);
        strcpy((*neighborptr)->packet_file, machine->packet_file);
        printf("neighbor info: %ld %ld %hu\n", (*neighborptr)->ip_address, (*neighborptr)->real_ip, (*neighborptr)->port);
        neighborptr++;
    }
}

void *createClientSocket(void * arg)
{
    struct host* machine;
    pcap_t *pp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char buffer[BUFLEN]; 
    const unsigned char *packet;
    struct sockaddr_in serverAddr; 
    struct pcap_pkthdr header;
    int serverSock;
    socklen_t slen = sizeof(serverAddr);
 
    machine = (struct host*) arg;
    
    /*socket creation*/
    if ((serverSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    }

    memset(&serverAddr, 0, sizeof(serverAddr)); 
 
    /*address*/
    serverAddr.sin_family = AF_INET; 
    serverAddr.sin_addr.s_addr = machine->real_ip; 
    serverAddr.sin_port = htons(machine->port); 

    /*open pcap file*/
    pp = pcap_open_offline(machine->packet_file, errbuf);
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

    close(serverSock);
}

void *createClient(void * arg)
{
     
    pthread_t *threads;
    int status;
    void *exit_value; 
    struct host* machine;

    /*get info*/
    machine = (struct host *)arg;
    
    threads = malloc(sizeof(pthread_t) * (machine->total_neighbors));

    if (threads == NULL) {
        printf("out of memory\n");
        exit(EXIT_FAILURE);
    }
    
    /*create sockets for each neighbor*/
    for (int i = 0; i < machine->total_neighbors; i++) {
        if (pthread_create(&threads[i], NULL, createClientSocket, machine->neighbors[i]) != 0) {
            printf("creating socket thread failed.\n");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < machine->total_neighbors; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            printf("socket threads join failed.\n");
            exit(EXIT_FAILURE);
        }
    }    
}

void *createServer(void * arg)
{

}

