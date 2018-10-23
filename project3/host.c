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

#define BUFLEN 1024 
#define WLANTYPE_IP 0x0800
    
struct host {
    short port;
    long ip_address;
    long real_ip;
    int total_neighbors;
    char packet_file[BUFLEN];
    struct host** neighbors;
    short source_port;
};

struct socket {
    long src_address;
    struct host* neighbor;
};

struct wlan_header {
    u_short packet_type;
    u_short addr_type;
    u_short addr_length;
    u_char addr_src[6];
    u_char unused[2];
    u_short protocol; 
};

void readConfigFile (char* filename, struct host* machine);
void *createClient(void * arg);
void *createServer(void * arg);
void parsePacket(const u_char* packet, const int size, const unsigned long machine_ip);
void *createClientSocket(void * arg);
long getPacketDestination(const u_char* packet);
long getPacketSource(const u_char* packet);

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
    
    /* get packet file name */
    strcpy(machine->packet_file, argv[2]);

    /* read from config file */
    readConfigFile(argv[1], machine);

    /* create client thread */
    status = pthread_create(&threads[0], NULL, createClient, machine);
    /* create server thread */
    status = pthread_create(&threads[1], NULL, createServer, machine);

    /* join threads */
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
    machine->ip_address = inet_addr(buffer);
    printf("from text file: %s\n", buffer);
    printf("port number: %hu\n", machine->port);
    
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
        printf("neighbor info: %s %s %hu\n", buffer, ip, (*neighborptr)->port);
        neighborptr++;
    }
    machine->source_port = 0;
}

void *createClientSocket(void * arg)
{
    struct socket* sock;
    struct host* machine;
    pcap_t *pp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char buffer[BUFLEN]; 
    const unsigned char *packet;
    struct sockaddr_in serverAddr; 
    struct pcap_pkthdr header;
    int serverSock;
    socklen_t slen = sizeof(serverAddr); 
    sock = (struct socket*) arg;
    machine = sock->neighbor;
    const struct ip* ipHeader;
    struct timeval tv;

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

    /* set timeout */
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(serverSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        
        /*open pcap file*/
        pp = pcap_open_offline(machine->packet_file, errbuf);
        if (pp == NULL) {
            fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
            return 0;
        }


        /* send packets to the server*/
        while ((packet = pcap_next(pp, &header)) != NULL) {

            int i = 0;

            /* parse packet to find matching source*/
            ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
            if (ipHeader->ip_src.s_addr == sock->src_address) {
                if (sendto(serverSock, packet, header.len,
                    MSG_CONFIRM, (const struct sockaddr *) &serverAddr,
                    slen) < 0) {
                    perror("send error\n");
                } 
            }
        }
 
         /* get reply from the server and get out of the loop */
        if(recvfrom(serverSock, buffer, sizeof(buffer), 0, (struct sockaddr *)&serverAddr, &slen) > 0) {
            //printf("server received packets.\n");
            break;
        }

        /* close pcap file */
        //pcap_close(pp);
    }

    /*clean memory*/
    free(machine);
    free(sock);
    machine = NULL;
    sock = NULL;
    close(serverSock);
}

void *createClient(void * arg)
{
    
    pthread_t *threads;
    int status;
    int total_threads;
    void *exit_value; 
    struct host* machine;    
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    /*get info*/
    machine = (struct host *)arg;

    total_threads = machine->total_neighbors;
    if (machine->source_port != 0) {
        total_threads--;
    }
    threads = malloc(sizeof(pthread_t) * total_threads);

    if (threads == NULL) {
        printf("out of memory\n");
        exit(EXIT_FAILURE);
    }
    
    /*create sockets for each neighbor*/
    int thread_idx = 0;
    for (int i = 0; i < machine->total_neighbors; i++) {
        /* do not send back where packets come from */
        if (machine->source_port == 0 || machine->neighbors[i]->port != machine->source_port) {
	    struct socket* sock = malloc(sizeof(struct socket));
            sock->src_address = machine->ip_address;
            sock->neighbor = machine->neighbors[i];
            inet_ntop(AF_INET, &(sock->neighbor->ip_address), destIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(machine->ip_address), sourceIP, INET_ADDRSTRLEN);
            printf("%s forwarding packets to %s\n", sourceIP, destIP);
            if (pthread_create(&threads[thread_idx], NULL, createClientSocket, sock) != 0) {
                printf("creating socket thread failed.\n");
                exit(EXIT_FAILURE);
            }
            thread_idx++;
        }
    }

    /* join threads */
    for (int i = 0; i < total_threads; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            printf("socket threads join failed.\n");
            exit(EXIT_FAILURE);
        }
    }    
}

void *createServer(void * arg)
{
    char buffer[BUFLEN];
    char packet[BUFLEN];
    struct sockaddr_in serverAddr, clientAddr;
    int serverSock;
    int recv_len;
    socklen_t slen = sizeof(clientAddr); 
    struct host* machine;

    /*get info*/
    machine = (struct host *)arg;
     
    /*create socket*/
    if ((serverSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket failed\n");
    }
     
    memset(&serverAddr, 0, slen);
    memset(&clientAddr, 0, slen);
    
    /*addresses*/ 
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(machine->port);
    serverAddr.sin_addr.s_addr = machine->real_ip;
    
    
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
            /* parse packet when destination matches*/
            if (getPacketDestination(buffer) == -1) {
                //skip if not IP packet
            } else if (getPacketDestination(buffer) == machine->ip_address) {
                parsePacket(buffer, recv_len, machine->ip_address);
                /* acknowledge to client */
                if (sendto(serverSock, buffer, slen, 0, (struct sockaddr *)&clientAddr, slen) < 0) {
                    printf("acknowledge failed.\n");
                }
            /* forward packet when destination does not match its own address*/
            } else {
                /* forward packet*/
		machine->source_port = clientAddr.sin_port;
            	createClient(machine);
            }
       	}
    }
 
    close(serverSock);

}

long getPacketDestination(const u_char* packet)
{
    const struct wlan_header* wlanHeader;
    const struct ip* ipHeader;
    char destIP[INET_ADDRSTRLEN];
    wlanHeader = (struct wlan_header*)packet;
    if (htons(wlanHeader->protocol) == WLANTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
        return ipHeader->ip_dst.s_addr;
    } else {
        return -1;
    }
}

long getPacketSource(const u_char* packet)
{
    const struct wlan_header* wlanHeader;
    const struct ip* ipHeader;
    char destIP[INET_ADDRSTRLEN];
    wlanHeader = (struct wlan_header*)packet;
    if (htons(wlanHeader->protocol) == WLANTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
        return ipHeader->ip_src.s_addr;
    } else {
        return -1;
    }
}

void parsePacket(const u_char* packet, const int size, const unsigned long machine_ip)
{

    const struct wlan_header* wlanHeader;
    const struct ip* ipHeader;
    char ip_protocol_str[5];
    char sourceWLAN[ETH_ALEN * 3];
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_char tos;
    u_char *data;
    int i;

    /*get wlan Info*/
    wlanHeader = (struct wlan_header*)packet;
    if (htons(wlanHeader->protocol) == WLANTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
        if (ipHeader->ip_dst.s_addr == machine_ip) {
            /* get source and dest ip addresses */
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
            ether_ntoa_r((struct ether_addr *)&(wlanHeader->addr_src), sourceWLAN);
            /* get protocol */
            if (ipHeader->ip_p == 6) {
                strcpy(ip_protocol_str, "TCP");
            } else if (ipHeader->ip_p == 17) {
                strcpy(ip_protocol_str, "UDP");
            } else if (ipHeader->ip_p == 1) {
                strcpy(ip_protocol_str, "ICMP");
            } else { 
                strcpy(ip_protocol_str, "");
            }
            tos = ipHeader->ip_tos;
            /* wlan info*/
            printf("WLAN:   -----WLAN HEADER-----\n"
                   "WLAN: Packet type: %hu \n"
                   "WLAN: Link-layer address type: %hu\n"
                   "WLAN: Link-layer address length: %hu\n"
                   "WLAN: Source: %s\n"
                   "WLAN: Unused: %02hhx%02hhx\n"
                   "WLAN: protocol: %04x (IPv%d)\n",
               ntohs(wlanHeader->packet_type),
               ntohs(wlanHeader->addr_type),
               ntohs(wlanHeader->addr_length),
               sourceWLAN,
               wlanHeader->unused[0] & 0xff, wlanHeader->unused[1] & 0xff,
               ntohs(wlanHeader->protocol),
               ipHeader->ip_v & 0x0f);
            fflush(stdout);
            /* ip info */
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
                   "IP:  Fragment offset = %hu\n"
                   "IP:  Time to live = %d seconds/hops\n"
                   "IP:  Protocol = %d (%s)\n"
                   "IP:  Header checksum = 0x%x\n"
                   "IP:  Source address = %s\n"
                   "IP:  Destination address = %s\n"
                   "IP:  %s options\n",
                   ipHeader->ip_v & 0x0F,
                   (ipHeader->ip_hl & 0x0F) * 4,
                   tos,
                   tos >> 13,
                   (tos == IPTOS_LOWDELAY? '1' : '0'),
                   (tos == IPTOS_THROUGHPUT? '1' : '0'),
                   (tos == IPTOS_RELIABILITY? '1' : '0'),
                   ntohs(ipHeader->ip_len),
                   ntohs(ipHeader->ip_id),
                   ((u_char*)ipHeader)[6],((u_char*)ipHeader)[7],
                   (((u_char*)ipHeader)[6] & 0x40 ? '1' : '0'), (((u_char*)ipHeader)[6] & 0x20 ? '1' : '0'),
                   //ipHeader->ip_off,
                   (((u_char*)ipHeader)[6] & 0x2f >> 8) | (((u_char*)ipHeader)[7] & 0xff),
                   ipHeader->ip_ttl,
                   ipHeader->ip_p, ip_protocol_str,
                   ntohs(ipHeader->ip_sum),
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
        }
    } else {
        printf("Not IP header\n\n");
    }
}  
