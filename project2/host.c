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
void parsePacket(const u_char* packet, const int size, const unsigned long machine_ip);

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
            parsePacket(buffer, recv_len, machine->ip_address);
        }
    }
 
    close(serverSock);

}

void parsePacket(const u_char* packet, const int size, const unsigned long machine_ip)
{
    
    struct ether_header* ethernetHeader;
    struct wlan_header {
        u_short packet_type;
	u_short addr_type;
        u_short addr_length;
        u_char addr_src[6];
        u_char unused[2];
        u_short protocol; 
    };
    const u_char *bssid;
    const u_char *essid;
    const u_char *essidLen;
    const u_char *channel;
    const u_char *rssi;

    const struct wlan_header* wlanHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    u_char mac_dest[ETH_ALEN * 3],  mac_src[ETH_ALEN * 3];
    u_int16_t ether_type;
    char ether_type_str[10];
    char ether_address_type;
    char ether_saddress_glb[20];
    char ether_saddress_grp[20];
    char ether_daddress_glb[20];
    char ether_daddress_grp[20];
    char ip_protocol_str[5];
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char tos;
    u_char *data;
    int dataLength = 0;
    int i;

    /*get Ethernet Info*/
    wlanHeader = (struct wlan_header*)packet;
    /*ethernetHeader = (struct ether_header*)packet;
    ether_type = ntohs(ethernetHeader->ether_type);
    if (ether_type == ETHERTYPE_IP) {
        strcpy(ether_type_str, "IP");
    } else if (ether_type == ETHERTYPE_ARP){
        strcpy(ether_type_str, "ARP");
    } else {
        strcpy(ether_type_str, "UNKNOWN");
    }
    /*source address type*/
    /*if (packet[0] & 0x02) {
        strcpy(ether_daddress_glb, "Local");
    } else {
        strcpy(ether_daddress_glb, "Global");
    }
    if (packet[0] & 0x01) {
        strcpy(ether_daddress_grp, "Group");
    } else {
        strcpy(ether_daddress_grp, "Individual");
    }
    /*dest address type*/
    /*if (packet[6] & 0x02) {
        strcpy(ether_saddress_glb, "Local");
    } else {
        strcpy(ether_saddress_glb, "Global");
    }
    if (packet[6] & 0x01) {
        strcpy(ether_saddress_grp, "Group");
    } else {
        strcpy(ether_saddress_grp, "Individual");
    }
        /*IP info*/
    if (1) {
        ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
        //ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        printf("dest ip address: %d\n", ipHeader->ip_dst.s_addr);
        printf("machine ip address %ld\n", machine_ip);
        if (ipHeader->ip_dst.s_addr == machine_ip) {
            inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
            if (ipHeader->ip_p == 6) {
                strcpy(ip_protocol_str, "TCP");
            } else if (ipHeader->ip_p == 17) {
                strcpy(ip_protocol_str, "UDP");
            } else { 
                strcpy(ip_protocol_str, "");
            }
            tos = ipHeader->ip_tos;
            /*printf("ETHER:   -----ETHER HEADER-----\nETHER: Packet size\t: %d bytes\nETHER: Destination\t: %s  Type: %s %s\nETHER: Source\t\t: %s  Type: %s %s\nETHER: Ethertype\t: 0%x (%s)\n",
               size,
               ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_dhost), mac_dest),
               ether_daddress_grp, ether_daddress_glb,
               ether_ntoa_r((struct ether_addr *)&(ethernetHeader->ether_shost), mac_src),
               ether_saddress_grp, ether_daddress_glb,
               ether_type, ether_type_str);
            fflush(stdout);*/
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
                   "IP:  Fragment offset = %d\n"
                   "IP:  Time to live = %d seconds/hops\n"
                   "IP:  Protocol = %d (%s)\n"
                   "IP:  Header checksum = %x\n"
                   "IP:  Source address = %s\n"
                   "IP:  Destination address = %s\n"
                   "IP:  %s options\n",
                   ipHeader->ip_v & 0x0F,
                   (ipHeader->ip_hl & 0x0F) * 4,
                   tos,
                   packet[15] >> 5,
                   (tos == IPTOS_LOWDELAY? '1' : '0'),
                   (tos == IPTOS_THROUGHPUT? '1' : '0'),
                   (tos == IPTOS_RELIABILITY? '1' : '0'),
                   ntohs(ipHeader->ip_len),
                   ntohs(ipHeader->ip_id),
                   packet[20],packet[21],
                   (packet[20] & 0x40 ? '1' : '0'), (packet[20] & 0x20 ? '1' : '0'),
                   ipHeader->ip_off,
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
