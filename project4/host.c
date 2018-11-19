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
#define DAMPENING_MEM 1024
    
struct host {
    unsigned short port;
    unsigned long ip_address;
    unsigned long real_ip;
    int total_neighbors;
    int total_entries;
    char packet_file[BUFLEN];
    struct host** neighbors;
    struct frame_queue* f_queue; /* forward queue */
    struct frame_queue* p_queue; /* parse queue */
    struct routing_entry** routing_table;
};

struct frame_queue {    
    unsigned char** recent_frames;
    int current_pos;
};

struct wlan_header {
    u_short packet_type;
    u_short addr_type;
    u_short addr_length;
    u_char addr_src[6];
    u_char unused[2];
    u_short protocol; 
};

// routing table
struct routing_entry {
    unsigned long dest; // destination ip
    unsigned long nexthop; // nexthop ip
};

void readConfigFile (char* filename, struct host* machine);
void *createClient(void * arg);
void *createServer(void * arg);
void parsePacket(const u_char* packet, const int size, struct host* machine, const unsigned short source_port, int forward_sock);
void forwardPacket(const unsigned char* packet, const int size, unsigned short source_port, unsigned long dest_ip, struct host* machine, int forward_sock); 
int isInFrameQueue(const unsigned char* frame_id, unsigned char** frames, int size);
unsigned long find_nexthop(struct host* machine, unsigned long dest_ip);

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

    // create forwarding queue
    machine->f_queue = malloc(sizeof(struct frame_queue));
    machine->f_queue->recent_frames = malloc(sizeof(unsigned char*) * DAMPENING_MEM);
    for (int i = 0; i < DAMPENING_MEM; i++) {
        machine->f_queue->recent_frames[i] = malloc(sizeof(unsigned char) * 2);
    }
    if (machine->f_queue == NULL) {
        printf("Cannot create queue\n");
        exit(EXIT_FAILURE);
    }
    machine->f_queue->current_pos = 0;
    
    // create parsing queue
    machine->p_queue = malloc(sizeof(struct frame_queue));
    machine->p_queue->recent_frames = malloc(sizeof(unsigned char*) * DAMPENING_MEM);
    for (int i = 0; i < DAMPENING_MEM; i++) {
        machine->p_queue->recent_frames[i] = malloc(sizeof(unsigned char) * 2);
    }
    if (machine->p_queue == NULL) {
        printf("Cannot create queue\n");
        exit(EXIT_FAILURE);
    }
    machine->p_queue->current_pos = 0;
 
    /* get packet file name */
    strcpy(machine->packet_file, argv[2]);

    /* read from config file */
    readConfigFile(argv[1], machine);

    /* create server thread */
    status = pthread_create(&threads[0], NULL, createServer, machine);

    /* create client thread */
    status = pthread_create(&threads[1], NULL, createClient, machine);

    /* join threads */
    status = pthread_join(threads[0], &exit_value);
    status = pthread_join(threads[1], &exit_value);
    
    /*clean memory*/
    for (int i = 0; i < DAMPENING_MEM; i++) {
        free(machine->f_queue->recent_frames[i]);
    }
    free(machine->f_queue->recent_frames);
    free(machine->f_queue);
    for (int i = 0; i < DAMPENING_MEM; i++) {
        free(machine->p_queue->recent_frames[i]);
    }
    free(machine->p_queue->recent_frames);
    free(machine->p_queue);
    for (int i = 0; i < machine->total_entries; i++) {
	free(machine->routing_table[i]);
    }
    for (int i = 0; i < machine->total_neighbors; i++) {
        free(machine->neighbors[i]);
    }
    free(machine->neighbors);
    free(machine->routing_table);
    free(machine);
    machine = NULL;
    
    return 0;
}

void readConfigFile (char* filename, struct host* machine)
{
    FILE *config_file;
    int num_entries;
    char buffer1[16];
    char buffer2[16];
    struct host** neighborptr;

    // test for file not existing
    if ((config_file = fopen(filename, "r")) == NULL) {
        printf("Error. Cannot open file.\n");
        exit(-1);
    }

    /*read info for this machine*/
    fscanf(config_file, "%s\n\n%hu\n\n%d\n\n", buffer1, &machine->port, &machine->total_neighbors);
    machine->ip_address = inet_addr(buffer1);
    printf("ip address: %s\n", buffer1);
    printf("port number: %hu\n", machine->port);
    
    /* read neighbors info*/
    machine->neighbors = malloc(sizeof(struct host*) * machine->total_neighbors); 
    neighborptr = machine->neighbors;
    for (int i = 0; i < machine->total_neighbors; i++) {
        *neighborptr = malloc(sizeof(struct host));
        memset(buffer1, 0, sizeof buffer1);
        memset(buffer2, 0, sizeof buffer2);
        fscanf(config_file, "%s %s %hu\n\n", buffer1, buffer2, &(*neighborptr)->port);
        (*neighborptr)->ip_address = inet_addr(buffer1);
        (*neighborptr)->real_ip = inet_addr(buffer2);
        strcpy((*neighborptr)->packet_file, machine->packet_file);
        printf("neighbor info: %s %s %hu\n", buffer1, buffer2, (*neighborptr)->port);
        neighborptr++;
    }

    // read routing table
    printf("routing table:\n");
    fscanf(config_file, "%d\n\n", &num_entries);
    machine->total_entries = num_entries;
    machine->routing_table = malloc(sizeof(struct routing_entry*) * num_entries);
    for (int i = 0; i < num_entries; i++) {
        machine->routing_table[i] = malloc(sizeof(struct routing_entry));
        memset(buffer1, 0, sizeof buffer1);
        memset(buffer2, 0, sizeof buffer2);
        fscanf(config_file, "%s %s\n\n", buffer1, buffer2);
        machine->routing_table[i]->dest = inet_addr(buffer1);
        machine->routing_table[i]->nexthop = inet_addr(buffer2);
        printf("%s %s\n", buffer1, buffer2);
    }
}



void *createClient(void * arg)
{
    
    struct host* machine;
    struct frame_queue* f_queue;
    pcap_t *pp;
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char *packet;
    struct sockaddr_in serverAddr; 
    struct pcap_pkthdr header;
    int serverSock;
    socklen_t slen = sizeof(serverAddr); 
    struct wlan_header* wlanHeader;
    const struct ip* ipHeader;
    unsigned int frame_id = 1;
    unsigned long nexthop;

    /*get info*/
    machine = (struct host *)arg;

    /*open pcap file*/
    pp = pcap_open_offline(machine->packet_file, errbuf);
    if (pp == NULL) {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        return 0;
    }

    /*socket creation*/
    if ((serverSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    }

    /* sleep before send incase server not set up*/
    sleep(2);
    
    while ((packet = pcap_next(pp, &header)) != NULL) {
 
        wlanHeader = (struct wlan_header*)packet;
        ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
        // add frame id for flooding dampening
        wlanHeader->unused[1] = frame_id & 0xff;
        wlanHeader->unused[0] = frame_id >> 8 & 0xff;
        if (++frame_id == 1 >> 16 - 1) frame_id = 0;

        // send packet only when source ip matches its own ip
        if (ipHeader->ip_src.s_addr == machine->ip_address) {
           
            // add to forward queue
            f_queue = machine->f_queue;
            f_queue->recent_frames[f_queue->current_pos][0] = wlanHeader->unused[0];
            f_queue->recent_frames[f_queue->current_pos][1] = wlanHeader->unused[1];
            
            if (++(f_queue->current_pos) == DAMPENING_MEM) {
                // wrapping forward queue if needed 
                f_queue->current_pos = 0;
            } 

            // find nexthop
            if ((nexthop = find_nexthop(machine, ipHeader->ip_dst.s_addr)) == 0) {
                printf("Missing routing info. Cannot send packet.");
                return;
            }
            // send according to routing table
            for (int i = 0; i < machine->total_neighbors; i++) {
        
                if (machine->neighbors[i]->ip_address == nexthop) {

                    memset(&serverAddr, 0, sizeof(serverAddr)); 
 
                    // address
                    serverAddr.sin_family = AF_INET; 
                    serverAddr.sin_addr.s_addr = machine->neighbors[i]->real_ip; 
                    serverAddr.sin_port = htons(machine->neighbors[i]->port); 

                    // send
                    if (sendto(serverSock, packet, header.len,
                        MSG_CONFIRM, (const struct sockaddr *) &serverAddr,
                        slen) < 0) {
                        perror("send error\n");
                    }
                }
            }
        }
    }

    close(serverSock);
}

void *createServer(void * arg)
{
    char buffer[BUFLEN];
    char packet[BUFLEN];
    struct sockaddr_in serverAddr, clientAddr;
    int serverSock;
    int forwardSock;
    int recv_len;
    socklen_t slen = sizeof(clientAddr); 
    struct host* machine;

    // get host
    machine = (struct host *)arg;
     
    //create server socket
    if ((serverSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket failed\n");
    }
    //create forward socket
    if ((forwardSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket failed\n");
    }
 
    memset(&serverAddr, 0, slen);
    memset(&clientAddr, 0, slen);
    
    // addresses 
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(machine->port);
    serverAddr.sin_addr.s_addr = machine->real_ip;
    
    
    // socket binding 
    if( bind(serverSock , (struct sockaddr*)&serverAddr, slen) < 0){
        perror("binding failed\n");
    }
     
    // keep receiving
    while(1)
    {
        // receive packet
        memset(buffer,'\0', BUFLEN);
        if ((recv_len = recvfrom(serverSock, buffer, BUFLEN, 0, (struct sockaddr *) &clientAddr, &slen)) == -1) {
            perror("receiving failed\n");
        } else {
            // parse packet
            parsePacket(buffer, recv_len, machine, clientAddr.sin_port, forwardSock);
        }
    }
 
    close(serverSock);
    close(forwardSock);
}

void forwardPacket(const unsigned char* packet, const int size, unsigned short source_port, unsigned long dest_ip,struct host* machine, int forward_sock) 
{
    
    struct frame_queue* f_queue; 
    struct sockaddr_in serverAddr; 
    int serverSock;
    socklen_t slen = sizeof(serverAddr); 
    struct wlan_header* wlanHeader;
    const struct ip* ipHeader;
    unsigned long frame_id;
    unsigned long nexthop;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    char neighborIP[INET_ADDRSTRLEN];

    serverSock = forward_sock;

    // get forward queue
    f_queue = machine->f_queue;

    wlanHeader = (struct wlan_header*)packet;
    ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    // do not forward if already in forward queue
    if (isInFrameQueue(wlanHeader->unused, f_queue->recent_frames, DAMPENING_MEM) == 1) {
        return;
    }
    // update forward queue
    f_queue->recent_frames[f_queue->current_pos][0] = wlanHeader->unused[0];
    f_queue->recent_frames[f_queue->current_pos][1] = wlanHeader->unused[1];
    if (++(f_queue->current_pos) == DAMPENING_MEM) {
         f_queue->current_pos = 0;
    } 

    // forward
    // find nexthop
    nexthop = find_nexthop(machine, dest_ip);
    if (!nexthop) {
        printf("Missing routing info. Cannot forward packet\n");
        return;
    } 

    for (int i = 0; i < machine->total_neighbors; i++) {
        
        // forward according to routing table
        if (machine->neighbors[i]->ip_address == nexthop ) {

            memset(&serverAddr, 0, sizeof(serverAddr)); 
 
            // address
            serverAddr.sin_family = AF_INET; 
            serverAddr.sin_addr.s_addr = machine->neighbors[i]->real_ip; 
            serverAddr.sin_port = htons(machine->neighbors[i]->port); 

            // log 
            inet_ntop(AF_INET, &(machine->neighbors[i]->ip_address), neighborIP, INET_ADDRSTRLEN);
            printf("forwarding packet id %02x%02x src- %s dest- %s to neighbor %s\n", 
                   wlanHeader->unused[0] & 0xff, wlanHeader->unused[1] & 0xff, sourceIP, destIP, neighborIP);

            // forward packet
            if (sendto(serverSock, packet, size,
                MSG_CONFIRM, (const struct sockaddr *) &serverAddr,
                slen) < 0) {
                perror("send error\n");
            }
        }
    }  

    // close(serverSock); 
}


void parsePacket(const u_char* packet, const int size, struct host* machine, const unsigned short source_port, int forward_sock)
{

    const struct wlan_header* wlanHeader;
    const struct ip* ipHeader;
    struct frame_queue* p_queue;
    char ip_protocol_str[5];
    char sourceWLAN[ETH_ALEN * 3];
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    char machineIP[INET_ADDRSTRLEN];
    u_char tos;
    u_char *data;
    int i;

    // get wlan header
    wlanHeader = (struct wlan_header*)packet;
    
    // do not parse if in parse queue
    p_queue = machine->p_queue;
    if (isInFrameQueue(wlanHeader->unused, p_queue->recent_frames, DAMPENING_MEM) == 1) {
        return;
    }

    if (htons(wlanHeader->protocol) == WLANTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct wlan_header));
        // get source and dest ip addresses
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        ether_ntoa_r((struct ether_addr *)&(wlanHeader->addr_src), sourceWLAN);
        if (ipHeader->ip_dst.s_addr == machine->ip_address) {
            
            // update parse queue 
            p_queue->recent_frames[p_queue->current_pos][0] = wlanHeader->unused[0];
            p_queue->recent_frames[p_queue->current_pos][1] = wlanHeader->unused[1];
            if (++(p_queue->current_pos) == DAMPENING_MEM) {
                 p_queue->current_pos = 0;
            }
 
            // get protocol
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
            // wlan info
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
            // ip info
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

            // print raw
            int i = 0;
            char letters[16];
            for (i = 0; i < size; i++) {
                // print line number
                if (i%16 == 0) {
                    printf("%03d0  ", i / 16);
                } 
                printf("%02x  ", packet[i]);
                if(((i+1)%16 == 0 && i != 0) || i == size-1) { 
                    // add padding
                    if (i == size-1 && (i+1)%16 != 0) {
                        int j = 16;
                        while((i+1)%16 != 0){
                            printf("    ");
                            i++;
                        } 
                    }
                    // print letters
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
        } else {
            // forward if not its own IP
            forwardPacket(packet, size, source_port, ipHeader->ip_dst.s_addr, machine, forward_sock);
        }
    } else {
        printf("Not IP header\n\n");
    }
}  

int isInFrameQueue(const unsigned char* frame_id, unsigned char** frames, int size)
{
    int i;
    for (i = 0; i < size; i++) {
        if ((frames[i][0] & 0xff) == (frame_id[0] & 0xff) && (frames[i][1] & 0xff) == (frame_id[1] & 0xff)) {
            return 1;
        }
    }
    return 0;

}

unsigned long find_nexthop(struct host* machine, unsigned long dest_ip)
{
    for (int i = 0; i < machine->total_entries; i++) {
        if (machine->routing_table[i]->dest == dest_ip) {
            return machine->routing_table[i]->nexthop;
        }
    }
    return 0;
}
