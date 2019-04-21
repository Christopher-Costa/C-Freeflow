#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "netflow.h"

#define PROCESSES 25
#define BUFLEN 65536 //Max length of buffer
#define PORT 2055    //The port on which to listen for incoming data

char hec_server[] = "10.10.10.10";
int  hec_port = 8088;
char hec_token[] = "2365442b-8451-4d96-9e37-46a9d5f2f9f1";

void die(char *s)
{
    perror(s);
    exit(1);
}

int parse_packet(char* packet, int packet_len, char** payload) {
    char exporter[] = "127.0.0.1";
    char sourcetype[] = "netflow:csv";

    // Make sure the size of the packet is sane for netflow.
    if ( (packet_len - 24) % 48 > 0 ){
        printf("Invalid length\n");
        return 1;
    }

    struct netflow_header *h = (struct netflow_header*)packet;

    // Make sure the version field is correct
    if (ntohs(h->version) != 5){
        printf("Invalid version\n");
        return 1;
    }

    short num_records = ntohs(h->count);

    // Make sure the number of records is sane
    if (num_records != (packet_len - 24) / 48){
        printf("Invalid number of records\n");
        return 1;
    }

    long sys_uptime = ntohl(h->sys_uptime);
    long unix_secs = ntohl(h->unix_secs);
    long unix_nsecs = ntohl(h->unix_nsecs);

    // The maximum size of a record minus the variable sourcetype is 233 bytes.
    // 250 bytes provides a reasonable safety buffer.
    int record_size = (250 + strlen(sourcetype));

    char splunk_payload[record_size * num_records];
    splunk_payload[0] = '\0';

    int record_count;
    struct netflow_record *r;
    for ( record_count = 0; record_count < num_records; record_count++){
        r = (struct netflow_record*)((char*)h + 24 + 48 * record_count);
        struct in_addr s = {r->srcaddr};
        struct in_addr d = {r->dstaddr};
        struct in_addr n = {r->nexthop};

        char srcaddr[16];
        strcpy(srcaddr, inet_ntoa(s));

        char dstaddr[16];
        strcpy(dstaddr, inet_ntoa(d));

        char nexthop[16];
        strcpy(nexthop, inet_ntoa(n));

        short input = ntohs(r->input);
        short output = ntohs(r->output);
        long packets = ntohl(r->packets);
        long bytes = ntohl(r->bytes);
        long first = ntohl(r->first);
        long last = ntohl(r->last);
        long duration = last - first;
        short sport = ntohs(r->srcport);
        short dport = ntohs(r->dstport);
        int flags = r->tcp_flags;
        int prot = r->prot;
        int tos = r->tos;
        short srcas = ntohs(r->src_as);
        short dstas = ntohs(r->dst_as);
        int srcmask = r->src_mask;
        int dstmask = r->dst_mask;

        char record[record_size];
        sprintf(record, "{\"event\": \"%s,%s,%s,%s,%u,%u,%lu,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u\", \"sourcetype\": \"%s\", \"time\": \"%.6f\"}",
            exporter, srcaddr, dstaddr, nexthop,
            input, output, packets, bytes, duration,
            sport, dport, flags, prot, tos, srcas, dstas,
            srcmask, dstmask, sourcetype,
            (  (double)unix_secs 
             + (double)unix_nsecs / 1000000000 
             - (double)sys_uptime/1000 
             + (double)first/1000)
        );
        strcat(splunk_payload, record);
    }
    
    char post_message[200 + strlen(hec_server) + 5 + strlen(hec_token)];
    sprintf(post_message, 
            "POST /services/collector HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: freeflow\r\nConnection: keep-alive\r\nAuthorization: Splunk %s\r\nContent-Length: %d\r\n\r\n", 
            hec_server, hec_port, hec_token, (int)strlen(splunk_payload));
    strcat(post_message, splunk_payload);

    *payload = post_message;
    return 0;
}

int splunk_worker() {

    struct sockaddr_in addr;
    struct hostent *host;
    int sock;

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Error opening socket\n");
        return -1;
    }

    addr.sin_family = AF_INET;

    host = gethostbyname(hec_server);
    if(host == NULL) {
        printf("%s unknown host.\n", hec_server);
        return -1;
    }

    bcopy(host->h_addr, &addr.sin_addr, host->h_length);
    addr.sin_port = htons(hec_port);
    connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)); 

    printf("Successfully bound to splunk\n");

    while(1){
        sleep(1);
    }
}

int bind_socket(void) {
    struct sockaddr_in si_me;
    struct sockaddr_in si_other;
    
    int s, i, slen = sizeof(si_other);
    char buf[BUFLEN];
    
    //create a UDP socket
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        die("socket");
    }
    
    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));
    
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    
    //bind socket to port
    if (bind(s, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
        die("bind");
    }
    
    //keep listening for data
    printf("Socket Open\n");
    while(1)
    {
        int bytes_recv;
        bytes_recv = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *)&si_other, &slen);

        char *payload;
        char results = parse_packet(buf, bytes_recv, &payload);        
        printf("%s\n", payload);
    }

    close(s);
    return 0;
}

int main() {

    pid_t pids[PROCESSES];
    int i;


    for (i = 0; i < PROCESSES; ++i) {
       if ((pids[i] = fork()) == 0 ) {
            printf("%d: CHILD\n", i);
            splunk_worker();
        }
       else {
            printf("%d: PARENT\n", i);
        }
    }

    for (i = 0; i < PROCESSES; ++i) {
        printf("%d\n", pids[i]);
    }

    bind_socket();
}
