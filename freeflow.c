#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <arpa/inet.h>   /* Provides: inet_ntoa */
#include "freeflow.h"
#include "netflow.h"
#include "config.h"

void die(char *s)
{
    perror(s);
    exit(1);
}

int parse_packet(packet_buffer* packet, char** payload, freeflow_config* config) {
    // Make sure the size of the packet is sane for netflow.
    if ( (packet->packet_len - 24) % 48 > 0 ){
        logger("Invalid length");
        return 1;
    }

    netflow_header *h = (netflow_header*)packet->packet;

    // Make sure the version field is correct
    if (ntohs(h->version) != 5){
        logger("Invalid version: %d", ntohs(h->version));
        return 1;
    }

    short num_records = ntohs(h->count);

    // Make sure the number of records is sane
    if (num_records != (packet->packet_len - 24) / 48){
        logger("Invalid number of records: %d", num_records);
        return 1;
    }

    long sys_uptime = ntohl(h->sys_uptime);
    long unix_secs = ntohl(h->unix_secs);
    long unix_nsecs = ntohl(h->unix_nsecs);

    // The maximum size of a record minus the variable sourcetype is 233 bytes.
    // 250 bytes provides a reasonable safety buffer.
    int record_size = (250 + strlen(config->sourcetype));

    char splunk_payload[record_size * num_records];
    splunk_payload[0] = '\0';

    int record_count;
    netflow_record *r;
    for ( record_count = 0; record_count < num_records; record_count++){
        r = (netflow_record*)((char*)h + 24 + 48 * record_count);
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
            packet->sender, srcaddr, dstaddr, nexthop,
            input, output, packets, bytes, duration,
            sport, dport, flags, prot, tos, srcas, dstas,
            srcmask, dstmask, config->sourcetype,
            (  (double)unix_secs 
             + (double)unix_nsecs / 1000000000 
             - (double)sys_uptime/1000 
             + (double)first/1000)
        );
        strcat(splunk_payload, record);
    }

    char header[500];
    strcpy(header, "POST /services/collector HTTP/1.1\r\n");        
    strcat(header, "Host: %s:%d\r\n");
    strcat(header, "User-Agent: freeflow\r\n");
    strcat(header, "Connection: keep-alive\r\n");
    strcat(header, "Authorization: Splunk %s\r\n");
    strcat(header, "Content-Length: %d\r\n\r\n"); 

    sprintf(*payload, header, config->hec_server, 
                              config->hec_port, 
                              config->hec_token,
                              (int)strlen(splunk_payload));
    strcat(*payload, splunk_payload);
    return 0;
}

int splunk_worker(int worker_num, freeflow_config *config, int log_queue) {
    struct sockaddr_in addr;
    struct hostent *host;
    int sock;

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        logger("Error opening socket.", log_queue);
        return -1;
    }
 
    addr.sin_family = AF_INET;

    host = gethostbyname(config->hec_server);
    if(host == NULL) {
        logger("%s unknown host.", config->hec_server);
        return -1;
    }

    bcopy(host->h_addr, &addr.sin_addr, host->h_length);
    addr.sin_port = htons(config->hec_port);
    connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)); 

    char log_message[128];
    sprintf(log_message, "Splunk worker #%d started.", worker_num);
    logger(log_message, log_queue);

    int packet_queue = create_queue(config->config_file, '2');
    set_queue_size(packet_queue, config->queue_size);

    char *payload, *recv_buffer;
    payload = malloc(PACKET_BUFFER_SIZE);
    recv_buffer = malloc(PACKET_BUFFER_SIZE);
    
    packet_buffer *packet = malloc(sizeof(packet_buffer));
    while(1) {
        msgrcv(packet_queue, packet, sizeof(packet_buffer), 2, 0);
        char results = parse_packet(packet, &payload, config);
        
        int bytes_sent = write(sock, payload, strlen(payload));
        if (bytes_sent < strlen(payload)) {
            logger("Incomplete packet delivery.", log_queue);
        }

        read(sock, recv_buffer, PACKET_BUFFER_SIZE);
    }
    free(packet);
    free(payload);
    free(recv_buffer);
}

int receive_packets(int log_queue, freeflow_config *config) {
    struct sockaddr_in si_me;
    struct sockaddr_in si_other;
    
    int s, i, slen = sizeof(si_other);
    char packet[PACKET_BUFFER_SIZE];
    
    //create a UDP socket
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        die("socket");
    }
    
    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));
    
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(config->bind_port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    
    //bind socket to port
    if (bind(s, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
        die("bind");
    }
    logger("Socket bound and listening", log_queue);

    int packet_queue = create_queue(config->config_file, '2');

    packet_buffer message;
    message.mtype = 2;

    //keep listening for data
    while(1)
    {
        int bytes_recv;
        bytes_recv = recvfrom(s, packet, PACKET_BUFFER_SIZE, 0, 
                              (struct sockaddr *)&si_other, &slen);

        message.packet_len = bytes_recv;
        strcpy(message.sender, inet_ntoa(si_other.sin_addr));
        memcpy(message.packet, packet, bytes_recv);
        msgsnd(packet_queue, &message, sizeof(packet_buffer), 0); 
    }

    close(s);
    return 0;
}

/*
 * Function: main
 *
 * Initialize the program by reading and processing the command line arguments 
 * and the program configuration file, fork additional processes to handle 
 * logging and packet processing and transmission to Splunk.  The main process 
 * will handle send and receive functions for the Netflow UDP socket.
 */
int main(int argc, char** argv) {
    freeflow_config *config = malloc(sizeof(freeflow_config));

    parse_command_args(argc, argv, config);
    read_configuration(config);

    int i;
    int log_queue = create_queue(config->config_file, '1');

    if (fork() == 0) {
        start_logger(config->log_file, log_queue);
        exit(0);
    }

    for (i = 0; i < config->threads; ++i) {
       if (fork() == 0) {
            splunk_worker(i, config, log_queue);
            exit(0);
        }
    }
    
    receive_packets(log_queue, config);
    free(config);
}
