#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <arpa/inet.h>   /* Provides: inet_ntoa */
#include <sys/msg.h>     /* Provides: IPC_NOWAIT */
#include <signal.h>
#include "freeflow.h"
#include "netflow.h"
#include "config.h"
#include "socket.h"
#include "queue.h"

int keep_working = 1;

int hec_header(hec* server, int content_length, char* header) {
    char h[500];

    strcpy(h, "POST /services/collector HTTP/1.1\r\n");        
    strcat(h, "Host: %s:%d\r\n");
    strcat(h, "User-Agent: freeflow\r\n");
    strcat(h, "Connection: keep-alive\r\n");
    strcat(h, "Authorization: Splunk %s\r\n");
    strcat(h, "Content-Length: %d\r\n\r\n"); 

    sprintf(header, h, server->addr, server->port, server->token, content_length); 
}

int empty_payload(char* payload, hec* server) {
    hec_header(server, 0, payload);
    return 0;
}

int parse_packet(packet_buffer* packet, char* payload, freeflow_config* config, 
                 int server_instance, int log_queue) {

    char log_message[LOG_MESSAGE_SIZE];

    // Make sure the size of the packet is sane for netflow.
    if ( (packet->packet_len - 24) % 48 > 0 ){
        log_warning("Invalid netflow packet length", log_queue);
        return 1;
    }

    netflow_header *h = (netflow_header*)packet->packet;

    // Make sure the version field is correct
    if (ntohs(h->version) != 5){
        char log_message[LOG_MESSAGE_SIZE];
        sprintf(log_message, "Packet received with invalid version: %d", ntohs(h->version));
        log_warning(log_message, log_queue);
        return 1;
    }

    short num_records = ntohs(h->count);

    // Make sure the number of records is sane
    if (num_records != (packet->packet_len - 24) / 48){
        sprintf(log_message, "Invalid number of records: %d", num_records);
        log_warning(log_message, log_queue);
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

        char srcaddr[IPV4_ADDR_SIZE];
        strcpy(srcaddr, inet_ntoa(s));

        char dstaddr[IPV4_ADDR_SIZE];
        strcpy(dstaddr, inet_ntoa(d));

        char nexthop[IPV4_ADDR_SIZE];
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

    hec_header(&config->hec_server[server_instance], (int)strlen(splunk_payload), payload);
    strcat(payload, splunk_payload);
    return 0;
}

int response_code(char* response) {
    char *token;
    char delim[2] = " ";
    token = strtok(response, delim);
    token = strtok(NULL, delim);
    return(atoi(token));
}

void handle_worker_sigterm(int sig) {
    keep_working = 0;
}

void handle_worker_sigint(int sig) {}

int splunk_worker(int worker_num, freeflow_config *config, int log_queue) {
    signal(SIGTERM, handle_worker_sigterm);
    signal(SIGINT, handle_worker_sigint);

    char log_message[LOG_MESSAGE_SIZE];
    char error_message[LOG_MESSAGE_SIZE];
    int socket_id = connect_socket(worker_num, config, log_queue);

    if (socket_id < 0) {
        kill(getppid(), SIGTERM);
    }

    char *payload = malloc(PACKET_BUFFER_SIZE);
    char *dummy = malloc(PACKET_BUFFER_SIZE);
    char *recv_buffer = malloc(PACKET_BUFFER_SIZE);

    int instance = worker_num % config->num_servers;

    // Send an empty HEC message to prevent Splunk from closing the connection
    // within 40s.  Use the opportunity to validate the authentication token.
    empty_payload(dummy, &config->hec_server[instance]);
    write(socket_id, dummy, strlen(dummy));
    read(socket_id, recv_buffer, PACKET_BUFFER_SIZE);
    free(dummy);
    if (response_code(recv_buffer) == 403) {
        sprintf(log_message, "Splunk worker #%d unable to authenticate with Splunk.", worker_num);
        log_error(log_message, log_queue);
        kill(getppid(), SIGTERM);
    };

    sprintf(log_message, "Splunk worker #%d [PID %d] started.", worker_num, getpid());
    log_info(log_message, log_queue);

    int packet_queue = create_queue(config->config_file, PACKET_QUEUE, error_message);
    if (packet_queue < 0) {
        sprintf(log_message, 
                "Splunk worker #%d [PID %d] unable to open packet queue: %s.", 
                worker_num, getpid(), error_message);        
        log_error(log_message, log_queue);
        kill(getppid(), SIGTERM);
    }

    int result = set_queue_size(packet_queue, config->queue_size, error_message);
    if (result < 0) {
        sprintf(log_message, 
                "Splunk worker #%d [PID %d] unable to set queue size: %s.", 
                worker_num, getpid(), error_message);        
        log_error(log_message, log_queue);
        kill(getppid(), SIGTERM);
    }

    packet_buffer *packet = malloc(sizeof(packet_buffer));
    while(keep_working) {
        int bytes = msgrcv(packet_queue, packet, sizeof(packet_buffer), 2, IPC_NOWAIT);
        if (bytes <= 0) {
            usleep(1000);
            continue;
        }

        char results = parse_packet(packet, payload, config, instance, log_queue);
        
        int bytes_sent = write(socket_id, payload, strlen(payload));
        if (bytes_sent < strlen(payload)) {
            log_warning("Incomplete packet delivery.", log_queue);
        }

        read(socket_id, recv_buffer, PACKET_BUFFER_SIZE);
    }
    free(packet);
    free(payload);
    free(recv_buffer);
}
