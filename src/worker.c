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
#include "session.h"
#include "queue.h"

int keep_working = 1;
int sigpipe_caught = 0;

static void handle_worker_sigterm(int sig);
static void handle_worker_sigpipe(int sig);
static void handle_worker_sigint(int sig);
static int parse_packet(packet_buffer* packet, char* payload, freeflow_config* config, 
                 hec_session* session, int log_queue);

/*
 * Function: parse_packet
 *
 * Receive an IP packet containing netflow records, parse them, and create an
 * HTTP POST message suitable for sending to a Splunk HEC server. 
 *
 * Inputs:   packet_buffer*    server           Packet containing netflow record(s)
 *           char*             payload          String to store HEC payload
 *           freeflow_config*  config           Pointer to configuration object
 *           int               server_instance  Instance # of HEC server to send to
 *           int               log_queue        Id of IPC queue for logging
 *
 * Returns:  0                 Success
 */
static int parse_packet(packet_buffer* packet, char* payload, freeflow_config* config, 
                 hec_session* session, int log_queue) {

    char log_message[LOG_MESSAGE_SIZE];

    // Make sure the size of the packet is sane for netflow.
    if ( (packet->packet_len - 24) % 48 > 0 ){
        log_warning("Invalid netflow packet length", log_queue);
        return 1;
    }

    netflow_header *h = (netflow_header*)packet->packet;

    // Make sure the version field is correct
    if (ntohs(h->version) != 5){
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
     
    if (config->debug) {
        sprintf(log_message, "Packet contains %d records", num_records);
        log_debug(log_message, log_queue);
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

    hec_header(session->hec, (int)strlen(splunk_payload), payload);
    strcat(payload, splunk_payload);
    if (config->debug) {
        sprintf(log_message, "HTTP message of length %d assembled to send to HEC.", strlen(payload));
        log_debug(log_message, log_queue);
    } 
    return 0;
}

/*
 * Function: handle_worker_sigterm
 *
 * Handle SIGTERM signals by toggling the 'keep_listening' variable.  
 * This variable controls the main while loop, and will allow the
 * program to end gracefully and ensure everything is cleaned up properly.
 *
 * Inputs:   int sig        The signal being passed.  Currently unused.
 *
 * Returns:  None
 */
static void handle_worker_sigterm(int sig) {
    keep_working = 0;
}

/*
 * Function: handle_worker_sigpipe
 *
 * Handle SIGPIPE signals by toggling the 'sigpipe_caught' variable.  
 * This variable indicates that a the function sent data to a closed socket, and 
 * for the error handling functions to take appropraite action.
 *
 * Inputs:   int sig        The signal being passed.  Currently unused.
 *
 * Returns:  None
 */
static void handle_worker_sigpipe(int sig) {
    sigpipe_caught = 1;
}
/*
 * Function: handle_worker_sigint
 *
 * Do nothing.  Simply catch the SIGINT and take no action, to allow the 
 * main program to orchestrate the cleanup among all processes.
 *
 * Inputs:   int sig        The signal being passed.  Currently unused.
 *
 * Returns:  None
 */
static void handle_worker_sigint(int sig) {}

/*
 * Function: splunk_worker
 *
 * The main function of a worker process.  This routine tests connectivity
 * to Splunk HEC, and validates the authentication credentials.  If
 * successful, it will continually poll an IPC message queue looking for
 * new netflow packets, parse them, and then send to HEC.  This process
 * continues indefinitely until receiving a SIGTERM.
 *
 * Inputs:   int               worker_num  Id of this worker process
 *           freeflow_config*  config      Configuration object
 *           int               log_queue   Id of the IPC message queue to
 *                                         send logs to.
 *
 * Returns:  0          Success
 */
int splunk_worker(int worker_num, freeflow_config *config, int log_queue) {
    signal(SIGTERM, handle_worker_sigterm);
    signal(SIGINT, handle_worker_sigint);
    signal(SIGPIPE, handle_worker_sigpipe);

    char log_message[LOG_MESSAGE_SIZE];
    char error_message[LOG_MESSAGE_SIZE];
    char recv_buffer_header[PACKET_BUFFER_SIZE];
    char recv_buffer_payload[PACKET_BUFFER_SIZE];
    char payload[PAYLOAD_BUFFER_SIZE];

    hec_session session;

    if ((initialize_session(&session, worker_num, config, log_queue)) < 0 ) {;
        kill(getppid(), SIGTERM);
    }

    if ((test_connectivity(&session, worker_num, config, log_queue)) < 0 ) {
        kill(getppid(), SIGTERM);
    }

    sprintf(log_message, "Splunk worker #%d [PID %d] started.", worker_num, getpid());
    log_info(log_message, log_queue);

    int packet_queue = create_queue(config->config_file, PACKET_QUEUE, error_message, config->queue_size);
    if (packet_queue < 0) {
        sprintf(log_message, 
                "Splunk worker #%d [PID %d] unable to open packet queue: %s.", 
                worker_num, getpid(), error_message);        
        log_error(log_message, log_queue);
        kill(getppid(), SIGTERM);
    }

    packet_buffer packet;
    while(keep_working) {
        /* If there are no messages in the queue, don't wait for one to
         * arrive.  This is to give an opportunity for the loop to be 
         * broken by a SIGTERM.  If the queue was empty, sleep for 0.01s
         * to prevent the CPU from saturating. */  
        int bytes = msgrcv(packet_queue, &packet, sizeof(packet), 2, IPC_NOWAIT);
        if (bytes <= 0) {
            usleep(1000);
            continue;
        }

        if (config->debug){
            sprintf(log_message, "Worker #%d accepted packet from queue", worker_num);
            log_debug(log_message, log_queue);
        }
        int results = parse_packet(&packet, payload, config, &session, log_queue);

        int bytes_sent = session_write(&session, payload, strlen(payload));

        if (bytes_sent < strlen(payload)) {
            log_warning("Worker #%d Incomplete packet delivery.", worker_num,log_queue);
        }
        else if (config->debug) {
            sprintf(log_message,"Worker #%d delivered packet to HEC [%s]."
                               , worker_num, session.hec->addr);
            log_debug(log_message, log_queue);
        }

        int bytes_read_header = session_read(&session, recv_buffer_header, PACKET_BUFFER_SIZE);

        /* If a SIGPIPE was signalled, or no bytes were read, we may have a problem . */
        if ((bytes_read_header <= 0) || (sigpipe_caught)) {
            int retry_count = 1;
            while (keep_working && ((bytes_read_header <= 0) || (sigpipe_caught))) {
                int status = session_status(&session, error_message);

                /* If the session is still up, keep trying */
                if ((status == 0) && !(sigpipe_caught)) {
                    sprintf(log_message, "Worker #%d received no response from HEC.  Retrying [#%d]."
                                       , worker_num, retry_count);
                    log_warning(log_message, log_queue);

                    sleep(1);
                    bytes_read_header = session_read(&session, recv_buffer_header, PACKET_BUFFER_SIZE);
                    retry_count++;
                }
                
                /* If it isn't, requeue the packet so it may be delivered by another worker */
                else {
                    if (sigpipe_caught) {
                        strcpy(error_message, "Not connected");
                    }
                    sprintf(log_message, "Worker #%d HEC socket error: %s.", worker_num, error_message);
                    log_warning(log_message, log_queue);                

                    sprintf(log_message, "Worker #%d requeuing undelivered packet.", worker_num);
                    log_info(log_message, log_queue); 
                    msgsnd(packet_queue, &packet, sizeof(packet_buffer), 0);

                    sprintf(log_message, "Worker #%d attempting to reestablish connection to HEC.", worker_num);
                    log_info(log_message, log_queue); 
                    reestablish_session(&session, worker_num, config, log_queue);

                    sprintf(log_message, "Worker #%d reestablish connection to HEC.  Reentering service."
                                       , worker_num);
                    log_info(log_message, log_queue); 
                    break;
                }
            }
            sigpipe_caught = 0;
            continue;
        }

        int code = response_code(recv_buffer_header);

        /* If Splunk returns an error, requeue the packet for future delivery and take this worker
         * out of service for 10s to see if the problem clears.
         */
        if (code != 200) {
            sprintf(log_message, "Worker #%d received error writing to HEC [%d]."
                               , worker_num, code);
            log_warning(log_message, log_queue);

            sprintf(log_message, "Worker #%d requeuing undelivered packet.", worker_num);
            log_info(log_message, log_queue); 
            msgsnd(packet_queue, &packet, sizeof(packet_buffer), 0);
            
            sleep(10);
            sprintf(log_message, "Worker #%d reentering service.", worker_num);
            log_info(log_message, log_queue);
        }

        int bytes_read_payload = session_read(&session, recv_buffer_payload, PACKET_BUFFER_SIZE);
    }
    
    close(session.socket_id);

    return 0;
}
