#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <arpa/inet.h>   /* Provides: inet_ntoa */
#include <signal.h>      /* Provides: signal */
#include "freeflow.h"
#include "netflow.h"
#include "config.h"
#include "session.h"
#include "queue.h"
#include "worker.h"

static int keep_listening = 1;

static void handle_signal(int sig);
static int receive_packets(int log_queue, freeflow_config *config);
static void handle_signal(int sig);
static void clean_up(freeflow_config* config, pid_t workers[], pid_t logger_pid, int log_queue);

/*
 * Function: handle_signal
 *
 * Handle SIGINT and SIGTERM signals by setting toggling the 'keep_listening'
 * variable.  This variable controls the main while loop, and will allow the
 * program to end gracefully and ensure everything is cleaned up properly.
 *
 * Inputs:   int sig        The signal being passed.  Currently unused.
 *
 * Returns:  None
 */
static void handle_signal(int sig) {
    keep_listening = 0;
}

/*
 * Function: receive_packets
 *
 * Bind a receive UDP socket and continue pulling packets off the wire until
 * the program is terminated.  Packets are placed into an IPC message queue
 * for one of the worker processes to handle.
 *
 * Inputs:  int             log_queue    The signal being passed.
 *          freeflow_config *config      Pointer to the configuration object. 
 * 
 * Return:  0   Success
 *          -1  Couldn't bind to socket
 *          -2  Couldn't create IPC packet queue
 */
static int receive_packets(int log_queue, freeflow_config *config) {
    char log_message[LOG_MESSAGE_SIZE];
    char error_message[LOG_MESSAGE_SIZE];
    char packet[PACKET_BUFFER_SIZE];

    int socket_id;
    if ((socket_id = bind_socket(config, log_queue)) < 0) {
        sprintf(log_message, "bind_socket returned error: %d.", socket_id);
        log_error(log_message, log_queue);
        return -1;
    }
        
    int packet_queue = create_queue(config->config_file, PACKET_QUEUE, error_message, 0);
    if (packet_queue < 0) {
        sprintf(log_message, "Unable to create IPC queue for packets: %s.", error_message);        
        log_error(log_message, log_queue);
        return -2;
    }
    else if (config->debug) {
        sprintf(log_message, "Created IPC queue [%d] for packets.", packet_queue);        
        log_debug(log_message, log_queue);
    }

    struct sockaddr_in sender;
    int socket_len = sizeof(sender);

    packet_buffer message;
    message.mtype = 2;

    /* Continue receiving packets until signalled to stop */
    while(keep_listening) {
        int bytes_recv;
        bytes_recv = recvfrom(socket_id, packet, PACKET_BUFFER_SIZE, 0, 
                              (struct sockaddr*)&sender, &socket_len);
        if (bytes_recv > 0) {
            if (config->debug) {
                char s[IPV4_ADDR_SIZE];
                strcpy(s, inet_ntoa(sender.sin_addr));
                sprintf(log_message, "Netflow packet received from %s.", s);
                log_debug(log_message, log_queue);
            }
            message.packet_len = bytes_recv;
            strcpy(message.sender, inet_ntoa(sender.sin_addr));
            memcpy(message.packet, packet, bytes_recv);
            msgsnd(packet_queue, &message, sizeof(packet_buffer), 0); 
            if (config->debug) {
                sprintf(log_message, "Packet sent to packet queue [%d].", packet_queue);
                log_debug(log_message, log_queue);
            }
        }
    }

    close(socket_id);
    delete_queue(packet_queue);
    return 0;
}

/*
 * Function: clean_up_processes
 *
 * Gracefully iterate through all working and logging processes, terminate
 * them and waiting for them to exit gracefully.
 *
 * Inputs:  freeflow_config *config      Pointer to the configuration object. 
 *          pid_t           workers[]    Array of worker process PIDs
 *          pit_t           logger_pid   PID of the loggere process
 *          int             log_queue    Id of the IPC logging queue
 * 
 * Return:  None
 */
static void clean_up_processes(freeflow_config* config, pid_t workers[], 
                               pid_t logger_pid, int log_queue) {

    char log_message[LOG_MESSAGE_SIZE];

    int i, status;
    for (i = 0; i < config->threads; ++i) {
        sprintf(log_message, "Terminating Splunk worker #%d [PID %d].", i, workers[i]);
        log_info(log_message, log_queue);
        kill(workers[i], SIGTERM);
        waitpid(workers[i], &status, 0);
    }

    sprintf(log_message, "Terminating logging process [PID %d].", logger_pid);
    log_info(log_message, log_queue);
    kill(logger_pid, SIGTERM);
    waitpid(logger_pid, &status, 0);
}

/*
 * Function: main
 *
 * Initialize the program by reading and processing the command line arguments 
 * and the program configuration file, fork additional processes to handle 
 * logging and packet processing and transmission to Splunk.  The main process 
 * will handle send and receive functions for the Netflow UDP socket.
 * 
 * Return:  0   Success
 * Return:  -1  Unable to create IPC log queue
 */
int main(int argc, char** argv) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    char log_message[LOG_MESSAGE_SIZE];
    char error_message[LOG_MESSAGE_SIZE];
    freeflow_config config;

    parse_command_args(argc, argv, &config);
    read_configuration(&config);

    int i;
    int log_queue;
    if ((log_queue = create_queue(config.config_file, LOG_QUEUE, error_message, 0)) < 0) {
        sprintf(log_message, "Unable to create IPC queue for logging: %s.", error_message);        
        log_error(log_message, log_queue);
        return -1;
    }

    pid_t logger_pid;
    if ((logger_pid = fork()) == 0) {
        start_logger(config.log_file, log_queue);
        exit(0);
    }

    int workers[config.threads];
    for (i = 0; i < config.threads; ++i) {
        if ((workers[i] = fork()) == 0) {
            splunk_worker(i, &config, log_queue);
            exit(0);
        }
    }

    receive_packets(log_queue, &config);

    clean_up_processes(&config, workers, logger_pid, log_queue);
}
