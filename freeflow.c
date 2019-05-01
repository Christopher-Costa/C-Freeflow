#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <arpa/inet.h>   /* Provides: inet_ntoa */
#include <signal.h>
#include "freeflow.h"
#include "netflow.h"
#include "config.h"
#include "socket.h"
#include "queue.h"
#include "worker.h"

// This is global by design, so a signal handler can access it.
int keep_working = 1;

int receive_packets(int log_queue, freeflow_config *config) {
    char packet[PACKET_BUFFER_SIZE];
    int socket_id = bind_socket(log_queue, config);
    int packet_queue = create_queue(config->config_file, LOG_QUEUE);

    struct sockaddr_in *sender = malloc(sizeof(struct sockaddr));;
    int socket_len = sizeof(*sender);

    packet_buffer message;
    message.mtype = 2;

    //keep listening for data
    while(keep_working) {
        int bytes_recv;
        bytes_recv = recvfrom(socket_id, packet, PACKET_BUFFER_SIZE, 0, 
                              (struct sockaddr*)sender, &socket_len);

        if (bytes_recv > 0) {
            message.packet_len = bytes_recv;
            strcpy(message.sender, inet_ntoa(sender->sin_addr));
            memcpy(message.packet, packet, bytes_recv);
            msgsnd(packet_queue, &message, sizeof(packet_buffer), 0); 
        }
    }

    free(sender);
    close(socket_id);
    delete_queue(packet_queue);
    return 0;
}

void handle_signal(int sig) {
    keep_working = 0;
}

void clean_up(freeflow_config* config, pid_t workers[], pid_t logger_pid, int log_queue) {
    char log_message[128];

    int i;
    for (i = 0; i < config->threads; ++i) {
        sprintf(log_message, "Terminating Splunk worker #%d [PID %d].", i, workers[i]);
        logger(log_message, log_queue);
        kill(workers[i], SIGTERM);
    }

    sprintf(log_message, "Terminating logging process [PID %d].", logger_pid);
    logger(log_message, log_queue);
    kill(logger_pid, SIGTERM);
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
    int log_queue = create_queue(config->config_file, PACKET_QUEUE);

    pid_t logger_pid;
    if ((logger_pid = fork()) == 0) {
        start_logger(config->log_file, log_queue);
        exit(0);
    }

    int workers[config->threads];
    for (i = 0; i < config->threads; ++i) {
        if ((workers[i] = fork()) == 0) {
            splunk_worker(i + 1, config, log_queue);
            exit(0);
        }
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    receive_packets(log_queue, config);

    clean_up(config, workers, logger_pid, log_queue);
    free(config);
}
