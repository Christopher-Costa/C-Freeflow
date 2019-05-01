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

// This is global by design, so a signal handler can
// access it.
int log_queue;
int number_of_workers;
pid_t *worker_children;
pid_t logger_pid;

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
    return 0;
}

void handle_parent_sigterm(int sig) {
    int i;
    char log_message[128];
    for (i = 0; i < number_of_workers; ++i) {
        sprintf(log_message, "Terminating Splunk worker #%d [PID %d].", i, worker_children[i]);
        logger(log_message, log_queue);
        kill(worker_children[i], SIGTERM);
    }
    sprintf(log_message, "Terminating logging process [PID %d].", logger_pid);
    logger(log_message, log_queue);

    kill(logger_pid, SIGTERM);
    exit(0);
}

void handle_parent_sigint(int sig) {
    int i;
    char log_message[128];
    for (i = 0; i < number_of_workers; ++i) {
        kill(worker_children[i], SIGTERM);
    }

    kill(logger_pid, SIGTERM);
    exit(0);
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
    log_queue = create_queue(config->config_file, PACKET_QUEUE);

    if ((logger_pid = fork()) == 0) {
        start_logger(config->log_file, log_queue);
        exit(0);
    }

    number_of_workers = config->threads;
    worker_children = malloc(sizeof(pid_t) * number_of_workers);
    for (i = 0; i < config->threads; ++i) {
        if ((worker_children[i] = fork()) == 0) {
            splunk_worker(i + 1, config, log_queue);
            exit(0);
        }
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, handle_parent_sigterm);
    signal(SIGINT, handle_parent_sigint);

    receive_packets(log_queue, config);
    free(config);
    free(worker_children);
}
