#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <signal.h>
#include <errno.h>
#include <netinet/tcp.h>
#include "config.h"

int connect_socket(int worker_num, freeflow_config *config, int log_queue) {
    struct sockaddr_in addr;
    struct hostent *host;
    char log_message[128];
    int socket_id;

    if((socket_id = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_error("Error opening socket.", log_queue);
        return -1;
    }

    int yes = 1;
    setsockopt(socket_id, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));

    int idle = 60;
    setsockopt(socket_id, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));

    int interval = 60;
    setsockopt(socket_id, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));
 
    addr.sin_family = AF_INET;

    int   hec_instance = worker_num % config->num_servers;
    int   hec_port = config->hec_server[hec_instance].port;
    char* hec_addr = config->hec_server[hec_instance].addr;

    host = gethostbyname(hec_addr);
    if(host == NULL) {
        sprintf(log_message, "%s unknown host.", hec_addr);
        log_error(log_message, log_queue);
        return -1;
    }

    bcopy(host->h_addr, &addr.sin_addr, host->h_length);
    addr.sin_port = htons(hec_port);
    if (connect(socket_id, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) < 0) {
        sprintf(log_message, "Couldn't connect to %s:%d: %s.", hec_addr, hec_port,
                                                               strerror(errno));
        log_error(log_message, log_queue);
        return(-1);
    } 

    sprintf(log_message, "Worker #%d connected to HEC %s:%d", worker_num
                                                            , hec_addr
                                                            , hec_port);
    log_info(log_message, log_queue);
    return(socket_id);
}

int bind_socket(int log_queue, freeflow_config *config) {
    struct sockaddr_in si_me;
    struct sockaddr_in si_other;
    char log_message[128];
    
    int socket_id;
    
    //create a UDP socket
    if ((socket_id = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        log_error("Couldn't open UDP socket for netflow.", log_queue);
        kill(getpid(), SIGTERM);
    }

    // Set the socket to recv timeout after 1s
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(socket_id, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));
    
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(config->bind_port);
    //si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    si_me.sin_addr.s_addr = inet_addr(config->bind_addr);
    
    //bind socket to port
    if (bind(socket_id, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
        sprintf(log_message, "Couldn't bind local socket %s:%d.", config->bind_addr, 
                                                                  config->bind_port);
        log_error(log_message, log_queue);
        kill(getpid(), SIGTERM);
    }

    sprintf(log_message, "Socket bound and listening on %s:%d.", config->bind_addr,
                                                                 config->bind_port);
    log_info(log_message, log_queue);
    return(socket_id);
}
