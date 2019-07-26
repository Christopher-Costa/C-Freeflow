#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <errno.h>
#include <netinet/tcp.h>
#include "freeflow.h"
#include "config.h"

static int enable_keepalives(int socket_id, char* error);

/*
 * Function: enable_keepalives
 *
 * Enable keepalives on a socket object.  Set 'error' if
 * unsuccessful. 
 *
 * Inputs:   int   socket_id    Id of the socket
 *           char* error        Error string, if operation fails
 *
 * Returns:  0     Success
 *           -1    Couldn't enable keepalives
 *           -2    Couldn't set idle time
 *           -3    Couldn't set interval
 */
static int enable_keepalives(int socket_id, char* error) {
    int rc;

    int yes = 1;
    rc = setsockopt(socket_id, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));
    if (rc < 0) {
        sprintf(error, "Unable to enable TCP keepalive: %s", strerror(errno));
        return -1;
    }
    int idle = 60;
    rc = setsockopt(socket_id, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));
    if (rc < 0) {
        sprintf(error, "Unable to enable TCP idle time: %s", strerror(errno));
        return -2;
    }

    int interval = 60;
    rc = setsockopt(socket_id, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));
    if (rc < 0) {
        sprintf(error, "Unable to enable TCP keepalive interval: %s", strerror(errno));
        return -3;
    }
    
    return 0;
}

/*
 * Function: connect_socket
 *
 * Initialize and establish a TCP connection to a Splunk HTTP Event Collector
 * using information in the 'config' object.  Return an error if unsuccessful.
 *
 * Inputs:   int              worker_num    Id of the worker process
 *           freeflow_config* config*       Configuration object
 *           int              log_queue     Id of IPC queue for logging
 *
 * Returns:  <socket id>    Success
 *           -1             Couldn't create socket object
 *           -2             Couldn't enable keepalives
 *           -3             Unable to gethostbyname
 *           -4             Couldn't connect to server
 */
int connect_socket(int worker_num, freeflow_config *config, int log_queue) {
    struct sockaddr_in addr;
    struct hostent *host;
    char log_message[LOG_MESSAGE_SIZE];
    char error_message[LOG_MESSAGE_SIZE];
    int socket_id;

    if((socket_id = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        sprintf(log_message, "Error opening socket: %s", strerror(errno));
        log_error(log_message, log_queue);
        return -1;
    }

    if (enable_keepalives(socket_id, error_message) < 0) {
        sprintf(log_message, "Unable to enable keepalives on socket: %s", error_message);
        log_error(log_message, log_queue);
        return -2;
    }

    addr.sin_family = AF_INET;

    int   hec_instance = worker_num % config->num_servers;
    int   hec_port = config->hec_server[hec_instance].port;
    char* hec_addr = config->hec_server[hec_instance].addr;

    host = gethostbyname(hec_addr);
    if(host == NULL) {
        sprintf(log_message, "Unknown host: %s.", hec_addr);
        log_error(log_message, log_queue);
        return -3;
    }

    bcopy(host->h_addr, &addr.sin_addr, host->h_length);
    addr.sin_port = htons(hec_port);
    if (connect(socket_id, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) < 0) {
        sprintf(log_message, "Couldn't connect to %s:%d: %s.", hec_addr, hec_port,
                                                               strerror(errno));
        log_error(log_message, log_queue);
        return -4;
    } 

    sprintf(log_message, 
            "Worker #%d connected to HEC %s:%d", 
            worker_num , hec_addr , hec_port);
    log_info(log_message, log_queue);
    return(socket_id);
}

/*
 * Function: bind_socket
 *
 * Initialize and bind a UDP socket for receiving Netflow using information 
 * passed in the 'config' object.  Return an error if unsuccessful.
 *
 * Inputs:   freeflow_config* config*       Configuration object
 *           int              log_queue     Id of IPC queue for logging
 *
 * Returns:  <socket id>    Success
 *           -1             Couldn't create socket object
 *           -2             Couldn't enable keepalives
 *           -3             Couldn't bind local socket
 */
int bind_socket(freeflow_config *config, int log_queue) {
    struct sockaddr_in si_me;
    struct sockaddr_in si_other;
    char log_message[LOG_MESSAGE_SIZE];
    
    int rc;
    int socket_id;
    
    if ((socket_id = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        sprintf(log_message, "Couldn't open UDP socket for netflow: %s", strerror(errno));
        log_error(log_message, log_queue);
        return -1;
    }

    /* Set a receive timeout of 1s so the main worker loop doesn't 
     * block indefinitely */
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    rc = setsockopt(socket_id, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if (rc < 0) {
        sprintf(log_message, "Unable to set socket receive timeout: %s", strerror(errno));
        log_error(log_message, log_queue);
        return -2;
    }
    
    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(config->bind_port);
    si_me.sin_addr.s_addr = inet_addr(config->bind_addr);
    
    if (bind(socket_id, (struct sockaddr *)&si_me, sizeof(si_me)) < 0) {
        sprintf(log_message, "Couldn't bind local socket %s:%d: %s", config->bind_addr, 
                                                                     config->bind_port,
                                                                     strerror(errno));
        log_error(log_message, log_queue);
        return -3;
    }

    sprintf(log_message, "Socket bound and listening on %s:%d.", config->bind_addr,
                                                                 config->bind_port);
    log_info(log_message, log_queue);
    return(socket_id);
}
