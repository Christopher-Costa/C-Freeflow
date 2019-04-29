#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <netinet/tcp.h>
#include "config.h"

int connect_socket(int worker_num, freeflow_config *config, int log_queue) {
    struct sockaddr_in addr;
    struct hostent *host;
    int socket_id;

    if((socket_id = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        logger("Error opening socket.", log_queue);
        return -1;
    }

    int yes = 1;
    setsockopt(socket_id, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));

    int idle = 60;
    setsockopt(socket_id, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int));

    int interval = 60;
    setsockopt(socket_id, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int));
 
    addr.sin_family = AF_INET;

    host = gethostbyname(config->hec_server);
    if(host == NULL) {
        logger("%s unknown host.", config->hec_server);
        return -1;
    }

    bcopy(host->h_addr, &addr.sin_addr, host->h_length);
    addr.sin_port = htons(config->hec_port);
    connect(socket_id, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)); 

    return(socket_id);
}

int bind_socket(int log_queue, freeflow_config *config) {
    struct sockaddr_in si_me;
    struct sockaddr_in si_other;
    
    int socket_id;
    
    //create a UDP socket
    if ((socket_id = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        logger("Couldn't open local socket for netflow.", log_queue);
        exit(1);
    }
    
    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));
    
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(config->bind_port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    
    //bind socket to port
    if (bind(socket_id, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
        logger("Couldn't bind local socket for netflow.", log_queue);
        exit(1);
    }

    logger("Socket bound and listening", log_queue);
    return(socket_id);
}
