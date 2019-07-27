#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <errno.h>
#include <netinet/tcp.h>
#include "freeflow.h"
#include "config.h"
#include "session.h"

static int ssl_initialize(hec_session* session, int worker_num, freeflow_config* config, int log_queue);
static int enable_keepalives(int socket_id, char* error);
static int connect_socket(hec_session* session, int worker_num, freeflow_config *config, int log_queue);

/*
 * Function: ssl_initialize
 *
 * Initialize an SSL session over an open TCP socket.  Return
 * the session handle if successful, and NULL otherwise.
 *
 * Inputs:   int   socket_id    Id of the socket
 *           int   log_queue    Id of IPC queue for logging
 *
 * Returns:  <SSL object>     Success
 *           NULL             Failure
 */
static int ssl_initialize(hec_session* session, int worker_num, freeflow_config* config, int log_queue) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    char log_message[LOG_MESSAGE_SIZE];
    char ssl_error[120];

    session->is_ssl = 1;
 
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);

    if ( ctx == NULL )
    {
        ERR_error_string(ERR_get_error(), ssl_error);
        sprintf(log_message, "Worker #%d SSL Error: ", worker_num);
        strcat(log_message, ssl_error);
        log_error(log_message, log_queue);
        return -1;        
    }
    else if (config->debug){
        sprintf(log_message, "Worker #%d SSL initialized using TLS 1.2 method.", worker_num);
        log_debug(log_message, log_queue);
    }

    session->ssl_session = SSL_new(ctx);
    SSL_set_fd(session->ssl_session, session->socket_id);
    if ( SSL_connect(session->ssl_session) == -1 ) {
        ERR_error_string(ERR_get_error(), ssl_error);
        sprintf(log_message, "Worker #%d SSL Error: ", worker_num);
        strcat(log_message, ssl_error);
        log_error(log_message, log_queue);
        return -2;        
    }
    else if (config->debug){
        sprintf(log_message, "Worker #%d SSL is connected over socket #%d.", worker_num, session->socket_id);
        log_debug(log_message, log_queue);
    }
    
    return 0;
}

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
 * using information in the configuration object.  Return an error 
 * if unsuccessful.
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
 *           -5             Couldn't enable recv timeout
 */
static int connect_socket(hec_session* session, int worker_num, freeflow_config *config, int log_queue) {
    struct sockaddr_in addr;
    struct hostent *host;
    char log_message[LOG_MESSAGE_SIZE];
    char error_message[LOG_MESSAGE_SIZE];

    if((session->socket_id = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        sprintf(log_message, "Error opening socket: %s", strerror(errno));
        log_error(log_message, log_queue);
        return -1;
    }

    if (enable_keepalives(session->socket_id, error_message) < 0) {
        sprintf(log_message, "Unable to enable keepalives on socket: %s", error_message);
        log_error(log_message, log_queue);
        return -2;
    }

    /* TODO:  This should be in a separate function */
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (setsockopt(session->socket_id, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        sprintf(log_message, "Unable to enable keepalives on socket: %s", error_message);
        log_error(log_message, log_queue);
        return -5;
    }

    addr.sin_family = AF_INET;

    int hec_instance = worker_num % config->num_servers;
    int   hec_port = config->hec_server[hec_instance].port;
    char* hec_addr = config->hec_server[hec_instance].addr;
    session->hec = &config->hec_server[hec_instance];

    host = gethostbyname(hec_addr);
    if(host == NULL) {
        sprintf(log_message, "Unknown host: %s.", hec_addr);
        log_error(log_message, log_queue);
        return -3;
    }

    bcopy(host->h_addr, &addr.sin_addr, host->h_length);
    addr.sin_port = htons(hec_port);
    if (connect(session->socket_id, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) < 0) {
        sprintf(log_message, "Worker #%d couldn't connect to %s:%d: %s."
                           , worker_num, hec_addr, hec_port, strerror(errno));
        log_error(log_message, log_queue);
        return -4;
    } 
    else if (config->debug) {
        sprintf(log_message, "Worker #%d TCP socket [%d] connected to %s:%d."
                           , worker_num, session->socket_id, hec_addr, hec_port);
        log_debug(log_message, log_queue);
    }
        

    sprintf(log_message, "Worker #%d connected to HEC %s:%d", worker_num, hec_addr, hec_port);
    log_info(log_message, log_queue);

    return 0;
}

/*
 * Function: bind_socket
 *
 * Initialize and bind a UDP socket for receiving Netflow using information 
 * passed in the configuration object.  Return an error if unsuccessful.
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
    
    int result;
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
    result = setsockopt(socket_id, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if (result < 0) {
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

/*
 * Function: initialize_session
 *
 * Initialize either a normal TCP or SSL connection to a Splunk HTTP Event Collector
 * based on the information in the configuration object.  Return an error
 * if unsuccessful.
 *
 * Inputs:   hec_session*     session       Object to store session information
 *           int              worker_num    Id of the worker process
 *           freeflow_config* config*       Configuration object
 *           int              log_queue     Id of IPC queue for logging
 *
 * Returns:  0    Success
 *           -1   Couldn't create socket object
 *           -2   Couldn't initialize SSL
 */
int initialize_session(hec_session* session, int worker_num, freeflow_config *config, int log_queue) {
    char log_message[LOG_MESSAGE_SIZE];

    if ((connect_socket(session, worker_num, config, log_queue)) < 0) {
        return -1;        
    }

    if (config->ssl_enabled == 1) {
        if ((ssl_initialize(session, worker_num, config, log_queue)) < 0) {
            sprintf(log_message, "Worker #%d can't establish SSL connection with Splunk.", worker_num);
            log_error(log_message, log_queue);
            return -2;
        }
    }
    return 0;
}

/*
 * Function: reestablish_session
 *
 * Attempt to reinitialize a Splunk HTTP Event Collector session that failed during
 * the program's operations.  This process will attempt to establish a new connection
 * every 10s indefinitely, effectively blocking the calling process until the condition 
 * clears.
 *
 * Inputs:   hec_session*     session       Object to store session information
 *           int              worker_num    Id of the worker process
 *           freeflow_config* config*       Configuration object
 *           int              log_queue     Id of IPC queue for logging
 *
 * Returns:  0    Success
 */
int reestablish_session(hec_session* session, int worker_num, freeflow_config *config, int log_queue) {
    char log_message[LOG_MESSAGE_SIZE];
    int result;

    do {
        sleep(10);
        result = initialize_session(session, worker_num, config, log_queue);
    } while (result != 0);

    return 0;
}

/*
 * Funtion: session_read
 *
 * Wrapper function to call the appropiate socket or SSL read function
 * for this particular session.  Sets the message variable with the
 * message read.
 *
 * Inputs:   hec_session*  session       Object to store session information
 *           char*         message       Message read from the session
 *           int           message_len   Size of the message object
 *
 * Returns:  <number of bytes read>   Success
 *           <negative integer>       Failure
 */
int session_read(hec_session* session, char* message, int message_len) {
    memset(message, 0, message_len);

    if (session->is_ssl) {
        return SSL_read(session->ssl_session, message, message_len);
    }
    else {
        return read(session->socket_id, message, message_len);
    }
}

/*
 * Funtion: session_write
 *
 * Wrapper function to call the appropiate socket or SSL write function
 * for this particular session.  Sends the bytes set in the message
 * variable.
 *
 * Inputs:   hec_session*  session       Object to store session information
 *           char*         message       Message read from the session
 *           int           message_len   Size of the message object
 *
 * Returns:  <number of bytes sent>   Success
 * Returns:  <negative integer>       Failure
 */
int session_write(hec_session* session, char* message, int message_len) {
    if (session->is_ssl) {
        return SSL_write(session->ssl_session, message, message_len);
    }
    else {
        return write(session->socket_id, message, message_len);
    }
}

/*
 * Funtion: session_status
 *
 * Wrapper function to call the appropiate socket or SSL read function
 * for this particular session.
 *
 * Inputs:   hec_session*  session         Object to store session information
 *           char*         error_message   Error message, if any
 *
 * Returns:  0                   No error
 * Returns:  <negative integer>  Error code
 */
int session_status(hec_session* session, char* error_message) {
    int error = 0;
    socklen_t len = sizeof(error);
    int result = getsockopt (session->socket_id, SOL_SOCKET, SO_ERROR, &error, &len);
    
    if (result != 0) {
        sprintf(error_message, "Unabled to get status of session");
        return result;
    }

    if (error != 0) {
        sprintf(error_message, "%s",  strerror(error));
    }
    return error;
}
