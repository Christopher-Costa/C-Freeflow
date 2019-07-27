#include <stdio.h>       /* Provides: sprintf */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include "freeflow.h"
#include "config.h"
#include "session.h"
#include "logger.h"
#include "splunk.h"

static int empty_hec_payload(char* header, hec* server);

/*
 * Function: response_code
 *
 * Pull the HTTP response code from an HTTP response and return it as an integer.
 *
 * Inputs:   char*      response_code  HTTP response message
 *
 * Returns:  <response code>  Success
 *           -1               Failure to parse
 */
int response_code(char* response) {
    char* token;
    char delim[2] = " ";
    char token_str[PACKET_BUFFER_SIZE];

    strcpy(token_str, response);
    token = strtok(token_str, delim);
    token = strtok(NULL, delim);
    if (!token) {
        return -1;
    }
    return(atoi(token));
}

/*
 * Function: hec_header
 *
 * Create the HTTP POST header for sending to Splunk HTTP Event
 * Collector.
 *
 * Inputs:   hec*       server          Splunk HEC server object
 *           int        content_length  length of the message being sent
 *           char*      header          Header string
 *
 * Returns:  0          Success
 */
int hec_header(hec* server, int content_length, char* header) {
    char h[500];

    strcpy(h, "POST /services/collector HTTP/1.1\r\n");
    strcat(h, "Host: %s:%d\r\n");
    strcat(h, "User-Agent: freeflow\r\n");
    strcat(h, "Connection: keep-alive\r\n");
    strcat(h, "Authorization: Splunk %s\r\n");
    strcat(h, "Content-Length: %d\r\n\r\n");

    sprintf(header, h, server->addr, server->port, server->token, content_length);
    return 0;
}

/*
 * Function: empty_hec_payload
 *
 * Wrapper to create a 0 length, no payload  HTTP POST header for sending to
 * to start Splunk HTTP Event Collector connection.
 *
 * Inputs:   hec*       server          Splunk HEC server object
 *           char*      header          Header string
 *
 * Returns:  <length of header>  Success
 */
static int empty_hec_payload(char* header, hec* server) {
    hec_header(server, 0, header);
    return strlen(header);
}

/*
 * Function: test_connectivity
 *
 * Called after a session has been established, to verify connectivity to the
 * Splunk HTTP Event Collector.  Send an empty message to verify the expected
 * response code is received.   This serves the purpose of validating that the
 * authentication token is valid, and preventing Splunk from tearing down the
 * session prematurely if no data is sent immediately.
 *
 * Inputs:   hec_session*      session       Object to store session information
 *           int               worker_num    Id of the worker process
 *           freeflow_config*  config        Pointer to configuration object
 *           int               log_queue     Id of IPC queue for logging
 *
 * Returns:  0   Success
 *           -1  Incomplete transmission
 *           -2  Error received when sending transmissionk
 *           -3  Unexpected response code received from Splunk
 *           -4  Authentication failure
 */    
int test_connectivity(hec_session* session, int worker_num, freeflow_config *config, int log_queue) {
    char payload[PAYLOAD_BUFFER_SIZE];
    char log_message[LOG_MESSAGE_SIZE];
    char recv_buffer_header[PACKET_BUFFER_SIZE];
    char recv_buffer_payload[PACKET_BUFFER_SIZE];
    
    /* Send an empty HEC message to prevent Splunk from closing the connection
     * within 40s.  Use the opportunity to validate the authentication token.
     *
     * Responses are received in 2 parts;  The first part is the HTML response
     * header.  The second is JSON encoded payload from Splunk.
     */
    int payload_len = empty_hec_payload(payload, session->hec);
    int bytes_written = session_write(session, payload, payload_len);
    int header_bytes_read = session_read(session, recv_buffer_header, PACKET_BUFFER_SIZE);
    int payload_bytes_read = session_read(session, recv_buffer_payload, PACKET_BUFFER_SIZE);

    if (payload_len != bytes_written) {
        sprintf(log_message, "Worker #%d failed to write all bytes to Splunk HEC during test."
                           , worker_num);
        log_error(log_message, log_queue);
        return -1;
    }
    
    if (header_bytes_read < 0 || payload_bytes_read < 0) {
        sprintf(log_message, 
                "Worker #%d received error response from Splunk HEC during test (SSL mismatch?)",
                worker_num);
        log_error(log_message, log_queue);
        return -2;
    }

    int code = response_code(recv_buffer_header);
    if (code < 0) {
        sprintf(log_message, "Worker #%d received invalid response from Splunk HEC.", worker_num);
        log_error(log_message, log_queue);
        return -3;
    }
    if (code == 403) {
        sprintf(log_message, "Worker #%d unable to authenticate with Splunk.", worker_num);
        log_error(log_message, log_queue);
        return -4;
    }
    return 0;
}
