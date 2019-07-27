#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include "freeflow.h"
#include "config.h"
#include "session.h"
#include "splunk.h"

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
    char *token;
    char delim[2] = " ";
    token = strtok(response, delim);
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
 * Returns:  0          Success
 */
int empty_hec_payload(char* header, hec* server) {
    hec_header(server, 0, header);
    return strlen(header);
}

int test_connectivity(hec_session* session, int worker_num, freeflow_config *config, int log_queue) {
    char payload[PAYLOAD_BUFFER_SIZE];
    char log_message[LOG_MESSAGE_SIZE];
    char error_message[LOG_MESSAGE_SIZE];
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
        sprintf(log_message, "Failed to write all bytes to Splunk HEC during test.", worker_num);
        log_error(log_message, log_queue);
        return -1;
        //kill(getppid(), SIGTERM);
    }
    
    if (header_bytes_read < 0) {
        sprintf(log_message, 
                "Error receiving response from Splunk HEC during test (SSL configuration mismatch?)",
                worker_num);
        log_error(log_message, log_queue);
        return -2;
        //kill(getppid(), SIGTERM);
    }

    int code = response_code(recv_buffer_header);
    if (code < 0) {
        sprintf(log_message, "Received invalid response from Splunk HEC.", worker_num);
        log_error(log_message, log_queue);
        return -3;
        //kill(getppid(), SIGTERM);
    }
    if (code == 403) {
        sprintf(log_message, "Splunk worker #%d unable to authenticate with Splunk.", worker_num);
        log_error(log_message, log_queue);
        return -4;
        //kill(getppid(), SIGTERM);
    }
    return 0;
}
