#include <stdio.h>       /* Provides: sprintf */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include "freeflow.h"
#include "config.h"
#include "ssl.h"

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
SSL* ssl_initialize(int socket_id, int log_queue) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    char log_message[LOG_MESSAGE_SIZE];
    char ssl_error[120];
 
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);

    if ( ctx == NULL )
    {
        ERR_error_string(ERR_get_error(), ssl_error);
        sprintf(log_message, "SSL Error: ");
        strcat(log_message, ssl_error);
        log_error(log_message, log_queue);
        return NULL;        
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket_id);
    if ( SSL_connect(ssl) == -1 ) {
        ERR_error_string(ERR_get_error(), ssl_error);
        sprintf(log_message, "SSL Error: ");
        strcat(log_message, ssl_error);
        log_error(log_message, log_queue);
        return NULL;        
    }
    return ssl;
}
