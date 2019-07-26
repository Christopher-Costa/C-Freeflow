#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <errno.h>
#include "freeflow.h"
#include "config.h"
#include "ssl.h"

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
SSL* ssl_initialize(int socket_id, int log_queue) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    char log_message[LOG_MESSAGE_SIZE];
    char ssl_error[120];
 
    SSL_library_init();
    OpenSSL_add_all_algorithms();      /* Load cryptos, et.al. */
    SSL_load_error_strings();          /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);         /* Create new context */

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
