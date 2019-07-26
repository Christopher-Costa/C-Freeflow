#include <stdio.h>       /* Provides: sprintf */
#include <stdlib.h>      /* Provides: malloc, free, exit */
#include <string.h>      /* Provides: strcpy, strcat, memcpy */
#include <netdb.h>       /* Provides: gethostbyname */
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "freeflow.h"
#include "config.h"

static SSL_CTX* initialize(void);

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
static SSL_CTX* initialize(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();      /* Load cryptos, et.al. */
    SSL_load_error_strings();          /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);         /* Create new context */

    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}
