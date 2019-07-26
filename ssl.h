#include <openssl/ssl.h>
#include <openssl/err.h>

SSL* ssl_initialize(int socket_id, int log_queue);
