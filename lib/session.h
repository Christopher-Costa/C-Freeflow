#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct hec_session {
    int  is_ssl;
    int  socket_id;
    SSL* ssl_session;
    hec* hec;
} hec_session;

int bind_socket(freeflow_config *config, int log_queue);

int initialize_session(hec_session* session, int worker_num, freeflow_config* config, int log_queue);
int reestablish_session(hec_session* session, int worker_num, freeflow_config *config, int log_queue);

int session_write(hec_session* session, char* message, int message_len);
int session_read(hec_session* session, char* message, int message_len);
int session_status(hec_session* session, char* error_message);
