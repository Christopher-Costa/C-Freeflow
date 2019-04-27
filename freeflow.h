#define BUFLEN 4 * 1024 // Max length of buffer

typedef struct freeflow_config {
    char* bind_addr;
    int bind_port;
    int threads;
    long queue_size;
    char *sourcetype;
    char *hec_token;
    char *hec_server;
    int hec_port;
    char *log_file;
} freeflow_config;

typedef struct msgbuf {
    long mtype;  /* must be positive */
    char packet[BUFLEN];
    int packet_len;
    struct in_addr sender;
} msgbuf;

typedef struct logbuf {
    long mtype;  /* must be positive */
    char message[BUFLEN];
} logbuf;
