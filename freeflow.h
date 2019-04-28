#define BUFLEN 4*1024 // Max length of buffer
#define PACKET_BUFFER_SIZE 64*1024

typedef struct msgbuf {
    long mtype;  /* must be positive */
    char packet[BUFLEN];
    int packet_len;
    char sender[16];
} msgbuf;
