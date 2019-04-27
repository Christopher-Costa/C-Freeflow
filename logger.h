//#include "config.h"

#define LOGBUF 4096

void logger(char* message, int queue_id);
void start_logger(char* filename, freeflow_config config, int queue_id);

typedef struct logbuf {
    long mtype;  /* must be positive */
    char message[LOGBUF];
} logbuf;
