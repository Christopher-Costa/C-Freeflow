#include <stdio.h>    /* Provides: printf */
#include <string.h>   /* Provides: strcpy */
#include <sys/msg.h>  /* Provides: ftok */
#include "freeflow.h"
#include "logger.h"

void logger(char* message, int queue_id) {
    logbuf log_message;
    log_message.mtype = 1;
    strcpy(log_message.message, message);

    if (queue_id > 0) {
        msgsnd(queue_id, &log_message, sizeof(logbuf), 0);
    }
}

void start_logger(char* filename, freeflow_config config, int queue_id) {
    while(1) {
        logbuf l;
        msgrcv(queue_id, &l, sizeof(logbuf), 1, 0);
        printf("Logger: %s\n", l.message);        
    }
}
