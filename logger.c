#include <stdio.h>    /* Provides: printf */
#include <stdlib.h>   /* Provides: exit */
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

void write_log(FILE *fd, char* message) {
        fprintf(fd, "%s\n", message);        
        fflush(fd);
}

void start_logger(char *log_file, int queue_id) {
    FILE *fd;

    if ((fd = fopen(log_file, "a")) == NULL) {
        printf("Couldn't open log file.\n");
        exit(0);
    }
    logbuf *l = malloc(sizeof(logbuf)); 
    while(1) {
        msgrcv(queue_id, l, sizeof(logbuf), 1, 0);
        write_log(fd, l->message);
    }
    free(l);
    fclose(fd);
}
