#include <stdio.h>    /* Provides: printf */
#include <stdlib.h>   /* Provides: exit */
#include <string.h>   /* Provides: strcpy */
#include <time.h>     /* Provides: time_t */
#include <sys/msg.h>  /* Provides: ftok */
#include <signal.h>
#include "freeflow.h"
#include "logger.h"

void set_current_time(char* current_time) {
    time_t now;
    time(&now);
    struct tm *time_info = malloc(sizeof(struct tm));
    time_info = localtime(&now);
    sprintf(current_time, "%4d/%02d/%02d %02d:%02d:%02d", time_info->tm_year + 1900,
                                                          time_info->tm_mon + 1,
                                                          time_info->tm_mday,
                                                          time_info->tm_hour,
                                                          time_info->tm_min,
                                                          time_info->tm_sec);
}

void handle_signal(int sig) {
    exit(0);
}

void logger(char* message, int queue_id) {
    logbuf log_message;
    log_message.mtype = 1;
    strcpy(log_message.message, message);
    msgsnd(queue_id, &log_message, sizeof(logbuf), 0);
}

void write_log(FILE *fd, char* message) {
    char current_time[30];
    set_current_time(current_time);
    fprintf(fd, "%s freeflow: %s\n", current_time, message);        
    fflush(fd);
}

void start_logger(char *log_file, int queue_id) {
    FILE *fd;
    
    signal(SIGTERM, handle_signal);

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
