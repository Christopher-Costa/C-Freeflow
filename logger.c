#include <stdio.h>    /* Provides: printf */
#include <stdlib.h>   /* Provides: exit */
#include <string.h>   /* Provides: strcpy */
#include <time.h>     /* Provides: time_t */
#include <sys/msg.h>  /* Provides: ftok */
#include <signal.h>
#include "freeflow.h"
#include "logger.h"

int keep_logging = 1;

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

void handle_sigterm(int sig) {
    keep_logging = 0;
}

// Catch an interupt signal and do nothing.  We don't want the logging
// process to cease until the main process tells it to, so that all 
// expected log messages get written first.
void handle_sigint(int sig) {}

void logger(char* message, char* severity, int queue_id) {
    logbuf log_message;
    log_message.mtype = 1;
    strcpy(log_message.message, message);
    strcpy(log_message.severity, severity);
    msgsnd(queue_id, &log_message, sizeof(logbuf), 0);
}

void log_info(char* message, int queue_id) {
    logger(message, "INFO", queue_id);
}

void log_warning(char* message, int queue_id) {
    logger(message, "WARNING", queue_id);
}

void log_error(char* message, int queue_id) {
    logger(message, "ERROR", queue_id);
}

void write_log(FILE *fd, logbuf log) {
    char current_time[30];
    set_current_time(current_time);
    fprintf(fd, "%s freeflow: %s %s\n", current_time, log.severity, log.message);        
    fflush(fd);
}

void start_logger(char *log_file, int queue_id) {
    FILE *fd;
    
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigint);

    if ((fd = fopen(log_file, "a")) == NULL) {
        printf("Couldn't open log file.\n");
        exit(0);
    }

    char log_message[128];
    sprintf(log_message, "Logging process [PID %d] started.", getpid());
    log_info(log_message, queue_id);

    logbuf l;
    while(keep_logging || queue_length(queue_id)) {
        int bytes = msgrcv(queue_id, &l, sizeof(logbuf), 1, IPC_NOWAIT);
        if (bytes > 0) {
            write_log(fd, l);
        }
        else {
            // If there were no messages, just wait 0.01s and try again.
            usleep(10000);
        }        
    }

    delete_queue(queue_id);
    fclose(fd);
}
