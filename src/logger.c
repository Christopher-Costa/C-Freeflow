#include <stdio.h>    /* Provides: printf */
#include <stdlib.h>   /* Provides: exit */
#include <string.h>   /* Provides: strcpy */
#include <time.h>     /* Provides: time_t */
#include <sys/msg.h>  /* Provides: ftok */
#include <signal.h>
#include "freeflow.h"
#include "logger.h"

static int keep_logging = 1;

static void handle_sigterm(int sig);
static void handle_sigint(int sig);

static void set_current_time(char* current_time);
static void logger(char* message, char* severity, int queue_id);
static void write_log(FILE* fd, logbuf* log);

/*
 * Function: handle_sigterm
 *
 * Toggle the keep_logging variable to allow the main logging routing to 
 * stop and stop cleanly after emptying the logging queue.
 *
 * Inputs:   int sig    Signal being caught (SIGTERM)
 *
 * Returns:  None
 */
static void handle_sigterm(int sig) {
    keep_logging = 0;
}

/*
 * Function: handle_sigint
 *
 * Do nothing.  Simply catch the SIGINT and take no action, to allow the 
 * main program to orchestrate the cleanup among all processes and allow 
 * logging to continue in the meanwhile. 
 *
 * Inputs:   int sig    Signal being caught (SIGTERM)
 *
 * Returns:  None
 */
static void handle_sigint(int sig) {
}

/*
 * Function: set_current_time
 *
 * Sets 'current_time' variable to a human readable representation of 
 * the current system time.
 *
 * Inputs:   char* current_time    Pointer to human readable timestamp
 *
 * Returns:  None
 */
void set_current_time(char* current_time) {
    time_t now;
    time(&now);
    struct tm* time_info = localtime(&now);
    sprintf(current_time, "%4d/%02d/%02d %02d:%02d:%02d", time_info->tm_year + 1900,
                                                          time_info->tm_mon + 1,
                                                          time_info->tm_mday,
                                                          time_info->tm_hour,
                                                          time_info->tm_min,
                                                          time_info->tm_sec);
}

/*
 * Function: logger
 *
 * Accepts a log message and severity, and create a message to send to an IPC
 * message queue, to be processed later. 
 *
 * Inputs:   char* message     Log message string
 *           char* severity    Log message severity (INFO, ERROR, etc.)
 *           int   queue_id    Id value of IPC message queue to use
 *
 * Returns:  None
 */
static void logger(char* message, char* severity, int queue_id) {
    logbuf log_message;

    log_message.mtype = 1;
    strcpy(log_message.message, message);
    strcpy(log_message.severity, severity);

    msgsnd(queue_id, &log_message, sizeof(logbuf), 0);
}

/*
 * Function: log_debug
 *
 * Wrapper function to be used to create a message of DEBUG severity and
 * have it logged.
 *
 * Inputs:   char* message     Log message string
 *           int   queue_id    Id value of IPC message queue to use
 *
 * Returns:  None
 */
void log_debug(char* message, int queue_id) {
    logger(message, "DEBUG", queue_id);
}

/*
 * Function: log_info
 *
 * Wrapper function to be used to create a message of INFO severity and
 * have it logged.
 *
 * Inputs:   char* message     Log message string
 *           int   queue_id    Id value of IPC message queue to use
 *
 * Returns:  None
 */
void log_info(char* message, int queue_id) {
    logger(message, "INFO", queue_id);
}

/*
 * Function: log_warning
 *
 * Wrapper function to be used to create a message of WARNING severity 
 * and have it logged.
 *
 * Inputs:   char* message     Log message string
 *           int   queue_id    Id value of IPC message queue to use
 *
 * Returns:  None
 */
void log_warning(char* message, int queue_id) {
    logger(message, "WARNING", queue_id);
}

/*
 * Function: log_error
 *  
 * Wrapper function to be used to create a message of ERROR severity 
 * and have it logged.
 *
 * Inputs:   char* message     Log message string
 *           int   queue_id    Id value of IPC message queue to use
 *
 * Returns:  None
 */
void log_error(char* message, int queue_id) {
    logger(message, "ERROR", queue_id);
}

/*
 * Function: write_log
 *
 * Function to write the contents of a log message buffer to a specificed
 * log file on disk.
 *
 * Inputs:   FILE*   fd     Descriptor of log file
 *           logbuf* log    Buffer for log message
 *
 * Returns:  None
 */
static void write_log(FILE* fd, logbuf* log) {
    char current_time[30];
    set_current_time(current_time);

    fprintf(fd, "%s freeflow: %s %s\n", current_time, log->severity, log->message);        
    fflush(fd);
}

/*
 * Function: start_logger
 * 
 * Main logging function, which handles log file opening and closure,
 * and reading new messages off the IPC logging queue and having them
 * written to disk.
 *
 * Inputs:   char* log_file    The filesystem path of the log file
 *           int   queue_id    Id of the IPC queue for logging
 *
 * Returns:  None
 */
void start_logger(char* log_file, int queue_id) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigint);

    FILE *fd;
    
    if ((fd = fopen(log_file, "a")) == NULL) {
        printf("Couldn't open log file.\n");
        exit(0);
    }

    char log_message[LOG_MESSAGE_SIZE];
    sprintf(log_message, "Logging process [PID %d] started.", getpid());
    log_info(log_message, queue_id);

    logbuf l;

    /* Don't stop reading from the queue until instructed to stop, and
     * the queue is empty */
    while(keep_logging || queue_length(queue_id)) {

        /* If there are no messages in the queue, don't wait for one to
         * arrive.  This is to give an opportunity for the loop to be 
         * broken by a SIGTERM.  If the queue was empty, sleep for 0.01s
         * to prevent the CPU from saturating. */  
        int bytes = msgrcv(queue_id, &l, sizeof(logbuf), 1, IPC_NOWAIT);
        if (bytes <= 0) {
            usleep(10000);
            continue;
        }
           
        write_log(fd, &l);
    }

    delete_queue(queue_id);
    fclose(fd);
}
