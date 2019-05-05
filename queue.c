#include <stdio.h>    /* Provides: printf */
#include <string.h>   /* Provides: strcpy */
#include <sys/msg.h>  /* Provides: struct msqid_ds */
#include <errno.h>    /* Provides: strerror */
#include "queue.h"

/*
 * Function: queue_length
 * 
 * Helper function to return the number of messages currently waiting
 * in an IPC message queue.
 *
 * Inputs:   int   queue_id    Id of the IPC queue to check
 *
 * Returns:  <# of messages in the queue>
 */
int queue_length(int queue_id) {
    struct msqid_ds ds;
    msgctl(queue_id, IPC_STAT, &ds);
    return ds.msg_qnum;
}

/*
 * Function: create_queue
 * 
 * Helper function to create an IPC queue and return its Id.
 *
 * Inputs:   char* filename    name of a file to seed key creation
 *           int   id          Unique identifier to seed key creation
 *           char* error       Error string, if operation fails
 *
 * Returns:  <queue id>  Success
 *           -1          Failure 
 */
int create_queue(char* filename, int id, char* error) {
    key_t key = ftok(filename, id);

    int queue_id;
    queue_id =  msgget(key, 0666 | IPC_CREAT);
    if (queue_id < 0) {
        strcpy(error, strerror(errno));
    }
    return queue_id;
}

/*
 * Function: delete_queue
 * 
 * Helper function to delete an IPC queue.
 *
 * Inputs:   int   queue_id    Id of queue to delete
 *
 * Returns:  0   Success
 *           -1  Failure 
 */
int delete_queue(int queue_id) {
    int rc;

    rc = msgctl(queue_id, IPC_RMID, NULL);
    return rc;
}

/*
 * Function: create_queue
 *
 * Helper function to create an IPC queue and return its Id.
 *
 * Inputs:   int   queue_id      Unique identifier to seed key creation
 *           int   queue_size    Size of the queue to set
 *           char* error         Error string, if operation fails
 *
 * Returns:  0    Success
 *           -1   Couldn't stat the message queue
 *           -2   Couldn't set the queue size
 */
int set_queue_size(int queue_id, int queue_size, char* error) {
    struct msqid_ds ds = {0};
    int rc;
    rc = msgctl(queue_id, IPC_STAT, &ds);
    if (rc < 0) {
        strcpy(error, strerror(errno));
        return -1;
    }

    ds.msg_qbytes = queue_size;
    rc =msgctl(queue_id, IPC_SET, &ds);
    if (rc < 0) {
        strcpy(error, strerror(errno));
        return -2;
    }
    return 0;
}
