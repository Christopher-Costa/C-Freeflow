#include <stdio.h>    /* Provides: printf */
#include <sys/msg.h>  /* Provides: struct msqid_ds */
#include "queue.h"

int queue_length(int queue_id) {
    struct msqid_ds ds;
    msgctl(queue_id, IPC_STAT, &ds);
    return ds.msg_qnum;
}

int create_queue(char* filename, int id) {
    key_t key = ftok(filename, id);
    int queue_id = msgget(key, 0666 | IPC_CREAT);

    return(queue_id);
}

void set_queue_size(int queue_id, int queue_size) {
    struct msqid_ds ds = {0};
    msgctl(queue_id, IPC_STAT, &ds);
    ds.msg_qbytes = queue_size;
    msgctl(queue_id, IPC_SET, &ds);
}
