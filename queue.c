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
    return msgget(key, 0666 | IPC_CREAT);
}

int delete_queue(int queue_id) {
    return msgctl(queue_id, IPC_RMID, NULL);
}

void set_queue_size(int queue_id, int queue_size) {
    struct msqid_ds ds = {0};
    msgctl(queue_id, IPC_STAT, &ds);
    ds.msg_qbytes = queue_size;
    msgctl(queue_id, IPC_SET, &ds);
}
