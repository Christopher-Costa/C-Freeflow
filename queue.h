#define PACKET_QUEUE 1
#define LOG_QUEUE    2

int create_queue(char* filename, int id, char* error, int queue_size);
int delete_queue(int queue_id);
int set_queue_size(int queue_id, int queue_size, char* error);
int queue_length(int queue_id);
