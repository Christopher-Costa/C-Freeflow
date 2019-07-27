#define PACKET_QUEUE 1
#define LOG_QUEUE    2

int create_queue(char* filename, int id, char* error, int queue_size);
int delete_queue(int queue_id);
int queue_length(int queue_id);
