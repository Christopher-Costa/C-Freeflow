#define PACKET_QUEUE 1
#define LOG_QUEUE    2

int create_queue(char* filename, int id);
int delete_queue(int queue_id);
void set_queue_size(int queue_id, int queue_size);
int queue_length(int queue_id);
