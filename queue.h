#define PACKET_QUEUE 1
#define LOG_QUEUE    2

int create_queue(char* filename, int id);
void set_queue_size(int queue_id, int queue_size);
