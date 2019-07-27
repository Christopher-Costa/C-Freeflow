#define LOGBUF 4096

typedef struct logbuf {
    long mtype;  /* must be positive */
    char message[LOGBUF];
    char severity[8];
} logbuf;

void log_info(char* message, int queue_id);
void log_warning(char* message, int queue_id);
void log_error(char* message, int queue_id);
void log_debug(char* message, int queue_id);
void start_logger(char* log_file, int queue_id);
