typedef struct freeflow_config {
    char* bind_addr;
    int bind_port;
    int threads;
    long queue_size;
    char *sourcetype;
    char *hec_token;
    char *hec_server;
    int hec_port;
    char *log_file;
    char *config_file;
} freeflow_config;

int parse_command_args(int argc, char** argv, freeflow_config* config_obj);
void read_configuration(freeflow_config* config_obj);

