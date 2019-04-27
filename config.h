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
} freeflow_config;

int parse_command_arguments(int argc, char** argv, char **config_file);
void read_configuration(char* config_file, freeflow_config* config_obj);

