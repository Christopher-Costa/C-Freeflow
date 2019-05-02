typedef struct hec {
    char addr[16];
    int port;
    char token[128];
} hec;

typedef struct freeflow_config {
    char bind_addr[16];
    int bind_port;
    int threads;
    int queue_size;
    char *sourcetype;
    char *hec_token;
    char *hec_tokens;
    char *hec_server;
    hec* hec_servers;
    int num_servers;
    int hec_port;
    char *log_file;
    char *config_file;
} freeflow_config;

int parse_command_args(int argc, char** argv, freeflow_config* config_obj);
void read_configuration(freeflow_config* config_obj);

