#define CONFIG_KEY_SIZE    128
#define CONFIG_VALUE_SIZE  1024
#define CONFIG_LINE_SIZE   1024
#define HEC_TOKEN_SIZE     128
#define IPV4_ADDR_SIZE     16

typedef struct hec {
    char addr[IPV4_ADDR_SIZE];
    int port;
    char token[HEC_TOKEN_SIZE];
} hec;

typedef struct freeflow_config {
    char bind_addr[IPV4_ADDR_SIZE];
    int bind_port;
    int threads;
    int queue_size;
    char *sourcetype;
    hec* hec_server;
    int num_servers;
    int hec_port;
    char *log_file;
    char *config_file;
} freeflow_config;

void parse_command_args(int argc, char** argv, freeflow_config* config_obj);
void read_configuration(freeflow_config* config_obj);
