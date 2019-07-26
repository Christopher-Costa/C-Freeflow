int hec_header(freeflow_config* config, int content_length, char* header);
int empty_payload(char* payload[], freeflow_config* config);
int parse_packet(packet_buffer* packet, char* payload, freeflow_config* config, int log_queue);
int response_code(char* response);
void handle_child_signal(int sig);
int splunk_worker(int worker_num, freeflow_config *config, int log_queue);
