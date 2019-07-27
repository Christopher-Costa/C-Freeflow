int response_code(char* response);
int hec_header(hec* server, int content_length, char* header);
int test_connectivity(hec_session* session, int worker_num, freeflow_config *config, int log_queue);
