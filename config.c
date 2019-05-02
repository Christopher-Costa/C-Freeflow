#include <stdio.h>     /* Provides: printf */
#include <string.h>    /* Provides: strcpy */
#include <stdlib.h>    /* Provides: malloc */
#include <unistd.h>    /* Provides: getopt */
#include <arpa/inet.h>
#include "config.h"

int parse_command_args(int argc, char** argv, freeflow_config* config_obj) {
    int option;
    int index;
    opterr = 0;

    while ((option = getopt (argc, argv, "c:")) != -1)
        switch (option) {
            case 'c':
                config_obj->config_file = malloc(strlen(optarg) + 1);
                strcpy(config_obj->config_file, optarg);
                break;
            case '?':
                if (optopt == 'c') {
                    fprintf (stderr,
                             "Option -%c requires an argument.\n",
                             optopt);
                }
                else if (isprint (optopt)) {
                    fprintf (stderr,
                             "Unknown option `-%c'.\n",
                             optopt);
                }
                else {
                    fprintf (stderr,
                             "Unknown option character `\\x%x'.\n",
                             optopt);
                }
                exit(0);
            default:
                abort ();
        }

    for (index = optind; index < argc; index++) {
        printf("Non-option argument %s\n", argv[index]);
        exit(0);
    }

    if (!config_obj->config_file) {
        printf("No configuration file provided.\n");
        exit(0);
    }

    return 0;
}

int object_count(char* str, char delim) {
    int num_objects = 1;
    int i;
    for (i = 0; i < strlen(str); i++) {
        if (str[i] == delim) {
            num_objects++;
        }
    }
    return num_objects;
}

int is_ip_address(char *addr) {
    unsigned long ip = 0;
    if (inet_pton(AF_INET, addr, &ip) > 0) {
        return 1;
    }
    return 0;
}

int is_integer(char *num) {
    int i;
    for (i = 0; i < strlen(num); i++) {
        if ((num[i] - '0' < 0) || (num[i] - '0' > 9)) {
            return 0;
        }
    }
    return 1;
}

int str_to_port(char *str) {
    if (!is_integer(str)) {
        return 0;
    }
    
    // Now, convert the string and make sure the result
    // falls into the valid port range.
    int port = atoi(str);
    if ((port < 1) || (port > 65535)) {
        return 0;
    }
    return port;
}

void handle_hec_servers(freeflow_config* config, char* servers) {

    if (config->num_servers == 0) {
        config->num_servers = object_count(servers, ';');
        config->hec_servers = malloc(sizeof(hec) * config->num_servers);
    }
    else if (config->num_servers != object_count(servers, ';')) {
        printf("Improper number of HEC servers\n");
        exit(0);
    }

    config->num_servers = object_count(servers, ';');

    int i;
    for (i = 0; i < config->num_servers; i++) {
        char* server = strtok_r(servers, ";", &servers);
        if (object_count(server, ':') != 2) {
            printf("Improperly formated HEC server: %s\n", server);
            exit(0);
        }

        char *addr = strtok(server, ":");
        char *port = strtok(NULL, ":");

        if (!is_ip_address(addr)) {
            printf("Invalid HEC server in position %d: %s\n", i+1, addr);
            exit(0);
        }

        int port_int = str_to_port(port);
        if (!port_int) {
            printf("Invalid HEC port in position %d: %s\n", i+1, port);
            exit(0);
        }

        strcpy(config->hec_servers[i].addr, addr);
        config->hec_servers[i].port = port_int;
    }
    printf("DONE\n");
}

void handle_hec_tokens(freeflow_config* config, char* tokens) {

    if (config->num_servers == 0) {
        config->num_servers = object_count(tokens, ';');
        config->hec_servers = malloc(sizeof(hec) * config->num_servers);
    }
    else if (config->num_servers != object_count(tokens, ';')) {
        printf("Improper number of HEC tokens\n");
        exit(0);
    }

    int i;
    for (i = 0; i < config->num_servers; i++) {
        char* token = strtok_r(tokens, ";", &tokens);
        if (token == NULL) {
            printf("Invalid HEC token in position %d: %s\n", i+1, token);
            exit(0);
        }
        strcpy(config->hec_servers[i].token, token);
    }
    printf("DONE\n");
}

void handle_bind_addr(freeflow_config* config, char* addr) {
        if (!is_ip_address(addr)) {
            printf("Invalid bind address: %s\n", addr);
            exit(0);
        }

        strcpy(config->bind_addr, addr);
}

void handle_bind_port(freeflow_config* config, char* port) {
    int port_int = str_to_port(port);

    if (!port_int) {
        printf("Invalid bind port: %s\n", port);
        exit(0);
    }

    config->bind_port = port_int;
}

void handle_threads(freeflow_config* config, char* threads) {
    if (!is_integer(threads)) {
        printf("Invalid setting for threads: %s\n", threads);
        exit(0);
    }

    config->threads = atoi(threads);
}

void handle_queue_size(freeflow_config* config, char* queue_size) {
    if (!is_integer(queue_size)) {
        printf("Invalid setting for queue_size: %s\n", queue_size);
        exit(0);
    }

    config->queue_size = atoi(queue_size);
}

void read_configuration(freeflow_config* config_obj) {
    char line[1024];
    FILE *c;

    if ((c = fopen(config_obj->config_file, "r")) == NULL) {
        printf("Couldn't open config file.\n");
        exit(0);
    }

    char key[128];
    char value[128];

    while (fgets(line, sizeof line, c) != NULL ){
        int result = sscanf(line,"%[^= \t\r\n] = %[^= \t\r\n]", key, value);
        if (result != 2) {
            result = sscanf(line,"%[^= \t\r\n]=%[^= \t\r\n]", key, value);
        } 

        if (result == 2) {
            if (key[0] == '#') {
                continue;
            }

            if (!strcmp(key, "bind_addr")) {
                handle_bind_addr(config_obj, value);
            }
            else if (!strcmp(key, "bind_port")) {
                handle_bind_port(config_obj, value);
            }
            else if (!strcmp(key, "threads")) {
                handle_threads(config_obj, value);
            }
            else if (!strcmp(key, "queue_size")) {
                handle_queue_size(config_obj, value);
            }
            else if (!strcmp(key, "sourcetype")) {
                config_obj->sourcetype = malloc(strlen(value) + 1);
                strcpy(config_obj->sourcetype, value);
            }
            else if (!strcmp(key, "hec_token")) {
                config_obj->hec_token = malloc(strlen(value) + 1);
                strcpy(config_obj->hec_token, value);
            }
            else if (!strcmp(key, "hec_server")) {
                config_obj->hec_server = malloc(strlen(value) + 1);
                strcpy(config_obj->hec_server, value);
            }
            else if (!strcmp(key, "hec_port")) {
                config_obj->hec_port = atoi(value);
            }
            else if (!strcmp(key, "hec_servers")) {
                handle_hec_servers(config_obj, value);
            }
            else if (!strcmp(key, "hec_tokens")) {
                handle_hec_tokens(config_obj, value);
            }
            else if (!strcmp(key, "log_file")) {
                config_obj->log_file = malloc(strlen(value) + 1);
                strcpy(config_obj->log_file, value);
            }
        }
    }

    fclose(c);
}
