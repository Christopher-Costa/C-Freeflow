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

int str_to_port(char *str) {
    // Since atoi has undefined behavior for invalid input,
    // first verify that this resembles a integer.
    int i;
    for (i = 0; i < strlen(str); i++) {
        if ((str[i] - '0' < 0) || (str[i] - '0' > 9)) {
            return 0;
        }
    }
    
    // Now, convert the string and make sure the result
    // falls into the valid port range.
    int port = atoi(str);
    if ((port < 1) || (port > 65535)) {
        return 0;
    }
    return port;
}

void parse_hec_servers(freeflow_config* config, char* servers) {

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

        char *ip = strtok(server, ":");
        char *port = strtok(NULL, ":");

        if (!is_ip_address(ip)) {
            printf("Invalid HEC server in position %d: %s\n", i+1, ip);
            exit(0);
        }

        int port_int = str_to_port(port);
        if (!port_int) {
            printf("Invalid HEC port in position %d: %s\n", i+1, port);
            exit(0);
        }

        strcpy(config->hec_servers[i].ip, ip);
        config->hec_servers[i].port = port_int;
    }
    printf("DONE\n");
}

void parse_hec_tokens(freeflow_config* config, char* tokens) {

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
                config_obj->bind_addr = malloc(strlen(value) + 1);
                strcpy(config_obj->bind_addr, value);
            }
            else if (!strcmp(key, "bind_port")) {
                config_obj->bind_port = atoi(value);
            }
            else if (!strcmp(key, "threads")) {
                config_obj->threads = atoi(value);
            }
            else if (!strcmp(key, "queue_size")) {
                config_obj->queue_size = atoi(value);
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
                parse_hec_servers(config_obj, value);
            }
            else if (!strcmp(key, "hec_tokens")) {
                parse_hec_tokens(config_obj, value);
            }
            else if (!strcmp(key, "log_file")) {
                config_obj->log_file = malloc(strlen(value) + 1);
                strcpy(config_obj->log_file, value);
            }
        }
    }

    fclose(c);
}
