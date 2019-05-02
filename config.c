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

void setting_error(char *setting_desc, char* value) {
    printf("Invalid setting for %s: %s\n", setting_desc, value);
    exit(0);
}

void handle_addr_setting(char *setting, char *value, char *setting_desc) {
        if (!is_ip_address(value)) {
            setting_error(setting_desc, value);
        }

        strcpy(setting, value);
}

void handle_int_setting(int *setting, char* value, char* setting_desc, int min, int max) {
    if (is_integer(value)) {
        int value_as_int = atoi(value);

        if (value_as_int >= min) {
            if ((value_as_int <= max) || (max == 0)) {
                *setting = value_as_int;
                return;
            }
        }
    }
    setting_error(setting_desc, value);
}

void handle_port_setting(int *setting, char* value, char* setting_desc) {
    handle_int_setting(setting, value, setting_desc, 1, 65535);
}

void read_configuration(freeflow_config* config) {
    char line[1024];
    FILE *c;

    if ((c = fopen(config->config_file, "r")) == NULL) {
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
                handle_addr_setting(config->bind_addr, value, key);
            }
            else if (!strcmp(key, "bind_port")) {
                handle_port_setting(&config->bind_port, value, key);
            }
            else if (!strcmp(key, "threads")) {
                handle_int_setting(&config->threads, value, key, 1, 64);
            }
            else if (!strcmp(key, "queue_size")) {
                handle_int_setting(&config->queue_size, value, key, 1, 0);
            }
            else if (!strcmp(key, "sourcetype")) {
                config->sourcetype = malloc(strlen(value) + 1);
                strcpy(config->sourcetype, value);
            }
            else if (!strcmp(key, "hec_token")) {
                config->hec_token = malloc(strlen(value) + 1);
                strcpy(config->hec_token, value);
            }
            else if (!strcmp(key, "hec_server")) {
                config->hec_server = malloc(strlen(value) + 1);
                strcpy(config->hec_server, value);
            }
            else if (!strcmp(key, "hec_port")) {
                config->hec_port = atoi(value);
            }
            else if (!strcmp(key, "hec_servers")) {
                handle_hec_servers(config, value);
            }
            else if (!strcmp(key, "hec_tokens")) {
                handle_hec_tokens(config, value);
            }
            else if (!strcmp(key, "log_file")) {
                config->log_file = malloc(strlen(value) + 1);
                strcpy(config->log_file, value);
            }
        }
    }

    printf("XXXX %d\n", config->threads);
    printf("XXXX %d\n", config->queue_size);
    printf("XXXX %s\n", config->bind_addr);
    printf("XXXX %d\n", config->bind_port);
    printf("XXXX %d\n", config->threads);
    fclose(c);
}
