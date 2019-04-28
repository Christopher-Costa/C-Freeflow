#include <stdio.h>    /* Provides: printf */
#include <string.h>   /* Provides: strcpy */
#include <stdlib.h>   /* Provides: malloc */
#include <unistd.h>   /* Provides: getopt */
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
            else if (!strcmp(key, "log_file")) {
                config_obj->log_file = malloc(strlen(value) + 1);
                strcpy(config_obj->log_file, value);
            }
        }
    }

    fclose(c);
}
