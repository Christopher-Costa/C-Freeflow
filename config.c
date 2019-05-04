#include <stdio.h>     /* Provides: printf */
#include <string.h>    /* Provides: strcpy */
#include <stdlib.h>    /* Provides: malloc */
#include <unistd.h>    /* Provides: getopt */
#include <arpa/inet.h> /* Provides: AF_INET */
#include "config.h"

static int token_count(char* str, char delim);
static int is_ip_address(char *addr);
static int is_integer(char *num);
static void setting_error(char *setting_desc, char* value);

static void initialize_hec_servers(freeflow_config* config, char *value);

static void handle_addr_setting(char *setting, char *value, char *setting_desc);
static void handle_int_setting(int *setting, char* value, char* setting_desc, int min, int max);
static void handle_port_setting(int *setting, char* value, char* setting_desc);
static void handle_hec_servers(freeflow_config* config, char* servers);

/*
 * Function: token_count
 *
 * Helper function that takes a string and a character delimiter as input
 * and computes how many distinct string objects would be created by
 * tokenize the string with that delimiter.
 *
 * Inputs:   char* str       The string to tokenize
 *           char  delim     The token delimiter
 *
 * Returns:  <integer # of tokens>
 */
static int token_count(char* str, char delim) {

    /* There's always at least one token */
    int num_tokens = 1;
    int i;

    /* Recurse through the string char by char and increment the 
       counter each time the delimiter is encountered */
    for (i = 0; i < strlen(str); i++) {
        if (str[i] == delim) {
            num_tokens++;
        }
    }
    return num_tokens;
}

/*
 * Function: is_ip_address
 *
 * Helper function that checks a string and verifies whether or not it
 * takes the form of a valid IPv4 address.
 *
 * Inputs:   char* addr      The string to check
 *
 * Return:  1   String is a valid IPv4 address
 *          0   String is not a valid IPv4 address
 */
static int is_ip_address(char *addr) {
    unsigned long ip = 0;
    if (inet_pton(AF_INET, addr, &ip) > 0) {
        return 1;
    }
    return 0;
}

/*
 * Function: is_integer
 *
 * Helper function that checks a string and verifies whether or not it
 * takes the form of a positive integer.  The main purpose of this 
 * function is to provide error checking that the standard 'atoi'
 * function does not.
 *
 * Inputs:  char* num       The string to check
 *
 * Return:  1   String is a positive integer
 *          0   String is not a positive integer
 */
static int is_integer(char *num) {
    int i;

    /* Recurse through the string char by char and return if a 
       a character other than '0' through '9' is encountered. */ 
    for (i = 0; i < strlen(num); i++) {
        if ((num[i] - '0' < 0) || (num[i] - '0' > 9)) {
            return 0;
        }
    }
    return 1;
}

/*
 * Function: setting_error
 * 
 * Called when an error is detected in the configuration.  Print
 * a message to STDOUT and exit the program.
 *
 * Inputs:  char* setting_desc    Text describing the error
 *          char* value           The config value causing the error
 * 
 * Return:  None
 */ 
static void setting_error(char *setting_desc, char* value) {
    printf("Invalid setting for %s: %s\n", setting_desc, value);
    exit(0);
}

/*
 * Function: handle_addr_setting
 *
 * Used to validate and set a configuration setting intended to be an
 * IP address.  Update the configuration object (passed by reference)
 * or generate an error.
 *
 * Inputs:  char* setting         Pointer to configuration object being set
 *          char* value           Value being set
 *          char* setting_desc    String description of setting
 *
 * Return:  None
 */
static void handle_addr_setting(char *setting, char *value, char *setting_desc) {
        if (!is_ip_address(value)) {
            setting_error(setting_desc, value);
        }

        strcpy(setting, value);
}

/*
 * Function: handle_int_setting
 *
 * Used to validate and set a configuration setting intended to be an
 * integer.  Update the configuration object (passed by reference)
 * or generate an error.
 *
 * Inputs:  char* setting         Pointer to configuration object being set
 *          char* value           Value being set
 *          char* setting_desc    String description of setting
 *          int   min             Expected minimum value
 *          int   max             Expected maximum value.  0 = no limit.
 *
 * Return:  None
 */
static void handle_int_setting(int *setting, char* value, char* setting_desc, 
                               int min, int max) {

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

/*
 * Function: handle_port_setting
 *
 * Wrapper function to validate and set a configuration setting intended 
 * to be a network port.  Update the configuration object (passed by 
 * reference) or generate an error.
 *
 * Inputs:  char* setting         Pointer to configuration object being set
 *          char* value           Value being set
 *          char* setting_desc    String description of setting
 *
 * Return:  None
 */
static void handle_port_setting(int *setting, char* value, char* setting_desc) {
    handle_int_setting(setting, value, setting_desc, 1, 65535);
}

/*
 * Function: initialize_hec_servers
 *
 * Allocate an appropriate amount of memory for all provided HEC servers if
 * needed, or verify that memory has already been allocated properly.
 *
 * Inputs:  freeflow_config* config    Pointer to configuration object
 *          char*            value     Value being set
 *
 * Return:  None
 */
static void initialize_hec_servers(freeflow_config* config, char *value) {
    if (config->num_servers == 0) {
        config->num_servers = token_count(value, ';');
        config->hec_server = malloc(sizeof(hec) * config->num_servers);
    }
    else if (config->num_servers != token_count(value, ';')) {
        printf("Invalid number of items in list: %s\n", value);
        exit(0);
    }
}

/*
 * Function: handle_hec_servers
 *
 * Used to validate and set a configuration array for one or more HEC server
 * objects.  Generates an error for improperly formatted configurations, or
 * if there are a different number of servers than tokens.
 *
 * Inputs:  freeflow_config* config    Pointer to configuration object
 *          char*            servers   String of one or more HEC servers
 *
 * Return:  None
 */
static void handle_hec_servers(freeflow_config* config, char* servers) {
    initialize_hec_servers(config, servers);

    int i;
    for (i = 0; i < config->num_servers; i++) {
        char* server = strtok_r(servers, ";", &servers);
        if ((server == NULL) || (token_count(server, ':') != 2)) {
            setting_error("HEC server", server);
        }

        char *addr = strtok(server, ":");
        char *port = strtok(NULL, ":");

        handle_addr_setting(config->hec_server[i].addr, addr, "HEC server IP address");
        handle_port_setting(&config->hec_server[i].port, port, "HEC server port");
    }
}

/*
 * Function: handle_hec_tokens
 *
 * Used to validate and set a configuration array for one or more HEC token
 * objects.  Generates an error for improperly formatted configurations, or
 * if there are a different number of tokens than servers.
 *
 * Inputs:  freeflow_config* config    Pointer to configuration object
 *          char*            tokens    String of one or more HEC servers
 *
 * Return:  None
 */
static void handle_hec_tokens(freeflow_config* config, char* tokens) {
    initialize_hec_servers(config, tokens);

    int i;
    for (i = 0; i < config->num_servers; i++) {
        char* token = strtok_r(tokens, ";", &tokens);
        if (token == NULL) {
            setting_error("HEC token", token);
        }
        strcpy(config->hec_server[i].token, token);
    }
}

/*
 * Function: read_configuration
 *
 * Open and recurse through the configuration file and handle all the
 * settings, storing them to the configuration object.
 *
 * Inputs:  freeflow_config* config    Pointer to configuration object
 *
 * Return:  None
 */
void read_configuration(freeflow_config* config) {
    char line[CONFIG_LINE_SIZE];
    FILE *c;

    if ((c = fopen(config->config_file, "r")) == NULL) {
        printf("Couldn't open config file.\n");
        exit(0);
    }

    char key[CONFIG_KEY_SIZE];
    char value[CONFIG_VALUE_SIZE];

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
            else if (!strcmp(key, "hec_server")) {
                handle_hec_servers(config, value);
            }
            else if (!strcmp(key, "hec_token")) {
                handle_hec_tokens(config, value);
            }
            else if (!strcmp(key, "log_file")) {
                config->log_file = malloc(strlen(value) + 1);
                strcpy(config->log_file, value);
            }
        }
    }

    fclose(c);
}

/*
 * Function: parse_command_args
 *
 * Process and store the command line arguments provided when executing the
 * program, and validate for unexpected options.
 *
 * Inputs:  int              argc      Number of arguments
 *          char*            argv      Pointer to array of arguments
 *          freeflow_config* config    Pointer to configuration object
 *
 * Return:  None
 */
void parse_command_args(int argc, char** argv, freeflow_config* config) {
    int option;
    int index;
    opterr = 0;

    while ((option = getopt (argc, argv, "c:")) != -1)
        switch (option) {
            case 'c':
                config->config_file = malloc(strlen(optarg) + 1);
                strcpy(config->config_file, optarg);
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

    if (!config->config_file) {
        printf("No configuration file provided.\n");
        exit(0);
    }
}
