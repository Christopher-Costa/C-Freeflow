#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <arpa/inet.h>
#include "freeflow.h"
#include "netflow.h"

char* config_file;
freeflow_config config;

void die(char *s)
{
    perror(s);
    exit(1);
}

void configure_queue(int queue) {
    struct msqid_ds ds = {0};
    msgctl(queue, IPC_STAT, &ds);
    ds.msg_qbytes = config.queue_size;
    msgctl(queue, IPC_SET, &ds);
}

int parse_packet(char* packet, int packet_len, char** payload, struct in_addr e) {
    // Make sure the size of the packet is sane for netflow.
    if ( (packet_len - 24) % 48 > 0 ){
        printf("Invalid length\n");
        return 1;
    }

    netflow_header *h = (netflow_header*)packet;

    // Make sure the version field is correct
    if (ntohs(h->version) != 5){
        printf("Invalid version: %d\n", ntohs(h->version));
        return 1;
    }

    short num_records = ntohs(h->count);

    // Make sure the number of records is sane
    if (num_records != (packet_len - 24) / 48){
        printf("Invalid number of records: %d\n", num_records);
        return 1;
    }

    long sys_uptime = ntohl(h->sys_uptime);
    long unix_secs = ntohl(h->unix_secs);
    long unix_nsecs = ntohl(h->unix_nsecs);

    // The maximum size of a record minus the variable sourcetype is 233 bytes.
    // 250 bytes provides a reasonable safety buffer.
    int record_size = (250 + strlen(config.sourcetype));

    char splunk_payload[record_size * num_records];
    splunk_payload[0] = '\0';

    int record_count;
    netflow_record *r;
    for ( record_count = 0; record_count < num_records; record_count++){
        r = (netflow_record*)((char*)h + 24 + 48 * record_count);
        struct in_addr s = {r->srcaddr};
        struct in_addr d = {r->dstaddr};
        struct in_addr n = {r->nexthop};

        char exporter[16];
        strcpy(exporter, inet_ntoa(e));

        char srcaddr[16];
        strcpy(srcaddr, inet_ntoa(s));

        char dstaddr[16];
        strcpy(dstaddr, inet_ntoa(d));

        char nexthop[16];
        strcpy(nexthop, inet_ntoa(n));

        short input = ntohs(r->input);
        short output = ntohs(r->output);
        long packets = ntohl(r->packets);
        long bytes = ntohl(r->bytes);
        long first = ntohl(r->first);
        long last = ntohl(r->last);
        long duration = last - first;
        short sport = ntohs(r->srcport);
        short dport = ntohs(r->dstport);
        int flags = r->tcp_flags;
        int prot = r->prot;
        int tos = r->tos;
        short srcas = ntohs(r->src_as);
        short dstas = ntohs(r->dst_as);
        int srcmask = r->src_mask;
        int dstmask = r->dst_mask;

        char record[record_size];
        sprintf(record, "{\"event\": \"%s,%s,%s,%s,%u,%u,%lu,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u\", \"sourcetype\": \"%s\", \"time\": \"%.6f\"}",
            exporter, srcaddr, dstaddr, nexthop,
            input, output, packets, bytes, duration,
            sport, dport, flags, prot, tos, srcas, dstas,
            srcmask, dstmask, config.sourcetype,
            (  (double)unix_secs 
             + (double)unix_nsecs / 1000000000 
             - (double)sys_uptime/1000 
             + (double)first/1000)
        );
        strcat(splunk_payload, record);
    }
    
    sprintf(*payload, 
            "POST /services/collector HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: freeflow\r\nConnection: keep-alive\r\nAuthorization: Splunk %s\r\nContent-Length: %d\r\n\r\n", 
            config.hec_server, config.hec_port, config.hec_token, (int)strlen(splunk_payload));
    strcat(*payload, splunk_payload);

    return 0;
}

int splunk_worker(int worker_num) {
    struct sockaddr_in addr;
    struct hostent *host;
    int sock;

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Error opening socket\n");
        return -1;
    }

    addr.sin_family = AF_INET;

    host = gethostbyname(config.hec_server);
    if(host == NULL) {
        printf("%s unknown host.\n", config.hec_server);
        return -1;
    }

    bcopy(host->h_addr, &addr.sin_addr, host->h_length);
    addr.sin_port = htons(config.hec_port);
    connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)); 

    key_t key = ftok(config_file, 'a');
    int msqid = msgget(key, 0666 | IPC_CREAT);

    char *payload, *recv_buffer;
    payload = malloc(64 * 1024);
    recv_buffer = malloc(64 * 1024);
    while(1) {
        msgbuf m;
        
        msgrcv(msqid, &m, sizeof(msgbuf), 2, 0);
        char results = parse_packet(m.packet, m.packet_len, &payload, m.sender);        
        int bytes_sent = write(sock, payload, strlen(payload));
        if (bytes_sent < strlen(payload)) {
            printf("Incomplete delivery\n");
        }
        read(sock, recv_buffer, 64 * 1024);
    }
    free(payload);
    free(recv_buffer);
}

int receive_packets(void) {
    struct sockaddr_in si_me;
    struct sockaddr_in si_other;
    
    int s, i, slen = sizeof(si_other);
    char buf[BUFLEN];
    
    //create a UDP socket
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        die("socket");
    }
    
    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));
    
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(config.bind_port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    
    //bind socket to port
    if (bind(s, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
        die("bind");
    }

    key_t key = ftok(config_file, 'a');
    int msqid = msgget(key, 0666 | IPC_CREAT);

    msgbuf message;
    message.mtype = 2;

    //keep listening for data
    while(1)
    {
        int bytes_recv;
        bytes_recv = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *)&si_other, &slen);

        message.packet_len = bytes_recv;
        message.sender = si_other.sin_addr;
        memcpy(message.packet, buf, bytes_recv);
        msgsnd(msqid, &message, sizeof(msgbuf), 0); 
    }

    close(s);
    return 0;
}

void read_configuration() {
    char line[1024];
    FILE *c;

    if ((c = fopen(config_file, "r")) == NULL) {
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
                config.bind_addr = malloc(strlen(value) + 1);
                strcpy(config.bind_addr, value);
            }
            else if (!strcmp(key, "bind_port")) {
                config.bind_port = atoi(value);
            }
            else if (!strcmp(key, "threads")) {
                config.threads = atoi(value);
            }
            else if (!strcmp(key, "queue_size")) {
                config.queue_size = atoi(value);
            }
            else if (!strcmp(key, "sourcetype")) {
                config.sourcetype = malloc(strlen(value) + 1);
                strcpy(config.sourcetype, value);
            }
            else if (!strcmp(key, "hec_token")) {
                config.hec_token = malloc(strlen(value) + 1);
                strcpy(config.hec_token, value);
            }
            else if (!strcmp(key, "hec_server")) {
                config.hec_server = malloc(strlen(value) + 1);
                strcpy(config.hec_server, value);
            }
            else if (!strcmp(key, "hec_port")) {
                config.hec_port = atoi(value);
            }
            else if (!strcmp(key, "log_file")) {
                config.log_file = malloc(strlen(value) + 1);
                strcpy(config.log_file, value);
            }
        }
    }

    fclose(c);
}

int parse_args(int argc, char** argv) {
    int option;
    int index;
    opterr = 0;

    while ((option = getopt (argc, argv, "c:")) != -1)
        switch (option) {
            case 'c':
                config_file = optarg;
                break;
            case '?':
                if (optopt == 'c') {
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                }
                else if (isprint (optopt)) {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                }
                else {
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                }
                exit(0);
            default:
                abort ();
        }

    for (index = optind; index < argc; index++) {
        printf("Non-option argument %s\n", argv[index]);
        exit(0);
    }

    if (!config_file) {
        printf("No configuration file provided.\n");
        exit(0);
    }

    return 0;
}

void logger(char* message) {
    key_t key = ftok(config_file, 'b');
    int log_queue = msgget(key, 0666 | IPC_CREAT);
    
    logbuf log_message;
    log_message.mtype = 1;
    strcpy(log_message.message, message);

    msgsnd(log_queue, &log_message, sizeof(logbuf), 0);
}

void start_logger() {
    key_t key = ftok(config_file, 'b');
    int log_queue = msgget(key, 0666 | IPC_CREAT);
    configure_queue(log_queue);

    while(1) {
        logbuf l;
        msgrcv(log_queue, &l, sizeof(logbuf), 1, 0);
        printf("Logger: %s\n", l.message);        
    }
}

int main(int argc, char** argv) {

    parse_args(argc, argv);
    read_configuration();

    pid_t pids[config.threads];
    int i;

    if (fork() == 0) {
        start_logger();
        exit(0);
    }

    for (i = 0; i < config.threads; ++i) {
       if ((pids[i] = fork()) == 0 ) {
            splunk_worker(i);
            exit(0);
        }
    }

    receive_packets();
}
