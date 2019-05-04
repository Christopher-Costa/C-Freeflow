/* Note:  The default maxmsg size on CentOS 7 is 8192, which means the
 *        packet_buffer structure must be no larger than that.  If the 
 *        PACKET_BUFFER_SIZE needed to be increased higher to support something
 *        like jumbo frames, the kernel setting (/proc/sys/kernel/msgmax) would
 *        need to be increased also.  1500 bytes is sufficient for a standard 
 *        Cisco netflow v5 datagram.
 */
#define LOG_MESSAGE_SIZE 256
#define PACKET_BUFFER_SIZE 1500

typedef struct packet_buffer {
    long mtype;
    char packet[PACKET_BUFFER_SIZE];
    int packet_len;
    char sender[16];
} packet_buffer;
