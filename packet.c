#define MAX_PACKET_LEN 1500
#define HEADER_LEN 16
#define CHUNKHASH_LEN 20
#define MAX_DATA_LEN MAX_PACKET_LEN-HEADER_LEN

#define WHOHAS 0
#define IHAVE 1
#define GET 2
#define DATA 3
#define ACK 4
#define DENIED 5

typedef struct header {
    short magic_num;
    char version;
    char packet_type;
    short header_len;
    short packet_len; 
    unsigned int seq_num;
    unsigned int ack_num;
} header_t;  

typedef struct packet{
    header h;
    char data[MAX_DATA_LEN];
}packet_t;

packet_t *make_packet (int type, short p_len, unsigned int seq, unsigned int ack, char *data){
    data_packet_t *p = (packet_t *)malloc(sizeof(packet_t));
    p->header.magicnum = 15441; 
    p->header.version = 1;
    p->header.packet_type = (char) type;
    p->header.header_len = HEADERLEN;
    p->header.packet_len = p_len;
    p->header.seq_num = seq;
    p->header.ack_num = ack;
    if (p->data != NULL) 
        memcpy(p->data, data, p_len - HEADERLEN);
    return p;
}

packet_t *make_whohas (){
    /*to do*/
}