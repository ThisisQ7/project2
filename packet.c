#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKETLEN 1500
#define BUFLEN 100
#define HEADERLEN 16
#define CHUNKHASHLEN 20
#define DATALEN MAX_PACKET_LEN-HEADER_LEN
#define MAX_HASH_NUM 74
#define SHA1_HASH_SIZE 20

#define WHOHAS 0
#define IHAVE 1
#define GET 2
#define DATA 3
#define ACK 4
#define DENIED 5

typedef struct header_s {
    short magicnum;
    char version;
    char packet_type;
    short header_len;
    short packet_len; 
    uint32_t seq_num;
    uint32_t ack_num;
} header_t;  

typedef struct packet_s {
    header_t header;
    char data[BUFLEN];
} packet_t;

typedef struct chunk_s { 
  int id;
  uint8_t hash[SHA1_HASH_SIZE];
  char *data;
} chunk_t;


/**
 * make_packets
 * 
 * make packets
 * 
 */
data_packet_t *make_packet (int type, short p_len, uint32_t seq, uint32_t ack, char *data){
    data_packet_t *p = (data_packet_t *)malloc(sizeof(data_packet_t));
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

/**
 * make_whohas
 * 
 * make a list of whohas packets with input of chunks we are 
 * trying to request, the number of chunks (size of chunks array)
 * is num_chunks
 * 
 */

data_packet_t **make_whohas (chunk_t *chunks, int num_chunks){
  int num_packets = num_chunks / MAX_HASH_NUM;
  if (num_chunks % MAX_HASH_NUM > 0)
    num_packets++;

  //array of packet pointers
  packet **whohas_packets = malloc(num_packets * sizeof (data_packet_t *));
  if (!whohas_packets){
    perror("Error alloc whohas_packet");
    exit(EXIT_FAILURE);
  }

  int chunk_index = 0;

  for (int i = 0; i < num_packets; i++){
    int hash_num;
    // the number of hashes to put in this packet
    if (i < (num_packets - 1)){
      hash_num = MAX_HASH_NUM;
    }else{
      hash_num = num_chunks % MAX_HASH_NUM;
    }
    char *data = malloc (HEADERLEN + 4 + hash_num * SHA1_HASH_SIZE);
    if(!data){
      perror("Error alloc data");
      exit(EXIT_FAILURE);
    }
    memset(data, 0, HEADERLEN + 4 + hash_num * SHA1_HASH_SIZE);
    //the number of hashes to be stored in the first 4 bytes
    data[0] = hash_num;
        
    //Put the chunk hashes into the packet data field
    for (int j = 0; j < hash_num; j++){
      memcpy(data + 4 + j * SHA1_HASH_SIZE, chunks[chunk_index].hash, SHA1_HASH_SIZE);
      chunk_index++;
    }
    //create a whohas packet
    whohas_packet[i] = make_packet(WHOHAS, HEADERLEN + 4 + hash_num * SHA1_HASH_SIZE, 0, 0, data);

    free(data);
  }
  return whohas_packets;
}


/**
 * flood_whohas
 * 
 * flood WHOHAS packet to every peer in the network
 * 
 */

 void flood_whohas(){
  
 }

/**
 * send_whohas
 * 
 * make whohas packets
 * 
 */
void send_whohas(chunk_t chunks, int num_chunks){
  printf("ENTER FLOOD_WHOHAS\n");
  data_packet_t whohas_packets = make_whohas(chunks, num_chunks);
  if (!whohas_packets){
    perror("Error making whohas_packet");
    exit(EXIT_FAILURE);
  }
  int num_packets = num_chunks / MAX_HASH_NUM;
  if (num_chunks % MAX_HASH_NUM > 0)
    num_packets++;

  //send each WHOHAS packet
  for (int i = 0; i < num_packets; i++){
    if(whohas_packets[i] == NULL)
      continue;
    flood_whohas(whohas_packets[i]); //flood this packet to every peer
    packet_free(whohas_packets[i]);
  }
  free(whohas_packets);
}

