/*
 * peer.c
 *
 * Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 */

 #include <sys/types.h>
 #include <arpa/inet.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "debug.h"
 #include "spiffy.h"
 #include "bt_parse.h"
 #include "input_buffer.h"
 #include "chunk.h"
 
 #include <assert.h>
 

#define PACKETLEN 1500
#define BUFLEN 1500
#define HEADERLEN 16
#define CHUNKHASHLEN 20
#define DATALEN PACKETLEN-HEADERLEN
#define MAX_HASH_NUM 74
#define SHA1_HASH_SIZE 20
#define LIST_ELEM_SIZE 52


#define WHOHAS 0
#define IHAVE 1
#define GET 2
#define DATA 3
#define ACK 4
#define DENIED 5



 //==================================================
 //STRUCTS
typedef struct chunk_s { 
  int id;
  uint8_t hash[SHA1_HASH_SIZE];
  char *data;
 } chunk_t;

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
  char data[DATALEN];
 } packet_t;
  

 //===========================================
 
void peer_run(bt_config_t *config);
 
int main(int argc, char **argv) {
  bt_config_t config;
 
  bt_init(&config, argc, argv);

  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");
 
#ifdef TESTING
  config.identity = 1; // your group number here
  strcpy(config.chunk_file, "chunkfile");
  strcpy(config.has_chunk_file, "haschunks");
#endif
 
  bt_parse_command_line(&config);
 
#ifdef DEBUG
  if (debug & DEBUG_INIT) {
    bt_dump_config(&config);
  }
#endif
   
  peer_run(&config);
  return 0;
}

/**
 * packet_parse
 * 
 * 
 * takes in a packet and check if the set headers are intact (maginum = 15441, version = 1, 
 * packet type within the range of 0 to 5), if the packet is damaged/invalid, return -1, 
 * if it is not, return the packet_type
 * 
 */
int packet_parser(packet_t* pkt) {

    
  short magic = ntohs(pkt->header.magicnum);
  if(magic != 15441){
    printf ("Invalid magicnum: not 15441 \n");
    return -1;
  }
  char version = pkt->header.version;
  if(version != 1){
    printf("Invalid version: not 1 \n");
    return -1;
  }
  
  int type = pkt->header.packet_type;
  if(type < 0 || type > 5){
    printf("packet_type out of range, packet_type %d \n", type);
    return -1;
  }
  return type;
}

void process_inbound_udp(int sock) {
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];
 
  fromlen = sizeof(from);
  int recv_len = spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);
  if(recv_len < HEADERLEN){
    printf("Received packet shorter than HEADERLEN: %d bytes \n", recv_len);
    return;
  }

  packet_t* pkt = (packet_t*) buf;
  int type = packet_parser(pkt);
  if (type == -1){
    printf("something is wrong, check packet type \n");
    return;
  }
  //printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
  //  "Incoming message from %s:%d\n%s\n\n", 
  //  inet_ntoa(from.sin_addr),
  //  ntohs(from.sin_port),
  //  buf);
  switch(type){
    case WHOHAS:{
      int hash_num = (unsigned char) pkt->data[0];
      printf("Received WHOHAS packet from %s:%d with %d hash(es)\n", 
              inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);
      // TODO: For each hash in pkt->data, check if I (current peer) has 
      // the corresponding chunk. if yes, prepare an IHAVE response and send it.
      break;
    }
    case IHAVE:{
      int hash_num = (unsigned char) pkt->data[0];
      printf("Received IHAVE packet from %s:%d with %d hash(es)\n", 
              inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);
      // TODO: Update internal state to record which chunks the sender possesses.
      // send GET as soon as I get "IHAVE" from a peer?
      break;
    }
    case GET:{
      printf("Received GET packet from %s:%d\n", 
              inet_ntoa(from.sin_addr), ntohs(from.sin_port));
      // save the requested hash
      unsigned char requested_hash[SHA1_HASH_SIZE];
      memcpy(requested_hash, pkt->data, SHA1_HASH_SIZE);
      // TODO: Check if I (current peer) have this chunk, if I have,
      // start sending DATA packet for this chunk. if I do not have,
      // send DENIED(? or should I ignore this)
      break;
    }
    case DATA:{
      uint32_t seq_num = ntohl(pkt->header.seq_num);
      int data_len = recv_len - HEADERLEN;
      printf("Received DATA packet (seq=%d) from %s:%d, data length=%d bytes\n", 
              seq_num, inet_ntoa(from.sin_addr), ntohs(from.sin_port), data_len);
      // TODO: Process the received the data:
      // save the data, update expecting chunks(sequence number?), 
      // send ACK to the sender
      break;
    }
    case ACK:{
      uint32_t ack_num = ntohl(pkt->header.ack_num);
      printf("Received ACK (ack=%d) from %s:%d\n", 
              ack_num, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
      // TODO: Update sender("I", as in this peer) state:
      // sliding window, update timer (not sure if there is more?)
      break;
    }
    case DENIED:{
      printf("Received DENIED from %s:%d\n", 
              inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    // TODO: Handle the denial
    // mark the peer as unavailable (remove the peer from the list 
    // of peers that has this chunk? we need data structure to keep
    // track of this then)
    // request the chunk from an alternate peer
      break;
    }
    default:{
      printf("Received unknown packet type %d from %s:%d\n", 
              type, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
      break;
    }
  }
}



//Helper that further processes the chunkfile to obtain each chunk_hash
chunk_t *process_chunkfile(char *chunkfile, int *num_chunks){
  FILE *f;
  char list_elem[LIST_ELEM_SIZE];

  f = fopen(chunkfile, "r");
  assert(f != NULL);
 
  while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
    (*num_chunks)++;        
  }

  printf("number of chunks function side : %d \n", (*num_chunks));
  chunk_t *res = (chunk_t *)malloc((*num_chunks) * sizeof(chunk_t)); //to free

  fseek(f, 0, SEEK_SET);
  int curr = 0;
  int id;
  char hashbuf[20];

  while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
    sscanf(list_elem, "%d %s", &id, hashbuf);
    res[curr].id = id;
    //binary2hex(hashbuf, 20, res[curr].hash);
    binary2hex(res[curr].hash, 20, hashbuf);

    curr++;

   }
  return res;
}


/**
 * make_packets
 * 
 * make packets
 * 
 */
packet_t *make_packet (int type, short p_len, uint32_t seq, uint32_t ack, char *data){
    packet_t *p = (packet_t *)malloc(sizeof(packet_t));
    if (!p){
      perror("Error alloc packet_t *p");
      exit(EXIT_FAILURE);
    }
    fprintf(stderr, "[DEBUG] Allocating packet_t of size %lu\n", sizeof(packet_t));
    p->header.magicnum = htons((short)15441); 
    p->header.version = (char)1;
    p->header.packet_type = (char) type;
    p->header.header_len = htons((short)HEADERLEN);
    p->header.packet_len = htons(p_len);
    p->header.seq_num = htonl(seq);
    p->header.ack_num = htonl(ack);
    //if (p->data != NULL) 
    if ((p_len - HEADERLEN) > DATALEN) {
        fprintf(stderr, "Error: Attempting to copy too much data into packet\n");
        exit(EXIT_FAILURE);
    }
    if (data != NULL) 
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

packet_t **make_whohas (chunk_t *chunks, int num_chunks){
  int num_packets = num_chunks / MAX_HASH_NUM;
  if (num_chunks % MAX_HASH_NUM > 0)
    num_packets++;

  //array of packet pointers
  packet_t **whohas_packets = malloc(num_packets * sizeof (packet_t *));
  if (!whohas_packets){
    perror("Error alloc whohas_packet");
    exit(EXIT_FAILURE);
  }

  int chunk_index = 0;

  for (int i = 0; i < num_packets; i++){
    int hash_num;
    // the number of hashes to put in this packet
    /*if (i < (num_packets - 1)){
      hash_num = MAX_HASH_NUM;
    }else{
      hash_num = (num_chunks % MAX_HASH_NUM == 0) ? MAX_HASH_NUM : num_chunks % MAX_HASH_NUM;
    }*/
    hash_num = (i < (num_packets - 1)) ? MAX_HASH_NUM : 
                    (num_chunks % MAX_HASH_NUM ? num_chunks % MAX_HASH_NUM : MAX_HASH_NUM);
    //char *data = malloc (4 + hash_num * SHA1_HASH_SIZE);
    //sanity check
    int data_size = 4 + hash_num * SHA1_HASH_SIZE;
    if (data_size > DATALEN) {
        fprintf(stderr, "Error: Data size exceeds DATALEN (%d > %d)\n", (4 + hash_num * SHA1_HASH_SIZE), DATALEN);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "[DEBUG] Allocating data of size %d\n", data_size);
    char *data = malloc(4 + hash_num * SHA1_HASH_SIZE);;
    if(!data){
      perror("Error alloc data");
      exit(EXIT_FAILURE);
    }
    memset(data, 0, 4 + hash_num * SHA1_HASH_SIZE);
    //the number of hashes to be stored in the first 4 bytes
    data[0] = hash_num;
    
    //Put the chunk hashes into the packet data field
    for (int j = 0; j < hash_num; j++){
      memcpy(data + 4 + j * SHA1_HASH_SIZE, chunks[chunk_index].hash, SHA1_HASH_SIZE);
      chunk_index++;
    }
    //create a whohas packet
    whohas_packets[i] = make_packet(WHOHAS, HEADERLEN + 4 + hash_num * SHA1_HASH_SIZE, 0, 0, data);

    //debug print
    printf("Created WHOHAS packet %d: contains %d hash(es), packet length %d\n", 
       i, hash_num, HEADERLEN + 4 + hash_num * SHA1_HASH_SIZE);
    
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

void flood_whohas(packet_t* whohas_packet, bt_config_t *config, int sock){
  printf("ENTER FLOOD_WHOHAS\n");
  bt_peer_t *peer = config->peers;
  
  while (peer != NULL){
    if(peer->id != config -> identity){
      printf("Flooding WHOHAS packet to peer id %d at %s:%d\n", 
             peer->id, inet_ntoa(peer->addr.sin_addr), ntohs(peer->addr.sin_port));
      spiffy_sendto(sock, whohas_packet, sizeof(packet_t), 0, (struct sockaddr *) &(peer->addr), sizeof(peer->addr));
    }
    peer = peer->next;
  }
 }

/**
 * send_whohas
 * 
 * make whohas packets
 * 
 */
void send_whohas(chunk_t *chunks, int num_chunks, bt_config_t *config, int sock){
  printf("ENTER SEND_WHOHAS\n");
  packet_t **whohas_packets = make_whohas(chunks, num_chunks);
  if (!whohas_packets){
    perror("Error making whohas_packet");
    exit(EXIT_FAILURE);
  }
  /*int num_packets = num_chunks / MAX_HASH_NUM;
  if (num_chunks % MAX_HASH_NUM > 0)
    num_packets++;*/
  int num_packets = (num_chunks + MAX_HASH_NUM - 1) / MAX_HASH_NUM;
  //send each WHOHAS packet
  for (int i = 0; i < num_packets; i++){
    if(whohas_packets[i] != NULL){
      flood_whohas(whohas_packets[i], config, sock); //flood this packet to every peer
      free(whohas_packets[i]);
      whohas_packets[i] = NULL; //prevent double free
    }
  }
  free(whohas_packets);
}



//Immediate landing space for processing get
void process_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock) {
  printf("PROCESS GET CALLED. (%s, %s)\n", 
  chunkfile, outputfile);
 
  //First, we access the chunks the user wishses to obtain
  int num_chunks = 0;
  chunk_t *chunk_list;
  chunk_list = process_chunkfile(chunkfile, &num_chunks);

  printf("number of chunks on the caller side : %d \n", num_chunks);

  send_whohas(chunk_list, num_chunks, config, sock);

}
 
 //obtain chunk and output file
void handle_user_input(char *line, void *cbdata, bt_config_t *config, int sock) {
  char chunkf[128], outf[128];
 
  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));
 
  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
    if (strlen(outf) > 0) {
      process_get(chunkf, outf, config, sock);
    }
  }
}
 
 
void peer_run(bt_config_t *config) {
  int sock;
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
   
  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
   
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }
   
  bzero(&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(config->myport);
   
  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }
   
  spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));
   
  while (1) {
    int nfds;
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);
     
    nfds = select(sock+1, &readfds, NULL, NULL, NULL);
     
    if (nfds > 0) {
      if (FD_ISSET(sock, &readfds)) {
        process_inbound_udp(sock);
      }
       
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
        process_user_input(STDIN_FILENO,userbuf, handle_user_input,"Currently unused", config, sock);
      }
    }
  }
}