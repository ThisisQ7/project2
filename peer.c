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
 #include <sys/time.h>
 
 #include <assert.h>
 
 #define SHA1_HASH_SIZE 20
 #define LIST_ELEM_SIZE 52
 #define HEADERLEN 16
 #define BUFLEN 1484
 #define WINDOW_SIZE 8
 #define TIMEOUT 300 //milli

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
  char data[BUFLEN];
 } packet_t;

 typedef struct {
  int last_packet_acked;
  int last_packet_sent;
  int last_packet_available;
  packet_t *window[WINDOW_SIZE]; // Buffer for sent but unacknowledged packets
  struct timeval timers[WINDOW_SIZE]; 
  } sender_state_t;

 //===========================================

 int sock;
 
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

 //helper function to look up chunkhash id
 int lookup_id(FILE *f, char *buf){
  char list_elem[LIST_ELEM_SIZE];
  char hash[40];
  int id;

  printf("buf : %s\n", buf);
  while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL){
    sscanf(list_elem, "%d %s", &id, hash);
    printf("hash : %s\n", hash);

    if (strcmp(hash, buf) == 0){
      printf("id from lookup_id: %d\n", id);
      return id;
    }
  } 
  
  return -1;
 }

 //Get handler: looks at chunk hash, looks up it's position within the master-chunk-file.
 // Based on the hash's file id, we displace a certain chunk distance and start sequentializing the chunk

 void get_handler(char *msg, struct sockaddr_in from, bt_config_t *config){
  printf("Here is the master chunk file %s\n", config->chunk_file);

  char buf[40];
  binary2hex(msg, 20, buf);

  FILE *f;
  char list_elem[LIST_ELEM_SIZE];
  char master_data_file[100];
  f = fopen(config->chunk_file, "r");  

  fgets(list_elem, LIST_ELEM_SIZE, f);
  sscanf(list_elem, "File: %s\n", master_data_file);
  printf("%s\n", master_data_file);  
  fseek(f, 0, SEEK_SET);

  int id = lookup_id(f, buf);

  fclose(f);

  f = fopen(master_data_file, "r");

  // get_data_packet_data(f, )
  // while(fgets(list_elem, LIST_ELEM_SIZE, f) != NULL){
  //   printf("%s\n", list_elem);
  // }

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

 void process_inbound_udp(int sock, bt_config_t *config) {
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];
 
  fromlen = sizeof(from);
  int recv_len;
  while ((recv_len = spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen))!= -1){
  //recv_len = spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

    if(recv_len < HEADERLEN){
      printf("Received packet shorter than HEADERLEN: %d bytes \n", recv_len);
      return;
    }

    packet_t* pkt = (packet_t*) buf;
    printf("Raw Packet Received: Type=%d, Magic=%d, Length=%d\n",
          pkt->header.packet_type, ntohs(pkt->header.magicnum), ntohs(pkt->header.packet_len));
    int type = packet_parser(pkt);
    if (type == -1){
      printf("something is wrong, check packet type \n");
      return;
    }

    switch(type){
      // case WHOHAS:{
      //   int hash_num = (unsigned char) pkt->data[0];
      //   printf("Received WHOHAS packet from %s:%d with %d hash(es)\n", 
      //           inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);
      //   // TODO: For each hash in pkt->data, check if I (current peer) has 
      //   // the corresponding chunk. if yes, prepare an IHAVE response and send it.
      //   //(packet_t *pkt, struct sockaddr *from, socklen_t fromlen;
      //                      //char *local_chunks, int sock
      //   process_whohas_packet(pkt, &from, (config->has_chunk_file), sock);
      //   break;
      // }
      // case IHAVE:{
      //   int hash_num = (unsigned char) pkt->data[0];
      //   printf("Received IHAVE packet from %s:%d with %d hash(es)\n", 
      //           inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);
      //   // TODO: Update internal state to record which chunks the sender possesses.
      //   // send GET as soon as I get "IHAVE" from a peer?
      //   break;
      // }
      case GET:{
        printf("Received GET packet from %s:%d\n", 
                inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        // save the requested hash
        // TODO: Check if I (current peer) have this chunk, if I have,
        // start sending DATA packet for this chunk. if I do not have,
        // send DENIED(? or should I ignore this)
        
        
        get_handler(pkt->data, from, config);
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
   char hashbuf[40];

   while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
    sscanf(list_elem, "%d %s", &id, hashbuf);
    res[curr].id = id;
    hex2ascii(hashbuf, 40, res[curr].hash);
   }
   fclose(f);
   return res;
  }
  
  packet_t *make_packet (int type, short p_len, uint32_t seq, uint32_t ack, char *data){
    packet_t *p = (packet_t *)malloc(sizeof(packet_t));
    p->header.magicnum = htons(15441); 
    p->header.version = 1;
    p->header.packet_type = (char) type;
    p->header.header_len = htons(HEADERLEN);
    p->header.packet_len = htons(p_len);
    p->header.seq_num = htonl(seq);
    p->header.ack_num = htonl(ack);
    memcpy(p->data, data, p_len - HEADERLEN);
    return p;
  }

 //Immediate landing space for processing get
 void process_get(char *chunkfile, char *outputfile) {
   printf("PROCESS GET CALLED. (%s, %s)\n", 
   chunkfile, outputfile);
 
   //First, we access the chunks the user wishses to obtain
   int num_chunks = 0;
   chunk_t *chunk_list;
   chunk_list = process_chunkfile(chunkfile, &num_chunks);

  }

  void send_test(char *msg){

    packet_t *pack;

    uint8_t hashed[20];
    hex2binary(msg, 40, hashed);

    pack = make_packet(GET, 56, 0, 0, hashed);

    struct sockaddr_in peer_addr; 
    short peer_port = 2222;
    char *peer_ip = "127.0.0.1";
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    // char request[50];

    // memset(request, 0, sizeof(request));
    // strcat(request, "GET ");
    // strcat(request, msg);

    // printf("Here is the sending string: %s \n", request);

    if(inet_pton(AF_INET, peer_ip, &(peer_addr.sin_addr)) <= 0){
      perror("printable to binary IP conversation in send test failed.\n");
      return EXIT_FAILURE;
    }

    spiffy_sendto(sock, pack, 56, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));

    printf("Message '%s' sent to addr: <%s>, and port: <%d>\n", msg, peer_ip, peer_port);
  }
 
 //obtain chunk and output file
 void handle_user_input(char *line, void *cbdata) {
   char chunkf[128], outf[128];
   char msg[10];
 
   bzero(chunkf, sizeof(chunkf));
   bzero(outf, sizeof(outf));
 
   if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
     if (strlen(outf) > 0) {
       process_get(chunkf, outf);
     }
   }

   if(sscanf(line, "send %s", &msg)){
    printf("Calling sender test with following message: %s\n", msg);
    send_test(msg);
   }
 }
 
 
 void peer_run(bt_config_t *config) {
  //  int sock;
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

   printf("Here is my receiving socket %d\n", sock);
   
   bzero(&myaddr, sizeof(myaddr));
   myaddr.sin_family = AF_INET;
   myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
   myaddr.sin_port = htons(config->myport);
   printf("Looking at myport %d\n", config->myport);
   
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
        process_inbound_udp(sock, config);
       }
       
       if (FD_ISSET(STDIN_FILENO, &readfds)) {
        process_user_input(STDIN_FILENO,userbuf, handle_user_input,"Currently unused");
       }
     }
   }
 }