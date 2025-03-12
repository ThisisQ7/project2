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
 
 #define SHA1_HASH_SIZE 20
 #define LIST_ELEM_SIZE 52

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
 
 
 void process_inbound_udp(int sock) {
   #define BUFLEN 1500
   struct sockaddr_in from;
   socklen_t fromlen;
   char buf[BUFLEN];
 
   fromlen = sizeof(from);
   spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);
 
   printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
    "Incoming message from %s:%d\n%s\n\n", 
    inet_ntoa(from.sin_addr),
    ntohs(from.sin_port),
    buf);
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
   return res;
  }

 //Immediate landing space for processing get
 void process_get(char *chunkfile, char *outputfile) {
   printf("PROCESS GET CALLED. (%s, %s)\n", 
   chunkfile, outputfile);
 
   //First, we access the chunks the user wishses to obtain
   int num_chunks = 0;
   chunk_t *chunk_list;
   chunk_list = process_chunkfile(chunkfile, &num_chunks);

  //  printf("number of chunks on the caller side : %d \n", num_chunks);

  make_packet()

  }
 
 //obtain chunk and output file
 void handle_user_input(char *line, void *cbdata) {
   char chunkf[128], outf[128];
 
   bzero(chunkf, sizeof(chunkf));
   bzero(outf, sizeof(outf));
 
   if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
     if (strlen(outf) > 0) {
       process_get(chunkf, outf);
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
        process_user_input(STDIN_FILENO,userbuf, handle_user_input,"Currently unused");
       }
     }
   }
 }