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

#include <assert.h>

#define SHA1_HASH_SIZE 20
#define LIST_ELEM_SIZE 52
#define BUF_SIZE 256

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

void process_get(char *chunkfile, char *outputfile) {
  printf("PROCESS GET SKELETON CODE CALLED. (%s, %s)\n", 
	chunkfile, outputfile);

  //First, we access the chunks the user wishses to obtain
  FILE *f;
  int chunks_count = 0;
  char chunk_hash[SHA1_HASH_SIZE], list_elem[LIST_ELEM_SIZE];

  f = fopen(chunkfile, "r");
  assert(f != NULL);
  
  while (fgets(list_elem, BT_FILENAME_LEN, f) != NULL) {
    chunks_count++; //count how many lines of chunks
    printf("chunk line: %s and size of line: %d \n", list_elem, sizeof(list_elem));
  }
  chunk_t *chunks = malloc (sizeof(chunk_t)*chunks_count);
  fseek(f, 0, SEEK_SET); //go back to the beginnin of the file

  int i = 0;
  char read_buff[BUF_SIZE];
  char hash_buffer[SHA1_HASH_SIZE * 2];

  //Initialize chunk
  while (fgets(read_buff, BT_FILENAME_LEN, f) != NULL){
    sscanf(read_buff, "%d %s", &(chunks[i].id), hash_buffer);
    hex2binary(hash_buffer, SHA1_HASH_SIZE*2, chunk[i].hash);//ASCII hash to binary
    chunks[i].data = malloc(512 * 1024); //chunk data(512kb)
    if(!chunks[i].data){
      free(chunks[i].data);
      perror("Error alloc chunk data");
      exit(EXIT_FAILURE);
    }
    i++;
  }
  
  fclose(file);
  make_whohas(chunks, chunks_count);
}

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
	process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused");
      }
    }
  }
}
