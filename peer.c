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
#define CHUNK_SIZE 512*1024

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
  int requested; // 0 if no GET sent, 1 if GET already sent
  int downloaded; //0 if not downloaded yet, 1 if already downloaded
  //int peer_recorded; 0 if no peer recorded, 1 if already recorded
  struct sockaddr_in* peer; // the peer that we will ask this chunk from
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

typedef struct connection_state {
    struct sockaddr_in addr;
    uint32_t expected_seq;
    char *data_buffer;
    size_t data_offset;
    size_t chunk_size;
    struct connection_state *next; 

} connection_state_t;

typedef struct {
  int last_packet_acked;
  int last_packet_sent;
  int last_packet_available;
  packet_t *window[WINDOW_SIZE]; // Buffer for sent but unacknowledged packets
  struct timeval timers[WINDOW_SIZE]; 
} sender_state_t;

//===========================================
//GLOBAL VARIABLE

// Global array and counter for requested chunks.
chunk_t *requested_chunks = NULL;
int requested_num = 0;
//Global state of existing state, linked list
connection_state_t *conn_states = NULL;

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

// Helper that further processes the chunkfile to obtain each chunk_hash
// chunks I want to request, have = 0
// chunks I have, have = 1 
chunk_t *process_chunkfile(char *chunkfile, int *num_chunks, int have){
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

  if (have == 0){
    while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
      sscanf(list_elem, "%d %s", &id, hashbuf);
      res[curr].id = -1;
      hex2binary(hashbuf, 40, res[curr].hash);
      //binary2hex(res[curr].hash, 20, hashbuf);
      res[curr].peer = NULL;
      res[curr].requested = 0;
      res[curr].downloaded = 0;
      curr++;
     }
    requested_chunks = res;
    requested_num = (*num_chunks);
  } else{
    while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
      sscanf(list_elem, "%d %s", &id, hashbuf);
      res[curr].id = id;
      hex2binary(hashbuf, 40, res[curr].hash);
      //binary2hex(res[curr].hash, 20, hashbuf);
      res[curr].peer = NULL;
      res[curr].requested = 0;
      res[curr].downloaded = 1;
      curr++;
     }
  }

  return res;
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

 void get_handler(char *msg, struct sockaddr_in from, bt_config_t *config, int sock){
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

  FILE* dataFile = fopen(master_data_file, "r");

  // get_data_packet_data(f, )
  // while(fgets(list_elem, LIST_ELEM_SIZE, f) != NULL){
  //   printf("%s\n", list_elem);
  // }
  if (!dataFile) {
        perror("Failed to open master data file");
        return;
    }

  // Constants: each chunk is 512KB, and each DATA packet carries up to DATALEN bytes.
  //const int CHUNK_SIZE = 512 * 1024;  // 512 KB
  int payload_size = DATALEN;     // typically 1484 bytes per DATA packet
  int total_packets = (CHUNK_SIZE + payload_size - 1) / payload_size;

  // Seek to the correct offset in the master data file.
  long offset = id * CHUNK_SIZE;
  if (fseek(dataFile, offset, SEEK_SET) != 0) {
      perror("Failed to seek to the chunk offset in master data file");
      fclose(dataFile);
      return;
  }

  // Allocate a buffer for one chunk.
  char *chunk_buffer = malloc(CHUNK_SIZE);
  if (!chunk_buffer) {
    perror("Failed to allocate memory for chunk data");
    fclose(dataFile);
    return;
  }

  // Read the entire chunk into memory.
  size_t bytes_read = fread(chunk_buffer, 1, CHUNK_SIZE, dataFile);
  if (bytes_read != CHUNK_SIZE) {
    fprintf(stderr, "Warning: Expected to read %d bytes, but read %zu bytes\n", CHUNK_SIZE, bytes_read);
  }
  fclose(dataFile);

  // For checkpoint 1, fixed window size 8 packets.
  int window_size = 8;
  uint32_t seq_num = 1;

  // Variables to track the sending window.
  int next_packet = 0;  // index of the next packet to send
  // In a complete implementation, you’d also track ACKs and set timers for retransmission.

  // Loop over the chunk and send DATA packets.
  while (next_packet < total_packets) {
    // Send packets within the window.
    for (int i = 0; i < window_size && next_packet < total_packets; i++, next_packet++) {
      int offset_in_chunk = next_packet * payload_size;
      int current_payload = (CHUNK_SIZE - offset_in_chunk) < payload_size ? (CHUNK_SIZE - offset_in_chunk) : payload_size;

      // Create a DATA packet for this segment.
      packet_t *data_pkt = make_packet(DATA, HEADERLEN + current_payload, seq_num, 0, chunk_buffer + offset_in_chunk);
      // Send the DATA packet to the requester.
      spiffy_sendto(sock, data_pkt, HEADERLEN + current_payload, 0, (struct sockaddr *) &from, sizeof(from));
      printf("Sent DATA packet seq %d (chunk id %d) to %s:%d\n", seq_num, id,
             inet_ntoa(from.sin_addr), ntohs(from.sin_port));

      // In a full reliable implementation, start a timer for this packet here.
      free(data_pkt);
      seq_num++;
    }

  }
  free(chunk_buffer);
}

connection_state_t *get_connection_state(struct sockaddr_in *from) {
    connection_state_t *curr = conn_states;
    
    // Search for an existing connection state that matches the sender's address.
    while (curr != NULL) {
        if ((curr->addr.sin_addr.s_addr == from->sin_addr.s_addr)
            && (curr->addr.sin_port == from->sin_port )) {
            return curr;
        }
        curr = curr->next;
    }
    
    // No existing state found; allocate a new connection state.
    connection_state_t *new_state = malloc(sizeof(connection_state_t));
    if (!new_state) {
        perror("malloc for connection_state failed");
        return NULL;
    }
    
    // Copy the sender's address.
    new_state->addr = *from;
    new_state->expected_seq = 1;   // Start with sequence number 1.
    new_state->data_offset = 0;
    new_state->chunk_size = CHUNK_SIZE;
    
    // Allocate the buffer for the incoming chunk data.
    new_state->data_buffer = malloc(new_state->chunk_size);
    if (!new_state->data_buffer) {
        perror("malloc for data_buffer failed");
        free(new_state);
        return NULL;
    }
    
    // Insert the new connection state at the beginning of the global list.
    new_state->next = conn_states;
    conn_states = new_state;
    
    return new_state;
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

/**
 * process_whohas_packet
 * 
 * Process an incoming WHOHAS packet. The function extracts the number of requested hashes, 
 * checks which do I(this peer) have, and if any are found, constructs and sends an IHAVE packet.
 * 
 */
void process_whohas_packet(packet_t *pkt, struct sockaddr_in *from, char *haschunk, int sock) {

  int num_local = 0;
  chunk_t *local_chunks = process_chunkfile(haschunk, &num_local, 1);
  int hash_count = (unsigned char) pkt->data[0];
  printf("Processing WHOHAS packet: %d hash(es) requested\n", hash_count);
  
  unsigned char *available_hashes = malloc(hash_count * SHA1_HASH_SIZE);
  if (!available_hashes) {
    perror("malloc available_hashes failed");
    exit(EXIT_FAILURE);
  }
  int available_count = 0;
  
  // Iterate over each hash in the WHOHAS packet.
  for (int i = 0; i < hash_count; i++) {
    int offset = 4 + i * SHA1_HASH_SIZE;
    unsigned char *current_hash = (unsigned char *) pkt->data + offset;
      
    // Check if this hash matches any chunk in our local chunk list.
    for (int j = 0; j < num_local; j++) {
      if (memcmp(current_hash, local_chunks[j].hash, SHA1_HASH_SIZE) == 0) {
      // Match found: copy the hash into our available list.
      memcpy(available_hashes + available_count * SHA1_HASH_SIZE,
              current_hash, SHA1_HASH_SIZE);
      available_count++;
      break; // No need to check other local chunks for this hash.
      }
    }
  }
    
  // If any matching chunks were found, send an IHAVE response.
  if (available_count > 0) {
    printf("available_count: %d \n", available_count);
    int ihave_data_size = 4 + available_count * SHA1_HASH_SIZE;
    char *ihave_data = malloc(ihave_data_size);
    if (!ihave_data) {
      perror("malloc ihave_data failed");
      exit(EXIT_FAILURE);
    }
    memset(ihave_data, 0, ihave_data_size);
    ihave_data[0] = (char) available_count;
        
    // Copy each matching hash into the payload after the first 4 bytes.
    for (int i = 0; i < available_count; i++) {
      memcpy(ihave_data + 4 + i * SHA1_HASH_SIZE,
             available_hashes + i * SHA1_HASH_SIZE, SHA1_HASH_SIZE);
    }
                
    // Create the IHAVE packet. 
    packet_t *ihave_pkt = make_packet(IHAVE, HEADERLEN + ihave_data_size, 0, 0, ihave_data);
    
    // Send the IHAVE packet back to the from.
    spiffy_sendto(sock, ihave_pkt, sizeof(packet_t), 0,
                  (struct sockaddr *)from, sizeof(*from));
    printf("Sent IHAVE packet with %d hash(es) to %s:%d\n", available_count,
           inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        
    free(ihave_pkt);
    free(ihave_data);
  } else {
    printf("No matching chunks found for WHOHAS request from %s:%d\n",
           inet_ntoa(from->sin_addr), ntohs(from->sin_port));
  }
    
  free(available_hashes);
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
      case WHOHAS:{
        int hash_num = (unsigned char) pkt->data[0];
        printf("Received WHOHAS packet from %s:%d with %d hash(es)\n", 
                inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);
        process_whohas_packet(pkt, &from, (config->has_chunk_file), sock);
        break;
      }
      case IHAVE:{
        int hash_num = (unsigned char) pkt->data[0];
        printf("Received IHAVE packet from %s:%d with %d hash(es)\n", 
                inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);

        // Iterate over each hash provided in the IHAVE packet
          for (int i = 0; i < hash_num; i++) {
              int offset = 4 + i * SHA1_HASH_SIZE;
              unsigned char *ihave_hash = (unsigned char *) pkt->data + offset;
              
              // For each requested chunk, check if the hash matches
              for (int j = 0; j < requested_num; j++) {
                  // If the chunk is not yet downloaded and not already requested
                  if (requested_chunks[j].downloaded == 0 && requested_chunks[j].requested == 0) {
                      if (memcmp(ihave_hash, requested_chunks[j].hash, SHA1_HASH_SIZE) == 0) {
                          // Update the chunk's peer information with the sender's address
                          if (requested_chunks[j].peer == NULL) {
                              requested_chunks[j].peer = malloc(sizeof(struct sockaddr_in));
                              if (requested_chunks[j].peer == NULL) {
                                  perror("malloc for peer failed");
                                  exit(EXIT_FAILURE);
                              }
                          }
                          memcpy(requested_chunks[j].peer, &from, sizeof(struct sockaddr_in));
                          
                          // Mark this chunk as requested
                          requested_chunks[j].requested = 1;
                          
                          // Create a GET packet with the chunk hash as payload
                          packet_t *get_pkt = make_packet(GET, HEADERLEN + SHA1_HASH_SIZE, 0, 0, (char *)ihave_hash);
                          spiffy_sendto(sock, get_pkt, sizeof(packet_t), 0, (struct sockaddr *) &from, sizeof(from));
                          
                          // FOR DEBUGGING: print out the hash in hexadecimal format.
                          char hash_hex[SHA1_HASH_SIZE*2+1];
                          binary2hex(ihave_hash, SHA1_HASH_SIZE, hash_hex);
                          printf("Sent GET for chunk with hash %s to %s:%d\n", hash_hex,
                                 inet_ntoa(from.sin_addr), ntohs(from.sin_port));

                          free(get_pkt);
                          
                          break;
                      }
                  }
              }
          }

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
        get_handler(pkt->data, from, config, sock);

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
        connection_state_t *conn = get_connection_state(&from);
        if (!conn) {
          fprintf(stderr, "Failed to get connection state for sender %s:%d\n",
                  inet_ntoa(from.sin_addr), ntohs(from.sin_port));
          break;
        }

        // Process the DATA packet.
        if (seq_num == conn->expected_seq) {
          // Append the received data into the buffer.
          memcpy(conn->data_buffer + conn->data_offset, pkt->data, data_len);
          conn->data_offset += data_len;
          conn->expected_seq++;  // Expect the next sequence number.

          // DEBUG PURPOSE
          if (conn->data_offset >= conn->chunk_size) {
            printf("Chunk fully received from %s:%d\n", 
                   inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            // TODO: Finalize the transfer (write buffer to file, free connection state)
          }
        } else if (seq_num > conn->expected_seq) {
          // Out-of-order packet: could buffer for later reordering.
          printf("Out-of-order DATA packet: expected %d, got %d\n", conn->expected_seq, seq_num);
        } else {
          // Duplicate packet
          printf("Duplicate DATA packet: seq %d already received, ignoring.\n", seq_num);
        }

        // Send cumulative ACK
        uint32_t ack_num = conn->expected_seq - 1;
        packet_t *ack_pkt = make_packet(ACK, HEADERLEN, 0, ack_num, NULL);
        spiffy_sendto(sock, ack_pkt, HEADERLEN, 0, (struct sockaddr *)&from, sizeof(from));
        printf("Sent ACK with ack=%d to %s:%d\n", ack_num, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        free(ack_pkt);
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
      // request the chunk from an alternate peer?
      // RELATED TO CONGESTION CONTROL, CHECKPOINT 2
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
    hash_num = (i < (num_packets - 1)) ? MAX_HASH_NUM : 
                    (num_chunks % MAX_HASH_NUM ? num_chunks % MAX_HASH_NUM : MAX_HASH_NUM);

    //sanity check
    int data_size = 4 + hash_num * SHA1_HASH_SIZE;
    if (data_size > DATALEN) {
        fprintf(stderr, "Error: Data size exceeds DATALEN (%d > %d)\n", (4 + hash_num * SHA1_HASH_SIZE), DATALEN);
        exit(EXIT_FAILURE);
    }
    char *data = malloc(4 + hash_num * SHA1_HASH_SIZE);
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
  chunk_list = process_chunkfile(chunkfile, &num_chunks, 0);

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
        process_inbound_udp(sock, config);
      }
       
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
        process_user_input(STDIN_FILENO,userbuf, handle_user_input,"Currently unused", config, sock);
      }
    }
  }
}