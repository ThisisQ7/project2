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
#include <sys/time.h>

/* Packet and network parameters */
#define PACKETLEN       1500
#define BUFLEN          1500           /* for UDP receive buffer */
#define HEADERLEN       16
#define CHUNKHASHLEN    20
#define DATALEN         (PACKETLEN - HEADERLEN)
#define MAX_HASH_NUM    74
#define SHA1_HASH_SIZE  20
#define LIST_ELEM_SIZE  52
#define CHUNK_SIZE      (512*1024)

/* Sliding window & congestion control parameters */
#define WINDOW_SIZE     8
#define TIMEOUT         300            /* in milliseconds */
#define MAX_PACKET_SIZE 1500
#define PAYLOAD_SIZE    1484           /* equals PACKETLEN-HEADERLEN */

/* Packet type codes */
#define WHOHAS   0
#define IHAVE    1
#define GET      2
#define DATA     3
#define ACK      4
#define DENIED   5

/*==================================================*/
/* STRUCTS */

/* Listed list for peers */
struct node {
  struct sockaddr_in* peer;
  struct node* next;
};

/* A chunk to be transferred. */
typedef struct chunk_s {
  int id;
  int requested;    // 0 if no GET sent, 1 if GET already sent
  
  //NEW
  //Check: should we also mention which peer is being set as our data provider
  int downloaded;   // 0 if not downloaded yet, 1 if already downloaded
  struct node* peer_node;  // the linked list of peers that could be requested this chunk from
  uint8_t hash[SHA1_HASH_SIZE];
  char *data;
} chunk_t;

/* Common packet header. */
typedef struct header_s {
  short magicnum;
  char version;
  char packet_type;
  short header_len;
  short packet_len;
  uint32_t seq_num;
  uint32_t ack_num;
} header_t;

/* Full packet (header plus payload). */
typedef struct packet_s {
  header_t header;
  char data[DATALEN];
} packet_t;

/* Connection state for a DATA transfer. */
typedef struct connection_state {
    struct sockaddr_in addr;
    uint32_t expected_seq;
    char *data_buffer;
    size_t data_offset;
    size_t chunk_size;
    struct connection_state *next;
} connection_state_t;


//NEW
/* Sender state for congestion control (sliding window). */
typedef struct sender_state{
  struct sockaddr_in addr;     //the sender state's servicing addr can be used to check GET requests
  int last_packet_acked;
  int last_packet_sent;
  int last_packet_available;
  int window_size;
  size_t data_offset;
  size_t chunk_size;
  int chunk_id;
  packet_t *window[WINDOW_SIZE];
  struct timeval timers[WINDOW_SIZE];
  struct sender_state *next;
} sender_state_t;

//S implement
// typedef struct {
//   int last_packet_acked;
//   int last_packet_sent;
//   int last_packet_available;
//   packet_t *window[WINDOW_SIZE]; // Buffer for sent but unacknowledged packets
//   struct timeval timers[WINDOW_SIZE];
// } sender_state_t;

/*==================================================*/
/* GLOBAL VARIABLES */
chunk_t *requested_chunks = NULL;
int requested_num = 0;
char master_data_file[100];

//NEW
sender_state_t *sender_states = NULL;
connection_state_t *conn_states = NULL;

/* Global socket variable so that DATA and congestion-control routines can use it. */
int sock;

/* Global sender state for DATA transmission */
sender_state_t *window8 = NULL;

/*==================================================*/
/* FUNCTION PROTOTYPES */
packet_t *make_packet(int type, short p_len, uint32_t seq, uint32_t ack, char *data);
void peer_run(bt_config_t *config);
void get_handler(char *msg, struct sockaddr_in from, bt_config_t *config);
void ack_handler(packet_t *pack, struct sockaddr_in from, int sock);
/*==================================================*/
/* FUNCTION IMPLEMENTATIONS */

/**
 * make_packet
 *
 * Allocates and initializes a packet with a header and optional payload.
 */
packet_t *make_packet (int type, short p_len, uint32_t seq, uint32_t ack, char *data) {
    packet_t *p = (packet_t *)malloc(sizeof(packet_t));
    if (!p) {
      perror("Error allocating packet_t *p");
      exit(EXIT_FAILURE);
    }
    p->header.magicnum = htons((short)15441);
    p->header.version = (char)1;
    p->header.packet_type = (char) type;
    p->header.header_len = htons((short)HEADERLEN);
    p->header.packet_len = htons(p_len);
    p->header.seq_num = htonl(seq);
    p->header.ack_num = htonl(ack);
    if ((p_len - HEADERLEN) > DATALEN) {
        fprintf(stderr, "Error: Attempting to copy too much data into packet\n");
        exit(EXIT_FAILURE);
    }
    if (data != NULL)
        memcpy(p->data, data, p_len - HEADERLEN);
    return p;
}

/**
 * process_chunkfile
 *
 * Reads a chunk file (list of chunk ids and hex hashes) and populates an array of chunk_t.
 * If have==0 then the chunks are ones to be requested; if have==1 then they are chunks the peer owns.
 */

//NEW
//Have here seems to be all encompassing to the chunkfile parameter. 
//What if we have a mix of possessed chunks and needed chunks
chunk_t *process_chunkfile(char *chunkfile, int *num_chunks, int have) {
  FILE *f;
  char list_elem[LIST_ELEM_SIZE];
  f = fopen(chunkfile, "r");
  assert(f != NULL);

  while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
    (*num_chunks)++;
  }

  printf("number of chunks function side: %d\n", (*num_chunks));
  chunk_t *res = (chunk_t *)malloc((*num_chunks) * sizeof(chunk_t));
  fseek(f, 0, SEEK_SET);
  int curr = 0;
  int id;
  char hashbuf[40];

  if (have == 0) {
    while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
      sscanf(list_elem, "%d %s", &id, hashbuf);
      res[curr].id = -1;
      hex2binary(hashbuf, 40, res[curr].hash);
      res[curr].peer_node = NULL;
      res[curr].requested = 0;
      res[curr].downloaded = 0;
      curr++;
    }
    requested_chunks = res;
    requested_num = (*num_chunks);
  } else {
    while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
      sscanf(list_elem, "%d %s", &id, hashbuf);
      res[curr].id = id;
      hex2binary(hashbuf, 40, res[curr].hash);
      res[curr].peer_node = NULL;
      res[curr].requested = 0;
      res[curr].downloaded = 1;
      curr++;
    }
  }
  fclose(f);
  return res;
}

/**
 * packet_parser
 *
 * Checks if a received packet’s header is valid.
 */
int packet_parser(packet_t* pkt) {
  short magic = ntohs(pkt->header.magicnum);
  if (magic != 15441) {
    printf("Invalid magicnum: not 15441\n");
    return -1;
  }
  char version = pkt->header.version;
  if (version != 1) {
    printf("Invalid version: not 1\n");
    return -1;
  }
  int type = pkt->header.packet_type;
  if (type < 0 || type > 5) {
    printf("packet_type out of range, packet_type %d\n", type);
    return -1;
  }
  return type;
}

/*
* Auxilary helper function to get_sender_state's new state 
* initialization functionality. 
*
* window_init simply allocates the window for the sender_state
*/
void window_init(sender_state_t *sender){

  packet_t *instance;
  int i;
  for (i = 0; i < WINDOW_SIZE ; i++) {
    instance = make_packet(DATA, MAX_PACKET_SIZE, i+1, 0, NULL);

    printf("mallocing window indices \n");
    sender->window[i] = (packet_t *)malloc(MAX_PACKET_SIZE);
    if (sender->window[i] == NULL) {
        perror("Failed to allocate memory for window packet");
        exit(EXIT_FAILURE);
      }
    memcpy(sender->window[i], instance, MAX_PACKET_SIZE); 
    free(instance);
  }
}

/*
* Helper pair to window_init, free_window will be called 
* when we're freeing allocated state memory
 */
void free_window(sender_state_t *sender) {
  int i;

  if (sender != NULL) {
    for (i = 0; i < WINDOW_SIZE; i++) {
      if (sender->window[i]) {
        free(sender->window[i]);
      }
    }
    free(sender);
  }
}

/**
 * find_sender_state
 * 
 * Find an existing connection state for a given peer. Searches the global connection state list 
 * for a connection state matching the sender's address.
 *
 */
sender_state_t* find_sender_state(struct sockaddr_in *from) {
  sender_state_t *curr = sender_states;
  while (curr != NULL) {
      if (curr->addr.sin_addr.s_addr == from->sin_addr.s_addr &&
          curr->addr.sin_port == from->sin_port) {
          return curr;
      }
      curr = curr->next;
  }
  return NULL;
}

/*
* clear_sender_state is a helper function that readies an already allocated 
* sender_state space for a few sender connection
*/
void clear_sender_state(sender_state_t *state){
  printf("Clearing existing sender state \n");

  state->last_packet_acked = 0;   // Start with sequence number 1.
  state->last_packet_sent = 0;
  state->last_packet_available = 8;
  state->chunk_id = 0;
  state->data_offset = 0;
  state->window_size = WINDOW_SIZE;

  int i;
  for (i = 0; i < WINDOW_SIZE ; i++) {
    printf("Zeroing out window \n");
    memset(state->window[i], 0, sizeof(state->window[i]));
  }
}

/*
* get_sender_state is a helper function useful in initializing sender states
* if a state already exists, i.e. the peer was previously used, 
*   it clears it's metadata to make it ready for the next transmission phase
* otherwise, for a new peer, it initializes a new sender state
*/
sender_state_t *get_sender_state(struct sockaddr_in *from){
  sender_state_t *curr = sender_states;

  // Search for an existing sender state that matches the sender's address.
  while (curr != NULL) {
    if ((curr->addr.sin_addr.s_addr == from->sin_addr.s_addr)
        && (curr->addr.sin_port == from->sin_port )) {
          clear_sender_state(curr);
          return curr;
    }
    curr = curr->next;
  }
  
  // No existing state found; allocate a new sender state.
  sender_state_t *new_state = malloc(sizeof(sender_state_t));
  if (!new_state) {
      perror("malloc for sender_state failed");
      return NULL;
  }
  
  // Copy the sender's address.
  new_state->addr = *from;
  new_state->last_packet_acked = 0;   // Start with sequence number 1.
  new_state->last_packet_sent = 0;
  new_state->last_packet_available = 8;
  new_state->chunk_size = CHUNK_SIZE;
  new_state->window_size = WINDOW_SIZE;
  new_state->chunk_id = 0;
  
  // Allocate the buffer for the incoming chunk data.
  // new_state->window = malloc(new_state->window_size * sizeof(packet_t));
  window_init(new_state);
  if (!new_state->window) {
      perror("malloc for window failed");
      free(new_state);
      return NULL;
  }
  new_state->data_offset = 0;
  
  // Insert the new connection state at the beginning of the global list.
  new_state->next = sender_states;
  sender_states = new_state;
  
  return new_state;
 }

connection_state_t* get_connection_state(struct sockaddr_in *from) {
    // Search for an existing connection state matching the sender address.
    connection_state_t *curr = conn_states;
    while (curr != NULL) {
        if (curr->addr.sin_addr.s_addr == from->sin_addr.s_addr &&
            curr->addr.sin_port == from->sin_port) {
            return curr;
        }
        curr = curr->next;
    }
    
    // No existing connection; create a new one.
    connection_state_t *new_conn = (connection_state_t *)malloc(sizeof(connection_state_t));
    if (new_conn == NULL) {
        perror("malloc failed for connection_state_t");
        return NULL;
    }
    
    // Initialize the new connection state.
    memset(new_conn, 0, sizeof(connection_state_t));
    new_conn->addr = *from;          // Copy the sender address.
    new_conn->expected_seq = 1;        // Start expecting sequence 1.
    new_conn->chunk_size = CHUNK_SIZE; // Assuming CHUNK_SIZE is defined (512*1024).
    
    // Allocate a data buffer for the chunk.
    new_conn->data_buffer = (char *)malloc(new_conn->chunk_size);
    if (new_conn->data_buffer == NULL) {
        perror("malloc failed for data_buffer");
        free(new_conn);
        return NULL;
    }
    new_conn->data_offset = 0;
    
    // Insert the new connection at the head of the global linked list.
    new_conn->next = conn_states;
    conn_states = new_conn;
    
    return new_conn;
}

/**
 * find_connection_state
 * 
 * Find an existing connection state for a given peer. Searches the global connection state list 
 * for a connection state matching the sender's address.
 *
 */
connection_state_t* find_connection_state(struct sockaddr_in *from) {
    connection_state_t *curr = conn_states;
    while (curr != NULL) {
        if (curr->addr.sin_addr.s_addr == from->sin_addr.s_addr &&
            curr->addr.sin_port == from->sin_port) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}
/**
 * process_whohas_packet
 *
 * Processes an incoming WHOHAS packet by checking which requested chunks the peer has and
 * sending an IHAVE packet back if any matches are found.
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
  
  for (int i = 0; i < hash_count; i++) {
    int offset = 4 + i * SHA1_HASH_SIZE;
    unsigned char *current_hash = (unsigned char *) pkt->data + offset;
    for (int j = 0; j < num_local; j++) {
      if (memcmp(current_hash, local_chunks[j].hash, SHA1_HASH_SIZE) == 0) {
        memcpy(available_hashes + available_count * SHA1_HASH_SIZE,
               current_hash, SHA1_HASH_SIZE);
        available_count++;
        break;
      }
    }
  }
  
  if (available_count > 0) {
    printf("available_count: %d\n", available_count);
    int ihave_data_size = 4 + available_count * SHA1_HASH_SIZE;
    char *ihave_data = malloc(ihave_data_size);
    if (!ihave_data) {
      perror("malloc ihave_data failed");
      exit(EXIT_FAILURE);
    }
    memset(ihave_data, 0, ihave_data_size);
    ihave_data[0] = (char) available_count;
    for (int i = 0; i < available_count; i++) {
      memcpy(ihave_data + 4 + i * SHA1_HASH_SIZE,
             available_hashes + i * SHA1_HASH_SIZE, SHA1_HASH_SIZE);
    }
    packet_t *ihave_pkt = make_packet(IHAVE, HEADERLEN + ihave_data_size, 0, 0, ihave_data);
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

/**
 * handle_ihave_payload
 *
 * Processes IHAVE packet by iterating through the provided hashes.
 * For each not-downloaded hash, it adds the sender (from)
 * to the chunk's peer list.
 */
void process_ihave_packet(packet_t *pkt, struct sockaddr_in *from) {
    int hash_num = (unsigned char) pkt->data[0];
    for (int i = 0; i < hash_num; i++) {
        int offset = 4 + i * SHA1_HASH_SIZE;
        unsigned char *ihave_hash = (unsigned char *) pkt->data + offset;
        for (int j = 0; j < requested_num; j++) {
            // Update peer list for matching chunk if it hasn't been downloaded.
            if (requested_chunks[j].downloaded == 0 &&
                memcmp(ihave_hash, requested_chunks[j].hash, SHA1_HASH_SIZE) == 0) {
                // Allocate a new node for the peer.
                struct node *new_node = malloc(sizeof(struct node));
                if (!new_node) {
                    perror("malloc for node failed");
                    exit(EXIT_FAILURE);
                }
                new_node->peer = malloc(sizeof(struct sockaddr_in));
                if (!new_node->peer) {
                    perror("malloc for peer failed");
                    exit(EXIT_FAILURE);
                }
                memcpy(new_node->peer, from, sizeof(struct sockaddr_in));
                new_node->next = requested_chunks[j].peer_node;
                requested_chunks[j].peer_node = new_node;
                
                // Convert hash to hex string for printing.
                char hash_hex[SHA1_HASH_SIZE * 2 + 1];
                binary2hex(requested_chunks[j].hash, SHA1_HASH_SIZE, hash_hex);
                printf("Added peer %s:%d to chunk with hash %s\n",
                       inet_ntoa(from->sin_addr), ntohs(from->sin_port), hash_hex);
                break; // Stop checking further chunks for this hash.
            }
        }
    }
}

/**
 * process_inbound_udp
 *
 * Receives UDP packets and dispatches them based on packet type.
 */
void process_inbound_udp(int sock, bt_config_t *config) {
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);
  char buf[BUFLEN];
  int recv_len;
  //while ((recv_len = spiffy_recvfrom(sock, buf, BUFLEN, 0,
  //                                   (struct sockaddr *) &from, &fromlen)) != -1) {
  recv_len = spiffy_recvfrom(sock, buf, BUFLEN, 0,(struct sockaddr *) &from, &fromlen);
    if (recv_len < HEADERLEN) {
      printf("Received packet shorter than HEADERLEN: %d bytes\n", recv_len);
      return;
    }
    packet_t* pkt = (packet_t*) buf;
    printf("Raw Packet Received: Type=%d, Magic=%d, Length=%d\n",
           pkt->header.packet_type, ntohs(pkt->header.magicnum), ntohs(pkt->header.packet_len));
    int type = packet_parser(pkt);
    if (type == -1) {
      printf("Something is wrong, check packet type\n");
      return;
    }
    switch(type) {
      case WHOHAS: {
        int hash_num = (unsigned char) pkt->data[0];
        printf("Received WHOHAS packet from %s:%d with %d hash(es)\n",
               inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);
        process_whohas_packet(pkt, &from, config->has_chunk_file, sock);
        break;
      }
      case IHAVE: {
        int hash_num = (unsigned char) pkt->data[0];
        printf("Received IHAVE packet from %s:%d with %d hash(es)\n",
               inet_ntoa(from.sin_addr), ntohs(from.sin_port), hash_num);
        process_ihave_packet(pkt, &from);
        break;
      }
      case GET: {
        printf("Received GET packet from %s:%d\n",
               inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        /* For GET packets, we now call our integrated get_handler,
         * which will use the chunk hash to look up its id from the master chunk file,
         * initialize the sliding window, and start sending DATA packets.
         */
        get_handler(pkt->data, from, config);
        break;
      }
      case DATA: {
        uint32_t seq_num = ntohl(pkt->header.seq_num);
        int data_len = recv_len - HEADERLEN;
        printf("Received DATA packet (seq=%d) from %s:%d, data length=%d bytes\n",
               seq_num, inet_ntoa(from.sin_addr), ntohs(from.sin_port), data_len);
        connection_state_t *conn = find_connection_state(&from);
        if (!conn) {
          fprintf(stderr, "Failed to get connection state for sender %s:%d\n",
                  inet_ntoa(from.sin_addr), ntohs(from.sin_port));
          break;
        }
        if (seq_num == conn->expected_seq) {
          memcpy(conn->data_buffer + conn->data_offset, pkt->data, data_len);
          conn->data_offset += data_len;
          conn->expected_seq++;
          printf("conn->data_offset: %ld \n", conn->data_offset);
          printf("conn->chunk_size: %ld \n", conn->chunk_size );

          if (conn->data_offset >= conn->chunk_size) {
            printf("Chunk fully received from %s:%d\n",
                   inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            //remove_connection(&from);
          }
        } else if (seq_num > conn->expected_seq) {
          printf("Out-of-order DATA packet: expected %d, got %d\n", conn->expected_seq, seq_num);
        } else {
          printf("Duplicate DATA packet: seq %d already received, ignoring.\n", seq_num);
        }
        uint32_t ack_num = conn->expected_seq - 1;
        packet_t *ack_pkt = make_packet(ACK, HEADERLEN, 0, ack_num, NULL);
        //ack_pkt->header.ack_num = ack_num;
        spiffy_sendto(sock, ack_pkt, HEADERLEN, 0, (struct sockaddr *)&from, sizeof(from));
        printf("Sent ACK with ack=%d to %s:%d\n", ack_num,
               inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        free(ack_pkt);
        break;
      }
      case ACK: {
        uint32_t ack_num = ntohl(pkt->header.ack_num);
        printf("Received ACK (ack=%d) from %s:%d\n",
               ack_num, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        // TODO: Update sender state (sliding window, timers, etc.)
        ack_handler(pkt, from, sock);
        break;
      }
      case DENIED: {
        printf("Received DENIED from %s:%d\n",
               inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        // TODO: Handle denial (e.g., try another peer)
        break;
      }
      default: {
        printf("Received unknown packet type %d from %s:%d\n",
               type, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        break;
      }
    }
  //}
}

/**
 * make_whohas
 *
 * Creates an array of WHOHAS packets to request chunks.
 */
packet_t **make_whohas (chunk_t *chunks, int num_chunks) {
  int num_packets = num_chunks / MAX_HASH_NUM;
  if (num_chunks % MAX_HASH_NUM > 0)
    num_packets++;
  packet_t **whohas_packets = malloc(num_packets * sizeof(packet_t *));
  if (!whohas_packets) {
    perror("Error allocating whohas_packets");
    exit(EXIT_FAILURE);
  }
  int chunk_index = 0;
  for (int i = 0; i < num_packets; i++) {
    int hash_num = (i < (num_packets - 1)) ? MAX_HASH_NUM : 
                    (num_chunks % MAX_HASH_NUM ? num_chunks % MAX_HASH_NUM : MAX_HASH_NUM);
    int data_size = 4 + hash_num * SHA1_HASH_SIZE;
    if (data_size > DATALEN) {
        fprintf(stderr, "Error: Data size exceeds DATALEN (%d > %d)\n", data_size, DATALEN);
        exit(EXIT_FAILURE);
    }
    char *data = malloc(data_size);
    if (!data) {
      perror("Error allocating data for whohas packet");
      exit(EXIT_FAILURE);
    }
    memset(data, 0, data_size);
    data[0] = hash_num;
    for (int j = 0; j < hash_num; j++) {
      memcpy(data + 4 + j * SHA1_HASH_SIZE, chunks[chunk_index].hash, SHA1_HASH_SIZE);
      chunk_index++;
    }
    whohas_packets[i] = make_packet(WHOHAS, HEADERLEN + data_size, 0, 0, data);
    printf("Created WHOHAS packet %d: contains %d hash(es), packet length %d\n", 
           i, hash_num, HEADERLEN + data_size);
    free(data);
  }
  return whohas_packets;
}

/**
 * flood_whohas
 *
 * Sends a WHOHAS packet to every peer in the network.
 */
void flood_whohas(packet_t* whohas_packet, bt_config_t *config, int sock) {
  printf("ENTER FLOOD_WHOHAS\n");
  bt_peer_t *peer = config->peers;
  while (peer != NULL) {
    if (peer->id != config->identity) {
      printf("Flooding WHOHAS packet to peer id %d at %s:%d\n", 
             peer->id, inet_ntoa(peer->addr.sin_addr), ntohs(peer->addr.sin_port));
      spiffy_sendto(sock, whohas_packet, sizeof(packet_t), 0,
                    (struct sockaddr *) &(peer->addr), sizeof(peer->addr));
    }
    peer = peer->next;
  }
}

/**
 * send_whohas
 *
 * Creates and sends WHOHAS packets for a list of chunks.
 */
void send_whohas(chunk_t *chunks, int num_chunks, bt_config_t *config, int sock) {
  printf("ENTER SEND_WHOHAS\n");
  packet_t **whohas_packets = make_whohas(chunks, num_chunks);
  int num_packets = (num_chunks + MAX_HASH_NUM - 1) / MAX_HASH_NUM;
  for (int i = 0; i < num_packets; i++) {
    if (whohas_packets[i] != NULL) {
      flood_whohas(whohas_packets[i], config, sock);
      free(whohas_packets[i]);
      whohas_packets[i] = NULL;
    }
  }
  free(whohas_packets);
}

/**
 * process_get
 *
 * Initiates a GET request by reading the get-chunk file and flooding WHOHAS packets.
 */
void process_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock) {
  printf("PROCESS GET CALLED. (%s, %s)\n", chunkfile, outputfile);
  int num_chunks = 0;
  chunk_t *chunk_list = process_chunkfile(chunkfile, &num_chunks, 0);
  printf("number of chunks on the caller side: %d\n", num_chunks);
  send_whohas(chunk_list, num_chunks, config, sock);
}

/**
 * handle_user_input
 *
 * Processes commands entered by the user.
 */
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

/*--------------------------------------------------*/
/* New functions for congestion control and data transmission */

/**
 * lookup_id
 *
 * Given an open file (typically the master chunk file) and a chunk hash (as a hex string),
 * returns the id (i.e. position/index) for that chunk.
 */
int lookup_id(FILE *f, char *buf) {
  char list_elem[LIST_ELEM_SIZE];
  char hash[40];
  int id;
  printf("buf: %s\n", buf);
  while (fgets(list_elem, LIST_ELEM_SIZE, f) != NULL) {
    sscanf(list_elem, "%d %s", &id, hash);
    printf("hash: %s\n", hash);
    if (strcmp(hash, buf) == 0) {
      printf("id from lookup_id: %d\n", id);
      return id;
    }
  }
  return -1;
}

/**
 * send_data_packet
 *
 * Reads a PAYLOAD_SIZE chunk of data from the master data file (at an offset determined by the
 * file’s id and the sequence number) into the current window slot and sends the DATA packet.
 */
/*void send_data_packet(struct sockaddr_in from, sender_state_t *state, int sock) {
  char line[PAYLOAD_SIZE];
  int seq_num = state->last_packet_sent + 1;
  packet_t *currpack = state->window[(seq_num % WINDOW_SIZE)];
  / Calculate offset:
     Assuming each chunk is BT_CHUNK_SIZE bytes and each DATA packet carries PAYLOAD_SIZE,
     we fseek to (id * BT_CHUNK_SIZE) + (seq_num * PAYLOAD_SIZE).
     (BT_CHUNK_SIZE is assumed to be defined in chunk.h.)
  /

  FILE *f = fopen(master_data_file, "r");
  if (!f) {
    perror("Failed to open master data file");
    return;
  }

  fseek(f, state->data_offset, SEEK_SET);
  fgets(line, PAYLOAD_SIZE, f);
  memcpy(currpack->data, line, strlen(line));
  spiffy_sendto(sock, currpack, MAX_PACKET_SIZE, 0, (struct sockaddr *)&from, sizeof(from));
  state->last_packet_sent = seq_num;
}*/
void send_data_packet(struct sockaddr_in from, sender_state_t *state, int sock) {
    char line[PAYLOAD_SIZE];
    int seq_num = state->last_packet_sent + 1;
    packet_t *currpack = state->window[(seq_num % WINDOW_SIZE)];
    
    // Update the packet header with the correct sequence number.
    currpack->header.seq_num = htonl(seq_num);
    
    FILE *f = fopen(master_data_file, "r");
    if (!f) {
        perror("Failed to open master data file");
        return;
    }
    fseek(f, (state->chunk_id * CHUNK_SIZE) + (seq_num * PAYLOAD_SIZE), SEEK_SET);
    fgets(line, PAYLOAD_SIZE, f);
    memcpy(currpack->data, line, strlen(line));
    spiffy_sendto(sock, currpack, MAX_PACKET_SIZE, 0, (struct sockaddr *)&from, sizeof(from));
    state->last_packet_sent = seq_num;
    fclose(f);
}
/**
 * start_data_transmission
 *
 * Begins sending DATA packets for a requested chunk. It initializes the sliding window and then sends out
 * an initial burst of DATA packets.
 */
void start_data_transmission(int id, struct sockaddr_in from, int sock) {
  printf("In start_data_transmission\n");
  //HERE is where we start the sender state
  sender_state_t *state = get_sender_state(&from);
  state->chunk_id = id;

  printf("Window initialized\n");
  int i;
  for (i = 0; i < WINDOW_SIZE; i++) {
    state->data_offset = (state->chunk_id * BT_CHUNK_SIZE) + (i * PAYLOAD_SIZE);
    send_data_packet(from, state, sock);
  }
}

/**
 * get_handler
 *
 * Handles a GET packet by looking up the requested chunk’s id (using its hash) in the master chunk file,
 * and then starting the DATA transmission for that chunk.
 */
void get_handler(char *msg, struct sockaddr_in from, bt_config_t *config) {
  printf("Handling GET: master chunk file is %s\n", config->chunk_file);
  char buf[40];
  binary2hex(msg, 20, buf);
  FILE *f = fopen(config->chunk_file, "r");
  if (!f) {
    perror("Failed to open master chunk file in get_handler");
    return;
  }
  char list_elem[LIST_ELEM_SIZE];
  /* The first line of the master chunk file is expected to be of the form:
     "File: <master_data_file>"
  */
  fgets(list_elem, LIST_ELEM_SIZE, f);
  sscanf(list_elem, "File: %s\n", master_data_file);
  printf("Master data file: %s\n", master_data_file);
  fseek(f, 0, SEEK_SET);
  int id = lookup_id(f, buf);
  fclose(f);
  printf("Starting data transmission for chunk id %d\n", id);
  start_data_transmission(id, from, sock);
}

/*
* ack_handler updates relevant sender state, and regenerates relevant window

 */
void ack_handler(packet_t *pack, struct sockaddr_in from, int sock){
  //printf("Acknowledgeing Packet number: %d\n", pack->header.ack_num); 

  sender_state_t *state = find_sender_state(&from);
  //FILE *f = fopen(master_data_file, "r");

  int pack_ack = ntohl(pack->header.ack_num);
  
  if (state->last_packet_sent < state->last_packet_acked){
    perror("Incorrect packet sequence updating\n");
    exit(EXIT_FAILURE);
  }

  if(state->last_packet_available < pack_ack){
    perror("Packet ACK received is higher than last packet available in window\n");
    exit(EXIT_FAILURE);
  }

  if(state->last_packet_sent <= state->last_packet_acked){
    perror("Last Packet Send is lower than last packet acknowledged\n");
    exit(EXIT_FAILURE);
  }

  if (pack_ack > state->last_packet_acked){

    state->last_packet_acked = pack_ack;
    state->last_packet_available = pack_ack + WINDOW_SIZE;
    
    int seq_num;
    for (seq_num = state->last_packet_sent + 1; seq_num <= state->last_packet_available; seq_num++){
      /*state->data_offset = (state->chunk_id * CHUNK_SIZE) + (seq_num * PAYLOAD_SIZE);
      pack->header.seq_num = seq_num;
      if (state->data_offset >= state->chunk_size) {
        printf("Reach chunk_size hit!");
        break;
      }*/
      int new_offset = (state->chunk_id * CHUNK_SIZE) + (seq_num * PAYLOAD_SIZE);
      if (new_offset >= state->chunk_size) {
        printf("Reach chunk_size hit!");
        break;
      }
      send_data_packet(from, state, sock);
    }
  }
}

/**
 * peer_available
 * 
 * Determine if a peer is available to handle a download by going through the list of 
 * connection states
 * 
 */

int peer_available(struct sockaddr_in* peer) {
  connection_state_t *curr = conn_states;
    while (curr != NULL) {
        if (curr->addr.sin_addr.s_addr == peer->sin_addr.s_addr &&
            curr->addr.sin_port == peer->sin_port) {
            // Peer is already in an active download session.
            return 0;
        }
        curr = curr->next;
    }
    return 1;
}

/**
 * remove_connection
 * 
 * Remove and free the connection state for a given peer by Searching the global connection state 
 * list for a connection state matching the given peer, removes it from the list, 
 * frees its allocated resources, and then returns.
 *
 */
void remove_connection(struct sockaddr_in *peer) {
    connection_state_t *prev = NULL;
    connection_state_t *curr = conn_states;

    while (curr != NULL) {
        if (curr->addr.sin_addr.s_addr == peer->sin_addr.s_addr &&
            curr->addr.sin_port == peer->sin_port) {
            if (prev == NULL) {
                conn_states = curr->next;
            } else {
                prev->next = curr->next;
            }
            free(curr->data_buffer);
            free(curr);
            printf("Removed connection state for peer %s:%d\n",
                   inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

/**
 * download_chunk 
 * 
 * Initiate GET requests for pending chunks. Iterates over global requested_chunks. 
 * For each chunk not yet downloaded or requested with a non-empty peer list, find an available 
 * peer and sends a GET packet using the chunk's hash, then marks the chunk as requested.
 * 
 */
void download_chunk(int sock) {
  //printf("Entered download_chunk!\n");
  for (int j = 0; j < requested_num; j++) {
    // Check if the chunk has not been requested or downloaded and has available peers.
    if (requested_chunks[j].downloaded == 0 && requested_chunks[j].requested == 0 &&
        requested_chunks[j].peer_node != NULL) {

      struct node *curr = requested_chunks[j].peer_node;
      while (curr != NULL) {
        if (peer_available(curr->peer)) {
          // Mark the chunk as requested.
          requested_chunks[j].requested = 1;
          // Create and send the GET packet.
          packet_t *get_pkt = make_packet(GET, HEADERLEN + SHA1_HASH_SIZE, 0, 0,
                                          (char *)requested_chunks[j].hash);
          spiffy_sendto(sock, get_pkt, sizeof(packet_t), 0,
                        (struct sockaddr *)curr->peer, sizeof(*(curr->peer)));
          char hash_hex[SHA1_HASH_SIZE * 2 + 1];
          binary2hex(requested_chunks[j].hash, SHA1_HASH_SIZE, hash_hex);
          printf("Sent GET for chunk with hash %s to %s:%d\n", hash_hex,
                 inet_ntoa(curr->peer->sin_addr), ntohs(curr->peer->sin_port));

          // Immediately establish a connection state for the peer.
          connection_state_t *cs = get_connection_state(curr->peer);
          if (cs == NULL) {
              fprintf(stderr, "Failed to create connection state for peer %s:%d\n",
                      inet_ntoa(curr->peer->sin_addr), ntohs(curr->peer->sin_port));
          }

          free(get_pkt);
          break; // Exit the while loop; we’ve sent a GET for this chunk.
        }
        curr = curr->next;
      }
    }
  }
}
/*--------------------------------------------------*/
/* Main peer loop */

/**
 * peer_run
 *
 * Sets up the UDP socket, initializes spiffy, and enters the main loop to process incoming UDP packets
 * and user input.
 */
void peer_run(bt_config_t *config) {
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
   
  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
   
  /* Create a global UDP socket */
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
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 250000;
    nfds = select(sock+1, &readfds, NULL, NULL, &timeout);//have a timeout for select
     
    if (nfds > 0) {
      if (FD_ISSET(sock, &readfds)) {
        process_inbound_udp(sock, config);
      }
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
        process_user_input(STDIN_FILENO, userbuf, handle_user_input, "Currently unused", config, sock);
      }
    }

    //download chunk
    if(nfds == 0){
      //printf("nfds == 0 triggered!\n");
      download_chunk(sock);
    }
  }
}

/*--------------------------------------------------*/
/* Main function */

int main(int argc, char **argv) {
  bt_config_t config;
  bt_init(&config, argc, argv);
  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");
  
#ifdef TESTING
  config.identity = 1;
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