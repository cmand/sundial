/* 
 Copyright (c) 2019, Erik Rye
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of the <organization> nor the
       names of its contributors may be used to endorse or promote products
       derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AN
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 Program:      $Id: timestampAnalyzer.c$
 Author:       Erik Rye <rye@cmand.org>
 Description:  https://www.cmand.org/sundial/

  Parses and writes results from sundial pcap
*/
#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include "analysisUtils.h"
#include <ctype.h>
#include <unistd.h>
#include "md5.h" /* Alternatively, <openssl/md6.h> */

int pktcnt = 0;
char result_path[256] = {0};
struct stats total = {0};
FILE * res;

/* @brief unused */
int isCorrect(uint32_t ts_a, uint32_t ts_b){
  /* @ Determines whether two timestamps should be considered
   * "correct"
   * @ Returns 1 if ts_a and ts_b are within MAX_DIFF of
   * each other, 0 otherwise*/
    int difference = ts_a - ts_b;
    if (abs(difference) <  MAX_DIFF)
      return 1;
    return 0;
}

/* @brief unused */
int isCorrectLE(uint32_t ts_a, uint32_t ts_b){
  /* @ Determines whether two timestamps should be considered
   * "correct" if ts_b (ts_a is always the originate ts) has 
   * its endianness flipped
   * @ Returns 1 if ts_a and ts_b are within MAX_DIFF of
   * each other, 0 otherwise*/
    int difference = ts_a - htonl(ts_b);
    if (abs(difference) <  MAX_DIFF)
      return 1;
    return 0;
}

/* @brief unused */
int isCorrectMSB(uint32_t ts_a, uint32_t ts_b){
  /* @ Determines whether two timestamps should be considered
   * "correct" if the MSB of ts_b is turned off (ts_a is always
   * the originate ts)
   * @ Returns 1 if ts_a and ts_b are within MAX_DIFF of
   * each other, 0 otherwise*/
  if (ts_b < MSB)
    return 0;
     
  int difference = ts_a - (ts_b - MSB);
  if (abs(difference) <  MAX_DIFF)
    return 1;
  return 0;
}

/* @brief unused */
int isNormal(uint32_t ts_a, uint32_t ts_b){
  /* @ Determines whether a timestamp 
   * reply is "normal", which means that 0 != rx != tx != 0
   * @ Returns 1 if they're normal, 0 otherwise */
  if (ts_a != ts_b && ts_b != 0 && ts_a != 0)
      return 1;
    return 0;
}

/* @brief unused */
int isBuggy(uint32_t ts) {
  /* @ Determines whether a timestamp 
   * reply is "buggy", which means that the lower
   * two bytes are 00 00 
   * @ Returns 1 if it's, 0 otherwise */
  if (( (ts & 0x0000ffff) == 0) && ts != 0)
    return 1;
  return 0;
}

/* @brief unused */
int isLazy(uint32_t ts_a, uint32_t ts_b){
  /* @ Determines whether a timestamp 
   * reply is "lazy", which means that rx == tx != 0
   * @ Returns 1 if they're normal, 0 otherwise */
  if (ts_a == ts_b && ts_a != 0)
      return 1;
    return 0;
}

/* @brief unused */
int isNonUTC(uint32_t ts_a) {
  /* @ Determines whether a timestamp 
   * reply is non-UTC, which means that the MSB is set.
   * @ Returns 1 if it's Non-UTC, 0 otherwise */
  if ((ts_a >> 31) & 1)
      return 1;
    return 0;
}


/* @brief Writes timestamp reply message to a comma-separated line:
 * Epoch timestamp,
 * ICMP Type (should only be 14 here),
 * Respondent's src IP &,
 * Origin timestamp,
 * Receive timestamp,
 * Transmit timestamp,
 * Output of validateReply -- VALID_REPLY, BAD_CLOCK, or BAD_REPLY
 * */
void write_reply(const struct pcap_pkthdr * header, 
    struct in_addr * src_addr, struct ts_header * ts_hdr, int hashType) {
  /* Just write to a flat file for later analysis */

  /* Big-endian timestamps */
  unsigned int o_ts = htonl(ts_hdr->originate_ts);
  unsigned int rx_ts = htonl(ts_hdr->receive_ts);
  unsigned int tx_ts = htonl(ts_hdr->transmit_ts);

  fprintf(res, "%ld.%ld,%d,%s,%u,%u,%u,%d\n", header->ts.tv_sec,
      header->ts.tv_usec, ts_hdr->type, inet_ntoa(*src_addr),
          o_ts, rx_ts, tx_ts, hashType);

  return;
}

/* @brief Writes timestamp request message to a comma-separated line:
 * ICMP Type (should only be 13 here),
 * Destination IP &,
 * Origin timestamp,
 * Receive timestamp,
 * Transmit timestamp,
 * Request type -- one of NORMAL, BAD_CLOCK, BAD_CHECKSUM, DUPLICATE_TS
 */
void write_req(const struct pcap_pkthdr * header,
    struct in_addr * dst_addr, struct ts_header * ts_hdr) {
  unsigned short seq = htons(ts_hdr->seq);
  unsigned short id = htons(ts_hdr->id);
  unsigned int origin_ts = htonl(ts_hdr->originate_ts);
  unsigned int receive_ts = htonl(ts_hdr->receive_ts);
  unsigned int transmit_ts = htonl(ts_hdr->transmit_ts);

  int reqType = getReqType(dst_addr, ts_hdr);

  _DEBUG("%s%d\n", "Request type: ", reqType);

  fprintf(res, "%ld.%ld,%d,%s,%u,%u,%u,%d\n", header->ts.tv_sec,
      header->ts.tv_usec, ts_hdr->type, inet_ntoa(*dst_addr), origin_ts,
      receive_ts, transmit_ts,reqType);

  return;
}

int getReqType(struct in_addr * dst_addr, struct ts_header * ts) {
  /* This method determines which type of probe a request was in order to be
   * able to correctly categorize replies. The categories are:
   * NORMAL -- normal probe
   * BAD_CLOCK -- bad clock probe
   * BAD_CHECKSUM -- incorrect checksum
   * DUPLICATE_TS -- all three ts same
   * Returns macro for the request type.
   * */

  uint32_t seqId;

  _DEBUG("%s%s\n", "Destination IP address: ",inet_ntoa(*dst_addr));
   
  /*  DUPLICATE_TS -- Are all timestamps the same? */
  if ( (ts->originate_ts == ts->receive_ts) && (ts->originate_ts == ts->transmit_ts))
    return DUPLICATE_TS;

  /* BAD_CHECKSUM -- Calc correct checksum, compare to packet */
  else if (ts->checksum != calcChecksum(ts))
    return BAD_CHECKSUM;

  /* BAD_CLOCK -- check if originate ts is a hash of the id/seq */
  else if (validateTimestamp(inet_ntoa(*dst_addr), ts->originate_ts,
        ts->id, ts->seq) > 0 )

    return BAD_CLOCK;

  /* NORMAL -- check if the id/seq are a hash of the originate timestamp */
  else if (validateIdSeq(inet_ntoa(*dst_addr), ts->originate_ts, ntohs(ts->id),
        ntohs(ts->seq)) > 0 )
    return NORMAL;

  /* Shouldn't reach this */
  else{
    return BAD_REQUEST;
  }

}


uint16_t calcChecksum(struct ts_header * ts){
  /* Calculates the 16-bit Internet
   * checksum given an ICMP timestamp header ts.
   * Returns the checksum.
   * */
  uint16_t checksum = 0;
  uint32_t sum = 0;
  int count = sizeof(struct ts_header);
  unsigned short * ptr = (unsigned short *) ts;

  /* Zero out the checksum field if not already */
  ts->checksum = 0;

  while( count > 1 )  {
  /*  This is the inner loop */
    sum += * ptr++;
    count -= 2;
  }

  /*  Add left-over byte, if any */
  if( count > 0 )
    sum += * ptr;

  /*  Fold 32-bit sum to 16 bits */
  while (sum>>16)
     sum = (sum & 0xffff) + (sum >> 16);

  checksum = ~sum;

  return checksum;

}

/* @brief Touches results file to blow away old stuff if present */
void init_file(void){
  res = fopen(result_path, "w");
}

void handle_ts_req(const struct pcap_pkthdr * header, struct in_addr * dst_ip, struct ts_header * req){
  /* Handles timestamp request packets. 
   * Parameters: dst IP in_addr struct pointer, pointer to ts_header struct
   * Returns: void
   */

  write_req(header, dst_ip, req);

  return;
}

/* @brief: Get hash of IP + whatever field was passed in
 * in the uint_32 data field. */
void getHash(unsigned char * digest, char * ip, uint32_t field){

  /* Data needs to be longer than IP + field */
  unsigned char * data = malloc(128);
  memset(data, 0, 128);   /* Rob would bzero here */

  memcpy(data, ip, strlen(ip));
  memcpy(data+strlen(ip), &field, sizeof(field));

  md5_state_t state;

  /* Hash ends up in digest */
  md5_init(&state);
  md5_append(&state, (const md5_byte_t *) data, strlen(ip) + sizeof(field));
  md5_finish(&state, digest);
  
  free(data);
  return;
}

/* @brief MD5 produces 128 bits, only want lower 32 for tamper-detection
 * b/c that's all the room we have. Returns it in hashVal
 */
void getHashInt(unsigned char * digest, uint32_t * hashVal){
  /* Set hashVal to be the lower 32 bits of the hash digest */
  memcpy(hashVal,  digest + (3 * sizeof(uint32_t)), sizeof(uint32_t));
  return;
}

/* Validates whether the id and sequence number fields are an
 * MD5 hash of the IP + originate timestamp. 
 * @Returns: int -- 1 if id and seq fields were populated from 
 * hashing the IP + originate timestamp, -1 if not */
int validateIdSeq(char * srcIp, uint32_t originate_ts,
                  uint16_t tsId, uint16_t tsSeq) {
  uint16_t id, seq;
  uint32_t hashInt;
  unsigned char digest[16];

  /* Hash the packet's IP and originate timestamp */
  getHash(digest, srcIp, originate_ts);
  getHashInt(digest, &hashInt);
  id = hashInt >> 16;
  seq = hashInt & 0xffff;


  _DEBUG("%s%u, %s%u, %s%u, %s%u\n", "Computed Id:", id, "Computed Seq:", seq,
      "Real Id:", tsId, "Real Seq:", tsSeq);

  /* The packet's id/seq are a hash of the IP and originate ts.
   * Return success */
  if ((id == tsId) && (seq == tsSeq))
   return 1;

  /* Return failure */
  return -1;

}

/* Validates whether the originate timestamp field is an
 * MD5 hash of the IP + id/seq number (as a 32bit uint). 
 * @Returns: int -- 1 if originate timestamp field was populated from 
 * hashing the IP + id/seq numbers, -1 if not */
int validateTimestamp(char * srcIp, uint32_t originate_ts,
                  uint16_t tsId, uint16_t tsSeq) {
  uint32_t hashInt;
  uint32_t idSeq;
  unsigned char digest[16];
  
  /* Initialize the 32 bit id + seq */
  idSeq = 0;
  /* This is really only necessary b/c I dorked the zmap bad clock
   * implementation for the all v4 scan. */
  if (opt.bork) {
    originate_ts = htonl(originate_ts);
    idSeq = ((tsId << 16) & 0xffff) | tsSeq;
  }
  else{
    originate_ts = htonl(originate_ts);
    idSeq = ((idSeq | tsId) << 16) | tsSeq;
  }

  /* Hash the packet's IP and 32-bit id/seq*/
  getHash(digest, srcIp, idSeq);
  getHashInt(digest, &hashInt);

  _DEBUG("%s%u, %s%u\n", "Computed originate_ts:", hashInt, "Real originate_ts:", originate_ts);

  /* The packet's originate timestamp a hash of the IP and id/seq.
   * Return success */
  if (hashInt == originate_ts)
    return 1;

  /* Return failure */
  return -1;

}

/* @remark
 * Determines what type of timestamp request must have elicited this
 * timestamp reply by checking whether certain fields are hashes of others,
 * or it determines that the reply has been modified and can't be trusted.
 * Possible return values are (a) BAD_CLOCK -- if the originate timestamp is
 * the hash of the id/seq numbers, (b) VALID_REPLY -- if the id/seq number
 * fields are a hash of the originate timestamp + IP, this could be a reply to
 * any of the other three timestamp requests, or (c) BAD_REPLY if neither of
 * the previous are true. This means that either the IP, originate timestamp,
 * or id/seq fields have been messed with (or more).
 * */
int validateReply(struct in_addr * src_ip, struct ts_header * reply){

  /* Check whether the id/seq is a hash of the source IP + originate 
   * timestamp. This could be a reply to any of these three request types --
   * BAD_CHECKSUM, DUPLICATE_TS, or NORMAL
   * */
  if (validateIdSeq(inet_ntoa(*src_ip), reply->originate_ts,
                    ntohs(reply->id), ntohs(reply->seq)) > 0)
    return VALID_REPLY;

  /* Check whether the originate timestamp is a hash of the source IP + id/seq.
   * This means it is a reply to a BAD_CLOCK request 
   * */
  else if (validateTimestamp(inet_ntoa(*src_ip), reply->originate_ts,
                    reply->id, reply->seq) > 0)
    return BAD_CLOCK;

  /* Some field has been messed with. Can't trust */
  else
    return BAD_REPLY;
}


/* Handles timestamp reply packets. 
 * Parameters: pointer to reply source in_addr struct, 
 * pointer to ts_header struct
 * Returns: void
 */
void handle_ts_reply(const struct pcap_pkthdr * header, struct in_addr * src_ip, struct ts_header * reply){

  int replyType;
  
  /* Want to determine whether it's been mucked with or not by some middlebox */
  replyType = validateReply(src_ip, reply);

  _DEBUG("%s%d\n", "Reply type: ", replyType);

  /* Write out the reply for later analysis */
  write_reply(header, src_ip, reply, replyType); 

  return;
}

/* @brief Packet callback. Decides whether to parse packet or
 * pass. Currently just parsing replies */
void pkt_handler(u_char *args, const struct pcap_pkthdr *header, 
                const u_char *packet) {


  struct ether_header *eth_header;
  int ethernet_header_length = 14; /* Doesn't change */
  int ip_header_length;

  /* If not IP, return */
  eth_header = (struct ether_header *) packet;
  if (! (ntohs(eth_header->ether_type) == ETHERTYPE_IP) ) {
    return;
  } 

  /* Get IP header fields in IP header struct */
  const u_char * ip = packet + ethernet_header_length;
  struct ip_hdr * ip_header = (struct ip_hdr *) ip;

  ip_header_length = IP_HL(ip_header) << 2; 

  /* If protocol != ICMP, return */
  if (ip_header->ip_p != IP_ICMP) {
    return;
  }

  struct ts_header * ts_hdr = (struct ts_header *) (packet + 
                          ethernet_header_length + 
                          ip_header_length );

  
  if (opt.requests) {
    /* This is a timestamp request */
    if (ts_hdr->type == TSTAMP) {
      handle_ts_req(header, &(ip_header->ip_dst), ts_hdr);
    }
  }
 
  if (opt.replies) {
    /* This is a timestamp reply */
    if (ts_hdr->type == TSTAMP_REPLY) {
      handle_ts_reply(header, &(ip_header->ip_src), ts_hdr);
    }
  }

  return;
}

void usage(char *prog) {
  printf("Usage: %s [-qrb]\n", prog);
  printf("\t-q: don't write requests\n");
  printf("\t-r: don't write replies\n");
  printf("\t-b: b0rk BAD_CLOCK from all-v4 scan\n");
  exit(-1);
}

/* @brief Main -- Opens pcap, reads pcap, calls callback */
int main (int argc, char * argv[]){

  pcap_t * fp;
  char errbuff[PCAP_ERRBUF_SIZE];
  char * filename = NULL;
  int c;
  int index;
  opterr = 0;

  while ((c = getopt (argc, argv, "qrb")) != -1)
  switch (c)
  {
    case 'q':
      opt.requests = 0;
      break;
    case 'r':
      opt.replies = 0;
      break;
    case 'b':
      opt.bork = 1;
      break;
    default:
      usage(argv[0]);
  }

  if (!opt.requests && !opt.replies) 
    usage(argv[0]);

  filename = argv[optind];

  strncpy(result_path, argv[optind], strlen(argv[optind]));
  strncat(result_path, "_results.txt", strlen("_results.txt")+1);
  result_path[strlen(argv[optind]) + strlen("_results.txt") + 1 ] = '\0';

  init_file();

  if (NULL == (fp = pcap_open_offline(filename, errbuff))){
    perror("pcap_open_offline");
    exit(1);
  }

  /* Packet handling loop. Where the magic happens */
  pcap_loop(fp, 0, pkt_handler, NULL);

  pcap_close(fp);

  fclose(res); 
  return 0;
}
