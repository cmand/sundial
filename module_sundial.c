/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP echo request (ping) scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>

#include "../../lib/includes.h"
#include "../../lib/md5.h"
#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

#define ICMP_SMALLEST_SIZE 5
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8

#define DAY_SEC (60 * 60 * 24)

#define REQ_STANDARD 1
#define REQ_BADCLOCK 2
#define REQ_BADCHECKSUM 3
#define REQ_DUPLICATETS 4

probe_module_t module_sundial;

static uint8_t requestType = REQ_STANDARD;

static int sundial_init_global(struct state_conf *conf) {
    if (conf->probe_args){
      if (atoi(conf->probe_args))
        requestType = atoi(conf->probe_args);
      else
        exit(1);
    }

    return EXIT_SUCCESS;
}

void getHash(unsigned char * digest, char * ip, uint32_t field){
  /* Get hash of IP + whatever field was passed in
   * in the uint_32 data field. */

  /* Data needs to be longer than IP + field */
  unsigned char * data = malloc(128);
  memset(data, 0, 128);

  memcpy(data, ip, strlen(ip));
  memcpy(data+strlen(ip), &field, sizeof(field));

  md5_state_t state;
  md5_init(&state);
  md5_append(&state, (const md5_byte_t *) data, strlen(ip) + sizeof(field));
  md5_finish(&state, digest);
  free(data);

}

static int sundial_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				    __attribute__((unused)) port_h_t dst_port,
				    __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);

	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct icmp) - 8);
	make_ip_header(ip_header, IPPROTO_ICMP, len);

	struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);
	make_ts_header(icmp_header);

	return EXIT_SUCCESS;
}

static int sundial_make_packet(void *buf, UNUSED size_t *buf_len,
				 ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
				 uint32_t *validation, UNUSED int probe_num,
				 UNUSED void *arg)
{
  struct ether_header *eth_header = (struct ether_header *)buf;
  struct ip *ip_header = (struct ip *)(&eth_header[1]);
  struct icmp *icmp_header = (struct icmp *)(&ip_header[1]);
  struct timeval tp;
  struct in_addr addr = { dst_ip };
  char * dst_addr = inet_ntoa(addr);
  unsigned char digest[16];
  uint32_t milliseconds, hashInt, idSeq;
  time_t sec, msec;

  /* Used for REQ_BADCLOCK, all other types store
   * hash of IP + originate timestamp  */
  uint16_t icmp_idnum = validation[1] & 0xFFFF;
  uint16_t icmp_seqnum = validation[2] & 0xFFFF;

  /* Get originate timestamp */
  if ( gettimeofday(&tp, NULL) < 0 ){
    perror("gettimeofday");
    exit(1);
  }
  sec = (tp.tv_sec % DAY_SEC) * 1000;
  msec = tp.tv_usec / 1000;
  milliseconds = htonl(sec + msec);

  switch (requestType)
  {
    case REQ_STANDARD:
    case REQ_BADCHECKSUM:
      icmp_header->icmp_otime = milliseconds;
      icmp_header->icmp_rtime = 0;
      icmp_header->icmp_ttime = 0;

      getHash(digest, dst_addr, milliseconds);
      memcpy(&hashInt,  digest + (3 * sizeof(uint32_t)), sizeof(uint32_t));

      icmp_header->icmp_id = htons(hashInt >> 16);
      icmp_header->icmp_seq = htons(hashInt & 0xffff);
      break;

    case REQ_BADCLOCK:
      idSeq = 0;
      idSeq = (icmp_idnum << 16) | icmp_seqnum;

      getHash(digest, dst_addr, idSeq);
      memcpy(&hashInt,  digest + (3 * sizeof(uint32_t)), sizeof(uint32_t));
      icmp_header->icmp_otime = htonl(hashInt);
      icmp_header->icmp_rtime = 0;
      icmp_header->icmp_ttime = 0;
   
      icmp_header->icmp_id = icmp_idnum;
      icmp_header->icmp_seq = icmp_seqnum;

      break;

    case REQ_DUPLICATETS:
      icmp_header->icmp_otime = milliseconds;
      icmp_header->icmp_rtime = milliseconds;
      icmp_header->icmp_ttime = milliseconds;

      getHash(digest, dst_addr, milliseconds);
      memcpy(&hashInt,  digest + (3 * sizeof(uint32_t)), sizeof(uint32_t));

      icmp_header->icmp_id = htons(hashInt >> 16);
      icmp_header->icmp_seq = htons(hashInt & 0xffff);
      break;
  }

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	icmp_header->icmp_cksum = 0;

  if (requestType == REQ_BADCHECKSUM){
    uint32_t checksum, tempChecksum;
    /* Calculate real checksum to make sure we don't 
     * accidentally put right one in the header*/
    tempChecksum = icmp_checksum((unsigned short *)icmp_header);

    do{
      checksum = rand();
    } while(checksum == tempChecksum);

    /* Fill in checksum */
    icmp_header->icmp_cksum = checksum;
  }
  else
    icmp_header->icmp_cksum = icmp_checksum((unsigned short *)icmp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static void sundial_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct icmp *icmp_header = (struct icmp *)(&iph[1]);

	fprintf(fp,
		"icmp { type: %u | code: %u "
		"| checksum: %#04X | id: %u | seq: %u }\n",
		icmp_header->icmp_type, icmp_header->icmp_code,
		ntohs(icmp_header->icmp_cksum), ntohs(icmp_header->icmp_id),
		ntohs(icmp_header->icmp_seq));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int sundial_validate_packet(const struct ip *ip_hdr, uint32_t len,
				uint32_t *src_ip, uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return 0;
	}
	// check if buffer is large enough to contain expected icmp header
	if (((uint32_t)4 * ip_hdr->ip_hl + ICMP_SMALLEST_SIZE) > len) {
		return 0;
	}
	struct icmp *icmp_h =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	uint16_t icmp_idnum = icmp_h->icmp_id;
	uint16_t icmp_seqnum = icmp_h->icmp_seq;
	// ICMP validation is tricky: for some packet types, we must look inside
	// the payload
	if (icmp_h->icmp_type == ICMP_TIMXCEED ||
	    icmp_h->icmp_type == ICMP_UNREACH) {
		// Should have 16B TimeExceeded/Dest_Unreachable header +
		// original IP header + 1st 8B of original ICMP frame
		if ((4 * ip_hdr->ip_hl + ICMP_TIMXCEED_UNREACH_HEADER_SIZE +
		     sizeof(struct ip)) > len) {
			return 0;
		}
		struct ip *ip_inner = (struct ip *)((char *)icmp_h + 8);
		if (((uint32_t)4 * ip_hdr->ip_hl +
		     ICMP_TIMXCEED_UNREACH_HEADER_SIZE + 4 * ip_inner->ip_hl +
		     8 /*1st 8 bytes of original*/) > len) {
			return 0;
		}
		struct icmp *icmp_inner =
		    (struct icmp *)((char *)ip_inner + 4 * ip_hdr->ip_hl);
		// Regenerate validation and icmp id based off inner payload
		icmp_idnum = icmp_inner->icmp_id;
		icmp_seqnum = icmp_inner->icmp_seq;
		*src_ip = ip_inner->ip_dst.s_addr;
		validate_gen(ip_hdr->ip_dst.s_addr, ip_inner->ip_dst.s_addr,
			     (uint8_t *)validation);
	}
	// validate icmp id and seqnum
  /*
	if (icmp_idnum != (validation[1] & 0xFFFF)) {
		return 0;
	}
	if (icmp_seqnum != (validation[2] & 0xFFFF)) {
		return 0;
	}
  */
	return 1;
}

static void sundial_process_packet(const u_char *packet,
				     __attribute__((unused)) uint32_t len,
				     fieldset_t *fs,
				     __attribute__((unused))
				     uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct icmp *icmp_hdr =
	    (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	fs_add_uint64(fs, "type", icmp_hdr->icmp_type);
	fs_add_uint64(fs, "code", icmp_hdr->icmp_code);
	fs_add_uint64(fs, "icmp_id", ntohs(icmp_hdr->icmp_id));
	fs_add_uint64(fs, "seq", ntohs(icmp_hdr->icmp_seq));
	fs_add_uint64(fs, "origin_ts", ntohl(icmp_hdr->icmp_otime));
	fs_add_uint64(fs, "receive_ts", ntohl(icmp_hdr->icmp_rtime));
	fs_add_uint64(fs, "transmit_ts", ntohl(icmp_hdr->icmp_ttime));
	switch (icmp_hdr->icmp_type) {
	case ICMP_TSTAMPREPLY:
		fs_add_string(fs, "classification", (char *)"timestampreply", 0);
		fs_add_uint64(fs, "success", 1);
		break;
	case ICMP_UNREACH:
		fs_add_string(fs, "classification", (char *)"unreach", 0);
		fs_add_bool(fs, "success", 0);
		break;
	case ICMP_SOURCEQUENCH:
		fs_add_string(fs, "classification", (char *)"sourcequench", 0);
		fs_add_bool(fs, "success", 0);
		break;
	case ICMP_REDIRECT:
		fs_add_string(fs, "classification", (char *)"redirect", 0);
		fs_add_bool(fs, "success", 0);
		break;
	case ICMP_TIMXCEED:
		fs_add_string(fs, "classification", (char *)"timxceed", 0);
		fs_add_bool(fs, "success", 0);
		break;
	default:
		fs_add_string(fs, "classification", (char *)"other", 0);
		fs_add_bool(fs, "success", 0);
		break;
	}
}

static fielddef_t fields[] = {
    {.name = "type", .type = "int", .desc = "icmp message type"},
    {.name = "code", .type = "int", .desc = "icmp message sub type code"},
    {.name = "icmp-id", .type = "int", .desc = "icmp id number"},
    {.name = "seq", .type = "int", .desc = "icmp sequence number"},
    {.name = "origin_ts", .type = "int", .desc = "originate timestamp"},
    {.name = "receive_ts", .type = "int", .desc = "receive timestamp"},
    {.name = "transmit_ts", .type = "int", .desc = "transmit timestamp"},
    {.name = "classification",
     .type = "string",
     .desc = "probe module classification"},
    {.name = "success",
     .type = "bool",
     .desc = "did probe module classify response as success"}};

probe_module_t module_sundial = {.name = "sundial",
				   .packet_length = 54,
				   .pcap_filter = "icmp[0]==14",
				   .pcap_snaplen = 96,
				   .port_args = 0,
				   .thread_initialize =
				       &sundial_init_perthread,
				   .make_packet = &sundial_make_packet,
				   .global_initialize = &sundial_init_global,
				   .print_packet = &sundial_print_packet,
				   .process_packet = &sundial_process_packet,
				   .validate_packet = &sundial_validate_packet,
				   .close = NULL,
				   .output_type = OUTPUT_TYPE_STATIC,
				   .fields = fields,
				   .numfields = 9};
