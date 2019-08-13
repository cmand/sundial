/* analysisUtils.h
 *
 * @brief: Header file for timestampAnalysis.c
 * Contains constants, structs, prototypes for pcap parsing.
 */

#ifdef DEBUG
    #define _DEBUG(fmt, args...) fprintf(stderr,"%s:%s:%d: "fmt, __FILE__, __FUNCTION__, __LINE__, args)                                                                          
#else
    #define _DEBUG(fmt, args...)
#endif


typedef struct {
   int requests;
   int replies;
   int bork;
} options;

options opt = {0};

/* @brief Protocol-related constants */
#define IP_ICMP 1
#define TSTAMP 13
#define TSTAMP_REPLY 14

/* @brief Analysis-related constants */
#define ERROR_MARGIN .2
#define MAX_DIFF 1000 * ERROR_MARGIN
#define DAY_MS (1000 * 60 * 60 * 24)
#define HOUR_MS (1000 * 60 * 60)
#define MSB 2147483648

/* @brief Probe request types */
#define REQ_STANDARD 0
#define REQ_BADCLOCK 1
#define REQ_BADCHECKSUM 2
#define REQ_DUPLICATETS 3

/* @brief Response types */
#define VALID_REPLY 0
#define BAD_REPLY -1

/* @brief Errors */
#define BAD_REQUEST -1

/* IP header */
struct ip_hdr {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* Timestamp header */
struct ts_header {
  u_char type; /* type */
  u_char code; /* code */
  u_short checksum; /* header checksum */
  u_short id; /* identifier */
  u_short seq; /* sequence number */
  u_int originate_ts; /* originate timestamp */
  u_int receive_ts; /* receive timestamp */
  u_int transmit_ts; /* transmit timestamp */

};


void getHash(unsigned char * digest, char * ip, uint32_t field);
int validateReply(struct in_addr * src_ip, struct ts_header * reply);
int getReqType(struct in_addr * dst_addr, struct ts_header * ts);
uint16_t calcChecksum(struct ts_header * ts);
int validateTimestamp(char * srcIp, uint32_t originate_ts, uint16_t tsId,
    uint16_t tsSeq);
int validateReply(struct in_addr * src_ip, struct ts_header * reply);
int validateIdSeq(char * srcIp, uint32_t originate_ts, uint16_t tsId, uint16_t
    tsSeq);
