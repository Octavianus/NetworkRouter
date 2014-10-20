/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * 90904102 
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* struct of ICMP header */
/*                       */
struct sr_ICMPhdr
{
    uint8_t type;               // ICMP type
    uint8_t code;               // ICMP code
    uint16_t checksum;          // ICMP checksum
	uint16_t id;                // ICMP id
	uint16_t seq;               // ICMP seq
} __attribute__ ((packed));


/* ----------------------------------------------------------------------------
 * struct arp_cache
 *
 * ARP cache tabke stores the IP-MAC address
 * -------------------------------------------------------------------------- */
struct arp_cache{
	uint8_t address[6]; // mac
	struct in_addr ip; // ip
	time_t timestamp; // time arrive

	struct arp_cache *next;
};

/* ----------------------------------------------------------------------------
 * struct arp_msg_cache
 *
 * Store the outstanding message of both request and reply locally
 * -------------------------------------------------------------------------- */
struct arp_req_cache{
	int counter; // req counter
	time_t timestamp; // time arrive
	struct in_addr ip; // ip

	struct arp_req_cache *next;
	struct req_msg_cache *msg;
};

/* ----------------------------------------------------------------------------
 * struct arp_msg_cache
 *
 * Msg that on the waiting request.
 * -------------------------------------------------------------------------- */
struct req_msg_cache{
	uint8_t *packet;
	char *interface;
	time_t timestamp; // time arrive

	unsigned int length;
	struct req_msg_cache *next;
};

/* ----------------------------------------------------------------------------
 * struct arp_msg_cache
 *
 * Msg that on the waiting request.
 * -------------------------------------------------------------------------- */
struct msg_cache{
	uint8_t *packet;
	struct in_addr ip; // ip
	char *interface;
	int counter; // req counter
	time_t timestamp; // time arrive
	unsigned int length;
	struct msg_cache *next;
};

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */
struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct arp_cache *arp_cache;
    struct arp_req_cache *arp_req;
	struct msg_cache *msg_cache;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );
short get_EtherType(uint8_t *packet);
int Sanity_IPCheck(uint8_t *packet/*,unsigned int len*/);
uint16_t Get_cksum(uint8_t * packet, int len);

#endif /* SR_ROUTER_H */
