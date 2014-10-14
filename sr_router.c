/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#define UNKOWN_TYPE -1
#define ERROR 0
#define OK 1

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    // Recognize the ethernet type
    short type = get_EtherType(packet);
    if(type == UNKOWN_TYPE)
    {
    	printf("Can't Recognize the ethernet type \n");
    	return;
    }

    // Request and respond function for ARP.
    if(type == ETHERTYPE_ARP){
    	// Get the router interfaces from the packet and initiate the apr header.
    	struct sr_if *sr_in = sr_get_interface(sr, interface);
    	struct sr_arphdr *arphdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));


    	if(sr_in == 0) {
    		printf("Bad interface \n");
    		return;
    	}

    	// Use ntohs function converts the unsigned short integer netshort from network byte order to host byte order.
    	if(ntohs(arphdr->ar_op) == ARP_REQUEST) {
    		// If it's the destination
    		if(arphdr->ar_tip == sr_in->ip){

    			unsigned int packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);

    			// Copy src, des and type to the send packet.
    			struct sr_ethernet_hdr *send_packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    			send_packet->ether_type = htons(ETHERTYPE_ARP);
    			memcpy(send_packet->ether_shost, src, ETHER_ADDR_LEN);
    			memcpy(send_packet->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);

    			// Define the arp header from the packet we receive
    			arphdr->ar_op = htons(ARP_REPLY);
    			arphdr->ar_hrd = htons(ARPHDR_ETHER);
    			arphdr->ar_hln = ETHER_ADDR_LEN;
    			arphdr->ar_pln = IP_ADDR_LEN;
    			arphdr->ar_pro = htons(ETHERTYPE_IP);
    			arphdr->ar_tip = arphdr->ar_sip;
    			arphdr->ar_sip = sr_in->ip;

    			memcpy(arphdr->ar_sha, sr_in->addr, ETHER_ADDR_LEN);
    			memcpy(arphdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);

    			// Send the packet to destinated interface.
    			// Have to cast the packet to uint8_t * to align with the sr_send_packet.
    			if(sr_send_packet(sr, (uint8_t *)send_packet, packet_len, sr_in->name)) {
    				printf("The host are unavaliable to response \n");
    			}
    			// Success to send the packet back.
    			// TODO What to respond ?
    			else {
    				// printf(" \n");
    			}

    			free(send_packet);
    		}
    		// If this is not the destination, just inform the user.
    		else
    			printf("Packet Received\n");
    	}

    	else if(ntohs(arphdr->ar_op) == ARP_REPLY) {
    			// Init and add a new arp entry.
    			struct arp_cache * cache_entry = NULL;
    			struct arp_req_cache * req = NULL;

    			// If there is no cach entry in the table, init it,
    			// otherwise, add the entry to the tail of the list.
    			if(sr->arp_cache == NULL) {
    				sr->arp_cache = malloc(sizeof(struct arp_cache));
    				cache_entry = sr->arp_cache;
    			} else {
    				cache_entry = sr->cache_entry;
    				while(cache_entry->next != NULL)
    					cache_entry = cache_entry->next;
    				cache_entry->next = malloc(sizeof(struct arp_cache));
    				cache_entry = cache_entry->next;
    			}

    			// Copy the message from the apr header to the cache entry.
    			memcpy(cache_entry->address, arphdr->ar_sha, ETHER_ADDR_LEN);
    			cache_entry->next = NULL;
    			cache_entry->ip.s_addr = arp_hdr->ar_sip;
    			cache_entry->time = time(NULL);

    			// //
    			//cache_send_outstanding(sr, record);

    			req = sr->arp_req;
    			if(req == NULL) {
    				printf("Does not have any request yet.\n");
    				return;
    			// Find the ip request in the list
    			}else{
					while(req != NULL) {
						// TODO struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr))
							// cache_entry could be arphdr->ar_sip
							if(req->ip.s_addr == cache_entry->ip.s_addr)
								// find it
								break;
							else
								req = req->next;
						}

					if(req == NULL){
						printf("Does not have any request yet.\n");
					    return;
					}
    			}

    			struct req_msg_cache *msg = NULL;
    			msg = req->msg;

    			if(msg == NULL) {
    				printf("Does not have any msg yet \n", /*inet_ntoa(arphdr->ar_sip)*/);
    			}

    			struct arp_msg_cache *prev = msg;
    			while(req != NULL) {
    				// TODO memcpy(record->address, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    				int status = 0;
    				struct sr_ethernet_hdr *eth_hdr = NULL;
    				eth_hdr = (struct sr_ethernet_hdr *)req->packet;
    				memcpy(eth_hdr->ether_dhost, cache_entry->address, ETHER_ADDR_LEN);

    				status = sr_send_packet(sr, msg->packet, msg->length, msg->interface);
    				if(status = ERROR) {
    					printf("Error when send IP packet \n");
   					}else{
   						// iterate to next msg
						free(msg->packet);
						msg = msg->next;
						free(prev);
						prev = msg;
   					}
   				}
    		}
    	}
    	/*
    	else {
    		printf("Unkown arp type"\n");
    	}
    	*/
    }
}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method: get_EtherType(uint8_t * packet)
 * Get the ethernet type from packet
 *---------------------------------------------------------------------*/
short get_EtherType(uint8_t * packet){
	// Type cast
	uint16_t type = (struct sr_ethernet_hdr *)packet->ether_type;

	// compare the type
	if(ntohs(type) == ETHERTYPE_ARP)
		return ETHERTYPE_ARP;
	else if(ntohs(type) == ETHERTYPE_IP)
		return ETHERTYPE_IP;
	else
		return UNKOWN_TYPE;
}


