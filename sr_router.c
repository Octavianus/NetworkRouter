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
#include<stdbool.h>

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
    			memcpy(send_packet->ether_shost, sr_in->addr, ETHER_ADDR_LEN);
    			memcpy(send_packet->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);

    			// Define the arp header from the packet we receive
    			arphdr->ar_op = htons(ARP_REPLY);
    			arphdr->ar_hrd = htons(ARPHDR_ETHER);
    			arphdr->ar_hln = ETHER_ADDR_LEN;
    			arphdr->ar_pln = 4;
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
    				cache_entry = sr->arp_cache;
    				while(cache_entry->next != NULL)
    					cache_entry = cache_entry->next;
    				cache_entry->next = malloc(sizeof(struct arp_cache));
    				cache_entry = cache_entry->next;
    			}

    			// Copy the message from the apr header to the cache entry.
    			memcpy(cache_entry->address, arphdr->ar_sha, ETHER_ADDR_LEN);
    			cache_entry->next = NULL;
    			cache_entry->ip.s_addr = arphdr->ar_sip;
    			cache_entry->timestamp = time(NULL);

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
    				printf("Does not have any msg yet \n"/*, inet_ntoa(arphdr->ar_sip)*/);
    			}

    			struct arp_msg_cache *prev = msg;
    			while(req != NULL) {
    				// TODO memcpy(record->address, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    				int status = 0;
    				struct sr_ethernet_hdr *eth_hdr = NULL;
    				eth_hdr = (struct sr_ethernet_hdr *)msg->packet;
    				memcpy(eth_hdr->ether_dhost, cache_entry->address, ETHER_ADDR_LEN);

    				status = sr_send_packet(sr, msg->packet, msg->length, msg->interface);
    				if(status = ERROR) {
    					printf("Error when send IP packet \n");
   					}else{
   						// iterate to next msg
						free(prev);
						free(msg->packet);

						prev = msg;
						msg = msg->next;
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


/*--------------------------------------------------------------------- 
 * Method: get_EtherType(uint8_t * packet)
 * Get the ethernet type from packet
 *---------------------------------------------------------------------*/
short get_EtherType(uint8_t *packet){
	// Type cast
	struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
	uint16_t type = eth_hdr->ether_type;

	// compare the type
	if(ntohs(type) == ETHERTYPE_ARP)
		return ETHERTYPE_ARP;
	else if(ntohs(type) == ETHERTYPE_IP)
		return ETHERTYPE_IP;
	else
		return UNKOWN_TYPE;
}

/*---------------------------------------------------------------------
 * Method: Sanity_IPCheck(uint8_t * packet)
 * Get the ethernet type from packet
 *---------------------------------------------------------------------*/
int Sanity_IPCheck(uint8_t *packet/*,unsigned int len*/) {
	/*
	if(len < sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)) {
		fprintf(stderr, "Too short: ");
		return ERROR; // Too short
	}
	*/

	struct ip *ip_hdr = NULL;
	ip_hdr = (struct ip *)(sizeof(struct sr_ethernet_hdr) + packet);

	if(ip_hdr->ip_v != 4) {
		printf("It's not IPV4 \n");
		return ERROR;
	}else
	{
		uint16_t temp_checksum = ip_hdr->ip_sum;
		ip_hdr->ip_sum = 0;

		bool Invalid = false;
		uint16_t temp_val1 = Get_cksum((uint8_t *)ip_hdr, sizeof(struct ip));
		uint16_t temp_val2 = ntohs(temp_checksum);

		if(temp_val1 != temp_val2)
			Invalid = true;

			if(Invalid) {
				printf("Invalid checksum(%x/%x): ", ntohs(temp_checksum), Get_cksum((uint8_t *)ip_hdr, sizeof(struct ip)));
				return ERROR; // Checksum should be correct
			}

		ip_hdr->ip_sum = temp_checksum;
	}



	/*
	if((len - sizeof(struct sr_ethernet_hdr)) != ntohs(ip_hdr->ip_len)) {
		fprintf(stderr, "Length doesn't match: ");
		return ERROR; // Packet length does not match length field
	}
	*/

	return OK;
}

/*---------------------------------------------------------------------
 * Method: Add_Cache_Entry(uint8_t * packet)
 * Add a cache entry to the arp table
 *---------------------------------------------------------------------*/
void Add_Cache_Entry(struct sr_instance * sr, uint8_t * packet, unsigned int length, char * interface, struct in_addr ip) {

	// Define the structure of ip, rtable and arp cache.
	struct in_addr dest_ip;
	struct sr_rt * rtable = NULL;
	struct sr_arp_record *cache_entry = NULL;
	rtable = sr->routing_table;
	uint32_t mask_valid = 0;

	// struct in_addr dest_ip = next_hop_ip(sr, ip);
	// find the next destination from the rtable.
	while(rtable != NULL){
		// If the ip address with on the mask is the same in the rtable, check if the mask is a submask.
		if((ip.s_addr & rtable->mask.s_addr) == rtable->dest.s_addr)
		{
			if(rtable->mask.s_addr > mask_valid) {
				mask_valid = rtable->mask.s_addr;
			}
		}

		rtable = rtable->next;
	}

	// if the mask is 0, then return the gw address from the rtable, else the next destination ip is the input ip
	if(mask_valid == 0)
		dest_ip = sr->routing_table->gw;
	else
		dest_ip = ip;



	struct sr_arp_record * cache_lookup(struct sr_instance * sr, struct in_addr nexthop) {
		struct sr_arp_record *record = sr->cache->records;

		while(record != NULL) {
			if(record->ip.s_addr == nexthop.s_addr) break;
			record = record->next;
		}

		return record;
	}

	if(record == NULL) {
		// Check to see if there is an outstanding ARP request
		struct sr_arp_request *request = cache_lookup_outstanding(sr, dest_ip);
		if(request == NULL) {
			// Create a new ARP request
			if(arp_request(sr, dest_ip, interface) == 0) {
				request = cache_add_request(sr, dest_ip);
				// Add the recieved message to the outstanding arp request
				cache_add_message(request, packet, length, interface, ip);
			} /* endif: arp request sent succesfully */

			else {
				printf("ARP request failed for address %s - dropping packet.\n", inet_ntoa(ip));
			} /* endelse: arp request not sent succesfully */

		} /* endif: no outstanding ARP request */

		else {
			cache_add_message(request, packet, length, interface, ip);
		} /* endelse: ARP request already outstanding for this ip */

	} /* endif: No record */
	else {
		// Send packet
		struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
		memcpy(eth_hdr->ether_dhost, record->address, ETHER_ADDR_LEN);
		sr_send_packet(sr, packet, length, interface);
	} /* endelse: ARP record already exists */
}

/*---------------------------------------------------------------------
 * Method: Arp_Request(uint8_t * packet)
 * Send the arp request when we need to know the mac address of the destination
 *---------------------------------------------------------------------*/
void arp_request(struct sr_instance * sr, struct in_addr dest){

	char * next_hop = NULL;
	/*
	 *  Get the next hop
	 */

	struct sr_if *interface = sr_get_interface(sr, next_hop);

	uint8_t * packet = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));

	static uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct sr_arphdr * arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_hrd = ntohs(1);
	arp_hdr->ar_op = ntohs(ARP_REQUEST);
	arp_hdr->ar_pro = ntohs(ETHERTYPE_IP);

	memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = interface->ip;
	memcpy(arp_hdr->ar_tha, broadcast_addr, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = dest.s_addr;

	if(sr_send_packet(sr, packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), next_hop)) {
		printf("arp_request not success.\n");
		return -1;
	}

	return 0;

}



/*---------------------------------------------------------------------
 * Method: Get_cksum(uint8_t * packet, unsigned int length)
 * Calculate the checksume of the packet.
 *---------------------------------------------------------------------*/
uint16_t Get_cksum(uint8_t * packet, int len) {

	uint32_t checksum = 0;
	uint16_t* packet_temp = (uint16_t *) packet;

	int i;
	for (i = 0; i < len / 2; i++) {
		checksum = checksum + packet_temp[i];
	}

	if(len > 0)
		checksum += packet_temp[0] << 8;

	while(checksum > 0xFFFF) {
		checksum = (checksum >> 16) + (checksum & 0xFFFF);
	}

	if(~checksum)
		return ~checksum;
	else
		return 0xFFFF;

	// return ~cksum ? ~cksum : 0xFFFF;
}
