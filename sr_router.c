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
#include <stdbool.h>
#include <sys/time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#define NO_ARP_REC -2
#define UNKOWN_TYPE -1
#define ERROR 0
#define PACKET_RESEND_TIME 1
#define OK 1
#define MAX_TIME_SENT 5
#define ARP_TIMEOUT 15

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


void sr_handleARPpacket(struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface);
void sr_handleICMPpacket(struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface,
        unsigned int ICMP_type,
        unsigned int ICMP_code); 
void sr_handleIPpacket(struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface);  
void sr_IPforward(struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface);
void ARP_Request(struct sr_instance * sr, char *interface, struct in_addr dest);


void sr_ARPcache_update(){};
void sr_WaitingMes_update(){};
void search_WaitingMes(){};

/*void setIPchecksum(struct ip* ip_hdr) {
		uint32_t sum = 0;
		ip_hdr->ip_sum = 0;

		uint16_t* tmp = (uint16_t *) ip_hdr;

		int i;
		for (i = 0; i < ip_hdr->ip_hl * 2; i++) {
			sum = sum + tmp[i];
		}

		sum = (sum >> 16) + (sum & 0xFFFF);
		sum = sum + (sum >> 16);

		ip_hdr->ip_sum = ~sum;
	}

void setICMPchecksum(struct sr_ICMPhdr* icmphdr, uint8_t * packet, int len) {
		uint32_t sum = 0;
		icmphdr->checksum = 0;
		uint16_t* tmp = (uint16_t *) packet;

		int i;
		for (i = 0; i < len / 2; i++) {
			sum = sum + tmp[i];
		}

		sum = (sum >> 16) + (sum & 0xFFFF);
		sum = sum + (sum >> 16);

		icmphdr->checksum = ~sum;
	}*/


/*------------------------------------------
 * Calculate the checksume of the packet.
 *------------------------------------------*/
uint16_t Get_cksum(uint8_t * packet, int len) 
{

    uint32_t checksum = 0;
    uint16_t* packet_temp = (uint16_t *) packet;

    int i;
    for (i = 0; i < len / 2; i++) 
        checksum = checksum + packet_temp[i];
      
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = checksum + (checksum >> 16);
    
    if(~checksum)
        return ~checksum;
    else
        return 0xFFFF;
}/* Get_cksum() */


/* ------------------------------------------------------- */
/*               handle packet function                    */
/* set packet to process based on their types, ARP or IP   */
/* ------------------------------------------------------- */

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
    if(type == ETHERTYPE_ARP)
    {
        printf("received ARP packet\n");
        sr_handleARPpacket(sr, packet, len, interface);
    }

    // Handle the IP packet.
    else if(type == ETHERTYPE_IP)
    {
        printf("received IP packet\n");
        sr_handleIPpacket(sr, packet, len, interface);    
    }   
     /*else {
            printf("Unkown arp type"\n");
        }
        */
} /* sr_handlepacket() */



/* ----------------- */
/* handle ARP packet */
/* ----------------- */
void sr_handleARPpacket(struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
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
            uint8_t  *send_packet = (uint8_t *)malloc(sizeof(uint8_t) * len);
            memcpy(send_packet, packet, len);
            struct sr_ethernet_hdr* ethr_hd = (struct sr_ethernet_hdr *)send_packet;
            struct sr_arphdr* arp_content = (struct sr_arphdr *) (send_packet + sizeof (struct sr_ethernet_hdr));

            memcpy(ethr_hd->ether_dhost, ethr_hd->ether_shost, ETHER_ADDR_LEN);
            memcpy(ethr_hd->ether_shost, sr_in->addr, ETHER_ADDR_LEN);
            ethr_hd->ether_type = htons(ETHERTYPE_ARP);

            // Define the arp header from the packet we receive
            arp_content->ar_op = htons(ARP_REPLY);
            arp_content->ar_hrd = htons(ARPHDR_ETHER);
            arp_content->ar_hln = ETHER_ADDR_LEN;
            arp_content->ar_pro = htons(ETHERTYPE_IP);
            arp_content->ar_pln = 4;
            arp_content->ar_sip = sr_in->ip;

            memcpy(arp_content->ar_sha, sr_in->addr, ETHER_ADDR_LEN);
            memcpy(arp_content->ar_tha, ethr_hd->ether_dhost, ETHER_ADDR_LEN);

            // exchange the ip address.
            uint32_t ip_t = arp_content->ar_tip;
            arp_content->ar_tip = arp_content->ar_sip;
            arp_content->ar_sip = ip_t;

            // Send the packet to destinated interface.
            // Have to cast the packet to uint8_t * to align with the sr_send_packet.
            int status;
            status = sr_send_packet(sr, (uint8_t *)send_packet, packet_len, interface);
            if(status == ERROR) {
                // printf("The host are unavaliable to response \n");
            }
            // Success to send the packet back.
            // TODO What to respond ?
            else {
                // printf("Packet send from ARP request!\n");
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
                if(status == ERROR) {
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
} /*  sr_handleARPpacket  */

        


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
 * Method: Add_Cache_Entry(struct sr_instance * sr, uint8_t * packet, unsigned int length, char * interface, struct in_addr ip)
 * Add request entry to the arp table
 *---------------------------------------------------------------------*/
void Add_Cache_Entry(struct sr_instance * sr, uint8_t * packet, unsigned int length, char * interface, struct in_addr ip) {

    // Define the structure of ip, rtable and arp cache.
    struct in_addr dest_ip;
    struct sr_rt * rtable = NULL;
    struct arp_cache *cache_entry = NULL;
    rtable = sr->routing_table;

    // If it does not have the ip in the cache table, check if there is already an arp request
    struct arp_req_cache *req = NULL;
    req = sr->arp_req;

    if(req == NULL)
    {
    	printf("Request table does not have any record yet \n");
    }
    else{
    	while(req != NULL) {
    		if(req->ip.s_addr == dest_ip.s_addr)
    			break;
    		req = req->next;
    	}
    }

    // If have not received the req that has the same ip yet, add a new req.
    if(req == NULL) {
    	// send arp request if this is the first request.
    	Arp_Request(sr, interface, dest_ip);
    	struct req_msg_cache *msg = NULL;
    	req = sr->arp_req;
    	msg = req->msg;

    	// If the req cache are not initialize yet
    	if(req == NULL) {
    		sr->arp_req = malloc(sizeof(struct arp_req_cache));
    		req = sr->arp_req;
    	}// else allocate a new memory space for the request
    	else{
    		while(req != NULL)
    			req = req->next;
    		req = malloc(sizeof(struct arp_req_cache));
    	}
    	req->msg = NULL;
    	req->msg = malloc(sizeof(struct req_msg_cache));
    	msg = req->msg;

    	/*
		if(msg == NULL) {
			req->msg = malloc(sizeof(struct req_msg_cache));
			msg = req->msg;
		}
		else {
			while(msg != NULL)
				msg = msg->next;
			msg = malloc(sizeof(struct req_msg_cache));
			//msg = msg->next;
		}
    	*/

    	// TODO change it
    	req->ip = ip;
    	req->counter = 1;
    	req->timestamp = time(NULL);
    	req->next = NULL;
    	uint8_t *pcopy = malloc(length);
    	memcpy(pcopy, packet, length);
    	msg->length = length;
    	msg->interface = interface;
    	msg->packet = pcopy;
    	msg->next = NULL;

    }
    // If already received the req, add a msg to that req.
    else
    {
    	struct req_msg_cache *msg = NULL;
    	msg = req->msg;

    	/* Allocate memory for message struct */
    	if(msg == NULL) {
    		req->msg = malloc(sizeof(struct req_msg_cache));
    		msg = req->msg;
    	}
    	else {
    		while(msg != NULL)
    			msg = msg->next;
    		msg = malloc(sizeof(struct req_msg_cache));
    		//msg = msg->next;
    	}

    	// TODO change it
    	uint8_t *pcopy = malloc(length);
    	memcpy(pcopy, packet, length);
    	msg->length = length;
    	msg->interface = interface;
    	msg->packet = pcopy;
    	msg->next = NULL;
    }
}
// if there already have that cache entry in the table, just send the packet.

void *Arp_Cache_Timeout(struct sr_instance *sr){

	while(1){
		sleep(1);

		// every time calling this function, init the scan.
		struct arp_cache *curCache = &(sr->arp_cache);
		struct arp_cache *prevCache = curCache;

		if(curCache != NULL){// protect
			while(curCache != NULL){
				time_t curtime = time(NULL);
				if(curtime - curCache->timestamp > ARP_TIMEOUT){
					struct arp_cache *freeCache = curCache;
					prevCache->next = curCache->next;
					curCache = curCache->next;
					free(freeCache);
				// Iterator moves forward
				}else{
					prevCache = curCache;
					curCache = curCache->next;
				}
			}
		}

		Req_Timeout(sr);
	}
}

void Req_Timeout(struct sr_instance *sr){
	struct arp_req_cache *curReq = NULL;
	struct arp_req_cache *nextReq = NULL;
	struct arp_req_cache *prevReq = NULL;

	curReq = sr->arp_req;
	if(curReq != NULL){
		nextReq = curReq->next;
	}
	while(curReq != NULL)
	{


		time_t dif = difftime(time(0),curReq->timestamp);
		if(dif > PACKET_RESEND_TIME){
			if(curReq->counter >= MAX_TIME_SENT){

				// icmp unreacheable

				// if doesn't have prevReq, free this node.
	            if (!prevReq) {
	                sr->arp_req = curReq->next;
	                free(curReq);
	                curReq = curReq->next;
	            // otherwise skip  this node.
	            } else {
	                prevReq->next = curReq->next;
	                free(curReq);
	                curReq = prevReq->next;
	            }
			}else{
	        	printf("Resend arp request ! \n");

	        	// next_hop

		        //Arp_Request(sr, next_hop(sr_handle, reqs->ip, curReq->ip));
		        curReq->counter++;
		        curReq->timestamp = time(NULL);
			}
		}

		prevReq = curReq;
		curReq = nextReq;
		if(curReq != NULL)
			nextReq = curReq->next;
	}
}

/*---------------------------------------------------------------------
 * Method: Look_up_ARPCache(struct sr_instance * sr, struct in_addr ip)
 * Look up the arp tabele when we need to know the mac address of the destination
 *
 * return NO_ARP_REC if there isn't a entry in the arp table
 *---------------------------------------------------------------------*/
uint8_t Look_up_ARPCache(struct sr_instance * sr, struct in_addr ip) {
	struct arp_cache *cache_entry = NULL;

	cache_entry = sr->arp_cache;
	uint8_t addr;

	while(cache_entry != NULL) {
		if(cache_entry->ip.s_addr == ip.s_addr)
			break;
		cache_entry = cache_entry->next;
	}

	// Return the address of the entry, otherwise return an error msg
	if(cache_entry == NULL)
		addr = NO_ARP_REC;
	else
		addr = cache_entry->address;

	cache_entry = NULL;
	return addr;
}


/*---------------------------------------------------------------------
 * Method: Arp_Request(struct sr_instance * sr, char *interface, struct in_addr dest)
 * Send the arp request when we need to know the mac address of the destination
 *---------------------------------------------------------------------*/
void Arp_Request(struct sr_instance * sr, char *intf, struct in_addr dest){

    // char * next_hop = NULL;
    // Get the next hop

	// find out the interface
    struct sr_if *interface = sr_get_interface(sr, intf);

    uint8_t * packet = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));

    static uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct sr_arphdr * arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_hrd = ntohs(1);
    arp_hdr->ar_op = ntohs(ARP_REQUEST);
    arp_hdr->ar_pro = ntohs(ETHERTYPE_IP);
    arp_hdr->ar_tip = dest.s_addr;

    // Give the interface mac address and broadcast mask to the arp header.
    memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = interface->ip;
    memcpy(arp_hdr->ar_tha, broadcast_addr, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = dest.s_addr;

    int status;
    status = sr_send_packet(sr, packet, sizeof (struct sr_ethernet_hdr) + sizeof (struct sr_arphdr), interface->name);
    if(status == ERROR)
        printf("Send arp request error ! \n");

	free(packet);
}


/*   handle ICMP packet   */
void sr_handleICMPpacket(
        struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface,
        unsigned int ICMP_type,
        unsigned int ICMP_code)
{
    // aquire interface name
    struct sr_if *sr_in = sr_get_interface(sr, interface);

    /* ---------------------------------- */
    /* the ICMP type and code       */
    /* ---------------------------------- */

    // ICMP message information
    if (ICMP_type == 11 && ICMP_code == 0){
        printf("TTL time out\n");}

    if (ICMP_type == 3 && ICMP_code == 1){
        printf("Host Unreachable\n");}

    if (ICMP_type == 3 && ICMP_code == 3){
        printf("Port Unreachable\n");}

    // ??? need differentiate ICMP reply or request
    if (ICMP_type == 0 && ICMP_code == 0){
        printf("ICMP echo reply\n");}
        

    /* ---------------------------------- */
    /* build ICMP packet                  */
    /* ---------------------------------- */

    // allocate memory for the whole ICMP ethernet packet
    uint8_t *icmp_packet = malloc(sizeof(uint8_t) * len);
    memcpy(icmp_packet, packet, len);
	
    printf("build ICMP\n");
    // initiate ICMP packet header
    struct sr_ICMPhdr *icmp_hdr = (struct sr_ICMPhdr *)(icmp_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    icmp_hdr->type = ICMP_type;
    icmp_hdr->code = ICMP_code;

	// recalculate checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = Get_cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
	
    // encapulate ICMP packet with ethernet and IP address
    // by switching the source/destination addresses in orignal packet 
    uint8_t *ethernet_temp = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
    struct sr_ethernet_hdr *icmp_ethernet = (struct sr_ethernet_hdr *)icmp_packet;
    struct ip *icmp_ip = (struct ip *)(icmp_packet + sizeof(struct sr_ethernet_hdr));
   
    memcpy(ethernet_temp, icmp_ethernet->ether_dhost, ETHER_ADDR_LEN);
    memcpy(icmp_ethernet->ether_dhost, icmp_ethernet->ether_shost, ETHER_ADDR_LEN);
    memcpy(icmp_ethernet->ether_shost, ethernet_temp, ETHER_ADDR_LEN);
	icmp_ethernet->ether_type = htons(ETHERTYPE_IP);
	
    struct in_addr ip_temp = icmp_ip->ip_dst;
	icmp_ip->ip_dst = icmp_ip->ip_src;
    icmp_ip->ip_src = ip_temp;
			
	// change TTL in IP header
	icmp_ip->ip_ttl = 64;
	
    // calculate the IP checksum
	icmp_ip->ip_sum = 0;
    icmp_ip->ip_sum = Get_cksum(icmp_ip, sizeof(struct ip));
	
	// send final ICMP packet	
    sr_send_packet(sr, icmp_packet, len, interface);
	printf("ICMP message sent from %s to ", inet_ntoa(icmp_ip->ip_src));
	printf("%s\n  ", inet_ntoa(icmp_ip->ip_dst));

    free(icmp_packet);
	free(ethernet_temp);
	
} /* sr_handleICMPpacket() */



/* handle forwarding IP packets */
void sr_IPforward(struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
    // use dest_IP address search routing table for next hop
    struct ip *ip_hdr = NULL;
    ip_hdr = (struct ip *)(sizeof(struct sr_ethernet_hdr) + packet);
    struct in_addr ip_dst_temp = ip_hdr->ip_dst;
    struct in_addr ip_nexthop;

    // searching routing table for next hop IP address
    struct sr_rt * rt_temp = sr->routing_table;
    while (rt_temp != NULL)
    {
        if (ip_dst_temp.s_addr == rt_temp->dest.s_addr)
        {
            ip_nexthop = rt_temp->gw;
            interface = (char *)(rt_temp->interface);
            break;
        }

        else
            rt_temp = rt_temp->next;
    }

    // not found destination IP in routing table
    // send ICMP, desitination unreachble error message
    if (rt_temp == NULL)
        sr_handleICMPpacket(sr, packet, len, interface, 3, 6);

    // found next hop of the destination IP
    if (rt_temp != NULL)
    {
        // searh ARP cache table find next hop mac address
        uint8_t ethAddr_nexthop = Look_up_ARPCache(sr, ip_nexthop);
        if (ethAddr_nexthop != NO_ARP_REC)
        {
            struct sr_ethernet_hdr *forward_ethernet = (struct sr_ethernet_hdr *)packet;
            memcpy(forward_ethernet->ether_shost, forward_ethernet->ether_dhost, ETHER_ADDR_LEN);
            memcpy(forward_ethernet->ether_dhost, &ethAddr_nexthop, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, interface);

        }

        else
            Add_Cache_Entry(sr, packet, len, interface, ip_nexthop);
    }

    // use next hop IP find its mac addr
    // if not in ARP table, send request
    // no ARP request, drop the packet, send ICMP response


}/* sr_IPforward() */


/* handle IP packet */
void sr_handleIPpacket(struct sr_instance* sr, 
        uint8_t * packet, unsigned int len,
        char* interface)
{
    struct ip *ip_hdr = NULL;
    ip_hdr = (struct ip *)(sizeof(struct sr_ethernet_hdr) + packet);
    
    // recalculate checksum
    //uint16_t checksum_received = Get_cksum(packet, len);

    // compare ip address
    // get interface IP address
    struct sr_if *sr_in = sr_get_interface(sr, interface);

    if (sr_in == 0)     
    {
        printf("Bad interface \n");
        return;
    }
    else 
    {
        struct sr_if *temp_interface = sr_in;

        // check if destination IP address is the router
        while (temp_interface)
        {
            if (temp_interface->ip == ip_hdr->ip_dst.s_addr) 
            {
                printf("destination is the router\n");

                // ICMP type
                if (ip_hdr->ip_p == IPPROTO_ICMP)
                {
                    sr_handleICMPpacket(sr, packet, len, interface, 0, 0);
					printf("finish ICMP echo\n");
                    break;
                }
                // TCP/UDP type, drop the packet, send port unreachable packets
                else if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP)
                {
                    if (ip_hdr->ip_p == IPPROTO_TCP)
                        printf("ip type TCP\n");
                    if (ip_hdr->ip_p == IPPROTO_TCP)
                        printf("ip type UDP\n");

                        sr_handleICMPpacket(sr, packet, len, interface, 3, 3);
                        break;


                }
                else 
                {
                    printf("ip type not recognized\n");
                    break;
                }
            }

            temp_interface = temp_interface->next;
        }

        // destination IP address is not the router
        if (temp_interface == NULL)
        {
            printf("destination is not the router\n");

            // decrease TTL, if = 0, ICMP error message
            ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;

            // recal checksum
            ip_hdr->ip_sum = Get_cksum(ip_hdr, sizeof(struct ip));

            if (ip_hdr->ip_ttl < 1)
            {
                printf("time limit reached");
                sr_handleICMPpacket(sr, packet, len, interface, 11, 0);
            }
            else sr_IPforward(sr, packet, len, interface);
        }
    }
   

    // check Checksum, not correct, ICMP error message
    // Des IP is router, TCP/UDP, ICMP error message
    // Des IP is router, ICMP, ICMP reply
    // Des IP is other, IP forward, DesIP not in the table, ICMP error message
    // Des IP is other, IP forward, find MAC address, in the cache, pack send
    // Des IP is other, IP forward, find MAC address, not in the cache, ARPrequest, wait 5 seconds, no reply, ICMP error message
    // Des IP is other, IP forward, find MAC address, not in the cache, ARPrequest, wait, get reply, pack send

} /* sr_handleIPpacket() */
