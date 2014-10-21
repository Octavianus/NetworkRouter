
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
#include <pthread.h>
#include <sys/time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#define NO_ARP_REC -2
#define UNKOWN_TYPE -1
#define ERROR -1
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
	sr->arp_cache = NULL;
	sr->msg_cache = NULL;

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
void Arp_Request(struct sr_instance * sr, struct in_addr dest);

/*------------------------------------------
 * Calculate the checksum of the IP header
 *------------------------------------------*/
uint32_t cal_IPchecksum(struct ip* ip_hdr) 
{
	uint32_t cksum = 0;
	uint16_t* hdr_temp = (uint16_t *) ip_hdr;

	int i;
	for (i = 0; i < ip_hdr->ip_hl * 2; i++)
		cksum = cksum + hdr_temp[i];

	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum = cksum + (cksum >> 16);

	return ~cksum;
}


/*------------------------------------------
 * Calculate the checksum of the ICMP header
 *------------------------------------------*/
uint16_t cal_ICMPcksum(uint8_t * packet, int len)
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
        return checksum;
}/* cal_ICMPcksum() */


/* ------------------------------------------------------- */
/*               packet handle function                    */
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

    // Recognize the Ethernet type
    short type = get_EtherType(packet);
    if(type == UNKOWN_TYPE)
    {
        printf("Can't Recognize the Ethernet type \n");
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

	else
	{
        printf("Unknown Ethernet type\n");
    }

} /* sr_handlepacket() */



/* ----------------- */
/* handle ARP packet */
/* ----------------- */
void sr_handleARPpacket(struct sr_instance* sr, 
        uint8_t * packet, unsigned int len,
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

		printf("get ARP_Request\n");
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

            // Send the packet to designated interface.
            // Have to cast the packet to uint8_t * to align with the sr_send_packet.
            int status;
            status = sr_send_packet(sr, (uint8_t *)send_packet, packet_len, interface);
            if(status == ERROR) {
                // printf("The host are unavaliable to response \n");
            }
            // Success to send the packet back.
            else {
                printf("Reply Packet sent for ARP request!\n");
            }

            free(send_packet);
        }
        // If this is not the destination, just inform the user.
        else
            printf("Packet Received\n");
    }

    else if(ntohs(arphdr->ar_op) == ARP_REPLY) {

			printf("get ARP_Reply\n");
            // Init and add a new arp entry.
            struct arp_cache * cache_entry = NULL;

            // If there is no cache entry in the table, init it,
            // Otherwise, add the entry to the tail of the list.
            if(sr->arp_cache == NULL) {
                sr->arp_cache = malloc(sizeof(struct arp_cache));
                cache_entry = sr->arp_cache;
            } 
			else {
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

			Search_Message_Entry(sr, arphdr->ar_sip, arphdr->ar_sha);

    }
} /*  sr_handleARPpacket  */



/*-------------------------------------------- 
 * Method: get_EtherType(uint8_t * packet)
 * Get the ethernet type from packet
 *--------------------------------------------*/
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

/*-------------------------------- 
 * Add message request to cache
 *--------------------------------*/
void Add_Message_Entry(struct sr_instance *sr, uint8_t *packet, 
		unsigned int len, char *interface_pre, char *interface, 
		struct in_addr ip)
{
	struct in_addr dest_ip = ip;
	uint8_t *packet_entry = malloc(len);
	memcpy(packet_entry, packet, len);
	struct msg_cache *msg_cache_index = sr->msg_cache;

	while(msg_cache_index != NULL)
	{
		msg_cache_index = msg_cache_index->next;
	}

	msg_cache_index = malloc(sizeof(struct msg_cache));
	if (sr->msg_cache == NULL)
	{
		sr->msg_cache = msg_cache_index;
	}

	msg_cache_index->packet = packet_entry;
	msg_cache_index->ip = ip;
	msg_cache_index->interface = interface;
	msg_cache_index->interface_pre = interface_pre;
	msg_cache_index->counter = 0;
	msg_cache_index->length = len;
	msg_cache_index->next = NULL;

	printf("add the msg entry\n");

	Arp_Request(sr, dest_ip);
	printf("send arp request\n");

} /* Add_Message_Entry() */



/*----------------------------------- 
 *  Search the waiting message with 
 *  the new IP-Mac address entry
 *-----------------------------------*/
void Search_Message_Entry(struct sr_instance *sr, uint32_t ipadr, uint8_t *eth_addr)
{
	struct arp_cache *arp_entry_index = sr->arp_cache;
	struct msg_cache *msg_cache_index = sr->msg_cache;
	struct msg_cache *pre_msg = NULL;

	while (msg_cache_index != NULL && (msg_cache_index->ip.s_addr != ipadr))
	{
		pre_msg = msg_cache_index;
		msg_cache_index = msg_cache_index->next;
	}
	printf("search msg cache\n");

	if (msg_cache_index != NULL)
	{
		printf("find a message entry\n");
		struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)(msg_cache_index->packet);
		memcpy(eth_hdr->ether_dhost, eth_addr, ETHER_ADDR_LEN);
		sr_send_packet(sr, msg_cache_index->packet, msg_cache_index->length, msg_cache_index->interface);
		printf("a waiting message been sent\n");

		if (pre_msg != NULL)
			pre_msg->next = msg_cache_index->next;
		else
			sr->msg_cache = msg_cache_index->next;
		
		free(msg_cache_index->packet);
		free(msg_cache_index);
		printf("delete sent message\n");
	}
	else
		printf("no IP matched message entry \n");
} /* Search_Message_Entry() */


/*-----------------------------------------------------------
 * Method: void Arp_Cache_Timeout(struct sr_instance *sr)
 * Calculate the timeout for arp table in every minute.
 * Remove the timeout Entry.
 *----------------------------------------------------------*/
void Arp_Cache_Timeout(struct sr_instance *sr){

	while(1){
		sleep(1);
		
		// every time calling this function, init the scan.
		struct arp_cache *curCache = NULL;
		
		if(sr->arp_cache != NULL)
			curCache = sr->arp_cache;

		if(curCache != NULL){// protect
			while(curCache != NULL){
				time_t curtime = time(NULL);
				if(difftime(curtime, curCache->timestamp) > ARP_TIMEOUT){
					struct arp_cache *freeCache = curCache;

					if(curCache->next != NULL){
						curCache = curCache->next;
						free(freeCache);
						sr->arp_cache = curCache;
					}
					else
						curCache = NULL;

				// Iterator moves forward
				}else{
					//prevCache = curCache;
					if(curCache-> next != NULL)
						curCache = curCache->next;
				}
			}
		}

		// Calculate the timeout for the outstanding request packets.
		Req_Timeout(sr);
		
	}
}


/*---------------------------------------------------------------------
 * Method: void Req_Timeout(struct sr_instance *sr)
 * Calculate the timeout for the outstanding request packets,
 * Remove the one doesn't get reply for 5 time resend
 *---------------------------------------------------------------------*/
void Req_Timeout(struct sr_instance *sr){
	struct msg_cache *curReq = NULL;
	struct msg_cache *nextReq = NULL;
	struct msg_cache *prevReq = NULL;

	curReq = sr->msg_cache;
	if(curReq != NULL){
		nextReq = curReq->next;
	}
	while(curReq != NULL)
	{

		time_t dif = difftime(time(0),curReq->timestamp);
		if(dif > PACKET_RESEND_TIME){
			if(curReq->counter >= MAX_TIME_SENT){
				// if doesn't have prevReq, free this node.
	            if (prevReq == NULL) {
	                sr->msg_cache = curReq->next;
		            // Send ICMP unreachable.
	                sr_handleICMPpacket(sr, curReq->packet , curReq->length, curReq->interface_pre, 3 , 1);
	                free(curReq);
	                curReq = curReq->next;
	            // otherwise skip  this node.
	            } else {
	                prevReq->next = curReq->next;
		            // Send ICMP unreachable.
	                sr_handleICMPpacket(sr, curReq->packet , curReq->length, curReq->interface_pre, 3 , 1);
	                free(curReq);
	                curReq = prevReq->next;
	            }
	            //sr_handleICMPpacket(sr, curReq->packet , curReq->length, curReq->interface,3 , 1);

			}else{
	        	printf("Resend arp request %d times ! \n", curReq->counter);
		        Arp_Request(sr, curReq->ip);
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


/*--------------------------------------------------------------------------
 * Method: Look_up_ARPCache(struct sr_instance * sr, struct in_addr ip)
 * Look up the arp tabele when we need to know the mac address of the 
 * destination return NO_ARP_REC if there isn't a entry in the arp table
 *-------------------------------------------------------------------------*/
struct arp_cache *Look_up_ARPCache(struct sr_instance * sr, struct in_addr ip) {
	struct arp_cache *cache_entry = NULL;

	cache_entry = sr->arp_cache;
	uint8_t addr = 0;
	printf("get into ARPCache look up\n");
	while(cache_entry != NULL) {
		if(cache_entry->ip.s_addr == ip.s_addr)
			break;
		cache_entry = cache_entry->next;
	}

	// Return the address of the entry, otherwise return an error msg
	if(cache_entry == NULL)
		addr = 0;
	else
	{
		printf("find matched IP entry %s \n",inet_ntoa(cache_entry->ip));
		addr = cache_entry->address;
	}
	
	return cache_entry;
}


/*------------------------------------------------------------------------------------
 * Method: Arp_Request(struct sr_instance * sr, char *interface, struct in_addr dest
 * Send the arp request when we need to know the mac address of the destination
 *-----------------------------------------------------------------------------------*/
void Arp_Request(struct sr_instance * sr, struct in_addr dest){

	uint8_t * packet = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));

    static uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct sr_arphdr * arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));
	struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;

	memcpy(eth_hdr->ether_dhost, broadcast_addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);

    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_hrd = ntohs(1);
    arp_hdr->ar_op = ntohs(ARP_REQUEST);
    arp_hdr->ar_pro = ntohs(ETHERTYPE_IP);
    arp_hdr->ar_tip = dest.s_addr;
	memcpy(arp_hdr->ar_tha, broadcast_addr, ETHER_ADDR_LEN);

	struct sr_if *interface = sr->if_list;

	// Broadcast to all the interface on router
	while(interface != NULL)
	{
		memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
		arp_hdr->ar_sip = interface->ip;
		int status;
		status = sr_send_packet(sr, packet, sizeof (struct sr_ethernet_hdr) + sizeof (struct sr_arphdr), interface->name);
		if(status == ERROR)
			printf("Send arp request error ! \n");
		interface = interface->next;
	}

    // Give the interface mac address and broadcast mask to the arp header.

	free(packet);
}



/* ---------------------  
 *  handle ICMP packet   
 *-----------------------*/
void sr_handleICMPpacket(
        struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface,
        unsigned int ICMP_type,
        unsigned int ICMP_code)
{
    // acquire interface name
    struct sr_if *sr_in = sr_get_interface(sr, interface);
	struct sr_if *temp_interface = sr_in;

    // ICMP message information
    if (ICMP_type == 11 && ICMP_code == 0){
        printf("TTL time out\n");}

    if (ICMP_type == 3 && ICMP_code == 1){
        printf("Host Unreachable\n");}

    if (ICMP_type == 3 && ICMP_code == 3){
        printf("Port Unreachable\n");}

    if (ICMP_type == 0 && ICMP_code == 0){
        printf("ICMP echo reply\n");}
        

    //     build ICMP packet       //           
    
	// allocate memory for the whole ICMP Ethernet packet
	uint8_t *icmp_packet = malloc(sizeof(uint8_t) * len);
    memcpy(icmp_packet, packet, len);
	
    printf("build ICMP\n");
	
    // initiate ICMP packet header
    struct sr_ICMPhdr *icmp_hdr = (struct sr_ICMPhdr *)(icmp_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    
	icmp_hdr->type = ICMP_type;
    icmp_hdr->code = ICMP_code;
	
	// encapulate ICMP packet with ethernet and IP address
    // by switching the source/destination addresses in orignal packet 
    uint8_t *ethernet_temp = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
    struct sr_ethernet_hdr *icmp_ethernet = (struct sr_ethernet_hdr *)icmp_packet;
    struct ip *icmp_ip = (struct ip *)(icmp_packet + sizeof(struct sr_ethernet_hdr));
	icmp_ip->ip_p = IPPROTO_ICMP;
   	
    memcpy(ethernet_temp, icmp_ethernet->ether_dhost, ETHER_ADDR_LEN);
	memcpy(icmp_ethernet->ether_dhost, icmp_ethernet->ether_shost, ETHER_ADDR_LEN);
    memcpy(icmp_ethernet->ether_shost, ethernet_temp, ETHER_ADDR_LEN);
	icmp_ethernet->ether_type = htons(ETHERTYPE_IP);
	
    struct in_addr ip_temp = icmp_ip->ip_dst;
	icmp_ip->ip_dst = icmp_ip->ip_src;
    icmp_ip->ip_src = ip_temp;
	if (ICMP_type != 0)      //NOT ICMP echo
		icmp_ip->ip_len = htons(sizeof(struct ip)+sizeof(struct sr_ICMPhdr)+sizeof(struct ip)+8);
		
	// change TTL in IP header
	icmp_ip->ip_ttl = 64;
	
    // calculate the IP checksum
	icmp_ip->ip_sum = 0;
    icmp_ip->ip_sum = cal_IPchecksum(icmp_ip);

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = cal_ICMPcksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
	
	// send final ICMP packet
	if (ICMP_type != 20)
		sr_send_packet(sr, icmp_packet, len, interface);
	else
		sr_send_packet(sr, icmp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ICMPhdr) + sizeof(struct ip)*2 + 8, interface);
	
	printf("ICMP message sent from %s to ", inet_ntoa(icmp_ip->ip_src));
	printf("%s\n  ", inet_ntoa(icmp_ip->ip_dst));

    free(icmp_packet);
	free(ethernet_temp);
	
} /* sr_handleICMPpacket() */



/* ---------------------  
 *  Forward IP packet   
 *-----------------------*/
void sr_IPforward(struct sr_instance* sr, 
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
	char* interface_temp = (char *)malloc(sizeof(char) * sr_IFACE_NAMELEN);
	strncpy(interface_temp, interface, sr_IFACE_NAMELEN);   // copy of the input interface;
	
    // use dest_IP address search routing table for next hop
    struct ip *ip_hdr = NULL;
    ip_hdr = (struct ip *)(sizeof(struct sr_ethernet_hdr) + packet);
    struct in_addr ip_dst_temp = ip_hdr->ip_dst;
    struct in_addr ip_nexthop;

    // searching routing table for next hop IP address
    struct sr_rt * rt_temp = sr->routing_table;
	struct sr_if *forward_if = NULL;

    while (rt_temp != NULL)
    {

        if ((rt_temp->dest.s_addr != 0) && ((ip_dst_temp.s_addr & rt_temp->mask.s_addr) == rt_temp->dest.s_addr))
        {
            printf("found next hop Ip\n");
            if (rt_temp->gw.s_addr != 0)
            {
                ip_nexthop = rt_temp->gw;
            }
            else
            {
                ip_nexthop = ip_dst_temp;
			}

			interface = (char *)(rt_temp->interface);
			forward_if = sr_get_interface(sr, interface);
			printf("next hop address %s \n", inet_ntoa(ip_nexthop));
            break;   
        }
               
        else
            rt_temp = rt_temp->next;
    }

    // not found destination IP in routing table
    // use default gateway
    if (rt_temp == NULL) 
    {
        rt_temp = sr->routing_table;
		while (rt_temp != NULL)
			if (rt_temp->dest.s_addr == 0)
			{
				ip_nexthop = rt_temp->gw;
				interface = (char *)(rt_temp->interface);
				forward_if = sr_get_interface(sr, interface);
				printf("next hop address %s \n", inet_ntoa(ip_nexthop));
				break;
			}
		else
            rt_temp = rt_temp->next;
    }
	
	// search ARP cache table find next hop mac address
    struct arp_cache *en = Look_up_ARPCache(sr, ip_nexthop);

	struct sr_ethernet_hdr *forward_ethernet = (struct sr_ethernet_hdr *)packet;
	memcpy(forward_ethernet->ether_shost, forward_if->addr, ETHER_ADDR_LEN);

    if (en != NULL)
    {
        printf("found Mac address for the destination %d, ethAddr_nexthop\n");

		memcpy(forward_ethernet->ether_dhost, en->address, ETHER_ADDR_LEN);
		sr_send_packet(sr, packet, len, interface);
		printf("send forward IP packet\n");
	}
	else 
	{
		printf("add to message cache\n");

		uint8_t * waiting_packet = malloc(len);
		memcpy(waiting_packet, packet, len);
		Add_Message_Entry(sr, waiting_packet, len, interface_temp, interface, ip_nexthop);
		free(waiting_packet);
	}

}/* sr_IPforward() */


/* ---------------------  
 *  Handle IP packet   
 *-----------------------*/
void sr_handleIPpacket(struct sr_instance* sr, 
        uint8_t * packet, unsigned int len,
        char* interface)
{
    struct ip *ip_hdr = NULL;
    ip_hdr = (struct ip *)(sizeof(struct sr_ethernet_hdr) + packet);

    printf("source IP address %s to ", inet_ntoa(ip_hdr->ip_src));
    printf("dest IP address %s \n", inet_ntoa(ip_hdr->ip_dst));

	// compare ip address and then get interface IP address
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

                // ICMP Type
                if (ip_hdr->ip_p == IPPROTO_ICMP)
                {
                    sr_handleICMPpacket(sr, packet, len, interface, 0, 0);
					printf("finish ICMP echo\n");
                    break;
                }
                // TCP/UDP type, drop the packet, send port unreachable packets
                else if (ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP)
                {             
                    sr_handleICMPpacket(sr, packet, len, interface, 3, 3);
                    break;
                }
                else 
                {
                    printf("IP type not recognized\n");
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
			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cal_IPchecksum(ip_hdr);

            if (ip_hdr->ip_ttl < 1)
            {
                printf("time limit reached");
                sr_handleICMPpacket(sr, packet, len, interface, 11, 0);
            }
            else sr_IPforward(sr, packet, len, interface);
        }
    }
   
} /* sr_handleIPpacket() */
