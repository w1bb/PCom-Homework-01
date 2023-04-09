#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/netdevice.h>

#include "protocols.h"
#include "lib.h"
#include "queue.h"
#include "trie.h"
#include "io.h"
#include "list.h"

#define get_best_route trie_search

void decrease_ttl(struct iphdr *ip_hdr) {
	uint16_t old_ttl = *((uint16_t *)&(ip_hdr->ttl));
    --ip_hdr->ttl;
	ip_hdr->check -= (~old_ttl) + *((uint16_t *)&(ip_hdr->ttl)) + 1;
}

list arp_table;

struct arp_entry *get_arp_entry(uint32_t given_ip) {
  printf("Entered get_arp_entry\n");
    printf(">>>>>>>>>>>JUST PRINTING STH %p\n", arp_table);
	for (list entry = arp_table; entry; entry = entry->next)
		if (((struct arp_entry *)(entry->element))->ip == given_ip)
			return (struct arp_entry *)(entry->element);
  printf("Will return NULL\n");
	return NULL;
}

void send_arp(uint32_t dest_addr,
              uint32_t send_addr,
              struct ether_header *eth_hdr,
              int interface,
              uint16_t op) {
    struct arp_header arp_hdr;
    arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	arp_hdr.op = op;
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	arp_hdr.spa = send_addr;
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, 6);
	arp_hdr.tpa = dest_addr;

    char frame_data[2048] = {};
    int length = 0;
    memcpy(frame_data,
           eth_hdr,
           sizeof(struct ether_header));
    length += sizeof(struct ether_header);
    memcpy(frame_data + length,
           &arp_hdr,
           sizeof(struct arp_header));
    length += sizeof(struct arp_header);
    send_to_link(interface, frame_data, length);
}

void send_arp_request(int interface,
					  struct ether_header *eth_hdr,
					  struct arp_header *arp_hdr) {
  printf("Entered send_arp_request\n");
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
	get_interface_mac(interface, eth_hdr->ether_shost);
  	
	struct in_addr router_ip;
	inet_aton(get_interface_ip(interface), &router_ip);

	send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, interface, htons(ARPOP_REPLY));
}

void send_arp_reply(struct arp_header *arp_hdr, queue *q) {
  printf("Entered send_arp_reply\n");
	struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
	new_entry->ip = arp_hdr->spa;
	memcpy(new_entry->mac, arp_hdr->sha, 6); 
	arp_table = cons(new_entry, arp_table);
    printf("! ! ! ! Consing with ip %u\n", new_entry->ip);
	while (!queue_empty(*q)) {
        printf("Freeing up the queue...\n");
		void *interface_p = queue_deq(*q);
		void *frame_data_p = queue_deq(*q);
		void *length_p = queue_deq(*q);
        printf(">>>FIND %d %lu...\n", *(int *)interface_p, *(size_t *)length_p);

		struct ether_header *new_eth_hdr = (struct ether_header *)frame_data_p;
		memcpy(new_eth_hdr->ether_dhost, arp_hdr->sha, 6); 
		send_to_link(*(int *)interface_p,
					 (char *)frame_data_p,
					 *(size_t *)length_p);
		free(interface_p);
		free(length_p);
	}
}

void missing_mac(int length, char *frame_data, size_t interface,
                 queue *q, struct route_table_entry *best_route) {
  printf("Entered no_mac_situation\n");
    int *interface_p = malloc(sizeof(int));
    *interface_p = best_route->interface;
    queue_enq(*q, interface_p);
    printf("[ missing mac ] Added to queue\n");

    char *frame_data_p = malloc(length + 1);
    // TODO - might need to free
    memcpy(frame_data_p, frame_data, length);
    queue_enq(*q, frame_data_p);
    
    size_t *length_p = malloc(sizeof(size_t));
    *length_p = length;
    queue_enq(*q, length_p);

    printf(">>>PUSH %d %lu...\n", *(int *)interface_p, *(size_t *)length_p);


    struct ether_header *eth_hdr = (struct ether_header *)frame_data;
    get_interface_mac(best_route->interface, eth_hdr->ether_shost);
    
    memset(eth_hdr->ether_dhost, 0xff, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    struct in_addr best_interface;
    inet_aton(get_interface_ip(best_route->interface), &best_interface);

    send_arp(best_route->next_hop, best_interface.s_addr, eth_hdr,
             best_route->interface, htons(ARPOP_REQUEST));
}

void send_icmp(uint32_t dest_addr,
               uint32_t send_addr,
               uint8_t *sha,
               uint8_t *dha,
               uint8_t icmp_type,
               uint8_t icmp_code,
               int interface,
               int id,
               int sequence) {
    // Generate ether header
    struct ether_header eth_hdr;
    memcpy(eth_hdr.ether_dhost, dha, 6);
    memcpy(eth_hdr.ether_shost, sha, 6);
    eth_hdr.ether_type = htons(ETHERTYPE_IP);

    // Generate ICMP header
    struct icmphdr icmp_hdr;
    icmp_hdr.type = icmp_type;
    icmp_hdr.code = icmp_code;
    icmp_hdr.checksum = 0;
    icmp_hdr.un.echo.id = id;
    icmp_hdr.un.echo.sequence = sequence;
    // Compute checksum
    icmp_hdr.checksum = checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

    // Generate IP header
    struct iphdr ip_hdr;
    ip_hdr.ihl = 5;
    ip_hdr.version = 4;
	ip_hdr.tos = 0;
    ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.check = 0;
	ip_hdr.saddr = send_addr;
	ip_hdr.daddr = dest_addr;
    // Compute checksum
    ip_hdr.check = checksum((uint16_t *)&ip_hdr, sizeof(struct iphdr));

    // Compute data to send
    char frame_data[2048] = {};
    int length = 0;
    memcpy(frame_data,
           &eth_hdr,
           sizeof(struct ether_header));
    length += sizeof(struct ether_header);
    memcpy(frame_data + length,
           &ip_hdr,
           sizeof(struct iphdr));
    length += sizeof(struct iphdr);
    memcpy(frame_data + length,
           &icmp_hdr,
           sizeof(struct icmphdr));
    length += sizeof(struct icmphdr);
    send_to_link(interface, frame_data, length);
}

int send_icmp_echo(struct in_addr ip_router,
                   struct ether_header *eth_hdr,
                   struct iphdr *ip_hdr,
                   struct icmphdr *icmp_hdr,
                   int length,
                   char *frame_data,
                   size_t interface) {
  printf("Entered send_icmp_echo_request\n");
    if (ip_router.s_addr != ip_hdr->daddr ||
        ip_hdr->protocol != IPPROTO_ICMP ||
        icmp_hdr->type != 8)
        return 0;
    
    send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
              eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, interface,
              icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
    return 1;
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
	char frame_data[2048];

	// Do not modify this line
	init(argc - 2, argv + 2);

    // Get the rtrie from file
	struct trie_node *rtrie = read_rtrie(argv[1]);

    // Create an empty queue
    queue q = queue_create();

	while (1) {

		int interface;
		size_t length;

		interface = recv_from_any_link(frame_data, &length);
        printf("Received sth of length %ld\n", length);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)frame_data;
		
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            printf("That was ETHERTYPE_ARP\n");
            struct arp_header *arp_hdr = (struct arp_header *)(frame_data + sizeof(struct ether_header));
            if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
                printf("That was ARPOP_REQUEST\n");
                send_arp_request(interface, eth_hdr, arp_hdr);
                continue;
            } else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
                printf("That was ARPOP_REPLY\n");
                send_arp_reply(arp_hdr, &q);
                continue;
            }
        } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            printf("That was ETHERTYPE_IP\n");
            struct iphdr *ip_hdr = (struct iphdr *)(frame_data + sizeof(struct ether_header));
            struct icmphdr *icmp_hdr = NULL;
            if (ip_hdr->protocol == 1)
                icmp_hdr = (struct icmphdr *)(frame_data + sizeof(struct ether_header) + sizeof(struct iphdr));

            struct in_addr ip_router;
            printf("Passing inet_aton get_interface_ip...\n");
            inet_aton(get_interface_ip(interface), &ip_router);

            printf("Passing send_icmp_echo...\n");
            if (send_icmp_echo(ip_router, eth_hdr, ip_hdr, icmp_hdr,
                               length, frame_data, interface)) {
                printf("Ended at send_icmp_echo\n");
                continue;
            }
            
            // Compute checksum
            printf("Passing checksum...\n");
            if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
                printf("Ended at checksum\n");
                continue;
            }
            
            // Check for TLE
            printf("Passing TLE...\n");
            if (ip_hdr->ttl <= 1) {
                printf("Ended at TLE\n");
                send_icmp(ip_hdr->saddr, ip_hdr->daddr,
                          eth_hdr->ether_dhost, eth_hdr->ether_shost,
                          ICMP_TIME_EXCEEDED, 0, interface,
                          0, 0);
                continue;
            }

            printf("Passing decrease_ttl...\n");
            decrease_ttl(ip_hdr);
            printf("Passing get_best_route...\n");
            struct route_table_entry *best_route = get_best_route(rtrie, ip_hdr->daddr);
            
            // Check if destination is reachable
            printf("Passing !best_route...\n");
            if (!best_route) {
                printf("Ended at best_route\n");
                send_icmp(ip_hdr->saddr, ip_hdr->daddr,
                          eth_hdr->ether_dhost, eth_hdr->ether_shost,
                          ICMP_DEST_UNREACH, 0, interface,
                          0, 0);
                continue;
            }

            printf("Passing get_arp_entry...\n");
            struct arp_entry *rentry = get_arp_entry(best_route->next_hop);
            printf("Passing !rentry...\n");
            if (!rentry) {
                printf("rentry is NULL\n");
                missing_mac(length, frame_data, interface, &q, best_route);
                continue;
            }

            // Send
            get_interface_mac(best_route->interface, eth_hdr->ether_shost);
            memcpy(eth_hdr->ether_dhost, rentry->mac, 6);
            send_to_link(best_route->interface, frame_data, length);
        }
	}
	free(rtrie);
    list_free(arp_table, free);
}

