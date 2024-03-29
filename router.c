#include "includes.h"

#include "protocols.h"
#include "lib.h"
#include "queue.h"
#include "trie.h"
#include "io.h"
#include "list.h"
#include "arp.h"

#define get_best_route trie_search

void decrease_ttl(struct iphdr *ip_hdr) {
	uint16_t old_ttl = *((uint16_t *)&(ip_hdr->ttl));
    --ip_hdr->ttl;
	ip_hdr->check -= (~old_ttl) + *((uint16_t *)&(ip_hdr->ttl)) + 1;
}

void missing_mac(int length, char *frame_data, size_t interface,
                 queue *q, struct route_table_entry *best_route) {
    int *interface_p = malloc(sizeof(int));
    *interface_p = best_route->interface;
    queue_enq(*q, interface_p);

    char *frame_data_p = malloc(length + 1);
    memcpy(frame_data_p, frame_data, length);
    queue_enq(*q, frame_data_p);
    
    size_t *length_p = malloc(sizeof(size_t));
    *length_p = length;
    queue_enq(*q, length_p);

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
    if (ip_router.s_addr != ip_hdr->daddr ||
        ip_hdr->protocol != IPPROTO_ICMP ||
        icmp_hdr->type != 8)
        return 0;
    
    send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
              eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, interface,
              icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
    return 1;
}

int main(int argc, char *argv[]) {
	init(argc - 2, argv + 2);
    
    list arp_table = NULL;
	char frame_data[2048];
	struct trie_node *rtrie = read_rtrie(argv[1]);
    queue q = queue_create();

	while (1) {
		int interface;
		size_t length;

		interface = recv_from_any_link(frame_data, &length);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)frame_data;
		
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            struct arp_header *arp_hdr = (struct arp_header *)(frame_data + sizeof(struct ether_header));
            if (ntohs(arp_hdr->op) == ARPOP_REQUEST)
                send_arp_request(interface, eth_hdr, arp_hdr);
            else if (ntohs(arp_hdr->op) == ARPOP_REPLY)
                send_arp_reply(&arp_table, arp_hdr, &q);
        } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            struct iphdr *ip_hdr = (struct iphdr *)(frame_data + sizeof(struct ether_header));
            struct icmphdr *icmp_hdr = NULL;
            if (ip_hdr->protocol == 1)
                icmp_hdr = (struct icmphdr *)(frame_data + sizeof(struct ether_header) + sizeof(struct iphdr));

            struct in_addr ip_router;
            inet_aton(get_interface_ip(interface), &ip_router);

            if (send_icmp_echo(ip_router, eth_hdr, ip_hdr, icmp_hdr,
                               length, frame_data, interface))
                continue;
            // Compute checksum
            if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
                continue;
            // Check for TLE
            if (ip_hdr->ttl <= 1) {
                send_icmp(ip_hdr->saddr, ip_hdr->daddr,
                          eth_hdr->ether_dhost, eth_hdr->ether_shost,
                          ICMP_TIME_EXCEEDED, 0, interface,
                          0, 0);
                continue;
            }

            decrease_ttl(ip_hdr);
            struct route_table_entry *best_route = get_best_route(rtrie, ip_hdr->daddr);
            
            // Check if destination is reachable
            if (!best_route) {
                send_icmp(ip_hdr->saddr, ip_hdr->daddr,
                          eth_hdr->ether_dhost, eth_hdr->ether_shost,
                          ICMP_DEST_UNREACH, 0, interface,
                          0, 0);
                continue;
            }

            struct arp_entry *rentry = get_arp_entry(arp_table, best_route->next_hop);
            if (!rentry) {
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

