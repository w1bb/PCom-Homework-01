#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"
#include "io.h"

#define get_best_route trie_search

void decrease_ttl(struct iphdr *ip_hdr) {
	uint16_t old_ttl = *((uint16_t *)ip_hdr->ttl);
	ip_hdr->check -= (~old_ttl) + *((uint16_t *)(--ip_hdr->ttl)) + 1;
}

struct list arp_table;

struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (list entry = arp_table; entry; entry = entry->next)
		if (((arp_entry *)(entry->element))->ip == given_ip)
			return (arp_entry *)(entry->element);
	return NULL;
}

void send_arp_request(int interface, size_t len,
					  struct ether_header *eth_hdr,
					  struct arp_header *arp_hdr) {
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
	get_interface_mac(interface, eth_hdr->ether_shost);
  	
	struct in_addr router_ip;
	inet_aton(get_interface_ip(interface), &router_ip);

	send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, interface, htons(ARPOP_REPLY));
}

int main(int argc, char *argv[])
{
	struct trie_node *rtrie = read_rtrie(argv[1]);

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
	free(rtrie);
}

