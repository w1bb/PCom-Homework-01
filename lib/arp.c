#include "arp.h"

struct arp_entry *get_arp_entry(list arp_table, uint32_t given_ip) {
	for (list entry = arp_table; entry; entry = entry->next)
		if (((struct arp_entry *)(entry->element))->ip == given_ip)
			return (struct arp_entry *)(entry->element);
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
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
	get_interface_mac(interface, eth_hdr->ether_shost);
  	
	struct in_addr router_ip;
	inet_aton(get_interface_ip(interface), &router_ip);

	send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, interface, htons(ARPOP_REPLY));
}

void send_arp_reply(list *arp_table, struct arp_header *arp_hdr, queue *q) {
	struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
	new_entry->ip = arp_hdr->spa;
	memcpy(new_entry->mac, arp_hdr->sha, 6); 
	*arp_table = cons(new_entry, *arp_table);
	while (!queue_empty(*q)) {
		void *interface_p = queue_deq(*q);
		void *frame_data_p = queue_deq(*q);
		void *length_p = queue_deq(*q);

		struct ether_header *new_eth_hdr = (struct ether_header *)frame_data_p;
		memcpy(new_eth_hdr->ether_dhost, arp_hdr->sha, 6); 
		send_to_link(*(int *)interface_p,
					 (char *)frame_data_p,
					 *(size_t *)length_p);
		free(interface_p);
        free(frame_data_p);
		free(length_p);
	}
}