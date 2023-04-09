#ifndef _WI_ARP_H_
#define _WI_ARP_H_

#include "includes.h"
#include "list.h"
#include "queue.h"
#include "protocols.h"
#include "lib.h"

struct arp_entry *get_arp_entry(list arp_table, uint32_t given_ip);

void send_arp(uint32_t dest_addr,
              uint32_t send_addr,
              struct ether_header *eth_hdr,
              int interface,
              uint16_t op);

void send_arp_request(int interface,
					  struct ether_header *eth_hdr,
					  struct arp_header *arp_hdr);

void send_arp_reply(list *arp_table, struct arp_header *arp_hdr, queue *q);

#endif // _WI_ARP_H_
