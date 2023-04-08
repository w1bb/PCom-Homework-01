#include "skel.h"
#include <queue.h>

struct route_table_entry *rtable;
int rtable_size = 0;

struct arp_entry *arp_table;
int arp_table_len = 0;
int max_size = 100;

// count the lines of a file
int count_lines(char *filename) {
  char line[100];
  int count = 0;
  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }
  for (count = 0; fgets(line, sizeof(line), fp); count++)
    ;
  fclose(fp);
  return count;
}

// Returns a pointer (eg. &rtable[idx]) to the best matching route
// for the given dest_ip. Or NULL if there is no matching route.
struct route_table_entry *get_best_route(uint32_t dest_ip) {
  int idx = -1;
  int mask_max = 0;
  int left = 0, right = rtable_size - 1, middle;
  while (left <= right) {
    middle = left + (right - left) / 2;
    if ((dest_ip & rtable[middle].mask) == rtable[middle].prefix) {
      if (rtable[middle].mask > mask_max) {
        mask_max = rtable[middle].mask;
        idx = middle;
      }
      left = middle + 1;
    } else if ((dest_ip & rtable[middle].mask) < rtable[middle].prefix) {
      left = middle + 1;
    } else {
      right = middle - 1;
    }
  }
  if (idx == -1) {
    return NULL;
  }
  return &rtable[idx];
}

// update checksum and ttl using incrementation algorithm
void rfc1624_checksum(struct iphdr *ip_hdr) {
  uint16_t old_field = *((uint16_t *) &ip_hdr->ttl);
  ip_hdr->ttl--;
  uint16_t new_field = *((uint16_t *) &ip_hdr->ttl);
  ip_hdr->check -= ((~old_field) + new_field + 1);
}

int comparator(const void *r1, const void *r2) {
  struct route_table_entry *x = (struct route_table_entry *)r1;
  struct route_table_entry *y = (struct route_table_entry *)r2;
  if (x->prefix != y->prefix) {
    return x->prefix < y->prefix;
  }
  return x->mask < y->mask;
}

//  Returns a pointer (eg. &arp_table[i]) to the best matching ARP entry.
//  for the given dest_ip or NULL if there is no matching entry.

struct arp_entry *get_arp_entry(__u32 ip) {
  for (int i = 0; i < arp_table_len; i++) {
    if (arp_table[i].ip == ip) {
      return &arp_table[i];
    }
  }
  return NULL;
}

// implemented with my team in the lab
void parse_route_table(char *filename) {
  FILE *f = fopen(filename, "r");
  DIE(f == NULL, "Failed to open rtable.txt");
  char line[100];
  int i = 0;
  for (i = 0; fgets(line, sizeof(line), f); i++) {
    char prefix_str[50], next_hop_str[50], mask_str[50], interface_str[10];
    sscanf(line, "%s %s %s %s", prefix_str, next_hop_str, mask_str,
           interface_str);
    rtable[i].prefix = inet_addr(prefix_str);
    rtable[i].next_hop = inet_addr(next_hop_str);
    rtable[i].mask = inet_addr(mask_str);
    rtable[i].interface = atoi(interface_str);
  }
  rtable_size = i;
  fclose(f);
}

void send_arp_request(packet *m, struct ether_header *eth_hdr,
                      struct arp_header *arp_hdr) {
  // send back reply, destination is the old source
  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);

  // get mac
  get_interface_mac(m->interface, eth_hdr->ether_shost);

  // get ip
  struct in_addr ip_router;
  inet_aton(get_interface_ip(m->interface), &ip_router);

  // send arp to the old source
  send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m->interface,
           htons(ARPOP_REPLY));
}

void send_arp_reply(struct arp_header *arp_hdr, queue *q) {
  // iau mac-ul si ip-ul sender-ului din struct arp_header
  uint32_t ip_needed = arp_hdr->spa;
  uint8_t mac_needed[ETH_ALEN];
  memcpy(mac_needed, arp_hdr->sha, ETH_ALEN);
  // ip not found in arp_table
  // update arp_table
  arp_table[arp_table_len].ip = ip_needed;
  memcpy(arp_table[arp_table_len].mac, mac_needed, 6);

  arp_table_len++;
  if (arp_table_len == max_size) {
    max_size = max_size * 2;
    arp_table = realloc(arp_table, max_size * sizeof(struct arp_entry));
  }

  // extract each package from queue
  while (!queue_empty(*q)) {
    packet *p = (packet *)queue_deq(*q);

    struct ether_header *new_eth = (struct ether_header *)p->payload;
    // put the mac address
    memcpy(new_eth->ether_dhost, mac_needed, 6);
    send_packet(p->interface, p);
    free(p);
    continue;
  }
}



void no_mac_situation(struct ether_header *eth_hdr, packet *m, queue *q,
                      struct route_table_entry *best) {
  // put package in queue
  packet *copy_p = malloc(sizeof(packet));
  memcpy(copy_p, m, sizeof(packet));
  copy_p->interface = best->interface;
  queue_enq(*q, copy_p);

  get_interface_mac(best->interface, eth_hdr->ether_shost);
  memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN * sizeof(u_char));
  eth_hdr->ether_type = htons(ETHERTYPE_ARP);

  struct in_addr best_interface_ip;
  inet_aton(get_interface_ip(best->interface), &best_interface_ip);

  // send request to find out the required mac address
  send_arp(best->next_hop, best_interface_ip.s_addr, eth_hdr, best->interface,
           htons(ARPOP_REQUEST));
}

int send_icmp_echo_request(struct in_addr ip_router,
                           struct ether_header *eth_hdr, struct iphdr *ip_hdr,
                           struct icmphdr *icmp_hdr, packet m) {
  if (ip_router.s_addr == ip_hdr->daddr) { // destination is router
    if (ip_hdr->protocol == IPPROTO_ICMP &&
        icmp_hdr->type == 8) { // echo request
      send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
                eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, m.interface,
                icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
      return 1;
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {

  packet m;
  int rc, ok, length = count_lines(argv[1]);
  init(argc - 2, argv + 2);
  rtable = malloc(sizeof(struct route_table_entry) * length);
  DIE(rtable == NULL, "memory");
  parse_route_table(argv[1]);
  // order rtable for O(log N) search
  qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator);
  arp_table = malloc(sizeof(struct arp_entry) * max_size);
  DIE(arp_table == NULL, "memory");
  queue q = queue_create();
  while (1) {
    rc = get_packet(&m);
    DIE(rc < 0, "get_message");
    struct ether_header *eth_hdr = (struct ether_header *)m.payload;
    struct arp_header *arp_hdr = parse_arp(m.payload);
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) { // ARP type
      u_int16_t op = ntohs(arp_hdr->op);
      if (op == ARPOP_REQUEST) { //  ARP Request type
        send_arp_request(&m, eth_hdr, arp_hdr);
        continue;
      } else if (op == ARPOP_REPLY) { // ARP Reply type
        send_arp_reply(arp_hdr, &q);
        continue;
      }
    }
    struct iphdr *ip_hdr =
        (struct iphdr *)(m.payload + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = parse_icmp(m.payload);
    struct in_addr ip_router;
    inet_aton(get_interface_ip(m.interface), &ip_router);
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) { // IP type
      ok = send_icmp_echo_request(ip_router, eth_hdr, ip_hdr, icmp_hdr, m);
      if (ok == 1) {
        continue;
      }
      // checksum not 0, got error
      if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
        continue;
      }
      if (ip_hdr->ttl <= 1) {
        // time limit excedeed
        send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
                        eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, 0,
                        m.interface);
        continue;
      }
      rfc1624_checksum(ip_hdr); // recalculate ttl and checksum
      struct route_table_entry *best = get_best_route(
          ip_hdr->daddr); // find best possible route for our packet
      if (best == NULL) {
        // destination unreachable
        send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
                        eth_hdr->ether_shost, ICMP_DEST_UNREACH, 0,
                        m.interface);
        continue;
      }
      struct arp_entry *entry = get_arp_entry(best->next_hop);
      if (entry == NULL) {
        no_mac_situation(eth_hdr, &m, &q, best);
        continue;
      }
      // send package to the best route
      get_interface_mac(best->interface, eth_hdr->ether_shost);
      memcpy(eth_hdr->ether_dhost, entry->mac, 6 * sizeof(uint8_t));
      send_packet(best->interface, &m);
      continue;
    }
  }
  free(rtable);
  free(arp_table);
}
