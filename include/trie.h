#ifndef _WI_TRIE_H_
#define _WI_TRIE_H_

#include <stdlib.h>
#include <stdint.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "lib.h"

struct trie_node {
    struct route_table_entry *rentry;
    struct trie_node *nodes[2];
};

struct trie_node *trie_create();

void trie_free(struct trie_node *trie,
               void (*free_elem)(void *));

void trie_insert(struct trie_node *trie,
                 struct route_table_entry *rentry);

struct route_table_entry *trie_search(struct trie_node *trie,
                                      uint32_t dest_ip);

#endif // _WI_TRIE_H_
