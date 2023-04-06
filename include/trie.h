#ifndef TRIE_H__
#define TRIE_H__

#include <stdlib.h>

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
                                      uint32_t ntohl_dest_ip);

#endif // TRIE_H__