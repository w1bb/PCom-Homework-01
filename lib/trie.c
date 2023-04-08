#include "trie.h"

struct trie_node *trie_create() {
    struct trie_node *trie = malloc(sizeof(struct trie_node));
    trie->rentry = NULL;
    trie->nodes[0] = trie->nodes[1] = NULL;
    return trie;
}

void trie_free(struct trie_node *trie,
               void (*free_elem)(void *)) {
    if (trie->nodes[0])
        trie_free(trie->nodes[0], free_elem);
    if (trie->nodes[1])
        trie_free(trie->nodes[1], free_elem);
    
    if (trie->rentry && free_elem)
        free_elem(trie->rentry);
    free(trie);
}

void trie_insert(struct trie_node *trie,
                 struct route_table_entry *rentry) {
    struct trie_node *current_node = trie;
    uint32_t ntohl_mask = ntohl(rentry->mask);
    uint32_t ntohl_prefix = ntohl(rentry->prefix);
    for (uint32_t i = 0x80000000; i & ntohl_mask; i >>= (uint32_t)1) {
        int p = (ntohl_prefix & i) ? 1 : 0;
        if (!current_node->nodes[p])
            current_node->nodes[p] = trie_create();
        current_node = current_node->nodes[p];
    }
    current_node->rentry = rentry;
}

struct route_table_entry *trie_search(struct trie_node *trie,
                                      uint32_t ntohl_dest_ip) {
    struct trie_node *current_node = trie;
    // uint32_t ntohl_dest_ip = ntohl(dest_ip);
    for (uint32_t i = 0x80000000; i; i >>= (uint32_t)1) {
        int p = (ntohl_dest_ip & i) ? 1 : 0;
        if (!current_node->nodes[p])
            break;
        current_node = current_node->nodes[p];
    }
    return (current_node == trie) ? NULL : current_node->rentry;
}
