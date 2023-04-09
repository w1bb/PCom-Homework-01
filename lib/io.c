#include "io.h"

struct trie_node *read_rtrie(char *filename) {
    struct trie_node *rtrie = trie_create();
    FILE *fin = fopen(filename, "r");
    DIE(!fin, "Cannot open rtable!");
    char line[128], prefix[64], next_hop[64], mask[64], interface[8];
    while (fgets(line, sizeof(line) / sizeof(char), fin)) {
        sscanf(line, "%s %s %s %s", prefix, next_hop, mask, interface);
        struct route_table_entry *rentry = malloc(sizeof(struct route_table_entry));
        rentry->prefix = inet_addr(prefix);
        rentry->next_hop = inet_addr(next_hop);
        rentry->mask = inet_addr(mask);
        rentry->interface = atoi(interface);
        printf("Read:  %d %d %d %d\n", rentry->prefix, rentry->next_hop, rentry->mask, rentry->interface);
        trie_insert(rtrie, rentry);
        // printf("Searching yields:  %p\n", trie_search(rtire))
    }
    fclose(fin);
    return rtrie;
}
