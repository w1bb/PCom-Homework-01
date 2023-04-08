#include "list.h"
#include <stdlib.h>

list cons(void *element, list l)
{
	list temp = malloc(sizeof(struct cell));
	temp->element = element;
	temp->next = l;
	return temp;
}

list cdr_and_free(list l)
{
	list temp = l->next; 
	free(l);
	return temp;
}

void list_free(list l, void (*free_elem)(void *)) {
	while (l) {
		if (free_elem)
			free_elem(l->element);
		l = cdr_and_free(l);
	}
}
