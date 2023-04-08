#ifndef _LIST_H_
#define _LIST_H_

typedef struct cell *list;

struct cell
{
  void *element;
  list next;
};

extern list cons(void *element, list l);
extern list cdr_and_free(list l);

void list_free(list l, void (*free_elem)(void *));

#endif /* _LIST_H_ */
