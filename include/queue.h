#ifndef _WI_QUEUE_H_
#define _WI_QUEUE_H_

#include <assert.h>
#include <stdlib.h>
#include "list.h"

struct queue {
    list head;
    list tail;
};

typedef struct queue *queue;

/* create an empty queue */
queue queue_create(void);

/* insert an element at the end of the queue */
void queue_enq(queue q, void *element);

/* delete the front element on the queue and return it */
void *queue_deq(queue q);

/* return a true value if and only if the queue is empty */
int queue_empty(queue q);

#endif // _WI_QUEUE_H_
