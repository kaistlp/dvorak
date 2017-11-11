#include <bitmap.h>
#include <list.h>
#include "threads/palloc.h"
#include "threads/init.h"

struct frame_entry {
	void* faddr;
	struct process* pcb;
	struct list_elem elem;
};

void frame_init(void);
void *frame_alloc(enum palloc_flags);
void frame_free(void* faddr);
void frame_dump(void);
struct frame_entry* frame_lookup(void* faddr);
