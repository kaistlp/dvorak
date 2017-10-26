#include "frame.h"
#include "userprog/process.h"
#include <list.h>

struct list frame_list;

void frame_init(void){
	list_init(&frame_list);
}

void *frame_alloc(enum palloc_flags flag, struct process* pcb) {
	struct frame_entry *fte = malloc(sizeof(struct frame_entry));
	void* faddr = palloc_get_page(flag);
	if (faddr){
		fte->pcb = pcb;
		fte->faddr = faddr;
		list_push_back(&frame_list, &fte->elem);
	} else {
		// swap
	}
	return faddr;
}

void frame_free(){

}

void frame_dump(void){
	printf("<Frame List>\n");
	struct list_elem *e;
	for (e = list_begin (&frame_list); e != list_end (&frame_list); e = list_next (e))
	{
	  struct frame_entry *f = list_entry(e, struct frame_entry, elem);
	  printf("[0x%lx]: pid %d\n", f->faddr, f->pcb->pid);
	}
	printf("\n");
}
