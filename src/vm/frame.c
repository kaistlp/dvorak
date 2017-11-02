#include <list.h>
#include "frame.h"
#include "page.h"
#include "userprog/process.h"
#include "threads/malloc.h"

struct list frame_list;

void frame_init(void){
	list_init(&frame_list);
}

void *frame_alloc(enum palloc_flags flag) {
	struct frame_entry *fte = malloc(sizeof(struct frame_entry));
	void* faddr = palloc_get_page(flag);
	if (faddr){
		fte->pcb = process_current();
		fte->faddr = faddr;
		list_push_back(&frame_list, &fte->elem);
	} else {
		// swap
	}
	return faddr;
}

void frame_free(void* faddr){
	printf("FREE\n");
	struct list_elem *e;
	for (e = list_begin (&frame_list); e != list_end (&frame_list); e = list_next (e))
	{
	  struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
	  if (fte->faddr == faddr){
	  	list_remove(&fte->elem);
	  	free(fte);
		palloc_free_page(faddr);
	  	break;
	  }
	}
}

void frame_dump(void){
	printf("<Frame List>\n");
	struct list_elem *e;
	for (e = list_begin (&frame_list); e != list_end (&frame_list); e = list_next (e))
	{
	  struct frame_entry *f = list_entry(e, struct frame_entry, elem);
	  printf("[0x%x]: pid %d\n", (uintptr_t) f->faddr, f->pcb->pid);
	}
	printf("\n");
}
