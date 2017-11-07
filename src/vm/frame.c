#include <list.h>
#include "frame.h"
#include "page.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "swap.h"

struct list frame_list;
void frame_insert(void* faddr);


void frame_init(void){
	list_init(&frame_list);
}

void frame_insert(void* faddr) {
	struct frame_entry *fte = malloc(sizeof(struct frame_entry));
	fte->pcb = process_current();
	fte->faddr = faddr;
	list_push_back(&frame_list, &fte->elem);
}

void *frame_alloc(enum palloc_flags flag) {
	void* faddr = palloc_get_page(flag);
	if (faddr){
		frame_insert(faddr);
	} else {
		// swap
		struct page *victim = suplpage_get_victim();
		struct thread *thread_victim = lookup_thread_by_pid(victim->pid);
		/* Insert Swap Table */
		if (!swap_insert(victim->addr, victim->kpage)) {
			printf("swap insert failed\n");
			return NULL; // swap-in failed
		}

		victim->location = DISK;
		pagedir_clear_page(thread_victim->pagedir, pg_round_down(victim->addr) );
		/* Remove from Frame Table */
		frame_free(victim->kpage);
		faddr = palloc_get_page(flag);
		ASSERT(faddr != NULL);
		frame_insert(faddr);
	}
	return faddr;
}

void frame_free(void* faddr){
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
	// printf("frame_free: kpage %08x\n", faddr);
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
