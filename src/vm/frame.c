#include <list.h>
#include "frame.h"
#include "page.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "swap.h"

struct list frame_list;
struct lock frame_lock;
struct lock palloc_lock;

void frame_insert(void* faddr);

void frame_init(void){
	lock_init(&frame_lock);
	lock_init(&palloc_lock);
	
	list_init(&frame_list);
}

void frame_insert(void* faddr) {
	struct frame_entry *fte = malloc(sizeof(struct frame_entry));
	fte->pcb = process_current();
	fte->faddr = faddr;
	list_push_back(&frame_list, &fte->elem);
}

void *frame_alloc(enum palloc_flags flag) {
	lock_acquire(&palloc_lock);
	void* faddr = palloc_get_page(flag);
	lock_release(&palloc_lock);

	if (faddr){
		lock_acquire(&frame_lock);
		frame_insert(faddr);
		lock_release(&frame_lock);
	} else {
		// swap
		lock_acquire(&frame_lock);
		struct page *victim = suplpage_get_victim();
		struct thread *thread_victim = lookup_thread_by_pid(victim->pid);
		
		/* Insert Swap Table */
		if (!swap_insert(victim->addr, victim->kpage)) {
			printf("swap insert failed\n");
			lock_release(&frame_lock);
			return NULL; // swap-in failed
		}
		victim->location = DISK;
		pagedir_clear_page(thread_victim->pagedir, pg_round_down(victim->addr) );

		/* Remove from Frame Table */
		if (frame_lookup(victim->kpage) == NULL) {
			PANIC("victim %p frame is not in frame table\n", victim->kpage);
		}

		struct frame_entry *fte = frame_lookup(victim->kpage);
	  	list_remove(&fte->elem);
	  	free(fte);

	  	lock_acquire(&palloc_lock);
		palloc_free_page(victim->kpage);
		faddr = palloc_get_page(flag);
		ASSERT(faddr != NULL);
		lock_release(&palloc_lock);

		frame_insert(faddr);
		lock_release(&frame_lock);

	}
	return faddr;
}

void frame_free(void* faddr){
	lock_acquire(&frame_lock);
	struct frame_entry *fte = frame_lookup(faddr);
	ASSERT(fte);

  	list_remove(&fte->elem);
  	free(fte);
  	lock_acquire(&palloc_lock);
	palloc_free_page(faddr);
	lock_release(&palloc_lock);

	lock_release(&frame_lock);
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

struct frame_entry* frame_lookup(void* faddr){
	struct list_elem *e;
	for (e = list_begin (&frame_list); e != list_end (&frame_list); e = list_next (e))
	{
	  struct frame_entry *fte = list_entry(e, struct frame_entry, elem);
	  if (fte->faddr == faddr)
	  	return fte;
	  
	}
	return NULL;
}
