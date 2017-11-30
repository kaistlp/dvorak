#include "page.h"
#include <hash.h>
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include "threads/malloc.h"
#include "frame.h"
#include "swap.h"

struct hash pages;
char* loc_str[3] = {"MEMORY", "DISK", "INVAILD"};
static struct lock page_lock;
static int time = 0;

struct page *lookup_pid (int pid);

unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry (p_, struct page, hash_elem);
	return hash_bytes(&p->addr, sizeof p->addr);
}

bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	return a->addr < b->addr;
}

void page_table_init (void){
	lock_init(&page_lock);
	hash_init(&pages, page_hash, page_less, NULL);
}

struct page * suplpage_lookup (void *supladdr) {
	struct page p;
	struct hash_elem *e;
	p.addr = supladdr;
	e = hash_find(&pages, &p.hash_elem);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

void suplpage_process_exit () {
	struct hash_iterator i;
	hash_first(&i, &pages);
	struct page *p;
	while ((p = lookup_pid(process_current()->pid))) {
		suplpage_clear_page(thread_current()->pagedir, pg_round_down(p->addr));
	}
}

struct page *lookup_pid (int pid) {
	struct hash_iterator i;
	hash_first(&i, &pages);
	while (hash_next(&i)) {
		struct page *p = hash_entry(hash_cur(&i), struct page, hash_elem);
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

void page_dump (void) {
	printf("<Page Table>\n");
	int count = 0;
	int m_count = 0;
	int d_count = 0;
	struct hash_iterator i;
	hash_first(&i, &pages);
	while (hash_next(&i)) {
		count++;
		struct page *p = hash_entry(hash_cur(&i), struct page, hash_elem);
		if (p->location == MEMORY){
			m_count++;
		} else {
			d_count++;
		}
		page_print(p);
	}
	printf("::%d Entries\tMEMORY:%d\tDISK:%d\n", count, m_count, d_count);
}

void page_print(struct page* p) {
	printf("[0x%08x] kpage: 0x%08x\tpid: %d\tlocation: %s\n", (uintptr_t) p->addr, (uintptr_t) p->kpage, p->pid, loc_str[p->location]);
}

void* suplpage_get_page(uint32_t *pd, void* upage) {
	//printf("va is %x", upage);
	//printf(" and pid %d\n", process_current()->pid);
	lock_acquire(&page_lock);
	void* suplpage = (void *) supladdr(upage, process_current()->pid);
	struct page *pg = suplpage_lookup(suplpage);
	if (pg == NULL) {
		lock_release(&page_lock);
		return NULL;
	}

	pg->updated_time = time;
	time++;
	if (pg->location == MEMORY) {
		lock_release(&page_lock);
		return pagedir_get_page(pd, upage);
	} else if (pg->location == DISK) {
		// swap out
		void* kpage = frame_alloc(PAL_USER);
		if (!kpage) {
			printf("Alloc failed\n");
			lock_release(&page_lock);
			return NULL;
		}

		if (!swap_out(suplpage, kpage)){
			printf("Swap out failed\n");
			lock_release(&page_lock);
			return NULL;
		}
		pg->kpage = kpage;
		pg->location = MEMORY;
		pagedir_set_page(thread_current()->pagedir, upage, kpage, true);
		lock_release(&page_lock);
		return kpage;
	} else {
		lock_release(&page_lock);
		return NULL;	
	}
}

bool suplpage_set_page(uint32_t *pd, void* upage, void *kpage, bool rw) {
	lock_acquire(&page_lock);
	struct page *p = malloc (sizeof (struct page));
	p->pid = process_current()->pid;
	p->addr = (void *) supladdr(upage, p->pid);
	p->location = MEMORY;
	p->kpage = kpage;
	p->updated_time = time;
	time++;
	hash_insert(&pages, &p->hash_elem);

	bool success = pagedir_set_page(pd, upage, kpage, rw);
	if (!success) {
		hash_delete(&pages, &p->hash_elem);
		free(p);
	}

	lock_release(&page_lock);
	return success;
}

void suplpage_insert (void* upage, enum page_location loc) {
	lock_acquire(&page_lock);
	struct page *p = malloc (sizeof (struct page));
	p->pid = process_current()->pid;
	p->addr = (void *) supladdr(upage, p->pid);
	p->location = loc;
	p->updated_time = time;
	time++;
	hash_insert(&pages, &p->hash_elem);
	lock_release(&page_lock);
}

void suplpage_clear_page(uint32_t *pd, void *upage) {
	void* suplpage = (void *) supladdr(upage, process_current()->pid);
	lock_acquire(&page_lock);
	struct page *pg = suplpage_lookup(suplpage);
	if (pg->location == MEMORY) {
		pagedir_clear_page(pd, upage);
		frame_free(pg->kpage);
	} else if (pg->location == DISK) {
		swap_clear(pg->addr);
	}
	hash_delete(&pages, &pg->hash_elem);
	free(pg);
	lock_release(&page_lock);
}

struct page* suplpage_get_victim (void) {
	if (hash_empty(&pages))
		return NULL;

	struct page *page_victim = NULL;
	struct hash_iterator i;
	hash_first(&i, &pages);
	while (hash_next(&i)) {
		struct page *p = hash_entry(hash_cur(&i), struct page, hash_elem);
		if (p->location == DISK)
			continue;

		if (!page_victim)
			page_victim = p;
		else {
			if (page_victim->updated_time > p->updated_time) {
				page_victim = p;
			}
		}
	}
	return page_victim;
	
}

bool suplpage_scan_consecutive (void* vaddr_start, void* vaddr_end) {
	if (hash_empty(&pages))
		return false;

	ASSERT(vaddr_start == pg_round_down(vaddr_start));
	struct process* cur_p = process_current();
	struct hash_iterator i;
	hash_first(&i, &pages);
	while (hash_next(&i)) {
		struct page *p = hash_entry(hash_cur(&i), struct page, hash_elem);
		if (p->pid != cur_p->pid) 
			continue; // ignore other process's pages

		if ((uintptr_t) pg_round_down(p->addr) >= (uintptr_t) vaddr_start 
			&& (uintptr_t) pg_round_down(p->addr) < (uintptr_t) vaddr_end)
			return false;
	}
	return true;

}

uintptr_t supladdr(void* upage, int pid) {
	return (uintptr_t) pg_round_down(upage) | pid; 
}
