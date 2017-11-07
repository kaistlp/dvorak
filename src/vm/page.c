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
	hash_init(&pages, page_hash, page_less, NULL);
}

struct page * suplpage_lookup (const void *supladdr) {
	struct page p;
	struct hash_elem *e;
	p.addr = supladdr;
	e = hash_find(&pages, &p.hash_elem);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
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

void* suplpage_get_page(uint32_t *pd, const void* upage) {
	void* suplpage = supladdr(upage, process_current()->pid);
	struct page *pg = suplpage_lookup(suplpage);
	if (pg == NULL) {
		return NULL;
	}

	if (pg->location == MEMORY) {
		return pagedir_get_page(pd, upage);
	} else if (pg->location == DISK) {
		// swap out
		void* kpage = frame_alloc(PAL_USER);
		if (!kpage) {
			printf("Alloc failed\n");
			return NULL;
		}

		if (!swap_out(suplpage, kpage)){
			printf("Swap out failed\n");
			return NULL;
		}
		pg->kpage = kpage;
		pg->location = MEMORY;
		pagedir_set_page(thread_current()->pagedir, upage, kpage, true);
		return kpage;
	} else {
		return NULL;	
	}
}

bool suplpage_set_page(uint32_t *pd, void* upage, void *kpage, bool rw) {
	struct page *p = malloc (sizeof (struct page));
	p->pid = process_current()->pid;
	p->addr = (void *) supladdr(upage, p->pid);
	p->location = MEMORY;
	p->kpage = kpage;
	hash_insert(&pages, &p->hash_elem);

	bool success = pagedir_set_page(pd, upage, kpage, rw);
	if (!success) {
		free(p);
	}

	return success;
}

void suplpage_clear_page(uint32_t *pd, void *upage) {
	struct page *pg = suplpage_lookup(upage);
	if (pg->location == MEMORY) {
		pagedir_clear_page(pd, upage);
	} else if (pg->location == DISK) {
		// TO DO : swap에서 찾아오기
	} 
}

struct page* suplpage_get_victim (void) {
	if (hash_empty(&pages))
		return NULL;

	// TO DO: Eviction Algorithm
	struct hash_iterator i;
	hash_first(&i, &pages);
	while (hash_next(&i)) {
		struct page *p = hash_entry(hash_cur(&i), struct page, hash_elem);
		struct process *curr_p = process_current();
		if (curr_p->esp != NULL && p->addr == (void *)supladdr(curr_p->esp, curr_p->pid) )
			continue;
		if (p->location == MEMORY)
			return p;
	}
	return NULL;
	
}

uintptr_t supladdr(void* upage, int pid) {
	return (uintptr_t) pg_round_down(upage) | pid; 
}
