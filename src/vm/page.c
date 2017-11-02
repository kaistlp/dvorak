#include "page.h"
#include <hash.h>
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include "threads/malloc.h"

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

void init_page_table (void){
	hash_init(&pages, page_hash, page_less, NULL);
}

struct page * page_lookup (const void *address) {
	struct page p;
	struct hash_elem *e;
	p.addr = address;
	e = hash_find(&pages, &p.hash_elem);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

void page_dump (void) {
	printf("<Page Table>\n");
	struct hash_iterator i;
	hash_first(&i, &pages);
	while (hash_next(&i)) {
		struct page *p = hash_entry(hash_cur(&i), struct page, hash_elem);
		printf("[0x%08x] kpage: 0x%08x\tpid: %d\tlocation: %s\n", (uintptr_t) p->addr, (uintptr_t) p->kpage, p->pid, loc_str[p->location]);
	}

}

void* suplpage_get_page(uint32_t *pd, const void* upage) {
	struct page *pg = page_lookup(upage);
	if (pg == NULL) {
		return NULL;
	}

	if (pg->location == MEMORY) {
		return pagedir_get_page(pd, upage);
	} else if (pg->location == DISK) {
		// TO DO : swap에서 찾아오기
		return NULL;
	} else {
		return NULL;	
	}
	// page_lookupdump();
}

bool suplpage_set_page(uint32_t *pd, void* upage, void *kpage, bool rw) {
	struct page *p = malloc (sizeof (struct page));
	p->pid = process_current()->pid;
	p->addr = (void *) (((uintptr_t) upage & ~PGMASK) | p->pid);
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
	struct page *pg = page_lookup(upage);
	if (pg->location == MEMORY) {
		pagedir_clear_page(pd, upage);
	} else if (pg->location == DISK) {
		// TO DO : swap에서 찾아오기
	} 
}
