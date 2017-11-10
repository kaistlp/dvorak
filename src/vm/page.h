#include <bitmap.h>
#include <list.h>
#include <hash.h>
#include "threads/init.h"
#include <stdio.h>

enum page_location {
	MEMORY,
	DISK,
	INVAILD
};

struct page {
	enum page_location location;
	int pid;
	int updated_time;

	const void *addr;
	void *kpage;
	struct hash_elem hash_elem; 
};
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void page_table_init (void);
void page_dump (void);
bool suplpage_set_page(uint32_t *pd, void* upage, void *kpage, bool rw);
void* suplpage_get_page(uint32_t *pd, const void* upage);
void suplpage_clear_page(uint32_t *pd, void *upage);

struct page* suplpage_get_victim (void);

struct page * suplpage_lookup (const void *supladdr);
void suplpage_process_exit ();

uintptr_t supladdr(void* upage, int pid);
void page_print(struct page* p);
