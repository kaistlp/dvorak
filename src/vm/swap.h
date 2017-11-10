#include "threads/init.h"
#include <devices/disk.h>
#include <bitmap.h>
#include <hash.h>

struct swap {
	const void *paddr;

	int pid;
	disk_sector_t disk_sec;
	struct hash_elem hash_elem; 
};


unsigned swap_hash (const struct hash_elem *p_, void *aux UNUSED);
bool swap_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void swap_init(void);
void swap_dump(void);
bool swap_insert(const void * supladdr, void *buf);
bool swap_out(void* supladdr, void* kpage_dest);
void swap_clear(void* supladdr);