#include <bitmap.h>
#include <hash.h>
#include <devices/disk.h>
#include "threads/init.h"
#include "threads/vaddr.h"
#include "swap.h"
#include "threads/malloc.h"
#include <stdio.h>

struct hash swaps;
struct disk *swap_disk;
struct bitmap *swap_disk_map;
struct swap * swap_lookup (const void *address);


unsigned swap_hash (const struct hash_elem *s_, void *aux UNUSED) {
	const struct swap *s = hash_entry (s_, struct swap, hash_elem);
	return hash_bytes(&s->paddr, sizeof s->paddr);
}

bool swap_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct swap *a = hash_entry(a_, struct swap, hash_elem);
	const struct swap *b = hash_entry(b_, struct swap, hash_elem);
	return a->paddr < b->paddr;
}

void swap_init(void) {
	hash_init(&swaps, swap_hash, swap_less, NULL);
	swap_disk = disk_get(1, 1);
	swap_disk_map = bitmap_create(disk_size(swap_disk) / 8);
	printf("Swap disk: %d sector available\n", disk_size(swap_disk) / 8);
}

struct swap * swap_lookup (const void *address) {
	struct swap s;
	struct hash_elem *e;
	s.paddr = address;
	e = hash_find(&swaps, &s.hash_elem);
	return e != NULL ? hash_entry(e, struct swap, hash_elem) : NULL;
}

/* Memory -> Disk */
bool swap_insert (const void *paddr, void *buf) {
	// printf("paddr:%08x swap in\n", paddr);
	struct swap *s = calloc (1, sizeof (struct swap));
	if (s == NULL) {
		return false;
	}

	s->pid = pg_ofs(paddr);
	size_t idx = bitmap_scan_and_flip(swap_disk_map, 0, 1, 0);
	if (idx == BITMAP_ERROR){
		free(s);
		return false;	// swap disk is full
	}
	s->disk_sec = idx;
	s->paddr = paddr;
	hash_insert(&swaps, &s->hash_elem);
	
	int i=0;
	for (i = 0; i < 8; ++i)
	{
		disk_write(disk_get(1, 1), (disk_sector_t) 8*idx + i, (const void *) ((uintptr_t) buf + i * 512));
	}
	return true;
}

/* Disk -> Memory */
bool swap_out (void* paddr, void* kpage_dest) {
	// printf("paddr:%08x swap out to %08x\n", paddr, kpage_dest);
	struct swap *s = swap_lookup(paddr);
	if (!s)
		return false;
	size_t idx = s->disk_sec;
	ASSERT(bitmap_test(swap_disk_map, idx) == true);

	int i;
	for (i = 0; i < 8; ++i)
	{
		disk_read(disk_get(1, 1), (disk_sector_t) 8*idx + i, (const void *) ((uintptr_t) kpage_dest + i * 512));
	}
	bitmap_flip(swap_disk_map, idx);
	hash_delete(&swaps, &s->hash_elem);
	return true;
}

void swap_clear (void* supladdr) {
	struct swap *s = swap_lookup(supladdr);
	if (!s)
		return;
	size_t idx = s->disk_sec;
	bitmap_set(swap_disk_map, idx, false);
	hash_delete(&swaps, &s->hash_elem);
	free(s);
}

void swap_dump (void) {
	printf("<Swap Table>\n");
	int count = 0;
	struct hash_iterator i;
	hash_first(&i, &swaps);
	while (hash_next(&i)) {
		count++;
		struct swap *s = hash_entry(hash_cur(&i), struct swap, hash_elem);
		printf("[0x%08x] disk_sec: 0x%u\tpid: %d\n", (uintptr_t) s->paddr, s->disk_sec, s->pid);
	}
	printf("::%d Entries\n", count);

}