#include "cache.h"
#include <hash.h>
#include "threads/synch.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "devices/disk.h"
#include <stdio.h>

struct hash bc_hash;
int bc_size;
struct lock bc_lock;

unsigned bc_hash_func (const struct hash_elem *bce_, void *aux UNUSED);
bool bc_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
struct bc_entry* bc_lookup (disk_sector_t sector_idx);
void bc_print (struct bc_entry *bce);


unsigned bc_hash_func (const struct hash_elem *bce_, void *aux UNUSED) {
	const struct bc_entry *bce = hash_entry (bce_, struct bc_entry, hash_elem);
	return hash_bytes(&bce->sector_idx, sizeof bce->sector_idx);
}

bool bc_hash_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct bc_entry *a = hash_entry(a_, struct bc_entry, hash_elem);
	const struct bc_entry *b = hash_entry(b_, struct bc_entry, hash_elem);
	return a->sector_idx < b->sector_idx;
}

void bc_init (void) {
	lock_init(&bc_lock);
	hash_init(&bc_hash, bc_hash_func, bc_hash_less, NULL);
	bc_size = 0;
}


void* bc_get (disk_sector_t sector_idx) {
	lock_acquire(&bc_lock);
	struct bc_entry *bce = bc_lookup(sector_idx);
	lock_release(&bc_lock);

	if (bce == NULL)
		return NULL;
	else
		return bce->kaddr;
}

struct bc_entry* bc_put (disk_sector_t sector_idx) {
	lock_acquire(&bc_lock);
	if (bc_size < MAX_BUFFER_CACHE_SIZE) {
		struct bc_entry *bce = malloc(sizeof(struct bc_entry));
		if (bce == NULL) {
			lock_release(&bc_lock);
			PANIC("Kernel memory low");
			return NULL;
		}
		bce->kaddr = malloc(DISK_SECTOR_SIZE);
		if (bce->kaddr == NULL) {
			free (bce);
			lock_release(&bc_lock);
			PANIC("Kernel memory low");
			return NULL;
		}
		bce->read_count = 0;
		bce->write_count = 0;
		bce->access = true;

		bce->read_count++;
		disk_read(filesys_disk, sector_idx, bce->kaddr);
		bce->read_count--;

		bce->sector_idx = sector_idx;
		hash_insert(&bc_hash, &bce->hash_elem);
		bc_size++;

		lock_release(&bc_lock);
		return bce;
	} else {
		// cache is full -> evict cache
		struct bc_entry *victim = bc_get_victim();
		ASSERT(victim != NULL);
		bc_write_back(victim);
		hash_delete(&bc_hash, &victim->hash_elem);
		free(victim->kaddr);
		free(victim);

		struct bc_entry *bce = malloc(sizeof(struct bc_entry));
		if (bce == NULL) {
			lock_release(&bc_lock);
			PANIC("Kernel memory low");
			return NULL;
		}
		bce->kaddr = malloc(DISK_SECTOR_SIZE);
		if (bce->kaddr == NULL) {
			free (bce);
			lock_release(&bc_lock);
			PANIC("Kernel memory low");
			return NULL;
		}
		bce->read_count = 0;
		bce->write_count = 0;
		bce->access = true;

		bce->read_count++;
		disk_read(filesys_disk, sector_idx, bce->kaddr);
		bce->read_count--;

		bce->sector_idx = sector_idx;
		hash_insert(&bc_hash, &bce->hash_elem);
		bc_size++;

		lock_release(&bc_lock);
		return victim;
	}
}

void bc_write_back_elem (struct hash_elem* e, void* aux UNUSED) {
	struct bc_entry *bce = hash_entry(e, struct bc_entry, hash_elem);
	bc_write_back(bce);
	free(bce->kaddr);
}

void bc_close (void) {
	lock_acquire(&bc_lock);
	hash_apply(&bc_hash, bc_write_back_elem);
	hash_destroy(&bc_hash, NULL);
	lock_release(&bc_lock);
}

struct bc_entry* bc_get_victim (void) {
	if (hash_empty(&bc_hash))
		return NULL;

	struct bc *bc_victim = NULL;
	struct hash_iterator i;

	bool loop = true;
	while (loop) {
		hash_first(&i, &bc_hash);
		while (hash_next(&i)) {
			struct bc_entry *bce = hash_entry(hash_cur(&i), struct bc_entry, hash_elem);
			if (bce->read_count > 0 || bce->write_count > 0)
				continue;
			else {
				if (bce->access) {
					bce->access = false;
				} else {
					bc_victim = bce;
					loop = false;
					break;
				}
			}
		}
	}
	ASSERT(bc_victim);
	// bc_dump();
	return bc_victim;
}

void bc_write_back (struct bc_entry* bce) {
	bce->write_count++;
	disk_write(filesys_disk, bce->sector_idx, bce->kaddr);
	bce->write_count--;
}

void bc_print (struct bc_entry *bce) {
	printf("[%p] disk_sector_t: %u\n", bce->kaddr, bce->sector_idx);
}

void bc_dump (void) {
	printf("<Buffer Cache Table>\n");
	int count = 0;
	struct hash_iterator i;
	hash_first(&i, &bc_hash);
	while (hash_next(&i)) {
		count++;
		struct bc_entry *p = hash_entry(hash_cur(&i), struct bc_entry, hash_elem);
		bc_print(p);
	}
	printf("::%d Entries\n", count);
}

struct bc_entry* bc_lookup (disk_sector_t sector_idx) {
	struct bc_entry bce;
	struct hash_elem *e;

	bce.sector_idx = sector_idx;
	e = hash_find(&bc_hash, &bce.hash_elem);
	return e != NULL ? hash_entry(e, struct bc_entry, hash_elem) : NULL;
}
