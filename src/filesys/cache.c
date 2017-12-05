#include "cache.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "devices/disk.h"

struct list bc_list;
int bc_size;

void bc_init (void) {
	list_init(&bc_list);
	bc_size = 0;
}

struct bc_entry* bc_get (struct inode* inode) {
	struct list_elem *e;
	for (e = list_begin (&bc_list); e != list_end (&bc_list); e = list_next (e))
	{
	  struct bc_entry *bce = list_entry(e, struct bc_entry, elem);
	  if (bce->inode == inode) {
	  	return bce;
	  }  
	}
	return NULL;
}

bool bc_put (struct inode* inode, int offset) {
	if (bc_size < MAX_BUFFER_CACHE_SIZE) {
		struct bc_entry *bce = malloc(sizeof(struct bc_entry));
		bce->inode = inode;
		bce->kaddr = malloc(DISK_SECTOR_SIZE);
		// inode_read_at(file->inode, bce->kaddr, DISK_SECTOR_SIZE, offset);
		bce->data_size;
		// bce->sector_idx = offset % DISK_SECTOR_SIZE;
	} else {
		// cache is full -> evict cache
		struct bc_entry *victim = bc_get_victim();
		ASSERT(victim != NULL);
		if (!bc_write_back(victim)) {
			return false;
		}

	}
	return false;
}

struct bc_entry* bc_get_victim (void) {
	return NULL;
}

bool bc_write_back (struct bc_entry* bce) {
	return false;
}
