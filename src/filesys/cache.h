#include "filesys/file.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include <list.h>

#define MAX_BUFFER_CACHE_SIZE 64

struct bc_entry {
	disk_sector_t sector_idx;	//  cached block's sector number
	struct inode *inode;  // inode for cache
	int data_size;		  // size of file data in this cache (< sector_size) 
	void* kaddr;		  // cache address
	struct list_elem elem;
};

void bc_init (void);
struct bc_entry* bc_get (struct inode* inode);
bool bc_put (struct inode* inode, int offset);

struct bc_entry* bc_get_victim (void);
bool bc_write_back (struct bc_entry* bce);

