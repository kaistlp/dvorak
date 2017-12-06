#include "filesys/file.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include <hash.h>
#include <list.h>

#define MAX_BUFFER_CACHE_SIZE 64

struct bc_entry {
	disk_sector_t sector_idx;	//  cached block's sector number
	void* kaddr;		  // cache address
	int read_count;
	int write_count;
	bool access;
	struct hash_elem hash_elem;
};

void bc_init (void);
void* bc_get (disk_sector_t sector_idx);
struct bc_entry* bc_put (disk_sector_t sector_idx);
void bc_close (void);

void bc_dump (void);

struct bc_entry* bc_get_victim (void);
void bc_write_back (struct bc_entry* bce);

