#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/directory.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

#define INIT_DIR_ENTRY_SIZE 16

/* Disk used for file system. */
extern struct disk *filesys_disk;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size, struct dir *dir);
struct file *filesys_open (const char *name, struct dir *dir);
bool filesys_remove (const char *name, struct dir *dir);
bool filesys_mkdir (const char* name, struct dir *cur_dir);
bool filesys_chdir (const char* name, struct dir *cur_dir);

#endif /* filesys/filesys.h */
