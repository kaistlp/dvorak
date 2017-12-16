#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_SIZE 63
#define INDIRECT_SIZE 63

#define DIRECT_MAX 32256 

struct lock inode_lock;

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    disk_sector_t direct_sector[DIRECT_SIZE];
    disk_sector_t indirect_sector[INDIRECT_SIZE];               
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

static inline int
bytes_to_sectors_indirect (off_t size)
{
  return  DIV_ROUND_UP(size - DIRECT_MAX, DIRECT_MAX); 
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */

    bool isdir;                         /* is inode directory? */
    char name[READDIR_MAX_LEN+1];

  };

bool inode_disk_growth (struct inode_disk *inode_disk, int target_size);
static disk_sector_t byte_to_sector_indirect (const struct inode *inode, off_t pos);
bool inode_disk_growth_indirect (struct inode_disk *inode_disk, int target_size);

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  off_t file_length = inode->data.length;
  if (pos < file_length) {
    if (pos < DIRECT_MAX) {
        return inode->data.direct_sector[pos / DISK_SECTOR_SIZE];
    } else {
      pos -= DIRECT_MAX;
      struct inode *indirect_inode = inode_open(inode->data.indirect_sector[pos / DIRECT_MAX], false);
      disk_sector_t output_sector = byte_to_sector_indirect(indirect_inode, pos % DIRECT_MAX);
      // printf("pos output_sector %d %d\n", pos, output_sector);  
      inode_close(indirect_inode);
      return output_sector;
    }
  }
  else
    return -1;
}


static disk_sector_t
byte_to_sector_indirect (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  return inode->data.direct_sector[pos / DISK_SECTOR_SIZE];
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init(&inode_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = 0;       // initial_size
      disk_inode->magic = INODE_MAGIC;

      inode_disk_growth(disk_inode, length);
      disk_write (filesys_disk, sector, disk_inode); // write disk_inode

      // Initialization
      size_t sectors = bytes_to_sectors (length);
      int i;
      int indirect_idx = 0;
      static char zeros[DISK_SECTOR_SIZE];
      for (i = 0; i < sectors; i++) {
        if (i < DIRECT_SIZE) {
           disk_write (filesys_disk, disk_inode->direct_sector[i], zeros); 
        } else {
          if (disk_inode->indirect_sector[indirect_idx] != 0) {
            struct inode *inode_indirect = inode_open(disk_inode->indirect_sector[indirect_idx], false);
            int j;
            for (j = 0; j < DIRECT_SIZE; j++) {
              if (inode_indirect->data.direct_sector[j] != 0) {
                disk_write (filesys_disk, inode_indirect->data.direct_sector[j], zeros);
              } else {
                break;
              }
            }
            indirect_idx++;
          } else {
            break;
          }
        }
      }
      free(disk_inode);
      success = true;
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector, bool isdir) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  lock_acquire(&inode_lock);
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          lock_release(&inode_lock);
          return inode; 
        }
    }
    lock_release(&inode_lock);

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_acquire(&inode_lock);
  list_push_front (&open_inodes, &inode->elem);
  lock_release(&inode_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->isdir = isdir;
  disk_read (filesys_disk, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

void
inode_indirect_close (disk_sector_t sector) 
{  
  if (sector == 0)
    return;

  struct inode *inode_indirect = inode_open(sector, false);
  int i;
  for (i = 0; i < DIRECT_SIZE; i++) {
    if (inode_indirect->data.direct_sector[i] != 0) {
      free_map_release(inode_indirect->data.direct_sector[i], 1);
    } else {
        break;
    }
  }
  free_map_release (sector, 1);
  list_remove (&inode_indirect->elem);
  free (inode_indirect); 
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          size_t sectors = bytes_to_sectors(inode->data.length);

          int i;
          for (i = 0; i < DIRECT_SIZE; ++i)
          {
            if (inode->data.direct_sector[i] != 0) {
              free_map_release(inode->data.direct_sector[i], 1);
            } else {
              break;
            }
          }

          for (i = 0; i < INDIRECT_SIZE; ++i)
          {
            inode_indirect_close(inode->data.indirect_sector[i]);
          }

        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

bool inode_isdir (struct inode *inode) {
  return inode->isdir;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  // uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      void* kaddr = bc_get(sector_idx);
      if (kaddr) { // cache is found
        memcpy(buffer + bytes_read, (uint8_t *) kaddr + sector_ofs, chunk_size);
      } else { // cache is not found
        struct bc_entry *bce = bc_put(sector_idx);
        if (bce == NULL) {
          break;
        }
        memcpy(buffer + bytes_read, (uint8_t *) bce->kaddr + sector_ofs, chunk_size);
      }

      // if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
      //   {
      //     /* Read full sector directly into caller's buffer. */
      //     disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
      //   }
      // else 
      //   {
      //      // Read sector into bounce buffer, then partially copy
      //      //   into caller's buffer. 
      //     if (bounce == NULL) 
      //       {
      //         bounce = malloc (DISK_SECTOR_SIZE);
      //         if (bounce == NULL)
      //           break;
      //       }
      //     disk_read (filesys_disk, sector_idx, bounce);
      //     memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
      //   }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  // free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt) {
    return 0;
  }

  if (offset + size > inode->data.length) {
    inode_growth(inode, offset+size);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */

      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      void* kaddr = bc_get(sector_idx);
      if (kaddr) { // cache is found
        memcpy((uint8_t * )kaddr + sector_ofs, buffer + bytes_written, chunk_size);
      } else { // cache is not found
        struct bc_entry *bce = bc_put(sector_idx);
        if (bce == NULL) {
          break;
        }
        memcpy((uint8_t * )bce->kaddr + sector_ofs, buffer + bytes_written, chunk_size);
      }

      // if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
      //   {
      //     /* Write full sector directly to disk. */
      //     disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
      //   }
      // else 
      //   {
      //     /* We need a bounce buffer. */
      //     if (bounce == NULL) 
      //       {
      //         bounce = malloc (DISK_SECTOR_SIZE);
      //         if (bounce == NULL)
      //           break;
      //       }

      //      // If the sector contains data before or after the chunk
      //      //   we're writing, then we need to read in the sector
      //      //   first.  Otherwise we start with a sector of all zeros. 
      //     if (sector_ofs > 0 || chunk_size < sector_left) 
      //       disk_read (filesys_disk, sector_idx, bounce);
      //     else
      //       memset (bounce, 0, DISK_SECTOR_SIZE);
      //     memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
      //     disk_write (filesys_disk, sector_idx, bounce); 
      //   }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  // free (bounce);

  return bytes_written;
}

bool inode_growth (struct inode *inode, int target_size) {
  inode_disk_growth(&inode->data, target_size);
  disk_write (filesys_disk, inode->sector, &inode->data); // write disk_inode
  return true;

}

bool inode_disk_growth (struct inode_disk *inode_disk, int target_size) {
  int remain_size = target_size;
  int sectors_idx = 0;
  int sector_indirect_idx = 0;

  // printf("length: %d\n", inode_disk->length);
  size_t current_direct_sectors = bytes_to_sectors(inode_disk->length);
  int current_indirect_sectors = bytes_to_sectors_indirect(inode_disk->length) -1;


  while (remain_size > 0) {
    if (sectors_idx < DIRECT_SIZE) {
      if (sectors_idx < current_direct_sectors) {
        sectors_idx++;
        remain_size -= DISK_SECTOR_SIZE;
      } else {
        if (!free_map_allocate(1, &inode_disk->direct_sector[sectors_idx])) {
            return false;
        }
        sectors_idx++;
        remain_size -= DISK_SECTOR_SIZE;
      }
    } else {
      // printf("sector_indirect_idx %d\n", sector_indirect_idx);
      // printf("remain_size %d\n", remain_size);
      // printf("current_indirect_sectors %d\n", current_indirect_sectors);
      // Indirect block
      if (sector_indirect_idx < current_indirect_sectors) {
        sector_indirect_idx++;
        sectors_idx += DIRECT_SIZE;
        remain_size -= DIRECT_MAX;

      } else {
        bool not_allocated = inode_disk->indirect_sector[sector_indirect_idx] == 0;
        struct inode_disk *inode_disk_indirect;
        disk_sector_t indirect_disk_sector;

        if (not_allocated) {
          // allocate indirect block
          if (!free_map_allocate(1, &indirect_disk_sector)) {
            return false;
          }

          inode_disk_indirect = calloc(1, sizeof(struct inode_disk));
          inode_disk_indirect->length = 0;
          inode_disk_indirect->magic = INODE_MAGIC;

          if (! inode_disk_growth_indirect(inode_disk_indirect, remain_size)) {
            free(inode_disk_indirect);
            free_map_release(indirect_disk_sector, 1);
            return false;
          }

          disk_write(filesys_disk, indirect_disk_sector, inode_disk_indirect);
          inode_disk->indirect_sector[sector_indirect_idx] = indirect_disk_sector;
          free(inode_disk_indirect);

        } else{
          struct inode *inode_indirect = inode_open(inode_disk->indirect_sector[sector_indirect_idx], false);
          inode_disk_indirect = &inode_indirect->data;

          if (! inode_disk_growth_indirect(inode_disk_indirect, remain_size)) {
            inode_close(inode_indirect);
            return false;
          }

          disk_write(filesys_disk, inode_indirect->sector, inode_disk_indirect);
          inode_close(inode_indirect);

        }
        remain_size -= DIRECT_MAX;
        sector_indirect_idx++;
        sectors_idx += DIRECT_SIZE;
      }
    }
  }

  inode_disk->length = target_size;
}

bool inode_disk_growth_indirect (struct inode_disk *inode_disk, int target_size) {
  if (target_size > DIRECT_MAX)
    target_size = DIRECT_MAX;
  size_t target_sectors = bytes_to_sectors (target_size);
   int i;
   for (i = 0; i < target_sectors; ++i)
   {  
     // printf("indirect [%d] %d\n", i, inode_disk->direct_sector[i]);
      if (inode_disk->direct_sector[i] != 0)
        continue;
      if (!free_map_allocate(1, &inode_disk->direct_sector[i])) {
        return false;
     }
   }
   // printf("success\n");
   return true;
}


/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

int inode_get_open_cnt (struct inode *inode) {
  return inode->open_cnt;
}

