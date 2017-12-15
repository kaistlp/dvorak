#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "devices/disk.h"
#include "userprog/process.h"
#include "threads/malloc.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

char* parse_filename (char* input, struct dir *cur_dir, struct dir **final_dir);
static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  inode_init ();
  free_map_init ();
  bc_init();
  lock_init(&file_internal_lock);

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  bc_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, struct dir *cur_dir) 
{
  disk_sector_t inode_sector = 0;

  struct dir *dir = (cur_dir == NULL)? dir_open_root () : cur_dir;
  struct dir* search_dir;
  char* filename  = parse_filename(name, dir, &search_dir);
  if (filename == NULL)
    return false;

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (search_dir, filename, inode_sector, false));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

  inode_close(dir_get_inode(search_dir));
  return success;
}

bool
filesys_mkdir (const char* name, struct dir *cur_dir) {
  struct dir *dir = (cur_dir == NULL)? dir_open_root () : cur_dir;

  struct dir* search_dir;
  char* filename  = parse_filename(name, dir, &search_dir);
  if (filename == NULL)
    return false;

  disk_sector_t sector = 0;
  bool success = (free_map_allocate(1, &sector)
    && dir_create(sector, INIT_DIR_ENTRY_SIZE)
    && dir_add(search_dir, filename, sector, true));

  struct inode *inode = inode_open(sector, true);
  struct dir *added_dir = dir_open(inode);
  success = success && dir_add(added_dir, ".", sector, true)
    && dir_add(added_dir, "..", inode_get_inumber(dir_get_inode(search_dir)), true);
  inode_close(inode);

  if (!success && sector != 0)
    free_map_release(sector, 1);

  inode_close(dir_get_inode(search_dir));
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name, struct dir *cur_dir)
{
  struct dir *dir = (cur_dir == NULL)? dir_open_root () : cur_dir;

  struct dir* search_dir;
  char* filename  = parse_filename(name, dir, &search_dir);

  if (filename == NULL)
    return NULL;

  struct inode *inode = NULL;
  if (dir != NULL)
    dir_lookup (search_dir, filename, &inode);
  if (cur_dir == NULL)
    dir_close (dir);

  inode_close(dir_get_inode(search_dir));
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name, struct dir *cur_dir) 
{
  struct dir *dir = (cur_dir == NULL)? dir_open_root () : cur_dir;

  struct dir* search_dir;
  char* filename  = parse_filename(name, dir, &search_dir);
  if (filename == NULL)
    return NULL;

  bool success = dir != NULL && dir_remove (search_dir, filename);

  inode_close(dir_get_inode(search_dir));
  return success;
}

bool 
filesys_chdir (const char* name, struct dir *cur_dir) {
  struct dir *dir = (cur_dir == NULL)? dir_open_root () : cur_dir;
  // root directory
  if(!strcmp(name, "/")) {
    dir_close(cur_dir);
    process_current()->cur_dir = dir_open_root();
    return true;
  }

  struct dir* search_dir;
  char* filename  = parse_filename(name, dir, &search_dir);
  if (filename == NULL) {
    dir_close(cur_dir);
    return false;
  }

  struct inode* inode;
  bool success = false;
  if (dir_lookup(search_dir, filename, &inode)) {
    dir_close(cur_dir);
    process_current()->cur_dir = dir_open(inode);
    success = true;
  } 

  // inode_close(inode);
  inode_close(dir_get_inode(search_dir));
  return success;
}


char* parse_filename (char* input, struct dir *cur_dir, struct dir **final_dir) {
  char *ret_ptr;
  char *next_ptr;
  char *str = calloc(strlen(input)+1, 1);
  memcpy(str, input, strlen(input));
  char* prev_ptr = str;
  char* output = input;  

  // absolute/relative path
  struct dir *search_dir;
  if (input[0] == '/') {
    search_dir = dir_open_root();
    str = str+1;
    output += 1;
  } else {
    search_dir = dir_reopen(cur_dir);
  }

  // filename itself
  if (strchr(str, '/') == NULL) {
    *final_dir = search_dir;
    return str;
  }

  ret_ptr = strtok_r(str, "/", &next_ptr);
  struct inode *inode;

  while(ret_ptr) {
    if (next_ptr == NULL || *next_ptr == '\0'  ) {
      break;
    }
    if (!dir_lookup(search_dir, ret_ptr, &inode)) {
      if (FS_VERBOSE) printf("not found\n");
      inode_close(inode);
      return NULL;
    }

    if (inode_isdir(inode)) {
      inode_close(dir_get_inode(search_dir));
      search_dir = dir_open(inode);
    } else {
      inode_close(inode);
      if (FS_VERBOSE) printf("not dir\n");
      return NULL;
    }
    ret_ptr = strtok_r(NULL, "/", &next_ptr);
  }

  *final_dir = search_dir;

  output +=  (ret_ptr - str); 
  free(prev_ptr);
  return output;


}



/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, INIT_DIR_ENTRY_SIZE))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
