#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static pid_t allocate_pid (void);
static struct list process_list; // Process list of running
static bool install_page (void *upage, void *kpage, bool writable);
static struct lock process_lock;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd_line) 
{  
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
    if (fn_copy == NULL) {
    if (VERBOSE) printf("fn_copy ALLOCATION FAIL\n");
    return TID_ERROR;
  }
  strlcpy (fn_copy, cmd_line, PGSIZE);

  // Intialize Process Control Block 
  struct process *pcb = malloc(sizeof(struct process));
  ASSERT(pcb);
  init_pcb(pcb, cmd_line);

  // Update Parent, Child Info
  struct process *ppcb = process_current();
  pcb->parent = ppcb;
  list_push_back(&ppcb->child_list, &pcb->elem_heir);
  list_push_back(&process_list, &pcb->elem);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmd_line, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR) {
    if (VERBOSE) printf("Thread Creation FAIL\n");
    // Remove p on list
    list_remove(&pcb->elem); // from process_list

    //free resource
    remove_child_list(pcb);

    palloc_free_page (fn_copy); 
    free (pcb);
    return TID_ERROR;
  }
  

  pcb->tid = tid;
  struct thread *child_t = lookup_all_list(tid);
  ASSERT(child_t != NULL);
  child_t->pid = pcb->pid;

  return tid;
}

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
  char *cmd_line = f_name;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  char *save_ptr;
  int argc = 0;
  int len = 0;


  char *file_name = strtok_r (cmd_line, " ", &save_ptr);
  success = load (file_name, &if_.eip, &if_.esp);

  if (success) {
    while(cmd_line) {
      argc++;
      len += strlen(cmd_line)+1;
      cmd_line = strtok_r (NULL, " ", &save_ptr);
    }

    // insert to stack pointer
    int i = 0;
    int arg_index = 0;
    char* cp_index = if_.esp - len;
    int argv_0 = (ROUND_DOWN((unsigned int)cp_index, 4) - 4 * (argc + 1 - arg_index));
    for (arg_index = 0; arg_index < argc; arg_index++) {
      while(*file_name == ' ') // igrnoe spaces
        file_name++;
      *(int *) (argv_0 + 4 *arg_index) = (int) (cp_index + i);
      while(*file_name) {
        *(cp_index+i) = *file_name;
        file_name++;
        i++;
      }
      i++;
      file_name++;
    }
    *(int *)(argv_0 - 4) = argv_0;
    *(int *)(argv_0 - 8) = argc;
    if_.esp = (void *)(argv_0 - 12);
    // printf("st: %lx\n", if_.esp);


    process_current()->load = LOAD_SUCESS;
    palloc_free_page (f_name); 



    //hex_dump (if_.esp, if_.esp, PHYS_BASE - if_.esp, 1);
  } else {
    /* If load failed, quit. */
    struct process *p = process_current();

    // Remove p on list
    list_remove(&p->elem); // from process_list
    
    //free resource
    remove_child_list(p);
    free(p);

    palloc_free_page (f_name); 
    p->load = LOAD_FAIL;
    if (VERBOSE) printf("LOAD_FAIL\n");
    thread_exit ();
  } 

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  // check whether child_tid is owned by child process of caller process
  struct process *child_process = get_child_process_by_tid(child_tid);
  if (child_process == NULL)
    return -1;

  while(thread_is_alive(child_tid)) { 
    thread_yield(); // waiting
  }

  child_process = get_child_process_by_tid(child_tid); // CHECK LOAD_FAIL
  if (child_process == NULL)
    return -1;
  // Remove child_process on list
  ASSERT(&child_process->elem);
  list_remove(&child_process->elem); // from process_list

  remove_child_list(child_process);
  int exit_status = child_process->exit_status;
  free (child_process);

  return exit_status;

}

void remove_child_list(struct process *p){
  list_remove(&p->elem_heir); // from parent's child_lsit
  struct list_elem *e;
  for (e = list_begin (&p->child_list); e != list_end (&p->child_list); e = list_next (e))
  {
    struct process *child_pcb = list_entry(e, struct process, elem_heir);
    child_pcb->parent = NULL;
  }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *curr = thread_current ();
  uint32_t *pd;
  struct process *pcb = process_current();
//  int pid = pcb->pid;
  // if NULL, process exited with LOAD_FAIL
  if (pcb != NULL){
    pcb->exit_status = curr->exit_status;
    printf("%s: exit(%d)\n", pcb->name, curr->exit_status);

    // free file descriptors
    while (!list_empty(&pcb->fd_list)){
      struct file_node* fn = list_entry(list_pop_back(&pcb->fd_list), struct file_node, elem); 
      file_close(fn->file);
      free(fn);
    }

    if (pcb->parent == NULL) { 
      // no parent waiting this process, so free resources
      list_remove(&pcb->elem);
      free(pcb);
    }
  }

  suplpage_process_exit();
  //frame_dump();
  
  // TO DO 여기에서 supple로 보고 frame_free외치기

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */

  pd = curr->pagedir;
  if (pd != NULL) 
    { 
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

void init_pcb(struct process *pcb, const char* name){
  memset(pcb, 0, sizeof *pcb);
  pcb->pid = allocate_pid();
  pcb->tid = -1; // NOT LOADED

  // Parse program name
  char* save_ptr;
  char* ptr = malloc(strlen(name)+1);
  char* name_copy = ptr;
  memset(name_copy, 0, strlen(name)+1);
  strlcpy (name_copy, name, strlen(name)+1);
  char *file_name = strtok_r(name_copy, " ", &save_ptr);
  strlcpy (pcb->name, file_name, strnlen(file_name, sizeof pcb->name)+1);

  pcb->load = NOT_LOAD;
  pcb->exit_status = -1;
  pcb->parent = NULL;
  list_init(&pcb->child_list);

  // file descriptor structure
  list_init(&pcb->fd_list);
  pcb->fd_num = 2;

  free(ptr);
}

struct process* process_current(void){
  struct list_elem* e;
  if (list_empty(&process_list)){
    return NULL;
  }

  for (e = list_begin (&process_list); e != list_end (&process_list); e = list_next (e))
  {
    struct process *pcb = list_entry(e, struct process, elem);
    if (pcb->tid == thread_current()->tid)
      return pcb;
  }
  return NULL;
}

void process_init(void) {
  list_init(&process_list);
  lock_init(&process_lock);

  struct process *root_pcb = malloc(sizeof(struct process));
  root_pcb->pid = 0; // root
  list_init(&root_pcb->child_list);
  list_push_back(&process_list, &root_pcb->elem);

  list_init(&root_pcb->fd_list);
  root_pcb->fd_num = 2;
  root_pcb->load = LOAD_SUCESS;
  root_pcb->tid = thread_current()->tid;

  page_table_init();
}

void print_all(void){
  struct list_elem* e;
  if (list_empty(&process_list)) {
    printf("[empty]\n");
    return;
  }
  for (e = list_begin (&process_list); e != list_end (&process_list); e = list_next (e))
  {
    struct process *pcb = list_entry(e, struct process, elem);
    print_process(pcb);
  }
  printf("\n");
}

void print_process(struct process *pcb){
  struct list_elem* e2;
  struct list_elem* e3;

  printf("[pid:%03d, tid:%03d]:\tparent: ", pcb->pid, pcb->tid);
  if (pcb->parent == NULL) {
    printf("NULL,\t");
  } else {
    printf("%d,\t",pcb->parent->pid);
  }
  printf("child: ["); 
  if (!list_empty(&pcb->child_list)) {
    for (e2 = list_begin (&pcb->child_list); e2 != list_end (&pcb->child_list); e2 = list_next (e2))
    {
      struct process *child_pcb = list_entry(e2, struct process, elem_heir);
      printf("%d, ", child_pcb->pid);
    }
  }
  printf("], ");

  printf("fd_list: ["); 
  if (!list_empty(&pcb->fd_list)) {
    for (e3 = list_begin (&pcb->fd_list); e3 != list_end (&pcb->fd_list); e3 = list_next (e3))
    {
      struct file_node *fe = list_entry(e3, struct file_node, elem);
      printf("%d, ", fe->fd);
    }
  }
  printf("]\n");
}

/* Returns a pid to use for a new process. */
static pid_t
allocate_pid (void) 
{
  static pid_t next_pid = 1;
  pid_t pid;
  pid = next_pid++;
  return pid;
} 

struct file_node* get_file_of_process(int fd) {
  struct process* cur_pcb = process_current();
  struct list_elem *e;
  for (e = list_begin (&cur_pcb->fd_list); e != list_end (&cur_pcb->fd_list); e = list_next (e))
  {
    struct file_node *f = list_entry(e, struct file_node, elem);
    if (f->fd == fd)
      return f;
  }
  return NULL;
}

bool is_running (const char* file_name) {
  struct list_elem* e;
  for (e = list_begin (&process_list); e != list_end (&process_list); e = list_next (e))
  {
    struct process *pcb = list_entry(e, struct process, elem);
    if (pcb->name != NULL && strcmp(pcb->name, file_name) == 0) {
      // file is running (exec)
      return true;
    } 
  }
  return false;
}
 
struct process* get_child_process_by_tid (tid_t tid){
  struct process* pcb = process_current();
  struct list_elem* e;
  for (e = list_begin (&pcb->child_list); e != list_end (&pcb->child_list); e = list_next (e))
  {
    struct process *p = list_entry(e, struct process, elem_heir);
    if (p->tid == tid)
      return p;
  }
  return NULL;
}

struct process* lookup_process_by_pid (pid_t pid) {
  struct list_elem* e;

  for (e = list_begin (&process_list); e != list_end (&process_list); e = list_next (e))
  {
    struct process *p = list_entry(e, struct process, elem);
    if (p->pid == pid)
      return p;
  }
  return NULL;
}


/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    { 
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr) {

        goto done;
      }
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable)) {
                if (VERBOSE) printf("Segment Load Failed\n");
                  goto done;
              }
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp)){
    if (VERBOSE) printf("Stack Failed\n");
    goto done;
  }

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */


/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Do calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = frame_alloc (PAL_USER);
      if (kpage == NULL) {
        if (VERBOSE) printf("frame allocation error\n");
        disk_print_stats();
        return false;
      }

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          frame_free (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          frame_free (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = frame_alloc (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
  {
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      frame_free (kpage);
  }
  process_current()->next_stptr = (void *) ((uintptr_t) PHYS_BASE - 2 * PGSIZE);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (suplpage_get_page (t->pagedir, upage) == NULL
          && suplpage_set_page (t->pagedir, upage, kpage, writable));
}

bool is_executable (struct file* fs){
  /* Read and verify executable header. */
  struct Elf32_Ehdr ehdr;
  return !(file_read_at (fs, &ehdr, sizeof ehdr, 0) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024);
}
