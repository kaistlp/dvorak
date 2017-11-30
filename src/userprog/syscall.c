#include <stdio.h>
#include "userprog/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "string.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;
struct lock mmap_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  lock_init(&mmap_lock);
}

void
syscall_exit(struct intr_frame *f UNUSED, int status) {
	thread_current()->exit_status = status;
	thread_exit();
}

void syscall_exec (struct intr_frame *f, const char *cmd_line) {
	tid_t tid = process_execute(cmd_line);
	if (tid == TID_ERROR){
		f->eax = -1;
		return;
	}

	struct process* child_process = get_child_process_by_tid(tid);	

	// Suspend execution until child_process is load
	while (child_process->load == NOT_LOAD) {
		barrier();
	}
	// TO DO: Synch?
	if (child_process->load == LOAD_SUCESS) {
		// LOAD Success
		f->eax = child_process->pid;
	} else {
		f->eax = -1;
	}
} 

void syscall_wait (struct intr_frame *f, pid_t pid) {
	struct process* p = lookup_process_by_pid(pid);
	if (p == NULL) { // pid is invaild
		f->eax = -1;
	} else {
		f->eax = process_wait(p->tid);
	}
}

void syscall_create (struct intr_frame *f, const char* file, unsigned initial_size) {
	f->eax = filesys_create(file, initial_size);
}

void syscall_remove(struct intr_frame *f, const char* file) {
	f->eax = filesys_remove(file);	
}

void syscall_open (struct intr_frame *f, const char* file_name) {
	struct file_node *fn = malloc(sizeof (struct file_node));
	if (fn == NULL){ // low-memory condition
		f->eax = -1;
		return;
	}

	struct process *pcb = process_current();
	lock_acquire(&file_lock);
	struct file *fs = filesys_open(file_name);
	lock_release(&file_lock);


	// file is invaild
	if(fs == NULL) {
		f->eax = -1;
		free(fn);
		return;
	}

	// if file_name is already running, deny writing.
	if (is_running(file_name)){
		file_deny_write(fs);
	}

	fn->fd = pcb->fd_num++;	// file descriptor allocation
	fn->file = fs;
	list_push_back(&pcb->fd_list, &fn->elem);

	f->eax = fn->fd;
}

void syscall_filesize (struct intr_frame *f, int fd) {
	struct file_node *fn = get_file_of_process(fd);
	if (fn == NULL) { // invaild file descriptor
		f->eax = -1;
		return;
	}
	f->eax = file_length(fn->file);
}

void syscall_read (struct intr_frame *f, int fd, void* buffer, unsigned size){
	unsigned i;
	if (fd == STDIN_FILENO) {
		for (i = 0; i < size; ++i)
		{
			*(uint8_t *)(buffer + i) = input_getc();
		}
		f->eax = 1;
		return;
	} else {
		struct file_node *fn = get_file_of_process(fd);
		if (fn == NULL) { // invaild file descriptor
			f->eax = -1;
			return;
		}

		lock_acquire(&file_lock);
		f->eax = file_read(fn->file, buffer, size);
		lock_release(&file_lock);
	}

}

void syscall_write(struct intr_frame *f, int fd, void* buffer, unsigned size) {
	if (fd == STDOUT_FILENO) { // console output
		putbuf (buffer, size);
	} else {
		struct file_node *fn = get_file_of_process(fd);
		if (fn == NULL) { // invaild file descriptor
			f->eax = 0;
			return;
		}
		lock_acquire(&file_lock);
		f->eax = file_write(fn->file, buffer, size);
		lock_release(&file_lock);
	}
}

void syscall_close (struct intr_frame *f UNUSED, int fd) {
	struct file_node *fn = get_file_of_process(fd);
	if (fn != NULL) {
		list_remove (&fn->elem);
		lock_acquire(&file_lock);
		file_close(fn->file);
		lock_release(&file_lock);
		free(fn);
	}
}

void syscall_seek(struct intr_frame *f UNUSED, int fd, unsigned position) {
	struct file_node *fn = get_file_of_process(fd);
	if (fn != NULL) 
		file_seek(fn->file, position);
}

void syscall_tell(struct intr_frame *f, int fd) {
	struct file_node *fn = get_file_of_process(fd);
	if (fn == NULL) { // invaild file descriptor
		f->eax = -1;
		return;
	}
	f->eax = file_tell(fn->file);
}

void syscall_mmap(struct intr_frame *f, int fd, void* addr) {
	// printf("Addr: %p\n", addr);
	struct file_node *fn = get_file_of_process(fd);
	if (fn == NULL) { // invaild file descriptor
		f->eax = -1;
		return;
	}

	if (addr == NULL) {
		f->eax = -1;
		return;	
	}

	int filesize = file_length(fn->file);

	if (filesize == 0) { // file is 0 byte
		f->eax = -1;
		return;
	}

	if (addr != pg_round_down(addr)) { // addr is not page-aligned
		f->eax = -1;
		return;
	}
	if (!suplpage_scan_consecutive(addr, addr + filesize)) {
		f->eax = -1;
		return;
	}

	lock_acquire(&mmap_lock);
	int remainSize = filesize;
	int index = 0;
	while (remainSize > 0) {
 		void* kpage = frame_alloc(PAL_USER | PAL_ZERO);
 		int readSize = MIN(PGSIZE, remainSize);
 		lock_acquire(&file_lock);
 		file_read(fn->file, kpage, readSize);
 		lock_release(&file_lock);
 		suplpage_set_page(thread_current()->pagedir, addr + index, 
 			kpage, true);
 		pagedir_set_dirty(thread_current()->pagedir, addr + index, false);
 		remainSize -= readSize;
 		index += readSize;
 		// hex_dump(kpage, kpage, PGSIZE, true);
	}
	file_seek(fn->file, 0);


	struct mmap_node *mm = malloc(sizeof(struct mmap_node));
	mm->mapid = process_current()->mapid_num++; // mapid allocation
	mm->addr = addr;
	mm->size = filesize;
	mm->file = fn->file;

	list_push_back(&process_current()->mmap_list, &mm->elem);
	f->eax = mm->mapid;
	lock_release(&mmap_lock);
}

void syscall_munmap(struct intr_frame *f UNUSED, int mapid) {
	struct mmap_node *mm = get_mmap_of_process(mapid);
	if (mm == NULL) { // invaild file descriptor
		return;
	}
	lock_acquire(&mmap_lock);
	int remainSize = mm->size;
	int index = 0;
	file_seek(mm->file, 0);

	while (remainSize > 0) {
		void *kpage = suplpage_get_page(thread_current()->pagedir, mm->addr + index);
		ASSERT(kpage != NULL);
		if (pagedir_is_dirty(thread_current()->pagedir, mm->addr + index)) {
			lock_acquire(&file_lock);
			file_write_at(mm->file, kpage, MIN(remainSize, PGSIZE), index);
			lock_release(&file_lock);
		}

		suplpage_clear_page(thread_current()->pagedir, mm->addr + index);
		remainSize -= PGSIZE;
		index += PGSIZE;
	}
	// printf("UNMAP\n");

	file_seek(mm->file, 0);
	list_remove(&mm->elem);
	free(mm);
	lock_release(&mmap_lock);
}

bool validate_memory (void* ptr) {
	if (is_kernel_vaddr(ptr)) {
		// Page Fault!
		return false;
	} else if (pagedir_get_page(thread_current()->pagedir, 
		(void *) ptr) == NULL) {
		// User Page Fault!
		return false;
	}
	return true;
}

static void
syscall_handler (struct intr_frame *f) 
{	
	int *st = (int *)f->esp;
	// printf("Syscall %d called!\n", *st);
	if (!validate_memory(st)){
		thread_exit();
	}
	int argc = 0;
	switch (*st) {
		case SYS_READ:
		case SYS_WRITE:
			argc++;
		case SYS_CREATE:
		case SYS_SEEK:
		case SYS_MMAP :
			argc++;
		case SYS_EXIT:
		case SYS_EXEC:
		case SYS_WAIT:
		case SYS_REMOVE:
		case SYS_OPEN:
		case SYS_FILESIZE:
		case SYS_TELL:
		case SYS_CLOSE:
		case SYS_MUNMAP :
			argc++;
	}
	if (!validate_memory(st+argc)) {
		// Page Fault!
		thread_exit();
	}

	// Check memory access
	int buf_index = 0;
	switch (*st) {
		case SYS_READ :
		case SYS_WRITE :
			buf_index = 2;
			break;
		case SYS_EXEC :
		case SYS_CREATE :
		case SYS_REMOVE :
		case SYS_OPEN :
			buf_index = 1;
	}
	if (buf_index != 0) {
		if (!validate_memory((void *)*(st+buf_index))){
			thread_exit();
		}
	}

	 
	
	switch (*st) {
		case SYS_HALT : 
			power_off();
			break;
		case SYS_EXIT : 
			syscall_exit(f, *(st+1));
			break;
		case SYS_EXEC :
			syscall_exec(f, (const char *)*(st+1));
			break;
		case SYS_WAIT :
			syscall_wait(f, (pid_t)*(st+1));
			break;
		case SYS_CREATE : 
			syscall_create(f, (const char *)(*(st+1)), (unsigned)(*(st+2)));
			break;
		case SYS_REMOVE : 
			syscall_remove(f, (const char *)(*(st+1)));
			break;
		case SYS_OPEN : 
			syscall_open(f, (const char *)(*(st+1)));
			break;
		case SYS_FILESIZE :
			syscall_filesize(f, (int)(*(st+1)));
			break;
		case SYS_READ : 
			syscall_read (f, (int)(*(st+1)), (void *)(*(st+2)), (unsigned)(*(st+3)));
			break;
		case SYS_WRITE :
			syscall_write(f, (int)*(st+1), (void *)(*(st+2)), (unsigned)(*(st+3)));
			break;
		case SYS_CLOSE : 
			syscall_close(f, (int)*(st+1));
			break;
		case SYS_SEEK :
			syscall_seek(f, (int)*(st+1), (unsigned)*(st+2));
			break;
		case SYS_TELL :
			syscall_tell(f, (int)*(st+1));
			break;
		case SYS_MMAP :
			syscall_mmap(f, (int)*(st+1), (void *)(*(st+2)));
			break;
		case SYS_MUNMAP :
			syscall_munmap(f, (int)*(st+1));
			break;
	}
}
