#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
syscall_write(int fd, void* buffer, unsigned size) {
	if (fd == 1) { // console output
		putbuf (buffer, size);
	}
	// not finished yet
}
void
syscall_exit(struct intr_frame *f, int status) {
	thread_current()->exit_status = status;
	thread_exit();
}

void syscall_exec (const char *cmd_line) {
	process_execute(cmd_line);
}

static void
syscall_handler (struct intr_frame *f) 
{
	int *st = (int *)f->esp;

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
	// check memory vaildation
	if (buf_index != 0) {
		if (is_kernel_vaddr((void *) *(st+buf_index))) {
			// Page Fault!
			printf("Page Fault!\n");
			thread_exit();
		} else if (pagedir_get_page(thread_current()->pagedir, 
			(void *) *(st+buf_index)) == NULL) {
			// Page Fault!
			printf("User Page Fault!\n");
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
		case SYS_WRITE :
			syscall_write(*(st+1), (void *)(*(st+2)), (unsigned)(*(st+3)));
			break;
		case SYS_EXEC :
			syscall_exec(*(st+1));
			break;
	}
}
