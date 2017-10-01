#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

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
syscall_exit(int status) {
	thread_exit();
}

static void
syscall_handler (struct intr_frame *f) 
{
	int *st = (int *)f->esp;
	switch (*st) {
		case SYS_HALT : 
			power_off();
		case SYS_EXIT : 
			syscall_exit(*(st+1));
			break;
		case SYS_WRITE :
			syscall_write(*(st+1), (void *)(*(st+2)), (unsigned)(*(st+3)));
			break;
	}
}
