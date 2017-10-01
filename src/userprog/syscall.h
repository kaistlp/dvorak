#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void syscall_write(int fd, void* buffer, unsigned size);
#endif /* userprog/syscall.h */
