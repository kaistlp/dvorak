#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process
{
    /* Owned by process.c. */
    pid_t pid;                          /* Thread identifier. */
    char name[16];                      /* Name (for debugging purposes). */

	int exit_status;

	struct process *parent;
	struct list child_list;
    struct list_elem elem;              /* List element. */
    struct list_elem elem_heir; 
};


void init_pcb(struct process *pcb, char* name);
void process_init(void);
struct process* process_current(void);

void print_process(void);

#endif /* userprog/process.h */
