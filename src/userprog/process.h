#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Process Loading state */
#define NOT_LOAD 0
#define LOAD_FAIL -1
#define LOAD_SUCESS	1

/* Process control blcok for process management */
struct process
{
    pid_t pid;							/* Process identifier. */
    tid_t tid;							/* Thread identifier that process running on.  */
    char name[16];						/* Program Name. */

	int load;							/* indicate process loading state */
	int exit_status;					/* contains process exit status */
	int fd_num;							/* For file descriptor allocation */

	struct process *parent;				/* Pcb for parent process */	
	struct list child_list;				/* Child list of current process */
    struct list_elem elem;              /* List element for process_list */
    struct list_elem elem_heir; 		/* List element for child_list */

    struct list fd_list;				/* List of file desciptor (file_noe) */

    void* next_stptr;					/* pointr of next stack */
    void* esp;
    
};

/* File node for file descriptor list */
struct file_node {
	int fd; 				// File desciprtor number
	struct file* file; 		// File structure (filesys/file.h)
	struct list_elem elem; 	// List element
};

void init_pcb(struct process *pcb, const char* name);
void process_init(void);
struct process* process_current(void);
struct file_node* get_file_of_process(int fd);

void print_all(void);
void print_process(struct process *p);

bool is_executable (struct file* fs);
bool is_running (const char* file_name);
struct process *get_child_process_by_tid (tid_t tid);
struct process *lookup_process_by_pid (pid_t pid);

void remove_child_list (struct process*);

#define VERBOSE 1

#endif /* userprog/process.h */
