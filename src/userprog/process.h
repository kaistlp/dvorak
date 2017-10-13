#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#define NOT_LOAD 0
#define LOAD_FAIL -1
#define LOAD_SUCESS	1

#define MAX_FILENAME 10000		

struct process
{
    /* Owned by process.c. */
    pid_t pid;                          /* Thread identifier. */
    tid_t tid;
    char name[16];                      /* Name. */
    // char arg1[8];

	int load;
	int exit_status;
	int fd_num;

	struct process *parent;
	struct list child_list;
    struct list_elem elem;              /* List element. */
    struct list_elem elem_heir; 

    struct list fd_list;
    
};

struct file_node {
	int fd;
	struct file* file;
	struct list_elem elem;
	int magic;
};

void init_pcb(struct process *pcb, char* name);
void process_init(void);
struct process* process_current(void);
struct file_node* get_file_of_process(int fd);

void print_process(void);
bool is_executable (struct file* fs);
bool is_running (const char* file_name);
struct process *get_child_process_by_tid (tid_t tid);
struct process *lookup_process_by_pid (pid_t pid);

void remove_child_list (struct process*);

struct semaphore process_sema; // sync for execution

#define VERBOSE 0
#endif /* userprog/process.h */
