#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <user/syscall.h>
#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

/*process control block for store process information*/
struct pcb
{

    pid_t pid; /* process id*/
    const char * cmd_line; /*command line executed*/

    struct list_elem elem;        /* list element */
    struct thread *parent; /* the parent process. */

    bool waiting;     /* does parent process waiting. useful for check does the wait on process called twice*/
    bool exited;      /* process completed and exited */
    int32_t exit_code; /* exit code of the process */

    /* For synchronization */
    struct semaphore sema_wait;           /* to block the process till the child exit */
    struct semaphore sema_start;           /* synchronization between process_execute and process_start() */ 
};

/* file descriptor */
struct file_desc
{
    int id;                     /* decriptor id */ 
    struct list_elem elem;      /* list element */
    struct file *file;          /* file */
};

#endif /* userprog/process.h */
