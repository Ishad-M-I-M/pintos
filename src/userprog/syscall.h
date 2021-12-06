#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void sys_exit(int); //used in few other places to replace `thread_exit()`. (process.c and exception.c)

#endif /* userprog/syscall.h */
