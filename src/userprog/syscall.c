#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "filesys/filesys.h"

/* lock for synchronization in file system operation */
struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static void arg_from_stack(uint8_t *uaddr, uint8_t *kaddr, size_t size);

/* Syscall function signatures */

void sys_halt(void);
void sys_exit(int);
pid_t sys_exec(const char *cmdline);
int sys_wait(pid_t pid);

bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);


void syscall_init(void)
{
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int syscall_num;
  arg_from_stack(f->esp, &syscall_num, sizeof(syscall_num));
  // printf("%d\n", syscall_num);  //debug

  switch (syscall_num)
  {
  case SYS_HALT:
  {
    sys_halt();
    NOT_REACHED();
    break;

  }
  case SYS_EXIT:
  {
    int status;
    arg_from_stack(f->esp + 4, &status, sizeof(status));

    sys_exit(status);
    NOT_REACHED();
    break;

  }
  case SYS_EXEC:
  {
    void *cmd_line;
    arg_from_stack(f->esp + 4, &cmd_line, sizeof(cmd_line));

    f->eax = (uint32_t)sys_exec((const char *)cmd_line);
    break;

  }
  case SYS_WAIT:
  {
    pid_t pid;
    arg_from_stack(f->esp + 4, &pid, sizeof(pid_t));

    f->eax = (uint32_t)sys_wait(pid);
    break;

  }
  case SYS_CREATE:
  {
    const char *file;
    unsigned initial_size;

    arg_from_stack(f->esp + 4, &file, sizeof(file));
    arg_from_stack(f->esp + 8, &initial_size, sizeof(initial_size));

    f->eax = sys_create(file, initial_size);
    break;
  }

  case SYS_WRITE:
  {
    int fd;
    const void *buffer;
    unsigned size;

    arg_from_stack(f->esp + 4, &fd, sizeof(fd));
    arg_from_stack(f->esp + 8, &buffer, sizeof(buffer));
    arg_from_stack(f->esp + 12, &size, sizeof(size));

    f->eax = (int32_t) sys_write(fd, buffer, size);
    break;

  }
  
  default:
    printf("system call not defined!\n");
    sys_exit(-1);
    break;
  }

  
}

/* Load consecutive `size` bytes from `uaddr` to `kaddr`
   page fault when failed.
   Used to get arguments to kernel space from stack of the user program.  */
static void arg_from_stack(uint8_t *uaddr, uint8_t *arg, size_t arg_size)
{
  int32_t byte;
  for (int i = 0; i < arg_size; i++)
  {
    byte = get_user(uaddr + i);
    if (byte == -1)
    {
      // TODO: implement to avoid memory leaks (released aquire locks or memory allocations).
      sys_exit(-1);
    }

    *(char *)(arg + i) = byte & 0xff;
  }
}

/* ======================  syscall functions =================================  */

void sys_halt(void)
{
  shutdown_power_off();
}

void sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status); // exit statement
  
  // Store the process exit info in pcb
  struct pcb *pcb = thread_current()->pcb;
  if (pcb != NULL)
  {
    pcb->exited = true;
    pcb->exit_code = status;
  }
  else
  {
    //TODO: handle the situation.
  }

  thread_exit();
}

pid_t sys_exec(const char *cmd_line)
{
  // check does the cmd_line in valid user space. If not exit the process
  if(get_user(cmd_line) == -1)
    sys_exit(-1);

  
  // TODO: implement synchronization
  pid_t pid = process_execute(cmd_line);

  return pid;
}

int sys_wait(pid_t pid)
{
  return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size)
{
  bool return_code;

  // memory validation
  if(get_user((const uint8_t *)file) == -1){
    sys_exit(-1);
  }

  lock_acquire(&filesys_lock);
  return_code = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return return_code;
}

int sys_write(int fd, const void *buffer, unsigned size)
{
  int return_code;

  if (fd == 1)
  { // write to stdout
    putbuf(buffer, size);
    return_code = size;
  }
  else
  {
    //TODO: implement writing to files
  }
  return return_code;

}
/* ======== provided in labsheet =========== */

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user(const uint8_t *uaddr)
{
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfaultoccurred.*/
static bool
put_user(uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}