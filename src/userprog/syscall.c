#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static void arg_from_stack(uint8_t *uaddr, uint8_t *kaddr, size_t size);

/* Syscall function signatures */

void sys_halt(void);
void sys_exit(int);
pid_t sys_exec(const char *cmdline);
int sys_wait(pid_t pid);

bool sys_create(const char *filename, unsigned initial_size);
bool sys_remove(const char *filename);
int sys_open(const char *file);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);


void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int syscall_num;
  arg_from_stack(f->esp, &syscall_num, sizeof(syscall_num));
  // printf("%d\n", syscall_num);

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
      printf("Failed to Acess Memory");
      sys_exit(-1);
    }

    *(char *)(arg + i) = byte & 0xff;
  }
}


/* syscall functions */

void sys_halt(void)
{
  shutdown_power_off();
}

void sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status); // exit statement
  //TODO: implement informing waiting parent process
  thread_exit();
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