#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

/* lock for synchronization in file system operation */
struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static void arg_from_stack(uint8_t *uaddr, uint8_t *kaddr, size_t size);

static struct file_desc* get_file_desc(struct thread *t, int fd);

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
  case SYS_REMOVE:
  {
    const char *file;
    arg_from_stack(f->esp + 4, &file, sizeof(file));

    f->eax = sys_remove(file);    
    break;

  }
  case SYS_OPEN: 
  {
    const char *file;
    arg_from_stack(f->esp + 4, &file, sizeof(file));

    f->eax = sys_open(file);
    break;

  }
  case SYS_FILESIZE:
  {
    int fd;
    arg_from_stack(f->esp + 4, &fd, sizeof(fd));

    f->eax = sys_filesize(fd);
    break;

  }
  case SYS_READ:
  {
    int fd;
    void *buffer;
    unsigned size;
    arg_from_stack(f->esp + 4, &fd, sizeof(fd));
    arg_from_stack(f->esp + 8, &buffer, sizeof(buffer));
    arg_from_stack(f->esp + 12, &size, sizeof(size));

    f->eax = (uint32_t)sys_read(fd, buffer, size);
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
  case SYS_SEEK:
  {
    int fd;
    unsigned position;

    arg_from_stack(f->esp + 4, &fd, sizeof(fd));
    arg_from_stack(f->esp + 8, &position, sizeof(position));

    sys_seek(fd, position);
    break;

  }
  case SYS_TELL:
  {
    int fd;
    arg_from_stack(f->esp + 4, &fd, sizeof(fd));

    f->eax = (uint32_t)sys_tell(fd);
    break;

  }
  case SYS_CLOSE:
  {
    int fd;
    arg_from_stack(f->esp + 4, &fd, sizeof(fd));

    sys_close(fd);
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
  if(status < 0){
    status = -1;
  }
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
  char *i = cmd_line;
  do{
    if(get_user(i) == -1)
    sys_exit(-1);

  }while(*i++);

  // load() on process execute access file system. 
  lock_acquire(&filesys_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&filesys_lock);

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

bool sys_remove(const char *file)
{
  bool return_code;
  // memory validation
  if(get_user((const uint8_t *)file) == -1){
    sys_exit(-1);
  }

  lock_acquire(&filesys_lock);
  return_code = filesys_remove(file);
  lock_release(&filesys_lock);
  return return_code;
}

int sys_open(const char *file)
{
  struct file *open_file;
  // memory validation
  if(get_user((const uint8_t *)file) == -1){
    sys_exit(-1);
  }

  struct file_desc *fd = palloc_get_page(0);
  if (!fd)
  {
    // failed to allocate memory to file descriptor
    return -1;
  }

  lock_acquire(&filesys_lock);
  open_file = filesys_open(file);
  if (!open_file)
  {
    palloc_free_page(fd);
    lock_release(&filesys_lock);
    return -1;
  }

  fd->file = open_file;

  struct list *fd_list = &thread_current()->file_descs;
  if (list_empty(fd_list))
  {
    // because stdin =0 , stdout = 1, stderr = 2 are reserved
    fd->id = 3;
  }
  else
  {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  lock_release(&filesys_lock);
  return fd->id;
}

void sys_close(int fd)
{
  lock_acquire(&filesys_lock);
  struct file_desc *file_desc = get_file_desc(thread_current(), fd);

  if (file_desc && file_desc->file)
  {
    file_close(file_desc->file);
    list_remove(&(file_desc->elem));
    palloc_free_page(file_desc);
  }
  lock_release(&filesys_lock);
}

int sys_read(int fd, void *buffer, unsigned size)
{
  // memory validation
  if( (unsigned)buffer +size -1 >= PHYS_BASE ||
    get_user((const uint8_t *)buffer) == -1 || 
    get_user((const uint8_t *)buffer +size -1) == -1){
    sys_exit(-1);
  }

  lock_acquire(&filesys_lock);
  int return_code;

  if (fd == 0)
  { 
    /* read from stdin */
    unsigned i;
    for (i = 0; i < size; ++i)
    {
      if (!put_user(buffer + i, input_getc()))
      {
        lock_release(&filesys_lock);
        sys_exit(-1);
      }
    }
    return_code = size;
  }
  else
  {
    /* read from file */
    struct file_desc *file_desc = get_file_desc(thread_current(), fd);

    if (file_desc && file_desc->file)
    {
      return_code = file_read(file_desc->file, buffer, size);
    }
    else //file not fount
      return_code = -1;
  }

  lock_release(&filesys_lock);
  return return_code;
}

int sys_write(int fd, const void *buffer, unsigned size)
{
  // memory validation
  if(get_user((const uint8_t *)buffer) == -1){
    sys_exit(-1);
  }

  int return_code;
  lock_acquire(&filesys_lock);

  if (fd == 1)
  { 
    /* write to stdout */
    putbuf(buffer, size);
    return_code = size;
  }
  else
  {
    /* write to a file */
    struct file_desc *file_desc = get_file_desc(thread_current(), fd);

    if (file_desc && file_desc->file)
    {
      return_code = file_write(file_desc->file, buffer, size);
    }
    else // File not found
      return_code = -1;
  }
  lock_release(&filesys_lock);
  return return_code;

}

int sys_filesize(int fd)
{
  struct file_desc *file_desc;

  lock_acquire(&filesys_lock);
  file_desc = get_file_desc(thread_current(), fd);

  if (file_desc == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }

  int return_code = file_length(file_desc->file);
  lock_release(&filesys_lock);
  return return_code;
}

void sys_seek(int fd, unsigned position)
{
  lock_acquire(&filesys_lock);
  struct file_desc *file_desc = get_file_desc(thread_current(), fd);

  if (file_desc && file_desc->file)
  {
    file_seek(file_desc->file, position);
  }
  else
  {
    // TODO: what to do here?
  }

  lock_release(&filesys_lock);
}

unsigned sys_tell(int fd)
{
  lock_acquire(&filesys_lock);
  struct file_desc *file_desc = get_file_desc(thread_current(), fd);

  unsigned return_code;
  if (file_desc && file_desc->file)
  {
    return_code = file_tell(file_desc->file);
  }
  else
    return_code = -1; // TODO need sys_exit?

  lock_release(&filesys_lock);
  return return_code;
}

/* helper function to find file descriptor in the thread's 
 file descriptor list*/
static struct file_desc *
get_file_desc(struct thread *t, int fd)
{
  ASSERT(t != NULL);

  if (fd < 3)
  {
    return NULL;
  }

  struct list_elem *e;

  if (!list_empty(&t->file_descs))
  {
    for (e = list_begin(&t->file_descs);
         e != list_end(&t->file_descs); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if (desc->id == fd)
      {
        return desc;
      }
    }
  }

  return NULL; // file descritor not found in the process descriptor list
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