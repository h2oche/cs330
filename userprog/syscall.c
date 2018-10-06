#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
struct fd_info
{
  int fd;
  struct file* file;
  struct list_elem elem;
};

/*---------------------------------------------------------------------------------------*/
/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

/*---------------------------------------------------------------------------------------*/
//
///* Writes BYTE to user address UDST.
//UDST must be below PHYS_BASE.
//Returns true if successful, false if a segfault occurred. */
//static bool put_user (uint8_t *udst, uint8_t byte)
//{
//  int error_code;
//  asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "r" (byte));
//  return error_code != -1;
//}
//
/*---------------------------------------------------------------------------------------*/

/* fd를 file 포인터로 바꿔줌. 존재하지 않을 경우 NULL return */
static struct file * fd_to_file (int fd)
{
  struct thread* curr = thread_current();
  struct list_elem* le;
  struct fd_info* pfd_info;
  
  for(le = list_begin(&curr->fd_infos); le != list_end(&curr->fd_infos); le = list_next(le)){
    pfd_info = list_entry(le, struct fd_info, elem);
    if(pfd_info->fd == fd)
      return pfd_info->file;
  }
  return NULL;
}

/*---------------------------------------------------------------------------------------*/

/* error에 의한 종료 */
static void error_exit (void)
{
  thread_current()->exit_status = -1;
  thread_exit();
}

/*---------------------------------------------------------------------------------------*/

/* user 포인터 확인하는 함수 */
static bool is_valid_ptr(void *base, unsigned size)
{
  uint8_t *ptr = (uint8_t *)base;

  /* get user 했을 때, segfault 발생하면 -1 return 됨 */
  if(!is_user_vaddr(ptr))
    return false;
  else if(get_user(ptr+size-1) == -1)
    return false; 
  return true;
}

static bool is_valid_string(const char *str)
{
  int c;
  uint8_t *p = (uint8_t)str;
  for(c=get_user(p); c != -1; c=get_user(p)){
    if(c=='\0')
      return true; // string 끝날 때 까지 다 valid 한 경우
    p = p+1;
  }
  return false; // get_user 결과가 -1인 경우
}

static bool is_valid_buffer(void * buffer, unsigned size)
{
  if(!is_valid_ptr(buffer, size))
    return false;
  return true;
}

/*---------------------------------------------------------------------------------------*/

static void syscall_exit(struct intr_frame *f)
{
  printf("syscall - exit\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int status = *(int *)(f->esp+4);
  thread_current()->exit_status = status;
  thread_exit();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_exec(struct intr_frame *f)
{
  printf("syscall - exec\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  const char *cmd_line = *(char **)(f->esp+4);
  if(!is_valid_string(cmd_line))
    return error_exit();

  f->eax = process_execute(cmd_line);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_wait(struct intr_frame *f)
{
  printf("syscall - wait\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int pid = *(int *)(f->esp+4);
  f->eax = process_wait(pid);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_create(struct intr_frame *f)
{
  printf("syscall - create\n");
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8, 4))
    return error_exit();

  const char *file = *(char **)(f->esp+4);
  if(!is_valid_string(file))
    return error_exit();
  unsigned initial_size = *(unsigned *)(f->esp+8);

  lock_acquire_filesys();
  f->eax = filesys_create(file, initial_size);
  lock_release_filesys();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_remove(struct intr_frame *f)
{
  printf("syscall - create\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  const char *file = *(char **)(f->esp+4);
  if(!is_valid_string(file))
    return error_exit();

  lock_acquire_filesys();
  f->eax = filesys_remove(file);
  lock_release_filesys();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_open(struct intr_frame *f)
{
  printf("syscall - open\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  const char *file = *(char **)(f->esp+4);
  if(!is_valid_string(file))
    return error_exit();

  int fd = -1;

  lock_acquire_filesys();
  struct file* open_file = filesys_open(file);

  /* process가 열 수 있는 파일 개수 128개로 제한 - FAQ */
  if(file == NULL || thread_current()->next_fd > 128){
    lock_release_filesys();
    return error_exit();
  }

  struct fd_info* pfd_info = malloc(sizeof(struct fd_info));
  pfd_info->fd = thread_current()->next_fd;
  thread_current()->next_fd++;
  pfd_info->file = open_file;
  list_push_back(&thread_current()->fd_infos, &pfd_info->elem);
  fd = pfd_info->fd;
  f->eax = fd;

  lock_release_filesys();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_filesize(struct intr_frame *f)
{
  printf("syscall - filesize\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);

  int len = -1;
  struct file* file = fd_to_file(fd);

  if(file == NULL){
    return error_exit();
  }

  lock_acquire_filesys();

  len = file_length(file);
  f->eax = len;
  lock_release_filesys();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_read(struct intr_frame *f)
{
  printf("syscall - read\n");
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8,4) || !is_valid_ptr(f->esp+12, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);
  void *buffer = *(void **)(f->esp+8);
  unsigned size = *(unsigned *)(f->esp+12);

  if(!is_valid_buffer(buffer, size))
    return error_exit();

  int read_size = -1;
  unsigned i;

  /* stdin 인 경우 */
  if(fd == 0){
    uint8_t* stdin_buf = (uint8_t *)buffer;
    for(i=0; i<size; i++){
      stdin_buf[i] = input_getc();
    }
    read_size = size;
  }
  else{
    struct file* file = fd_to_file(fd);
    if(file == NULL){
      return error_exit();
    }
    lock_acquire_filesys();
    read_size = file_read(file, buffer, size);
    lock_release_filesys();
  }

  f->eax = read_size;
}

/*---------------------------------------------------------------------------------------*/

static void syscall_write(struct intr_frame *f)
{
  printf("syscall - write\n");
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8, 4) || !is_valid_ptr(f->esp+12, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);
  const void *buffer = *(void **)(f->esp+8);
  unsigned size = *(unsigned *)(f->esp+12);

  if(!is_valid_buffer(buffer, size))
    return error_exit();

  int write_size = -1;
  /* stdout 인 경우 */
  if(fd == 1){
    putbuf((char *)buffer, (size_t)size);
    write_size = (int)size;
  }
  else{
    struct file* file = fd_to_file(fd);
    if(file == NULL){
      return error_exit();
    }
    lock_acquire_filesys();
    write_size = file_write(file, buffer, size);
    lock_release_filesys();
  }

  f->eax = write_size;
}

/*---------------------------------------------------------------------------------------*/

static void syscall_seek(struct intr_frame *f)
{
  printf("syscall - seek\n");
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);
  unsigned position = *(unsigned *)(f->esp+8);

  struct file* file = fd_to_file(fd);
  if(file == NULL){
    return error_exit();
  }
  lock_acquire_filesys();
  file_seek(file, position);
  lock_release_filesys();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_tell(struct intr_frame *f)
{
  printf("syscall - tell\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);

  struct file* file = fd_to_file(fd);
  if(file == NULL){
    return error_exit();
  }
  lock_acquire_filesys();
  f->eax = file_tell(file);
  lock_release_filesys();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_close(struct intr_frame *f)
{
  printf("syscall - close\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);

  struct file* file = fd_to_file(fd);
  if(file == NULL){
    return error_exit();
  }
  lock_acquire_filesys();
  file_close(file);
  lock_release_filesys();
}

/*---------------------------------------------------------------------------------------*/

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*---------------------------------------------------------------------------------------*/

static void syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");

  if(!is_valid_ptr(f->esp, 4)){
    return error_exit();
  }

  int syscall_number = *(int *)f->esp;
  switch(syscall_number){
    case SYS_HALT:
      power_off();
      break;
    case SYS_EXIT:
      syscall_exit(f);
      break;
    case SYS_EXEC:
      syscall_exec(f);
      break;
    case SYS_WAIT:
      syscall_wait(f);
      break;
    case SYS_CREATE:
      syscall_create(f);
      break;
    case SYS_REMOVE:
      syscall_remove(f);
      break;
    case SYS_OPEN:
      syscall_open(f);
      break;
    case SYS_FILESIZE:
      syscall_filesize(f);
      break;
    case SYS_READ:
      syscall_read(f);
      break;
    case SYS_WRITE:
      syscall_write(f);
      break;
    case SYS_SEEK:
      syscall_seek(f);
      break;
    case SYS_TELL:
      syscall_tell(f);
      break;
    case SYS_CLOSE:
      syscall_close(f);
      break;
    default:
      return error_exit();
  }

  thread_exit ();
}
