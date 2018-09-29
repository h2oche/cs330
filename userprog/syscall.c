#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  
  /* 시스템 함수 call */
  /* syscall_number = 어떻게 확인하지??
     syscall함수 argument는 어디서 얻을까 -> 스택에 push 되어 있음.(syscall.c) 
     return은 f->eax 에 넣기*/
  void *esp = intr_frame->esp;
  int syscall_number = *(int *)esp;
  
  switch(syscall_number){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(*(int *)(esp+1));
      break;
    case SYS_EXEC:
      exec(*(const char **)(esp+1));
      break;
    case SYS_WAIT:
      wait(*(pid_t *)(esp+1));
      break;
    case SYS_CREATE:
      create(*(const char **)(esp+1), *(unsigned *)(esp+2));
      break;
    case SYS_REMOVE:
      remove(*(const char **)(esp+1));
      break;
    case SYS_OPEN:
      open(*(const char **)(esp+1));
      break;
    case SYS_FILESIZE:
      filesize(*(int *)(esp+1));
      break;
    case SYS_READ:
      read(*(int *)(esp+1), *(void **)(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_WRITE:
      write(*(int *)(esp+1), *(void **)(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_SEEK:
      seek(*(int *)(esp+1), *(unsigned *)(esp+2));
      break;
    case SYS_TELL:
      tell(*(int *)(esp+1));
      break;
    case SYS_CLOSE:
      close(*(int *)(esp+1));
      break;
    default:
      break;
  }
    
  thread_exit ();
}

void halt (void)
{
  poser_off();
}

void exit (int status)
{
  /* 현재 user 프로그램 종료
     status가 parent한테 전달되어야 함. */
  thread_current()->exit_status = status;
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  //tid_t new_pid = process_execute(cmd_line);
  
  
  //return new_pid;
}

int wait (pid_t pid)
{
  
}

bool create (const char *file, unsigned initial_size)
{
  
}

bool remove (const char *file)
{
  
}

int open (const char *file)
{
  struct file* open_file = file_open(???);
  
  if(file != NULL){
    /* 새로 할당?? ㅇㅇ */
    struct fd_info* pfd_info = (fd_info *)malloc(sizeof(fd_info));
    pfd_info->fd = thread_current()->next_fd;
    thread_ccurrent()->next_fd++;
    pfd_info->file = open_file;
    list_push_back(&thread_current()->fd_infos, &fd_info->elem);
    return pfd_info->fd;
  }
  return -1;
}

int filesize (int fd)
{
  struct file* = fd_to_file(fd);
  if(file != NULL){
    file_length(file);
  }
}

int read (int fd, void *buffer, unsigned size)
{
  struct file* file = fd_to_file(fd);
  if(file != NULL){
    return file_read(file, buffer, size);
  }
}

int write (int fd, const void *buffer, unsigned size)
{
  struct file* file = fd_to_file(fd);
  if(file != NULL){
    return file_write(file, buffer, size);
  }
}

void seek (int fd, unsigned position)
{
  struct file* file = fd_to_file(fd);
  if(file != NULL){
    file_seek(file, position);
  }
}

unsigned tell (int fd)
{
  struct file* file = fd_to_file(fd);
  if(file != NULL){
    return file_tell(file);
  }
}

void close (int fd)
{
  struct file* file = fd_to_file(fd);
  if(file != NULL)
    file_close(file);
}

struct fd_info
{
  int fd;
  struct file* file;
  struct list_elem elem;
}

/* fd를 file 포인터로 바꿔줌. 존재하지 않을 경우 NULL return */
struct file *fd_to_file (int fd)
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
