#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
struct file *fd_to_file (int fd);
struct fd_info
{
  int fd;
  struct file* file;
  struct list_elem elem;
};

void halt (void)
{
  power_off();
}

void exit (int status)
{
  /* 현재 user 프로그램 종료
     status가 parent한테 전달되어야 함. */
  thread_current()->exit_status = status;
  thread_exit();
}

//pid_t exec (const char *cmd_line)
//{
//  lock_acquire_filesys();
//  //tid_t new_pid = process_execute(cmd_line);
//  lock_release_filesys();
//  return 0;
//  
//  //return new_pid;
//}
//
//int wait (pid_t pid)
//{
//  return 0;
//}
//
//bool create (const char *file, unsigned initial_size)
//{
//
//}
//
//bool remove (const char *file)
//{
//  
//}
//
int open (const char *file)
{
  lock_acquire_filesys();
  int fd = -1;
  struct file* open_file = filesys_open();

  /* process가 열 수 있는 파일 개수 128개로 제한 - FAQ */
  if(file != NULL && thread_current()->next_fd <= 128){
    struct fd_info* pfd_info = malloc(sizeof(struct fd_info));
    pfd_info->fd = thread_current()->next_fd;
    thread_current()->next_fd++;
    pfd_info->file = open_file;
    list_push_back(&thread_current()->fd_infos, &pfd_info->elem);
    fd = pfd_info->fd;
  }

  lock_release_filesys();
  return fd;
}

int filesize (int fd)
{
  lock_acquire_filesys();
  int len = -1;
  struct file* file= fd_to_file(fd);

  if(file != NULL){
    int len = file_length(file);
  }
  lock_release_filesys();
  return len;
}

int read (int fd, void *buffer, unsigned size)
{
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
    lock_acquire_filesys();
    if(file != NULL){
      read_size = file_read(file, buffer, size);
    }
    lock_release_filesys();
  }
  return read_size;
}

int write (int fd, const void *buffer, unsigned size)
{
  int write_size = -1;

  /* stdout 인 경우 */
  if(fd == 1){
    putbuf(buffer, size);
    write_size = size;
  }
  else{
    struct file* file = fd_to_file(fd);
    if(file != NULL){
      lock_acquire_filesys();
      write_size = file_write(file, buffer, size);
      lock_release_filesys();
    }
  }
  return write_size;
}

void seek (int fd, unsigned position)
{
  struct file* file = fd_to_file(fd);
  lock_acquire_filesys();
  if(file != NULL){
    file_seek(file, position);
  }
  lock_release_filesys();
}

unsigned tell (int fd)
{
  struct file* file = fd_to_file(fd);
  lock_acquire_filesys();
  if(file != NULL){
    return file_tell(file);
  }
  lock_release_filesys();
}

void close (int fd)
{
  struct file* file = fd_to_file(fd);
  lock_acquire_filesys();
  if(file != NULL)
    file_close(file);
  lock_release_filesys();
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
  void *esp = f->esp;
  int syscall_number = *(int *)esp;
  
  switch(syscall_number){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(*(int *)(esp+1));
      break;
//    case SYS_EXEC:
//      exec(*(const char **)(esp+1));
//      break;
//    case SYS_WAIT:
//      wait(*(int *)(esp+1));
//      break;
//    case SYS_CREATE:
//      create(*(const char **)(esp+1), *(unsigned *)(esp+2));
//      break;
//    case SYS_REMOVE:
//      remove(*(const char **)(esp+1));
//      break;
    case SYS_OPEN:
      f->eax = open(*(const char **)(esp+1));
      break;
    case SYS_FILESIZE:
      f->eax = filesize(*(int *)(esp+1));
      break;
    case SYS_READ:
      f->eax = read(*(int *)(esp+1), *(void **)(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_WRITE:
      f->eax = write(*(int *)(esp+1), *(void **)(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_SEEK:
      seek(*(int *)(esp+1), *(unsigned *)(esp+2));
      break;
    case SYS_TELL:
      f->eax = tell(*(int *)(esp+1));
      break;
    case SYS_CLOSE:
      close(*(int *)(esp+1));
      break;
    default:
      break;
  }
    
  thread_exit ();
}

