#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/init.h"
#include "devices/input.h"
#include <string.h>
#include "vm/spagetbl.h"
#include "vm/frametbl.h"
#include "lib/round.h"
#include "userprog/pagedir.h"

//struct semaphore filesys_sema;
static void syscall_handler (struct intr_frame *);
void munmap(int);

/*---------------------------------------------------------------------------------------*/
/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int get_user (const uint8_t *uaddr)
{
  if(!is_user_vaddr(uaddr))
    return -1;

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

/*---------------------------------------------------------------------------------------*/

/* Write a bte at user virtual address UDST */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "r" (byte));
  return error_code != -1;
}
/*---------------------------------------------------------------------------------------*/

/* user 포인터 확인하는 함수 */
static bool is_valid_ptr(const void *base, unsigned size)
{
  uint8_t *ptr = (uint8_t *)base;
  unsigned i = 0;

  for(;i<size;i++){
    if(get_user(ptr) == -1)
      return false;
    ptr++;
  }
  return true;
}

/*---------------------------------------------------------------------------------------*/

/* 스트링 끝날 때 까지('\0') 유효한 지 확인 */
static bool is_valid_string(const void *str)
{
  int c;
  uint8_t *ptr = (uint8_t *)str;

  while((c=get_user(ptr)) != -1){
    if(c=='\0')
      return true;
    ptr++;
  }
  return false;
}

/*---------------------------------------------------------------------------------------*/

/* 버퍼 끝까지 유효한 지 확인 */
static bool is_valid_buffer(const void *buffer, unsigned size)
{
  uint8_t* ptr = (uint8_t *)buffer;
  uint32_t i = 0;
  int result;
  
  for(;i < size; i++) {
    if((result = get_user(ptr)) == -1) return false;
    if(!put_user(ptr, (uint8_t)result)) return false;
    ptr++;
  }
  
  return true;
}

/*---------------------------------------------------------------------------------------*/

/* fd로 fd_info를 찾아줌. 존재하지 않을 경우 NULL return */
static struct fd_info * get_fd_info (int fd)
{
  struct thread* curr = thread_current();
  struct list_elem* le;
  struct fd_info* pfd_info;

  for(le = list_begin(&curr->fd_infos); le != list_end(&curr->fd_infos); le = list_next(le)){
    pfd_info = list_entry(le, struct fd_info, elem);
    if(pfd_info->fd == fd)
      return pfd_info;
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

static void syscall_exit(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, sizeof(int)))
    return error_exit();

  int status = *(int *)(f->esp+4);
  thread_current()->exit_status = status;
  thread_exit();
}

/*---------------------------------------------------------------------------------------*/

static void syscall_exec(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  const char *cmd_line = *(char **)(f->esp+4);
  if(!is_valid_string(cmd_line))
    return error_exit();

  /* TODO 파일 이름 파싱 -> 유효한 파일인 지 확인  */
  char *save_ptr;
  char *f_name = malloc(strlen(cmd_line)+1);
  // if(f_name == NULL)
  strlcpy (f_name, cmd_line, strlen(cmd_line)+1);
  f_name = strtok_r (f_name, " ", &save_ptr);

  sema_down(&filesys_sema);
  struct file* file = filesys_open(f_name);

  free(f_name);

  if(file == NULL){
    f->eax = -1;
    sema_up(&filesys_sema);
    return;
  }

  file_close(file);
  sema_up(&filesys_sema);
    
  f->eax = process_execute(cmd_line);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_wait(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int pid = *(int *)(f->esp+4);
  f->eax = process_wait(pid);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_create(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8, 4))
    return error_exit();

  const char *file = *(char **)(f->esp+4);
  if(!is_valid_string(file))
    return error_exit();

  unsigned initial_size = *(unsigned *)(f->esp+8);

  sema_down(&filesys_sema);
  f->eax = filesys_create(file, initial_size);
  sema_up(&filesys_sema);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_remove(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  const char *file = *(char **)(f->esp+4);
  if(!is_valid_string(file))
    return error_exit();

  sema_down(&filesys_sema);
  f->eax = filesys_remove(file);
  sema_up(&filesys_sema);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_open(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  const char *file = *(char **)(f->esp+4);
  if(!is_valid_string(file))
    return error_exit();

  int fd = -1;

  sema_down(&filesys_sema);
  struct file* open_file = filesys_open(file);

  /* process가 열 수 있는 파일 개수 제한 - FAQ */
  if(open_file == NULL || thread_current()->next_fd > 130){
    f->eax = fd;
    sema_up(&filesys_sema);
    return;
  }

  struct fd_info* pfd_info = malloc(sizeof(struct fd_info));
  //if(pfd_info == NULL)
  pfd_info->fd = thread_current()->next_fd;
  thread_current()->next_fd++;
  pfd_info->file = open_file;
  list_push_back(&thread_current()->fd_infos, &pfd_info->elem);
  fd = pfd_info->fd;
  f->eax = fd;

  sema_up(&filesys_sema);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_filesize(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);

  int len = -1;
  struct fd_info* fd_info = get_fd_info(fd);
  if(fd_info == NULL)
    return error_exit(); 

  struct file* file = fd_info->file;

  if(file == NULL){
    return error_exit();
  }

  sema_down(&filesys_sema);

  len = file_length(file);
  f->eax = len;
  sema_up(&filesys_sema);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_read(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8,4) || !is_valid_ptr(f->esp+12, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);
  void *buffer = *(void **)(f->esp+8);
  unsigned size = *(unsigned *)(f->esp+12);

  if(!is_valid_buffer(buffer, size)){
    return error_exit();
  }

  int read_size = -1;
  unsigned i;

  /* stdin 인 경우 */
  if(fd == 0){
    uint8_t* stdin_buf = (uint8_t *)buffer;
    sema_down(&filesys_sema);
    for(i=0; i<size; i++){
      stdin_buf[i] = input_getc();
    }
    read_size = size;
    sema_up(&filesys_sema);
  }
  else if(fd == 1){ /* stdout */
    return error_exit();
  }
  else{
    struct fd_info* fd_info = get_fd_info(fd);
    if(fd_info == NULL)
      return error_exit();

    struct file* file = fd_info->file;
    if(file == NULL){
      return error_exit();
    }
    sema_down(&filesys_sema);
    read_size = file_read(file, buffer, size);
    sema_up(&filesys_sema);
  }

  f->eax = read_size;
}


/*---------------------------------------------------------------------------------------*/

static void syscall_write(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8, 4) || !is_valid_ptr(f->esp+12, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);
  const void *buffer = *(char **)(f->esp+8);
  unsigned size = *(unsigned *)(f->esp+12);

  if(!is_valid_ptr(buffer, size))
    return error_exit();

  int write_size = -1;
 
  /* stdout 인 경우 */
  if(fd == 1){
    sema_down(&filesys_sema);
    putbuf((char *)buffer, (size_t)size);
    write_size = (int)size;
    sema_up(&filesys_sema);
  }
  else{
    struct fd_info *fd_info = get_fd_info(fd);
    if(fd_info == NULL){
      return error_exit();
    }
    struct file* file = fd_info->file;
    if(file == NULL){
      return error_exit();
    }
    sema_down(&filesys_sema);
    write_size = file_write(file, buffer, size);
    sema_up(&filesys_sema);
  }

  f->eax = write_size;
}

/*---------------------------------------------------------------------------------------*/

static void syscall_seek(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);
  unsigned position = *(unsigned *)(f->esp+8);

  struct fd_info* fd_info = get_fd_info(fd);
  if(fd_info == NULL)
    return error_exit();
  struct file* file = fd_info->file;
  if(file == NULL){
    return error_exit();
  }
  sema_down(&filesys_sema);
  file_seek(file, position);
  sema_up(&filesys_sema);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_tell(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);

  struct fd_info* fd_info = get_fd_info(fd);
  if(fd_info == NULL)
    return error_exit();
  struct file* file = fd_info->file;
  if(file == NULL){
    return error_exit();
  }
  sema_down(&filesys_sema);
  f->eax = file_tell(file);
  sema_up(&filesys_sema);
}

/*---------------------------------------------------------------------------------------*/

static void syscall_close(struct intr_frame *f)
{
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int fd = *(int *)(f->esp+4);

  /* stdin stdout 닫는 경우 */
  if(fd==0 || fd==1)
    return error_exit();

  struct fd_info *fd_info = get_fd_info(fd);
  if(fd_info == NULL)
    return error_exit();

  struct file* file = fd_info->file;
  if(file == NULL)
    return error_exit();
  
  sema_down(&filesys_sema);
  file_close(file);
  fd_info->file = NULL;
  sema_up(&filesys_sema);
}

/*---------------------------------------------------------------------------------------*/
static void syscall_mmap(struct intr_frame *f)
{
//printf("syscall mmap!\n");
  if(!is_valid_ptr(f->esp+4, 4) || !is_valid_ptr(f->esp+8, 4)){
    f->eax = -1;
    return;
  }

  int fd = *(int *)(f->esp+4);
  void *addr = *(void **)(f->esp+8);

  /* TODO fd 관련 fail */
  if(fd==0 || fd==1){
    f->eax = -1;
    return;
  }

  struct fd_info *fd_info = get_fd_info(fd);
  if(fd_info == NULL){
    f->eax = -1;
    return;
  }

  sema_down(&filesys_sema);
  struct file* file = file_reopen(fd_info->file);
  if(file == NULL){
    sema_up(&filesys_sema);
    f->eax = -1;
    return;
  }
  sema_up(&filesys_sema);

  off_t file_len;
  sema_down(&filesys_sema);
  if((file_len = file_length(file))==0){
    sema_up(&filesys_sema);
    f->eax = -1;
    return;
  }
  sema_up(&filesys_sema);

  /* TODO addr 관련 fail */
  if(addr==0 || ((uint32_t)addr%PGSIZE) != 0){
    f->eax = -1;
    return;
  }


  uint32_t read_bytes = ROUND_UP(file_len, PGSIZE);
  uint32_t zero_bytes = 0;
  struct spage_table_entry* spte = NULL;
  off_t ofs = 0;
  struct map_info* pmap_info = NULL;

  while(read_bytes>0||zero_bytes>0){
    uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    uint32_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* TODO spage_table_entry 만들어서 넣기 */
    if((spte = (struct spage_table_entry*)malloc(sizeof(struct spage_table_entry))) == NULL){
      munmap(thread_current()->mapid);
      f->eax = -1;
      return;
    }

    spte->upage = addr;
    spte->kpage = NULL;
    spte->type = SPG_MMAP;
    spte->offset = ofs;
    spte->read_bytes = page_read_bytes;
    spte->zero_bytes = page_zero_bytes;
    spte->writable = true;
    spte->file = file;

    if(hash_insert(&thread_current()->spagetbl, &spte->elem)){
      // 이미 있는 경우
      free(spte);
      munmap(thread_current()->mapid);
      f->eax = -1;
      return;
    }
    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    ofs += page_read_bytes;
    addr += PGSIZE;


    /* TODO map info 만들어서 thread의 map_infos에 저장 */
    if((pmap_info = malloc(sizeof(struct map_info))) == NULL){
      munmap(thread_current()->mapid);
      f->eax = -1;
      return;
    }
    pmap_info->mapid = thread_current()->mapid;
    pmap_info->spte = spte;
    list_push_back(&thread_current()->map_infos, &pmap_info->elem);
  } 

  thread_current()->mapid++;
  f->eax = pmap_info->mapid;
  printf("mmap mapid: %d\n", pmap_info->mapid);
  printf("mmap END\n");
}

/*---------------------------------------------------------------------------------------*/
static void syscall_munmap(struct intr_frame *f)
{
printf("syscall munmap!\n");
  if(!is_valid_ptr(f->esp+4, 4))
    return error_exit();

  int mapping = *(int *)(f->esp+4);
  printf("mapping: %d\n", mapping);

  munmap(mapping);
printf("unmap END\n");
}

/*---------------------------------------------------------------------------------------*/
void munmap(int mapid)
{
  struct map_info *pmap_info;
  struct spage_table_entry* spte;
  struct thread* curr = thread_current();
  struct list_elem* le;
  struct file* file = NULL;
  bool find = false;

  printf("munmap mapid: %d\n", mapid);

  for(le = list_begin(&curr->map_infos); le != list_end(&curr->map_infos); le = list_next(le)){
printf("a");
    pmap_info = list_entry(le, struct map_info, elem);
    if(pmap_info->mapid == mapid){
      spte = pmap_info->spte;
      if(file == NULL){
        find = true;
        file = spte->file;
      }
      /* TODO
         case 1) 메모리에 올려져 있다.
           case 1-1) dirty : 파일에 쓰고 frame 비우기
           case 1-2) not dirty : frame 비우기
         case 2) 메모리에 안 올려져 있다. : 넘어감.
      */
      if(spte->kpage != NULL){
        if(pagedir_is_dirty(curr->pagedir, spte->upage)){
          sema_down(&filesys_sema);
          file_write_at(spte->file, spte->upage, spte->read_bytes, spte->offset);
          sema_up(&filesys_sema);
        }
        frametbl_free_frame(spte->kpage);
        pagedir_clear_page(curr->pagedir, spte->upage);
        hash_delete(&curr->spagetbl, &spte->elem);
      }
      list_remove(&pmap_info->elem);
      free(spte);
      free(pmap_info);
    }
    else if(find)
      break;
  }

  /* 파일 닫기 */
  if(file != NULL){
    sema_down(&filesys_sema);
    file_close(file);
    sema_up(&filesys_sema);
  }
}

/*---------------------------------------------------------------------------------------*/

void
syscall_init (void) 
{
  sema_init(&filesys_sema, 1);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  /* esp 저장 */
  thread_current()->esp = f->esp;

  if(!is_valid_ptr(f->esp, 4))
    return error_exit();

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
    case SYS_MMAP:
      syscall_mmap(f);
    case SYS_MUNMAP:
      syscall_munmap(f);
    default:
      return error_exit();
  }

}
