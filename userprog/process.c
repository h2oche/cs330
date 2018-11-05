#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

/* VM */
#include "vm/frametbl.h" 
#include "vm/spagetbl.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

struct child_info
{
  tid_t tid;
  bool is_alive;
  bool is_waited;
  int exit_status;
  struct semaphore wait_sema;
  struct list_elem elem;
};

/*----------------------------------------------------------------------------*/

/* child info 생성 함수 */
static struct child_info *
create_child_info (tid_t tid)
{
  struct child_info *c = (struct child_info *)malloc(sizeof(struct child_info));

  // malloc 실패
  if(c==NULL)
    return NULL;

  c->tid = tid;
  c->is_alive = true;
  c->is_waited = false;
  c-> exit_status = 0;
  sema_init(&c->wait_sema, 0);

  return c;
}

/*----------------------------------------------------------------------------*/

/* thread가 가진 children 중 해당 tid를 갖는 child_info를 return. 없으면 NULL  */
static struct child_info *
get_child_info(struct thread *t, tid_t tid)
{
  if(t==NULL)
    return NULL;

  struct child_info* child = NULL;
  struct list_elem *le = NULL;
  struct list* lp = &t->children;
  for(le = list_begin(lp);
      le != list_end(lp);
      le = list_next(le))
  {
    child = list_entry(le, struct child_info, elem);
    if(child->tid == tid)
      return child;
  }
  return NULL;
}

/*----------------------------------------------------------------------------*/

/* child info를 모두 제거 함수 */
static void
destroy_children(struct thread* t)
{
  struct child_info *c = NULL;
  struct list_elem *le = NULL;
  struct list_elem *nle = NULL;
  struct thread* child;

  for(le = list_begin(&t->children);
      le != list_end(&t->children);
      le = nle)
  {
    nle = list_next(le);
    c = list_entry(le, struct child_info, elem);
    child = tid_to_thread(c->tid);
    child->parent = NULL;

    /* 리스트에서 없애고 free */
    list_remove(&c->elem);
    free(c);
  }
}

/*----------------------------------------------------------------------------*/

/* fd_info를 모두 제거하는 함수 */
static void
destroy_fd_infos(struct thread* t)
{
  struct fd_info *f = NULL;
  struct list_elem *le = NULL;
  struct list_elem *nle = NULL;

  for(le = list_begin(&t->fd_infos);
      le != list_end(&t->fd_infos);
      le = nle)
  {
    nle = list_next(le);
    f = list_entry(le, struct fd_info, elem);

    /* 열러 있는 파일 닫기 */
    if(f->file != NULL){
      sema_down(&filesys_sema);
      file_close(f->file);
      sema_up(&filesys_sema);
    }

    /* 리스트에서 없애고 free */
    list_remove(&f->elem);
    free(f);
  }
}

/*----------------------------------------------------------------------------*/


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* TODO 파일 이름 파싱 - thread name으로 사용 */
  char *save_ptr;
  char *f_name = malloc(strlen(file_name)+1);
  //if(f_name == NULL)
  strlcpy (f_name, file_name, strlen(file_name)+1);
  f_name = strtok_r (f_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  thread_current()->child_success = false;
  tid = thread_create (f_name, PRI_DEFAULT, start_process, fn_copy);

  /* TODO 파일 이름 free */
  free(f_name);

  /* TODO 자식 load 기다리기 */
  sema_down(&thread_current()->load_lock);

  if (tid == TID_ERROR){
    palloc_free_page (fn_copy);
    return tid;
  }

  if(thread_current()->child_success == false)
    return -1;

  /* TODO child_info를 만들어서 저장 */
  struct child_info *c = create_child_info(tid);
  if(c == NULL){
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  list_push_back(&thread_current()->children, &c->elem);

  return tid;
}

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
  char *file_name = f_name;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  struct thread* parent = thread_current()->parent;
  parent->child_success = success;
  sema_up(&parent->load_lock);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success){
//    PANIC("load\n");
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  int exit_status = -1;

  /* TODO 기다림 없이 바로 return 하는 상황 처리 */
  struct child_info* c = get_child_info(thread_current(), child_tid);
  if(c == NULL || c->is_waited)
    return exit_status;

  /* TODO 이미 죽은 process 처리 */
  if(!c->is_alive){
    exit_status = c->exit_status;
    list_remove(&c->elem);
    free(c);
    return exit_status;
  }

  /* TODO 기다리기 */
  c->is_waited = true;
  sema_down(&c->wait_sema);
  exit_status = c->exit_status;
  list_remove(&c->elem);
  free(c);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *curr = thread_current ();
  uint32_t *pd;

  int exit_status = curr->exit_status;
  struct child_info *c = get_child_info(curr->parent, curr->tid);

  /* TODO 종료 메세지 */
  printf("%s: exit(%d)\n", curr->name, exit_status);

  /* TODO 열었던 파일 모두 닫기, child_info 제거 */
  destroy_fd_infos(curr);
  destroy_children(curr);

  if(curr->exe_file != NULL){
    file_allow_write(curr->exe_file);
    sema_down(&filesys_sema);
    file_close(curr->exe_file);
    sema_up(&filesys_sema);
  }


  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* Destroy supplementary hash table */
  if( &curr->spagetbl != NULL) {
    while(hash_size(&curr->spagetbl) > 0) {
      struct hash_iterator i;
      hash_first(&i, &curr->spagetbl);
      hash_next(&i);
      struct spage_table_entry* spte = hash_entry(hash_cur(&i), struct spage_table_entry, elem);
      hash_delete(&curr->spagetbl, hash_cur(&i));
      if(spte!=NULL) free(spte);
    }
  }

  /* TODO parent가 가지고 있는 child_info 업데이트 */
   if(c!=NULL){
    c->is_alive = false;
    c->exit_status = exit_status;
    sema_up(&c->wait_sema);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char* file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  sema_down(&filesys_sema);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* init supplementary hash table */
  hash_init(&t->spagetbl, spagetbl_hash_func, spagetbl_hash_less_func, NULL);

  /* TODO 파일 이름 파싱 - open 위해서 */
  char *save_ptr;
  char *fn_copy = malloc(strlen(file_name)+1);
  //if(fn_copy == NULL)
  strlcpy(fn_copy, file_name, strlen(file_name)+1);
  fn_copy = strtok_r(fn_copy, " ", &save_ptr);

  /* Open executable file. */
  file = filesys_open (fn_copy);

  /* TODO 파일 이름 free */
  free(fn_copy); 

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  if (strlen(file_name) > PGSIZE / 2 || !setup_stack (esp, file_name))
    goto done;


//  hex_dump(PHYS_BASE - 0x70, PHYS_BASE - 0x70, 0x70, true);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(success){
    t->exe_file = file;
    file_deny_write(file);
  }
  sema_up(&filesys_sema);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while( read_bytes > 0 || zero_bytes > 0 )
    {
      /* TODO spage_table_entry 만들어서 insert */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct spage_table_entry* spte = (struct spage_table_entry*)malloc(sizeof(struct spage_table_entry));
      if(spte == NULL)
        return false;
      spte->vaddr = upage;
      spte->offset = ofs;
      spte->read_bytes = page_read_bytes;
      spte->zero_bytes = page_zero_bytes;
      spte->writable = writable;
      spte->storage = SPG_FILESYS; //page_read_bytes == 0 ? SPG_ZERO : SPG_FILESYS; -> 0인 경우는 while문 통과 못함.
      hash_insert(&thread_current()->spagetbl, &spte->elem);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }

  return true;

}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *file_name) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = frametbl_get_frame(PAL_USER|PAL_ZERO, PHYS_BASE-PGSIZE);

  if (kpage != NULL){
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);

    if(!success){
      frametbl_free_frame (kpage);
      return false;
    }

    /* TODO spage_table_entry 만들어서 insert */
    struct spage_table_entry* spte = (struct spage_table_entry*)malloc(sizeof(struct spage_table_entry));
    spte->vaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;
    spte->writable = true;
    spte->storage = SPG_MEMORY;
    hash_insert(&thread_current()->spagetbl, &spte->elem);

    *esp = PHYS_BASE;
  }

  /* TODO 파싱해서 스택에 넣기 */
  char *token, *save_ptr;
  int argc = 0;
  char *fn_copy = malloc(strlen(file_name)+1);
  if(fn_copy == NULL)
    return false;
  strlcpy(fn_copy, file_name, strlen(file_name)+1);

  /* argument 개수 세기 */
  for(token = strtok_r(fn_copy, " ", &save_ptr);
      token != NULL;
      token = strtok_r(NULL, " ", &save_ptr)){
    argc++;
  }

  strlcpy(fn_copy, file_name, strlen(file_name)+1);

  char **argv = (char **)calloc(argc, sizeof(char*));
  if(argv == NULL)
    return false;

  /* stack에 argument string 넣기 */
  int i = 0;
  for(token = strtok_r(fn_copy, " ", &save_ptr);
      token != NULL;
      token = strtok_r(NULL, " ", &save_ptr)){
    argv[i] = token;
    i++;
  }

  for(i=argc-1;i>=0;i--){
    *esp -= (strlen(argv[i])+1);
    memcpy(*esp, argv[i], strlen(argv[i])+1);
    argv[i] = *esp;
  }

  /* alignment */
  uint8_t zero = 0;
  for(i = (int)*esp%4; i>0; i--){
    *esp -= 1;
    memcpy(*esp, &zero, 1);
  }

  /* null */
  uint32_t zero2 = 0;
  *esp -= 4;
  memcpy(*esp, &zero2, 4);

  /* stack에 argument string 주소 넣기 */
  for(i=argc-1;i>=0;i--){
    *esp -= 4;
    memcpy(*esp, &argv[i], 4);
  }

  /* stack에 argv 주소 넣기 */
  void **cp = esp;
  uint32_t p = (uint32_t)*cp;
  *esp -= 4;
  memcpy(*esp, &p, 4);

  /* stack에 argc 넣기 */
  *esp -= 4;
  memcpy(*esp, &argc, 4);

  /* return address 넣기 */
  *esp -= 4;
  memcpy(*esp, &zero2, 4);

  /* free */
  free(argv);
  free(fn_copy);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  // printf("test\n");

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
