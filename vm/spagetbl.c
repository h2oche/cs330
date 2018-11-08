#include "vm/spagetbl.h"
#include <hash.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "lib/stdint.h"
#include "lib/string.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "vm/frametbl.h"
#include "threads/malloc.h"

static bool install_page (void *upage, void *kpage, bool writable);

/*---------------------------------------------------------------------------------------*/
/* Returns hash value for spte */
unsigned
spagetbl_hash_func(const struct hash_elem *elem, void * aux UNUSED)
{
    const struct spage_table_entry* spte = hash_entry(elem, struct spage_table_entry, elem);
    return hash_bytes(&spte->upage, sizeof(&spte->upage));
}

/*---------------------------------------------------------------------------------------*/
/* Returns true if spte a precedes page b */
bool
spagetbl_hash_less_func(const struct hash_elem* elem1, const struct hash_elem* elem2, void* aux UNUSED)
{
    const struct spage_table_entry* spte1 = hash_entry(elem1, struct spage_table_entry, elem);
    const struct spage_table_entry* spte2 = hash_entry(elem2, struct spage_table_entry, elem);
    return spte1->upage < spte2->upage;
}

/*---------------------------------------------------------------------------------------*/
bool
spagetbl_init(void)
{
  return hash_init(&thread_current()->spagetbl, spagetbl_hash_func, spagetbl_hash_less_func, NULL);
}

/*---------------------------------------------------------------------------------------*/
/* vaddr를 받아서 페이지 주소(virtual page address)로 변환 후
   spage_table_entry 찾기, 없는 경우 NULL */

struct spage_table_entry*
spagetbl_get_spte(void *vaddr)
{
  struct spage_table_entry spte;
  struct hash_elem* e = NULL;

  spte.upage = pg_round_down(vaddr);
  if((e=hash_find(&thread_current()->spagetbl, &spte.elem)) == NULL)
    return NULL; // 없는 경우
  return hash_entry(e, struct spage_table_entry, elem);
}

/*---------------------------------------------------------------------------------------*/
/* load하고 실패한 경우 false */
bool
spagetbl_load(struct spage_table_entry* spte)
{
  uint8_t *frame = NULL;

  switch(spte->storage){
    case SPG_FILESYS:
      /* TODO 할당 받은 frame에 파일 쓰고(남는 부분은 0으로 채우기), install page 하기 */ 
      frame = frametbl_get_frame(PAL_USER, spte->upage);
      if(frame == NULL) return false;

      sema_down(&filesys_sema);
      // 파일 읽어서 frame에 쓰기
      if(file_read_at(thread_current()->exe_file, frame, spte->read_bytes, spte->offset) != (int)spte->read_bytes)
      {
        sema_up(&filesys_sema);
        frametbl_free_frame(frame);
        return false;
      }
      sema_up(&filesys_sema);
      memset(frame + spte->read_bytes, 0, spte->zero_bytes);
//printf("FILE writable: %d\n", spte->writable);
      // install page
      if(!install_page(spte->upage, frame, spte->writable)){
        frametbl_free_frame(frame);
        return false;
      }
      spte->kpage = frame;
      spte->storage = SPG_MEMORY;
      return true;

    case SPG_ZERO:
      /* TODO 빈 페이지 install 하기 */
      frame = frametbl_get_frame(PAL_USER | PAL_ZERO, spte->upage);
      if(frame == NULL) return false;

      memset(frame, 0, PGSIZE); // frame 0으로 채우기
//printf("ZERO writable: %d\n", spte->writable);
      // install page
      if(!install_page(spte->upage, frame, spte->writable)){
        frametbl_free_frame(frame);
        return false;
      }
      spte->storage = SPG_MEMORY;
      spte->kpage = frame;
      return true;

    case SPG_SWAP:
      /* TODO 페이지 할당해서 swap disk에 있는 페이지 옮김 */
      frame = frametbl_get_frame(PAL_USER, spte->upage);
      if(frame==NULL) return false;
//printf("SWAP writable: %d\n", spte->writable);
      // install page
      if(!install_page(spte->upage, frame, spte->writable)){
        frametbl_free_frame(frame);
        return false;
      }

      swap_in(spte->swap_sec_no, spte->upage);
      spte->kpage = frame;
      spte->storage = SPG_MEMORY;
      return true;  

    case SPG_MEMORY:
      /* 이미 메모리에 있어서 아무것도 안해도 됨 */
      return true;
  }
  return false;
}

/*---------------------------------------------------------------------------------------*/
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/*---------------------------------------------------------------------------------------*/
bool
spagetbl_stack_grow(void * vaddr)
{
  /* TODO spte 만들어서 정보 저장하고 insert, 로드하기 */
  struct spage_table_entry* spte = (struct spage_table_entry *)malloc(sizeof(struct spage_table_entry));
  if(spte == NULL)
    return false;
  spte->upage = pg_round_down(vaddr);
  spte->kpage = NULL; // load에서 설정될 예정
  spte->storage = SPG_ZERO;
  spte->writable = true;
  hash_insert(&thread_current()->spagetbl, &spte->elem);

  if(!spagetbl_load(spte))
    return false;

//  printf("stack grow done\n");
  return true;
}
