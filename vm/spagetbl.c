#include "vm/spagetbl.h"
#include <hash.h>
#include <stdbool.h>
#include <stddef.h>
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "lib/stdint.h"
#include "lib/string.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "vm/frametbl.h"

static bool install_page (void *upage, void *kpage, bool writable);

/*---------------------------------------------------------------------------------------*/
/* Returns hash value for spte */
unsigned
spagetbl_hash_func(const struct hash_elem *elem, void * aux UNUSED)
{
    const struct spage_table_entry* spte = hash_entry(elem, struct spage_table_entry, elem);
    return hash_bytes(&spte->vaddr, sizeof(&spte->vaddr));
}

/*---------------------------------------------------------------------------------------*/
/* Returns true if spte a precedes page b */
bool
spagetbl_hash_less_func(const struct hash_elem* elem1, const struct hash_elem* elem2, void* aux UNUSED)
{
    const struct spage_table_entry* spte1 = hash_entry(elem1, struct spage_table_entry, elem);
    const struct spage_table_entry* spte2 = hash_entry(elem2, struct spage_table_entry, elem);
    return spte1->vaddr < spte2->vaddr;
}

/*---------------------------------------------------------------------------------------*/
/* vaddr로 spage_table_entry 찾기, 없는 경우 NULL */

struct spage_table_entry*
spagetbl_get_spte(void *vaddr)
{
  struct spage_table_entry spte;
  struct hash_elem* e = NULL;

  PANIC("SPAGE_TBL_ENTRY");

  spte.vaddr = pg_round_down(vaddr);
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

  PANIC("SPTBL_LOAD");

  switch(spte->storage){
    case SPG_FILESYS:
      /* TODO 할당 받은 frame에 파일 쓰고(남는 부분은 0으로 채우기), install page 하기 */ 
      frame = frametbl_get_frame(PAL_USER, spte->vaddr);
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

      // install page
      if(!install_page(spte->vaddr, frame, spte->writable)){
        frametbl_free_frame(frame);
        return false;
      }
      return true;

    case SPG_ZERO:
      /* TODO 빈 페이지 install 하기 */
      frame = frametbl_get_frame(PAL_USER | PAL_ZERO, spte->vaddr);
      if(frame == NULL) return false;

      memset(frame, 0, PGSIZE); // frame 0으로 채우기

      // install page
      if(!install_page(spte->vaddr, frame, spte->writable)){
        frametbl_free_frame(frame);
        return false;
      }
      return true;

    case SPG_SWAP:
      /* TODO 페이지 할당해서 swap disk에 있는 페이지 옮김 */
      frame = frametbl_get_frame(PAL_USER, spte->vaddr);
      if(frame==NULL) return false;

      // install page
      if(!install_page(spte->vaddr, frame, spte->writable)){
        frametbl_free_frame(frame);
        return false;
      }

      swap_in(spte->swap_sec_no, spte->vaddr);
      return true;  

    case SPG_MEMORY:
      /* 이미 메모리에 있어서 아무것도 안해도 됨 */
      return true;
  }
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

