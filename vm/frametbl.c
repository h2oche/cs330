#include "vm/frametbl.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include <stdio.h>
#include <stdlib.h>
#include <bitmap.h>
#include "threads/malloc.h"
#include "vm/swap.h"
#include "vm/spagetbl.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

/* GLOBAL */
size_t frame_left_cnt = 0;
size_t frame_max_cnt = 0;
struct lock frametbl_lock;
struct frame_table_entry* frame_table;
extern struct pool user_pool;
size_t frame_search = 0;

size_t search_idx (void);
size_t frametbl_index (void*);


/*---------------------------------------------------------------------------------------*/
/* circular queue 처럼 만들기 위해서 */
size_t 
search_idx (void){
  frame_search++;
  if(frame_search==frame_max_cnt)
    frame_search = 0;
  return frame_search;
}

/*---------------------------------------------------------------------------------------*/
/* get index of kpage in frame table */
size_t
frametbl_index(void* kpage) {
    return FT_INDEX(kpage, user_pool.base);
}

/*---------------------------------------------------------------------------------------*/
/* frame table initialization */
void
frametbl_init(void)
{      
    size_t i;

    lock_init(&frametbl_lock);
    frame_max_cnt = bitmap_size (user_pool.used_map);
//    printf("cnt: %u\n", frame_max_cnt);
    frame_left_cnt = frame_max_cnt;
    frame_table = (struct frame_table_entry*)calloc(frame_max_cnt, sizeof(struct frame_table_entry));
    if(frame_table == NULL) PANIC("frametbl_init error");

//    printf("%d frame table entries initialized\n", frame_max_cnt);

    for(i = 0 ; i < frame_max_cnt ; i += 1) {
        frame_table[i].presented = false;
    }
}

/*---------------------------------------------------------------------------------------*/
/* wrapper of palloc_get_page(PAL_USER) */ 
void*
frametbl_get_frame(enum palloc_flags flags, void *vaddr)
{
    void* kpage;
    struct frame_table_entry* fte;

    /* TODO check if user pool is full */
    lock_acquire(&frametbl_lock);

    if(frame_left_cnt == 0){
      /* user pool이 다 찬 경우  */
//PANIC("QQQ");
      while(true){
        fte = &frame_table[search_idx()];
        if(pagedir_is_accessed(fte->pagedir, fte->vaddr))
          // accessed bit 바꾸고 넘어감.
          pagedir_set_accessed(fte->pagedir, fte->vaddr, false);
        else break; // 선택
      }

      // swap disk에 저장
      struct spage_table_entry* spte = spagetbl_get_spte(fte->vaddr);
      spte->storage = SPG_SWAP;
      spte->swap_sec_no = swap_out(fte->frame);

      // 비우기
      frametbl_free_frame(fte->frame);
    }

    /* TODO
        1. update frame_left_cnt(synch) : DONE
        2. palloc_get_page : DONE
        3. update frametbl(synch) : DONE       */

//PANIC("AAA");

    frame_left_cnt--;
    lock_release(&frametbl_lock);

    kpage = palloc_get_page(flags);
    //update frame table - fte 값 설정
    lock_acquire(&frametbl_lock);
    fte = &frame_table[frametbl_index(kpage)];
    
    ASSERT(fte->presented == false);
    fte->presented = true;
    fte->frame = kpage;
    fte->pagedir = thread_current()->pagedir;
    fte->vaddr = vaddr;
      
    lock_release(&frametbl_lock);

//PANIC("ZZZ");
    return kpage;

}

/*---------------------------------------------------------------------------------------*/
/* wrapper of palloc_free_page() in user */
void
frametbl_free_frame(void* kpage)
{
    /* TODO check if kpage is valid -> if not valid exit*/
    ASSERT(kpage != NULL);
    ASSERT(frametbl_index(kpage) < frame_max_cnt);

    struct frame_table_entry* fte;
    
    /* TODO if frame is valid
    1. palloc_free_page
    1. update frametbl
    2. update frame_left_cnt */
    palloc_free_page(kpage);

    lock_acquire(&frametbl_lock);
    fte = &frame_table[frametbl_index(kpage)];
    fte->presented = false;
    fte->frame = NULL;

    frame_left_cnt++;
    lock_release(&frametbl_lock);
}
/*---------------------------------------------------------------------------------------*/
