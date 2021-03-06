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
#include "userprog/syscall.h"
#include "filesys/file.h"

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

void
frametbl_evict()
{
    struct frame_table_entry* fte;

    /* select victim */
    while(true){
        fte = &frame_table[search_idx()];
        if(fte->is_loading) continue;
        if(pagedir_is_accessed(fte->pagedir, fte->vaddr))
            // accessed bit 바꾸고 넘어감.
            pagedir_set_accessed(fte->pagedir, fte->vaddr, false);
        else break; // 선택
    }

    /* swap disk에 저장 */
    struct spage_table_entry* spte = spagetbl_get_spte(fte->spagetbl, fte->vaddr);
    ASSERT(spte != NULL);

    /* TODO MMAP인 경우, dirty면 파일에 써주기 */
    if(spte->type == SPG_MMAP){
      if(pagedir_is_dirty(fte->pagedir, spte->upage)){
        file_write_at(spte->file, spte->kpage, spte->read_bytes, spte->offset);
      }
      spte->kpage = NULL;
      /* pte update */
        pagedir_clear_page(fte->pagedir, fte->vaddr);
    }
    else{
        /* pte update */
        pagedir_clear_page(fte->pagedir, fte->vaddr);
      /* spte update */
      spte->swap_sec_no = swap_out(fte->frame);
      spte->type = SPG_SWAP;
    }

    /* swap out 된 frame 비우기 */
    ASSERT(fte->frame != NULL);
    palloc_free_page(fte->frame);
    
    /* fte update */
    fte = &frame_table[frametbl_index(fte->frame)];
    fte->presented = false;
    fte->frame = NULL;
    frame_left_cnt++;
}

/*---------------------------------------------------------------------------------------*/
/* wrapper of palloc_get_page(PAL_USER) */ 
void*
frametbl_get_frame(enum palloc_flags flags, void *vaddr)
{
    void* kpage;
    struct frame_table_entry* fte;

    lock_acquire(&frametbl_lock);

    /* TODO check if user pool is full */
    
    /* user pool이 다 찬 경우  */
    if(frame_left_cnt == 0){
        // lock_release(&frametbl_lock);
        frametbl_evict();
        // lock_acquire(&frametbl_lock);
    }

    /* TODO
        1. update frame_left_cnt(synch) : DONE
        2. palloc_get_page : DONE
        3. update frametbl(synch) : DONE       */

    frame_left_cnt--;
    kpage = palloc_get_page(flags);
    fte = &frame_table[frametbl_index(kpage)];
    
    /* fte update */
    ASSERT(fte->presented == false);
    fte->presented = true;
    fte->is_loading = true;
    fte->frame = kpage;
    fte->pagedir = thread_current()->pagedir;
    fte->spagetbl = &thread_current()->spagetbl;
    fte->vaddr = vaddr;
      
    lock_release(&frametbl_lock);
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

    lock_acquire(&frametbl_lock);
    
    /* TODO if frame is valid
    1. palloc_free_page
    1. update frametbl
    2. update frame_left_cnt */
    palloc_free_page(kpage);

    fte = &frame_table[frametbl_index(kpage)];
    fte->presented = false;
    fte->is_loading = false;
    fte->frame = NULL;

    frame_left_cnt++;
    lock_release(&frametbl_lock);
}
/*---------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------*/
void
frametbl_load_complete(void* kpage)
{   
    ASSERT(kpage != NULL);
    ASSERT(frametbl_index(kpage) < frame_max_cnt);

    struct frame_table_entry* fte;

    lock_acquire(&frametbl_lock);

    fte = &frame_table[frametbl_index(kpage)];
    fte->is_loading = false;

    lock_release(&frametbl_lock);
}

/*---------------------------------------------------------------------------------------*/
