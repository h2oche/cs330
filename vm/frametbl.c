#include "vm/frametbl.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include <stddef.h>
#include <malloc.h>

/* GLOBAL */
size_t frame_left_cnt = 0;
size_t frame_max_cnt = 0;
struct lock frametbl_lock;
struct frame_table_entry* frame_table;
extern struct pool user_pool;

/*---------------------------------------------------------------------------------------*/
/* get index of kpage in frame table */
int
frametbl_index(void* kpage) {
    return FT_INDEX(kpage, user_pool.base);
}
/*---------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------*/
/* frame table initialization */
void
frametbl_init(void)
{      
    int i;
    struct frame_table_entry* fte;

    lock_init(&frametbl_lock);
    frame_left_cnt = frame_max_cnt;
    frame_table = (struct frame_table_entry*)calloc(sizeof(struct frame_table_entry), frame_max_cnt);
    if(frame_table == NULL) PANIC("frametbl_init error");

    printf("%d frame table entries initialized\n", frame_max_cnt);

    for(i = 0 ; i < frame_max_cnt ; i += 1) {
        frame_table[i].presented = false;
    }
}
/*---------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------*/
/* wrapper of palloc_get_page(PAL_USER) */ 
void*
frametbl_get_frame(void)
{
    void* kpage;
    struct frame_table_entry* fte;

    /* TODO check if user pool is full */
    lock_acquire(&frametbl_lock);
    if(frame_left_cnt != 0) {
        /* TODO if user pool is not full
        1. update frame_left_cnt(synch) : DONE
        2. palloc_get_page : DONE
        3. update frametbl(synch) : DONE*/
        frame_left_cnt--;
        lock_release(&frametbl_lock);

        kpage = palloc_get_page(PAL_USER | PAL_ZERO);
        //update frame table
        lock_acquire(&frametbl_lock);
        fte = &frame_table[frametbl_index(kpage)];
    
        ASSERT(fte->presented == false);
        fte->presented = true;
        fte->frame = kpage;
        
        lock_release(&frametbl_lock);
        return kpage;
    }
    
    /* TODO if user pool is full, choose victim, evict, continue */
    // 우선 panic
    lock_release(&frametbl_lock);
    PANIC("NOT ENOUGH FRAME");
}
/*---------------------------------------------------------------------------------------*/


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
