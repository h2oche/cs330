#include "vm/frametbl.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include <stddef.h>

extern struct pool user_pool;
struct lock frametbl_lock;
size_t frame_left_cnt;

void
frametbl_init()
{      
    //TODO init lock, frame_left_cnt, frametbl
    lock_init(&frametbl_lock);
}
  
void*
frametbl_get_frame()
{
    /* TODO check if user pool is full */
    lock_acquire(&frametbl_lock);
    if(frame_left_cnt != 0) {
        /* TODO if user pool is not full
        1. update frame_left_cnt(synch) : DONE
        2. palloc_get_page : DONE
        3. update frametbl(synch)*/
        frame_left_cnt--;
        lock_release(&frametbl_lock);

        void* frame = palloc_get_page(PAL_USER);
        //update frame table

        return frame;
    }
    
    /* TODO if user pool is full, choose victim, evict, continue */
    // 우선 panic
    lock_release(&frametbl_lock);
    PANIC("NOT ENOUGH FRAME");
}

void
frametbl_free_frame(void* frame)
{
    /* TODO check if frame is valid -> if not valid error exit*/
    
    /* TODO if frame is valid
    1. palloc_free_page
    1. update frametbl
    2. update frame_left_cnt */
    lock_acquire(&frametbl_lock);

    lock_release(&frametbl_lock);
}