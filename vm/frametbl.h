#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stddef.h>
#include <stdbool.h>
#include <list.h>
#include "threads/vaddr.h"

#define FT_INDEX(KPAGE, BASE) ((uint32_t)((KPAGE) - (uintptr_t)(BASE))) >> PGBITS

extern size_t frame_max_cnt;

struct frame_table_entry {
    bool presented;
    void* frame;
};

void frametbl_init(void); 
void* frametbl_get_frame(void);
void frametbl_free_frame(void*);

#endif
