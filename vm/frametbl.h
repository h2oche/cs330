#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stddef.h>
#include <stdbool.h>
//#include <list.h>
#include "threads/vaddr.h"
#include "threads/palloc.h"

#define FT_INDEX(KPAGE, BASE) ((uint32_t)((KPAGE) - (uintptr_t)(BASE))) >> PGBITS

struct frame_table_entry {
    bool presented;
    void* frame;
    uint32_t *pagedir;
    struct hash *spagetbl;
    void* vaddr;

    bool is_evicting;
    bool is_loading;
};

void frametbl_init(void); 
void* frametbl_get_frame(enum palloc_flags, void *);
void frametbl_free_frame(void*);
void frametbl_load_complete(void*);

#endif
