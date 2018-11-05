#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "lib/stddef.h"

void swap_init(void);
size_t swap_out(void *frame);
void swap_in(size_t sec_no, void *frame);

#endif
