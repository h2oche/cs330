#ifndef VM_FRAME_H
#define VM_FRAME_H

void frametbl_init(); 
void* frametbl_get_frame();
void frametbl_free_frame();

#endif