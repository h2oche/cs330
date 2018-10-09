#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"
#include "threads/synch.h"

struct semaphore filesys_sema;

void syscall_init (void);

#endif /* userprog/syscall.h */
