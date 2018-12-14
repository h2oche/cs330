#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "stddef.h"
#include "stdbool.h"
#include "threads/synch.h"
#include "devices/disk.h"

#define BUFFER_CACHE_SIZE 64

/* buffer cache entry */
struct buffer_cache_entry {
  uint8_t data[DISK_SECTOR_SIZE];   /* data */
  disk_sector_t sector_idx;        /* sector */

  bool valid;                       /* valid bit */
  bool dirty;                       /* dirty bit */
  bool access;                      /* access bit */
  bool is_loaded;                   /* is_loaded */
  
  int reference_cnt;                /* for eviction */

  struct lock lock;                 /* cache entry lock */
  struct condition load_cond;       /* condvar for load */
};

void buffer_cache_init(void);
void buffer_cache_done(void);

void func_write_behind(void);
void func_read_ahead(void);

int buffer_cache_idx(disk_sector_t);
void buffer_cache_read(disk_sector_t, uint8_t*, off_t, int);
void buffer_cache_write(disk_sector_t, uint8_t*, off_t, int);

#endif