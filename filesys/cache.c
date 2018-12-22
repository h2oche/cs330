#include "filesys/cache.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/disk.h"
#include "devices/timer.h"
#include "filesys/off_t.h"
#include "filesys/filesys.h"
#include <stddef.h>
#include <string.h>

struct buffer_cache_entry* buffer_cache;
struct lock cache_lock;
int needle = -1;

void buffer_cache_select_victim(void);
int get_next_needle(void);
int buffer_cache_load(disk_sector_t); 
static void func_read_ahead(void *);
static void func_write_behind(void *);

/*---------------------------------------------------------------------------------------*/
int
get_next_needle(void) {
  return (needle = needle + 1) % BUFFER_CACHE_SIZE;
}
/*---------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------*/
/* buffer cache initialization */
void
buffer_cache_init(void) {
  buffer_cache = (struct buffer_cache_entry*)calloc(BUFFER_CACHE_SIZE, sizeof(struct buffer_cache_entry));
  if(buffer_cache == NULL)
    PANIC("can't initialize buffer cache");

  lock_init(&cache_lock);

  int i = 0;
  for(; i < BUFFER_CACHE_SIZE ; i += 1) {
    lock_init(&buffer_cache[i].lock);
    cond_init(&buffer_cache[i].load_cond);
  }

  /* TODO 주기적으로 write-back하는 thread 생성 */
  thread_create("write-behind", PRI_DEFAULT, func_write_behind, NULL);

  printf("buffer cache init...\n");
}
/*---------------------------------------------------------------------------------------*/

/* pintos가 모든 작업을 끝냈을 때 buffer_cache[dirty == true] -> disk */
void
buffer_cache_done(void) {
  int i = 0;
  /* TODO dirty 일 경우 disk-write */
  for(; i < BUFFER_CACHE_SIZE; i += 1)
    if(buffer_cache[i].valid && buffer_cache[i].dirty)
      disk_write(filesys_disk, buffer_cache[i].sector_idx, buffer_cache[i].data);
}
/*---------------------------------------------------------------------------------------*/

/* TODO 
  - index of buffer_cache[idx].sector_idx == sector_idx ?
*/

int
buffer_cache_idx(disk_sector_t sector_idx) {
  int i = 0;
  for(; i < BUFFER_CACHE_SIZE; i += 1)
    if(buffer_cache[i].valid && buffer_cache[i].sector_idx == sector_idx)
      return i;
  return -1;
}
/*---------------------------------------------------------------------------------------*/

/*
  - buffer_cache에서 빈 entry 하나를 가져옴
  - 반드시 cache_lock을 든 상태로 호출해야함
 */
int
buffer_cache_empty_idx() {
  int i = 0;
  for(; i < BUFFER_CACHE_SIZE; i += 1)
    if(buffer_cache[i].valid == false)
      return i;

  /* TODO
    1. clock-algorithm에 의해 victim 선택
      - reference_cnt > 0 인 것들은 read, wrtie 중인 것들이므로 victim 이 되면 안됨
    2. victim을 evict
      - evict 되는 동안 해당 entry는 read/write 는 불가능함(cache_lock에 의해 보장됨)
    3. evict된 entry 초기화 후 return */

  struct buffer_cache_entry* victim = NULL;
  int victim_idx;
  while(true) {
    victim_idx = get_next_needle();
    victim = &buffer_cache[victim_idx];
    if(victim->reference_cnt == 0) {
      if(victim->access) {
        victim->access = false;
        continue;
      }
      break;
    }
  }

  /* cache -> disk */
  disk_write(filesys_disk, victim->sector_idx, victim->data);
  // printf("victim : %d\n", victim_idx);

  /* cache entry 초기화 */
  victim->valid = false;
  victim->access = false;
  victim->dirty = false;
  victim->is_loaded = false;
  victim->reference_cnt = 0;
  victim->sector_idx = -1;
  memset(victim->data, 0, DISK_SECTOR_SIZE);
  return victim_idx;
}
/*---------------------------------------------------------------------------------------*/

/* TODO
  1. sector_idx가 buffer_cache에 있는지 확인
    1-1. 있으면 return
    1-2. 없으면 disk->cache 복사
*/
int
buffer_cache_load(disk_sector_t sector_idx) {
  struct buffer_cache_entry* ce = NULL;
  lock_acquire(&cache_lock);

  int cache_idx = buffer_cache_idx(sector_idx);
  // printf("buffer_cache_load->cache_idx : %d\n", cache_idx);

  if(cache_idx != -1) {
    buffer_cache[cache_idx].reference_cnt++;
    lock_release(&cache_lock);
    return cache_idx;
  }
  
  /* TODO 빈 entry 하나 가져와야 함 */
  int empty_idx = buffer_cache_empty_idx();
  // printf("buffer_cache_load->empty_idx : %d\n", empty_idx);

  /* 빈 entry 초기화 */
  ce = &buffer_cache[empty_idx];
  ce->sector_idx = sector_idx;
  ce->valid = true;
  ce->access = true;
  ce->is_loaded = false;
  ce->reference_cnt = 1;

  lock_release(&cache_lock);
  // printf("buffer_cache_load lock released\n");

  lock_acquire(&ce->lock);
  disk_read(filesys_disk, sector_idx, ce->data);
  ce->is_loaded = true;

  cond_broadcast(&ce->load_cond, &ce->lock);
  lock_release(&ce->lock);

  // printf("buffer_cache load completed\n");

  return empty_idx;
}
/*---------------------------------------------------------------------------------------*/

/*TODO 
  1. sector_idx가 buffer_cache에 있는지 확인
    - buffer_cache_load
    - cache -> buffer 복사
      - disk_read 중일 경우 있음(load가 덜 된 경우) -> is_loaded, lock 이용
        - 다른 kernel-thread가 읽고 있을 때 발생(disk_read, read_ahead)
      - read 도중 evict 되면 안됨 -> evictable 이용
  2. read-ahead(sector_idx + 1 이 buffer_cache에 있는지 확인)
    2-1. 있으면 return
    2-2. 없으면 새로운 thread 만들어서 disk[sector_idx + 1] -> buffer_cache 로 복사 (IO required)

  ** Read/Wrtie Synchronization **
  - disk[sector_idx]가 read-ahead에 의해 읽어지고 있는 경우
  - disk[sector_idx]가 write에 의해 쓰여지고 있는 경우

  ** Cache Synchronization **
  - empty_idx로 한번 선정된 index는 다시 empty_idx로 선택될 수 없음 -> global_lock 필요
  - disk[sector_idx]가 victim으로 선정되어 evict 되고 있는 경우
  - disk[sector_idx]가 timer_interrupt에 의해 disk에 쓰여지고 있는 경우
  */
void
buffer_cache_read(disk_sector_t sector_idx, uint8_t* buffer, off_t sector_ofs, int chunk_size) {
  struct buffer_cache_entry* ce = NULL;
  // printf("cache_read : %d\n", sector_idx);

  int cache_idx = buffer_cache_load(sector_idx);

  ce = &buffer_cache[cache_idx];
  ce->access = true;

  /* 아직 disk_read 중이면 기다려야 함 */
  lock_acquire(&ce->lock);
  if(ce->is_loaded == false)
    cond_wait(&ce->load_cond, &ce->lock);
  lock_release(&ce->lock);

  memcpy(buffer, ce->data + sector_ofs, chunk_size);

  lock_acquire(&cache_lock);
  ce->reference_cnt--;
  lock_release(&cache_lock);

  /* TODO read-ahead */
  lock_acquire(&cache_lock);
  cache_idx = buffer_cache_idx(sector_idx + 1);

  /* 있으면 return */
  if(cache_idx != -1) {
    lock_release(&cache_lock);
    return;
  }

  /* 없으면
    1. 새로운 thread 만듬
    2. disk[sector_idx + 1] -> buffer_cache 로 복사 (IO required) */
  lock_release(&cache_lock);
  disk_sector_t* next_sector_ptr = malloc(sizeof(disk_sector_t));
  if(next_sector_ptr == NULL)
    return;

  *next_sector_ptr = sector_idx + 1;
  thread_create("read-ahead", PRI_DEFAULT, func_read_ahead, next_sector_ptr);
}
/*---------------------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------------------*/
/* TODO read_ahead 구현 */
static void
func_read_ahead(void * next_sector_ptr) {
  ASSERT(next_sector_ptr != NULL);

  disk_sector_t next_sector_idx = *(disk_sector_t*)next_sector_ptr;
  free(next_sector_ptr);
  // printf("read-ahead: %d\n", next_sector_idx);
  
  // lock_acquire(&cache_lock);
  // int cache_idx = buffer_cache_idx(next_sector_idx);

  // /* 이미 loading 된 경우 바로 return */
  // if(cache_idx != -1) {
  //   lock_release(&cache_lock);
  //   return;
  // }
  // lock_release(&cache_lock);

  /* read-ahead */
  int cache_idx = buffer_cache_load(next_sector_idx);
  lock_acquire(&cache_lock);
  buffer_cache[cache_idx].reference_cnt--;
  lock_release(&cache_lock);
  // printf("read-ahead completed\n");
}
/*---------------------------------------------------------------------------------------*/


/* TODO 
  - buffer_cache_load
  - buffer -> cache 로 write
    - cache가 아직 load 안된 경우 기다려야함
    - write 도중 evict 되면 안됨
*/
void
buffer_cache_write(disk_sector_t sector_idx, uint8_t* buffer, off_t sector_ofs, int chunk_size) {
  struct buffer_cache_entry* ce = NULL;

  int cache_idx = buffer_cache_load(sector_idx);
  // printf("sector idx : %d\n", sector_idx);
  // printf("cache idx : %d\n", cache_idx);

  ce = &buffer_cache[cache_idx];

  /* cache가 아직 load 안된 경우 기다려야함 */
  lock_acquire(&ce->lock);
  if(ce->is_loaded == false)
    cond_wait(&ce->load_cond, &ce->lock);
  lock_release(&ce->lock);
  
  /* buffer -> cache 로 write */
  memcpy(ce->data + sector_ofs, buffer, chunk_size);

  lock_acquire(&cache_lock);
  ce->dirty = true;
  ce->access = true;
  ce->reference_cnt--;
  lock_release(&cache_lock);
}
/*---------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------*/
/* TODO 주기적으로 write-back 구현 */
static void
func_write_behind(void* aux UNUSED) {
  while(true) {
    timer_sleep(10000);
    int i = 0;
    struct buffer_cache_entry* ce;

    for(; i < BUFFER_CACHE_SIZE; i += 1) {
      lock_acquire(&cache_lock);
      
      ce = &buffer_cache[i];
      if(ce->valid && ce->is_loaded && ce->dirty) {
        disk_write(filesys_disk, ce->sector_idx, ce->data);
        ce->dirty = false;
      }
      lock_release(&cache_lock);
    }
  }
}
/*---------------------------------------------------------------------------------------*/
