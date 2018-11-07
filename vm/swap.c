#include "vm/swap.h"
#include "devices/disk.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"
#include "lib/debug.h"

#define PAGE_SECTOR_NUM 8

struct disk* swap_disk;
struct lock swap_lock;
struct bitmap* swap_table;

void swap_init(void);

/*---------------------------------------------------------------------------------------*/
void swap_init(void)
{

  swap_disk = disk_get(1,1);
  lock_init(&swap_lock);
  swap_table = bitmap_create(disk_size(swap_disk));
}

/*---------------------------------------------------------------------------------------*/
/* frame을 swap_disk에 쓰고, 제일 첫 번째 sector_num return */
size_t swap_out(void *frame)
{

  lock_acquire(&swap_lock);

  /* TODO 비어있는 부분 찾아서 page 복사해서 넣기 */
  size_t sec_no = bitmap_scan_and_flip(swap_table, 0, PAGE_SECTOR_NUM, 0);
  size_t i;

  if(sec_no == BITMAP_ERROR)
    PANIC("Disk is full");

  for(i=sec_no; i<PAGE_SECTOR_NUM; i++){
    disk_write(swap_disk, i, frame+i*DISK_SECTOR_SIZE);
  }

  lock_release(&swap_lock);

  return sec_no;

}

/*---------------------------------------------------------------------------------------*/
/* swap_disk에서 sector_num에 해당 하는 부분 읽어서 frame에 쓰기 */
void swap_in(size_t sec_no, void *frame)
{

  lock_acquire(&swap_lock);

  size_t i;
  for(i=0; i<PAGE_SECTOR_NUM; i++){
    disk_read(swap_disk, sec_no+i, frame+i*DISK_SECTOR_SIZE);
  }

  bitmap_set_multiple(swap_table, sec_no, PAGE_SECTOR_NUM, 0);

  lock_release(&swap_lock);
}

/*---------------------------------------------------------------------------------------*/
