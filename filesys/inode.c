#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define INDIRECT_ENTRY_CNT ((DISK_SECTOR_SIZE) / (sizeof(disk_sector_t)))
static char zeros[DISK_SECTOR_SIZE];

/* 추가된 자료구조 */
struct lock open_lock;

/* 추가된 함수 */
bool inode_create_indirect(disk_sector_t, size_t);
void inode_extend(struct inode*, off_t);

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    disk_sector_t direct;               /* First data sector. */
    disk_sector_t indirect;             /* indirect */
    disk_sector_t double_indirect;      /* double-indirect */
    size_t indirect_cnt;
    size_t double_indirect_cnt;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    /* TODO add */
    bool is_dir;
    disk_sector_t parent;
    uint32_t unused[119];               /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */                         
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */

    off_t max_read_length;

    bool dirty;
    disk_sector_t* indirect;
    disk_sector_t* double_indirect;
    disk_sector_t** double_indirect_data;

    struct lock lock;

    /* TODO add */
    bool is_dir;
    disk_sector_t parent;
  };

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  
  // lock_acquire(&inode->lock);
  if( pos >= inode->data.length) {
    // lock_release(&inode->lock);
    return -1;
  }

  int idx = pos / DISK_SECTOR_SIZE;
  disk_sector_t ret;

  /* direct (idx == 0) */
  if( idx == 0 )
    ret = inode->data.direct;
  /* indirect (idx == 1 ~ 128 ) */
  else if ( idx <= INDIRECT_ENTRY_CNT ) {
    // printf("indirect data sector(%d:%d)\n", inode->indirect[idx-1], inode->sector);
    ret = inode->indirect[idx - 1];
  }
  /* double indirect */
  else if ( idx <= INDIRECT_ENTRY_CNT * INDIRECT_ENTRY_CNT ) {
    int i = (idx - 1) / INDIRECT_ENTRY_CNT - 1;
    int j = (idx - 1) % INDIRECT_ENTRY_CNT;
    // printf("idx, i, j : %d %d, %d\n", idx, i, j);

    // printf("double indirect data sector(%d)\n", inode->double_indirect_data[i][j]);
    ret = inode->double_indirect_data[i][j];
  }

  if(ret == 0) {
    printf("inode sector : %d(%d)\n", inode->sector, inode->data.length);
    printf("inode indirect : %d(%d)\n", inode->data.indirect, inode->data.indirect_cnt);
    printf("inode double_indirect : %d(%d)\n", inode->data.double_indirect, inode->data.double_indirect_cnt);


    // size_t i = 0;
    // for(i=0;i<inode->data.indirect);

    PANIC("stop");
  }

  // lock_release(&inode->lock);

  return ret;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  lock_init (&open_lock);
  list_init (&open_inodes);
}

/* inode_create helper function */
bool
inode_create_indirect(disk_sector_t indirect, size_t sectors)
{
  ASSERT(sectors <= INDIRECT_ENTRY_CNT);

  /* TODO create indirect */
  disk_sector_t* indirect_table = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t));
  if(indirect_table == NULL) return false;

  size_t i = 0;
  disk_sector_t sector_idx = 0;

  for(; i < sectors ; i += 1) {
    if(free_map_allocate(1, &sector_idx)) {
      buffer_cache_write (sector_idx, zeros, 0, DISK_SECTOR_SIZE);
      indirect_table[i] = sector_idx;
    } else return false;
  }

  // printf("indirect#%d, \n", indirect);
  // // printf("indirect#%d, sectors(%d)\n", indirect, sectors);
  // for(i=0; i < sectors; i += 1) {
  //   printf("%d\n", indirect_table[i]);
  // }

  buffer_cache_write (indirect, indirect_table, 0, DISK_SECTOR_SIZE);
  free (indirect_table);

  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);
  size_t sectors = bytes_to_sectors (length);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      disk_inode->parent = ROOT_DIR_SECTOR;

      size_t i = 0;

      bool direct = false;
      bool indirect = false;
      bool double_indirect = false;

      disk_sector_t* double_indirect_table = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t));
      if(double_indirect_table == NULL) sectors = -1;

      while(sectors > 0) {
        /* TODO direct 할당 */
        if( !direct ) {
          /* make direct node */
          if( free_map_allocate(1, &disk_inode->direct) ) {
            buffer_cache_write(disk_inode->direct, zeros, 0, DISK_SECTOR_SIZE);
            direct = true;
            sectors--;
            // printf("direct(%d)\n", sectors);
          } else break;
        }
        /* TODO indirect 할당 */
        else if( !indirect ) {
          /* make indirect inode */
          if(!free_map_allocate(1, &disk_inode->indirect)) break;
          indirect = true;

          size_t temp_sectors = sectors > INDIRECT_ENTRY_CNT ? INDIRECT_ENTRY_CNT : sectors;
          if(!inode_create_indirect(disk_inode->indirect, temp_sectors)) break;
          disk_inode->indirect_cnt = temp_sectors;
          sectors -= temp_sectors;

          // printf("indirect(%d)\n", sectors);
        }
        /* TODO double_indirect 할당 */
        else {
          /* make double_indirect root node */
          if(!double_indirect && !free_map_allocate(1, &disk_inode->double_indirect)) break;
          double_indirect = true;

          disk_sector_t sector_idx = 0;

          /* make double_indirect child node */
          if(!free_map_allocate(1, &sector_idx)) break;

          /* make double_indirect data node */
          size_t temp_sectors = sectors > INDIRECT_ENTRY_CNT ? INDIRECT_ENTRY_CNT : sectors;
          if(!inode_create_indirect(sector_idx, temp_sectors)) break;

          double_indirect_table[i] = sector_idx;
          i++;
          sectors -= temp_sectors;

          // printf("double_indirect(%d)\n", sectors);

          if(sectors == 0) {
            buffer_cache_write(disk_inode->double_indirect, double_indirect_table, 0, DISK_SECTOR_SIZE);
            disk_inode->double_indirect_cnt = i;
          }
        }
      }

      if(double_indirect_table) free(double_indirect_table);
    }
  
  success = sectors == 0 ? true : false;
  // printf("success(%d)\n", success);

  if(success)
    buffer_cache_write(sector, disk_inode, 0, DISK_SECTOR_SIZE);
  free(disk_inode);


  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  lock_acquire(&open_lock);

  // printf("inode open start\n");

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          // printf("\n\nre-opened!!, cnt : %d\n\n", inode->open_cnt);
          lock_release(&open_lock);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->dirty = false;
  lock_init(&inode->lock);
  buffer_cache_read (inode->sector, &inode->data, 0, DISK_SECTOR_SIZE);
  inode->max_read_length = inode->data.length;

  inode->is_dir = inode->data.is_dir;
  inode->parent = inode->data.parent;

  /* TODO read indirect */
  if((inode->indirect = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t))) == NULL)
    return NULL;
  
  if(inode->data.indirect_cnt > 0) {
    buffer_cache_read (inode->data.indirect, inode->indirect, 0, DISK_SECTOR_SIZE);
  }

  /* TODO read double_indirect */

  if((inode->double_indirect = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t))) == NULL ||
      (inode->double_indirect_data = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t))) == NULL)
      return NULL;

  if(inode->data.double_indirect_cnt > 0) {    
    buffer_cache_read (inode->data.double_indirect, inode->double_indirect, 0, DISK_SECTOR_SIZE);

    size_t i = 0;
    for(; i < inode->data.double_indirect_cnt ; i += 1) {
      if((inode->double_indirect_data[i] = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t))) == NULL)
        return NULL;
      buffer_cache_read (inode->double_indirect[i], inode->double_indirect_data[i], 0, DISK_SECTOR_SIZE);
    }
  }

  lock_release(&open_lock);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          size_t i, j;

          /* delete inode, direct */
          free_map_release (inode->sector, 1);
          free_map_release (inode->data.direct, 1);

          /* delete indirect */
          for(i = 0 ; i < inode->data.indirect_cnt; i += 1)
            free_map_release (inode->indirect[i], 1);
 //         if(inode->data.indirect != 0)
            free_map_release (inode->data.indirect, 1);

          /* delete double_indirect */
          for(i = 0 ; i < inode->data.double_indirect_cnt; i += 1) {
            for(j = 0 ; j < INDIRECT_ENTRY_CNT && inode->double_indirect_data[i][j] != 0 ; j += 1)
              free_map_release (inode->double_indirect_data[i][j], 1);
            free_map_release(inode->double_indirect[i], 1);
          }
 //         if(inode->data.double_indirect != 0)
            free_map_release (inode->data.double_indirect, 1);
        }
      /* TODO inode 에 변경사항이 있을 경우, 변경사항 저장 */
      if(inode -> dirty) {
        // printf("change dirty!\n");
        // printf("indirect cnt : %d\n", inode->data.indirect);
        // size_t aa = 0;
        // for(; aa < inode->data.indirect_cnt; aa += 1)
        //   printf("indirect sector#%d\n", inode->indirect[aa]);

        (inode->data).is_dir = inode->is_dir;
        (inode->data).parent = inode->parent;

        /* inode, direct 저장 */
        buffer_cache_write(inode->sector, &inode->data, 0, DISK_SECTOR_SIZE);

        /* indirect 저장 */
        buffer_cache_write(inode->data.indirect, inode->indirect, 0, DISK_SECTOR_SIZE);

        /* double_indirect 저장 */
        buffer_cache_write(inode->data.double_indirect, inode->double_indirect, 0, DISK_SECTOR_SIZE);

        size_t i = 0;
        for(; i < inode->data.double_indirect_cnt ; i += 1)
          buffer_cache_write(inode->double_indirect[i], inode->double_indirect_data[i], 0, DISK_SECTOR_SIZE);
      }


      /* TODO inode 에 사용되었던 memory 해제 */
      free (inode->indirect);
      free (inode->double_indirect);
      
      size_t i = 0;
      for(;i < inode->data.double_indirect_cnt ; i += 1)
        free(inode->double_indirect_data[i]);
      free (inode->double_indirect_data);

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  if(!inode->is_dir)
    lock_acquire(&inode->lock);
  size = offset + size > inode->max_read_length ? inode->max_read_length - offset : size;
  if(!inode->is_dir)
    lock_release(&inode->lock);

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      // printf("read at sector#%d(%d)\n", sector_idx, inode->sector);
      if(sector_idx == -1) {
        return bytes_read;
      }
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      // off_t inode_left = prev_length - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      /* TODO bounce buffer 대신 cache에서 읽음 */
      buffer_cache_read(sector_idx, buffer + bytes_read, sector_ofs, chunk_size);

      // printf("read at sector completed#%d(%d)\n", sector_idx, inode->sector);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  /* TODO offset + size > file_length 인 경우 -> file extenstion 필요 */
  if(!inode->is_dir)
    lock_acquire(&inode->lock);

  if( offset + size > inode->data.length )
    inode_extend(inode, offset + size);

  if(!inode->is_dir)
    lock_release(&inode->lock);



  while (size > 0) 
    { 
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      // printf("write at sector#%d(%d)\n", sector_idx, inode->sector);
      // if(sector_idx == 0)
      //   printf("bad inode : %d\n", inode->sector);

      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      /* TODO bounce buffer 대신 cache에 씀 */
      buffer_cache_write(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

      // printf("write at sector completed#%d(%d)\n", sector_idx, inode->sector);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  if(!inode->is_dir)
    lock_acquire(&inode->lock);
  inode->max_read_length = inode->data.length;
  if(!inode->is_dir)
    lock_release(&inode->lock);

  return bytes_written;
}

/* TODO inode extenstion 구현
  1. file_length 만 변경되는 경우 -> internal fragmentation
  2. inode_disk 까지 변경해야 하는 경우
*/
void
inode_extend(struct inode* inode, off_t new_file_length) {
  int idx = new_file_length / DISK_SECTOR_SIZE;

  inode->dirty = true;

  /* direct 가 없으면 direct 부터 만들어줌 */
  if(inode->data.direct == 0) {
    if(!free_map_allocate(1, &inode->data.direct)) return;
    buffer_cache_write(inode->data.direct, zeros, 0, DISK_SECTOR_SIZE);
  }

  // printf("last sector : %d\n", last_sector);

  off_t bytes_to_add = new_file_length - inode->data.length;
  size_t capacity = DISK_SECTOR_SIZE - (inode->data.length % DISK_SECTOR_SIZE);
  if(capacity == DISK_SECTOR_SIZE && inode->data.length > 0)
    capacity = 0;

  // printf("new file length : %d\n", new_file_length);
  // printf("indirect_cn : %d\n", inode->data.indirect_cnt);
  // printf("bytes to add : %d\n", bytes_to_add);
  // printf("capacity : %d\n", capacity);

  /* 빈자리가 없는 경우, 새롭게 할당해야함 */
  if(bytes_to_add > capacity) {
    bytes_to_add -= capacity;

    int double_indirect_cnt2 = 0;
    if(inode->data.double_indirect_cnt > 0)
      while (double_indirect_cnt2 < INDIRECT_ENTRY_CNT &&
            inode->double_indirect_data[inode->data.double_indirect_cnt-1][double_indirect_cnt2] > 0)
        double_indirect_cnt2++;

    size_t sectors = bytes_to_sectors(bytes_to_add);

    while(sectors > 0) {
      /* 새로운 sector 할당 */
      disk_sector_t sector_idx = 0;
      if(!free_map_allocate(1, &sector_idx)) return;
      buffer_cache_write(sector_idx, zeros, 0, DISK_SECTOR_SIZE);

      /* indirect 채움 */
      if(inode->data.indirect_cnt < INDIRECT_ENTRY_CNT) {
        /* indirect 가 없을 경우 생성 */
        if(inode->data.indirect == 0) {
          if(!free_map_allocate(1, &inode->data.indirect)) return;
          buffer_cache_write(inode->data.indirect, zeros, 0, DISK_SECTOR_SIZE);
        }

        // printf("sector idx : %d\n", sector_idx);
        inode->indirect[inode->data.indirect_cnt] = sector_idx;
        inode->data.indirect_cnt++;
      }
      /* double indirect 채움 */
      else {
        /* double indirect 가 없을 경우 생성 */
        if(inode->data.double_indirect == 0) {
          if(!free_map_allocate(1, &inode->data.double_indirect)) return;
          buffer_cache_write(inode->data.double_indirect, zeros, 0, DISK_SECTOR_SIZE);

          if(!free_map_allocate(1, &inode->double_indirect[0])) return;
          buffer_cache_write(inode->double_indirect[0], zeros, 0, DISK_SECTOR_SIZE);

          inode->double_indirect_data[0] = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t));
          inode->data.double_indirect_cnt = 1;
        }

        /* double indirect 의 child 가 다 찬 경우 새로운 child 생성 */
        if(double_indirect_cnt2 == INDIRECT_ENTRY_CNT) {
          double_indirect_cnt2 = 0;

          disk_sector_t new_indirect_idx = 0;
          if(!free_map_allocate(1, &new_indirect_idx)) return;
          buffer_cache_write(new_indirect_idx, zeros, 0, DISK_SECTOR_SIZE);

          inode->double_indirect[inode->data.double_indirect_cnt] = new_indirect_idx;
          inode->double_indirect_data[inode->data.double_indirect_cnt] = calloc(INDIRECT_ENTRY_CNT, sizeof(disk_sector_t));
          inode->data.double_indirect_cnt++;
        }
        int i = inode->data.double_indirect_cnt - 1;
        int j = double_indirect_cnt2;

        inode->double_indirect_data[i][j] = sector_idx;
        double_indirect_cnt2++;
      }

      /* advance */
      sectors--;
    }
  } 

  inode->data.length = new_file_length;
  // printf("inode length changed!!(%d)\n", new_file_length);
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool inode_is_dir(struct inode *inode)
{
  return inode->is_dir;
}

disk_sector_t inode_get_parent(struct inode *inode){
  return inode->parent;
}

void inode_lock_acquire(struct inode* inode){
  lock_acquire(&inode->lock);
}

void inode_lock_release(struct inode* inode){
  lock_release(&inode->lock);
}

void inode_set_parent(struct inode* inode, disk_sector_t parent)
{
  inode->parent = parent;
}

int inode_get_open_cnt(struct inode* inode){
  return inode->open_cnt;
}
