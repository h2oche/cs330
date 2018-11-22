#ifndef VM_PAGETBL_H
#define VM_PAGETBL_H

#include <stdbool.h>
#include <hash.h>
#include <list.h>

/* indicate where page is currently located */
enum spte_flags
  {
    SPG_ZERO = 0x1,           /* 빈 페이지 */
    SPG_MMAP = 0x2,           /* mmap */
    SPG_FILESYS = 0x4,        /* file system */
    SPG_SWAP = 0x8,           /* swap disk에 저장 */
  };

struct spage_table_entry {
    void* upage;                    /* user page 주소(virtual address) */
    void* kpage;                    /* user page에 맵핑된 physical page, memory에 없으면 NULL */

    struct hash_elem elem;          /* Hash element */
    struct list_elem list_elem;     /* list element */

    enum spte_flags type;           /* type */

    /* for swap */
    size_t swap_sec_no;             /* swap disk에 저장되어 있을 경우, 저장된 sector 번호 기록 */
   
    /* for file system */
    uint32_t offset;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;

    /* for mmap */
    struct file* file;
};

bool spagetbl_init(void);
void spagetbl_create(void);
void spagetbl_destroy(void);
unsigned spagetbl_hash_func(const struct hash_elem*, void *);
bool spagetbl_hash_less_func(const struct hash_elem*, const struct hash_elem*, void*);
struct spage_table_entry* spagetbl_get_spte(struct hash*, void *);
bool spagetbl_load(struct spage_table_entry*);
bool spagetbl_stack_grow(void *);

#endif
