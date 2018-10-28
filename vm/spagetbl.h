#ifndef VM_PAGETBL_H
#define VM_PAGETBL_H

#include <stdbool.h>
#include <hash.h>

/* indicate where page is currently located */
enum spte_flags
  {
    SPG_ZERO = 0x1,           /* zero */
    SPG_MEMORY = 0x2,         /* memory */
    SPG_FILESYS = 0x4,        /* file system */
    SPG_SWAP = 0x8,           /* swap space */
  };

struct spage_table_entry {
    void* vaddr;                    /* spte를 가르킬 virtual address, hash table의 key */
    struct hash_elem elem;          /* Hash element */

    enum spte_flags storage;       /* 저장된 곳의 위치 */
    void* pos;                      /* 저장된 곳에서의 주소 */
    bool presented;                 /* 유효한 spage_table_entry 인지 */
};

void spagetbl_create(void);
void spagetbl_destroy(void);
unsigned spagetbl_hash_func(const struct hash_elem*, void *);
bool spagetbl_hash_less_func(const struct hash_elem*, const struct hash_elem*, void*);

#endif