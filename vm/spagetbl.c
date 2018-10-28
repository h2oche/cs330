#include "spagetbl.h"
#include <hash.h>
#include <stdbool.h>
#include <stddef.h>

/*---------------------------------------------------------------------------------------*/
/* Returns hash value for spte */
unsigned
spagetbl_hash_func(const struct hash_elem *elem, void * aux)
{
    const struct spage_table_entry* spte = hash_entry(elem, struct spage_table_entry, elem);
    return hash_bytes(&spte->vaddr, sizeof(&spte->vaddr));
}
/*---------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------*/
/* Returns true if spte a precedes page b */
bool
spagetbl_hash_less_func(const struct hash_elem* elem1, const struct hash_elem* elem2, void* aux)
{
    const struct spage_table_entry* spte1 = hash_entry(elem1, struct spage_table_entry, elem);
    const struct spage_table_entry* spte2 = hash_entry(elem2, struct spage_table_entry, elem);
    return spte1->vaddr < spte2->vaddr;
}
/*---------------------------------------------------------------------------------------*/