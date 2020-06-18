/*
 * libtem_memmap.h
 */

#ifndef __LIBTEM_MEMMAP_H_
#define __LIBTEM_MEMMAP_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <erim_processmappings.h>
#include <sys/mman.h>

#define PROT_EXEC_PENDING (0x1 << 24)

extern int ltem_memmap_inited;

typedef unsigned long long addr_t;

typedef struct ltem_pte_s {
    unsigned int prot;
    unsigned int pkey;
} ltem_pte_t;

int libtem_memmap_init(erim_procmaps * pmaps);

int libtem_memmap_fini();

void libtem_memmap_update(void* start, void* end, unsigned int prot, unsigned int pkey, int signal_safe);

ltem_pte_t* libtem_memmap_get_entry(void * addr);

#ifdef __cplusplus
}
#endif

#endif // __LIBTEM_MEMMAP_H_
