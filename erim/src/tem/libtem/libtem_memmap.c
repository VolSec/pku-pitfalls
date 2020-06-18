#include <stdlib.h>
#include <sys/mman.h>
//#include <bsd/string.h>

#include <libtem.h>
#include <libtem_memmap.h>

#include <erim.h>

#define LTEM_MEMMAP_MEM (LTEM_SEC->ltem_memmap)
#define SAFE_WRITE(S) write(2, (S), sizeof(S)-1)

#define BITS_PER_DIR (12)
#define ENTRIES_PER_DIR (1 << BITS_PER_DIR)
#define DIR_BITMASK (ENTRIES_PER_DIR-1)
#define PAGE_SIZE 4096

#define L1_IDX(A) (((A) >> (BITS_PER_DIR*3)) & DIR_BITMASK)
#define L2_IDX(A) (((A) >> (BITS_PER_DIR*2)) & DIR_BITMASK)
#define L3_IDX(A) (((A) >> (BITS_PER_DIR*1)) & DIR_BITMASK)

typedef struct ltem_ptd_s {
    void *dir[ENTRIES_PER_DIR];
} ltem_ptd_t;


#define GLOBAL_PTD (*(ltem_ptd_t*)LTEM_MEMMAP_MEM)

int ltem_memmap_inited = 0;

static ltem_ptd_t *new_ptd() {
    ltem_ptd_t *ptd;

    ptd = erim_malloc(sizeof(ltem_ptd_t));
    if (!ptd) {
        SAFE_WRITE("error allocating ptd. aborting\n");
        exit(1);
    }

    bzero(ptd, sizeof(ltem_ptd_t));
    return ptd;
}

int libtem_memmap_init(erim_procmaps * pmaps) {

  LTEM_DBM("memmap inited");

  LTEM_MEMMAP_MEM = new_ptd();
  ltem_memmap_inited = 1;

  
  // insert existing memmap into current layout (initial map is
  // inserted immediately, as it is checked by erim_memScan
  // and all executable memory is still executable).
  // This is required to be able to check the boundaries of executable
  // pages later when new pages are added.
  for(; pmaps ; pmaps = erim_pmapsNext(pmaps)) {
    //    ltem_memmap_t * e = NULL;// memmap_createEntry(start, end, prot, pathname);
    //memmap_insertEnd((ltem_memmap_t**)&LTEM_MEMMAP_MEM, e);
  }

  
  return 0;
}

int libtem_memmap_fini() {
  int ret = 0;
  erim_switch_to_trusted;

  LTEM_DBM("memmap finied");

  erim_switch_to_untrusted;
  
  return ret;
}


#define abort_if_sigsafe do { if (signal_safe) {SAFE_WRITE("ERROR: can't create new PT entries from signal handler\n"); exit(1);} } while(0)

// TODO although this should be reentrant with respect to other program components 
// (i.e. it doesn't mess with any global data structures outside this file)
// it does rely on the global data structure of the page table, so it is not technically reentrant.
// if the program received a signal while in this function, and it were called again, the PT
// could be in an invalid state. 
void libtem_memmap_update(void* vstart, void* vend, unsigned int prot, unsigned int pkey, int signal_safe) {
    SAFE_WRITE("now in libtem_memmap_update\n");

    int i, j, k;

    addr_t start = (addr_t)vstart;
    addr_t end = (addr_t)vend;
    end -= 1;
    
    if (!ltem_memmap_inited) {
        SAFE_WRITE("libtem_memmap not init'd - ignoring\n");
        return;
    }

    int l2_start, l2_end, l3_start, l3_end;

    ltem_ptd_t *l1_dir, *l2_dir;

    for (i=L1_IDX(start); i <= L1_IDX(end); i++) {
        l1_dir = (ltem_ptd_t*)GLOBAL_PTD.dir[i];
        if (l1_dir == NULL) {
            abort_if_sigsafe;
            l1_dir = new_ptd();
            GLOBAL_PTD.dir[i] = l1_dir;
        }

        l2_start = (i == L1_IDX(start)) ? L2_IDX(start) : 0;
        l2_end = (i == L1_IDX(end)) ? L2_IDX(end) : ENTRIES_PER_DIR - 1;

        for (j=l2_start; j <= l2_end; j++) {
            l2_dir = (ltem_ptd_t*) l1_dir->dir[j];
            if (l2_dir == NULL) {
                abort_if_sigsafe;
                l2_dir = new_ptd();
                l1_dir->dir[j] = l2_dir;
            }

            l3_start = (i == L1_IDX(start) && j == L2_IDX(start)) ? L3_IDX(start) : 0;
            l3_end = (i == L1_IDX(end) && j == L2_IDX(end)) ? L3_IDX(end) : ENTRIES_PER_DIR - 1;

            for (k=l3_start; k <= l3_end; k++) {
                ltem_pte_t *entry = (ltem_pte_t*) l2_dir->dir[k];
                if (entry == NULL) {
                    abort_if_sigsafe;
                    entry = erim_malloc(sizeof(ltem_pte_t));
                    if (entry == NULL) {
                        SAFE_WRITE("error allocating page table entry!\n");
                        exit(1);
                    }
                    l2_dir->dir[k] = entry;
                }
                entry->prot = prot;
                entry->pkey = pkey;
            }
        }
    }
}

ltem_pte_t *libtem_memmap_get_entry(void *vaddr) {
    ltem_ptd_t *l1_dir, *l2_dir;

    addr_t addr = (addr_t)vaddr;

    l1_dir = (ltem_ptd_t*)GLOBAL_PTD.dir[L1_IDX(addr)];
    if (l1_dir == NULL) return NULL;

    l2_dir = (ltem_ptd_t*)(l1_dir->dir[L2_IDX(addr)]);
    if (l2_dir == NULL) return NULL;

    return (ltem_pte_t*)(l2_dir->dir[L3_IDX(addr)]);
}


