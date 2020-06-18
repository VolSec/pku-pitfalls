#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <common.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stddef.h>

#include <erim.h>
#include <libtem.h>
#include <libtem_memmap.h>
#include <libtem_signals.h>

#define MT(pid)							\
  do { if(LTEM_SEC->trusted) LTEM_SEC->trusted(pid); } while(0)

#define MU(pid)								\
  do { if(LTEM_SEC->untrusted) LTEM_SEC->untrusted(pid); } while(0)

int start_erim(int erimFlags, erim_procmaps * pmaps) {
  return erim_init(1024*1024*1024ull, erimFlags) || erim_memScan(pmaps, NULL, ERIM_UNTRUSTED_PKRU);
}

int libtem_mpkey (void * addr, size_t len, int prot, int pkey) {
  return pkey_mprotect(addr, len, prot, pkey);
}

ltem_public_t ltem_pub;

int libtem_init(ltem_markfct trusted, ltem_markfct untrusted, int erimFlags) {
  void *(*lmmap)(void *addr, size_t length, int  prot, int flags,
		  int fd, off_t offset) = dlsym(RTLD_NEXT, "mmap");
  int (*lmprotect)(void *addr, size_t len, int prot)
        = dlsym(RTLD_NEXT, "mprotect");
#ifdef LATEST_GLIBC
  int (*lmprotect_pkey)(void *addr, size_t len, int prot, int pkey)
    = dlsym(RTLD_NEXT, "mprotect_pkey");
#else
  int (*lmprotect_pkey)(void *addr, size_t len, int prot, int pkey)
    = libtem_mpkey;
#endif

  LTEM_DBM("pid %d", getpid());

  ltem_pub.mmap = lmmap;
  ltem_pub.mprotect = lmprotect;
  ltem_pub.mprotect_pkey = lmprotect_pkey;

  LTEM_DBM("%p %p", ltem_pub.mmap, ltem_pub.mprotect);
  
  if(ltem_pub.mmap == NULL || ltem_pub.mprotect == NULL) {
    LTEM_ERR("couldn't find set/read_var");
    return 1;
  }

  erim_procmaps * pmaps = erim_pmapsParse(-1);
  if(start_erim(erimFlags, pmaps)) {
    LTEM_ERR("ERIM init failed");
    return 1;
  }

  LTEM_DBM("alloc ltem sec");
  // allocate function table
  void* mapret = mmap((void*)LTEM_SEC_LOC, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(mapret == MAP_FAILED || mapret != (void*)LTEM_SEC_LOC) {
    LTEM_ERR("allocation of secret failed");
    return 1;
  }
  if(pkey_mprotect((void*)LTEM_SEC_LOC, 4096, PROT_READ|PROT_WRITE, ERIM_TRUSTED_DOMAIN)) {
    return 1;
  }
  memset((void *)LTEM_SEC_LOC, 0, 4096);
  
  LTEM_DBM("mark trusted %p untrusted %p", trusted, untrusted);
  LTEM_SEC->trusted = trusted;
  LTEM_SEC->untrusted = untrusted;
  
  return libtem_memmap_init(pmaps) || libtem_reg_signals();
}


void *mmap(void *addr, size_t length, int prot, int flags,
        int fd, off_t offset) {

    void * ret = NULL;

    if(ltem_memmap_inited && __rdpkru() == ERIM_TRUSTED_PKRU) {
        LTEM_DBM("mmap trusted: %p", addr);
        pid_t p = gettid();

        MT(p);
        ret = ltem_pub.mmap(addr, length, prot, flags, fd, offset);
        MU(p);

        if(ret != MAP_FAILED) {  // only apply if mmap successful
            libtem_memmap_update(ret, ((char*)ret) + length, prot, 0, 0);
        }

    } else {
        LTEM_DBM("mmap untrusted: %p", addr);

        ret =  ltem_pub.mmap(addr, length, prot, flags, fd, offset);

        if(ret != MAP_FAILED && ltem_memmap_inited) {  // only apply if mmap successful
            if (prot & PROT_EXEC) {
                // for an untrusted map, exec will be removed by tracer/kernel.
                // instead mark this map as "pending" exec
                prot = (prot & ~PROT_EXEC) | PROT_EXEC_PENDING;
            }
            erim_switch_to_trusted;
            libtem_memmap_update(ret, ((char*)ret) + length, prot, 0, 0);
            erim_switch_to_untrusted;
        }
    }

    return ret;
}

int ltem_mprotect(void *addr, size_t len, int prot, int signal_safe) {
    int ret = 0;

    if(ltem_memmap_inited && __rdpkru() == ERIM_TRUSTED_PKRU) {
        LTEM_DBM("mprotect trusted");

        pid_t p = gettid();
        MT(p);
        ret = ltem_pub.mprotect(addr, len, prot);
        MU(p);

        if(ret == 0) { // only apply if mprotect successful
            LTEM_DBM("updating with non-pending");
            libtem_memmap_update(addr, ((char*)addr) + len, prot, 0, signal_safe);
        }

    } else {
        LTEM_DBM("mprotect untrusted or !PROT_EXEC");

        ret = ltem_pub.mprotect(addr, len, prot);

        if(ret == 0 && ltem_memmap_inited) { // only apply if mprotect successful
            if (prot & PROT_EXEC) {
                // for an untrusted map, exec will be removed by tracer/kernel.
                // instead mark this map as "pending" exec
                prot = (prot & ~PROT_EXEC) | PROT_EXEC_PENDING;
            }
            erim_switch_to_trusted;
            libtem_memmap_update(addr, ((char*)addr) + len, prot, 0, signal_safe);
            erim_switch_to_untrusted;
        }

    }

    return ret;

}

int mprotect(void *addr, size_t len, int prot) {
    return ltem_mprotect(addr, len, prot, 0);
}

#ifdef LATEST_GLIBC
int mprotect_pkey(void *addr, size_t len, int prot, int pkey) {
    int ret = 0;

    if(ltem_memmap_inited && __rdpkru() == ERIM_TRUSTED_PKRU) {
        pid_t p = gettid();

        MT(p);
        ret = ltem_pub.mprotect_pkey(addr, len, prot, pkey);
        MU(p);

        if(ret == 0) { // only apply if mprotect successful
            LTEM_DBM("updating with non-pending");
            libtem_memmap_update(addr, ((char*)addr) + len, prot, pkey, 0);
        }

    } else {
        ret = ltem_pub.mprotect_pkey(addr, len, prot, pkey);
        if(ret == 0 && ltem_memmap_inited) { // only apply if mprotect successful
            if (prot & PROT_EXEC) {
                // for an untrusted map, exec will be removed by tracer/kernel.
                // instead mark this map as "pending" exec
                prot = (prot & ~PROT_EXEC) | PROT_EXEC_PENDING;
            }
            erim_switch_to_trusted;
            libtem_memmap_update(addr, ((char*)addr) + len, prot, pkey, 0);
            erim_switch_to_untrusted;
        }
    }

    return ret;
}
#endif
