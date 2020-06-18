#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <erim.h>
#include <libtem.h>
#include <libtem_memmap.h>

extern void libtem_trampoline_handle_signal(int signal, siginfo_t *si, void *ptr);


#define SIG_WRITE(S) write(2, (S), sizeof(S)-1)

void libtem_handle_signal(int signal, siginfo_t *si, void *ptr) {

  SIG_WRITE("invoked signal handler\n");
  
  if(signal == SIGSEGV) {
    // oh shoot we have a segfault

    erim_switch_to_trusted;

    unsigned long long pagesize = sysconf(_SC_PAGESIZE);

    SIG_WRITE("handling SIGSEGV\n");
    
    // is it related to memory that we took away the execute bit?
    ltem_pte_t *pte;
    if(si && si->si_addr && (pte = libtem_memmap_get_entry(si->si_addr)) && (pte->prot & PROT_EXEC_PENDING)) {
      // it is! - lets scan it
      SIG_WRITE("scanning memory\n");
      void * alignedAddr = (void *) ((unsigned long long)(si->si_addr)
				     & ~(pagesize-1));
      char * start = alignedAddr; // page(addr) - 2 byte (if prev page was mapped as well)
      unsigned long long length = pagesize; // length = page + 2 byte if next page is mapped)
      unsigned long long * whitelist = NULL;
      unsigned int wlEntries = 0;

      if(erim_memScanRegion(ERIM_PKRU_VALUE_UNTRUSTED, start,
			    length, whitelist, wlEntries, NULL)) {
        SIG_WRITE("WRPKRU found in executable memory - EXIT\n");
	    // as a result we let the program crash
        exit(EXIT_FAILURE);
      } 
      SIG_WRITE("no WRPKRU found, continuing\n");

      // mprotect the page with execute permission
      if(ltem_mprotect(alignedAddr, pagesize, PROT_READ|PROT_EXEC, 1) != 0) {
        SIG_WRITE("WARNING: fail to dynamically mprotect\n");
      }

      SIG_WRITE("signal handler returning\n");

      // continue application - kernel will reset the PKRU register to its exeuction
      // xsafe state
      return;
    }

    else {
        SIG_WRITE("SIGSEGV not related to pending exec - exiting\n");
        exit(EXIT_FAILURE);
    }
  }

  SIG_WRITE("finished handler\n");

  return;
}

#undef SIG_WRITE

int libtem_reg_signals(int erimFlags) {
  LTEM_DBM("reg signals");

  if(ERIM_TRUSTED_DOMAIN_IDENT == ERIM_ISOLATED_DOMAIN) {
    char *sigstack = NULL;
    LTEM_DBM("allocate isolated stack");
    sigstack = mmap(NULL, SIGSTKSZ, PROT_READ | PROT_WRITE
				  | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(sigstack == MAP_FAILED) {
      LTEM_ERR("could not allocate signal stack");
      return 1;
    }
    
    stack_t ss = {
      .ss_size = SIGSTKSZ,
      .ss_sp = sigstack
    };
    
    if(sigaltstack(&ss, NULL) == -1) {
      LTEM_ERR("Could not install signal stack");
      return 1;
    }

    LTEM_DBM("installed isolated stack");
  }

  struct sigaction sa;
  sa.sa_sigaction = (ERIM_TRUSTED_DOMAIN_IDENT != ERIM_ISOLATED_DOMAIN) ?
    (void(*)(int, siginfo_t*, void*))&libtem_handle_signal :
    (void(*)(int, siginfo_t*, void*))&libtem_trampoline_handle_signal;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigfillset(&sa.sa_mask);
  
  if(sigaction(SIGSEGV, &sa, NULL) == -1) {
    LTEM_ERR("Signal handler couldn't be installed\n");
    return 1;
  }

  LTEM_DBM("signals registered %p from %p %p",
	   sa.sa_sigaction, libtem_handle_signal,
	   libtem_trampoline_handle_signal);
  
  return 0;
}


void printHello() {
  //  unsigned long long pkru = __rdpkru();
  //write(2, pkru, 8);
  write(2, "hello\n", 7);
  //printf("stack %p", ptr);
}
