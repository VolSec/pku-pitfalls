/*
 * test_application.c
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>

#include <erim.h>

#include <timer.h>

int myvar = 0;

void* mapUntrusted() {
    void * addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(addr == MAP_FAILED) {
        printf("map failed %d\n", errno);
        exit(1);
    }

    myvar = ((int*)addr)[0];
    return addr;
}

void *mapTrusted() {
    erim_switch_to_trusted;
    void *addr = mapUntrusted();
    erim_switch_to_untrusted;
    return addr;
}

int main(int argc, char **argv) {
    /*
    int x = *(int*)0x1337;
    fprintf(stderr, "hello world: %d\n", x);
    */

    void *addr = mapUntrusted();

    /*
    erim_switch_to_trusted;

    addr = erim_mmap_isolated(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    erim_switch_to_untrusted;

    if (addr == MAP_FAILED) {
        printf("map failed %d\n", errno);
        exit(0);
    }

    fprintf(stderr, "access with trust %p\n", addr);
    erim_switch_to_trusted;
    printf("result: %d\n", *(int*)addr);
    erim_switch_to_untrusted;

    fprintf(stderr, "access without trust\n");
    printf("result: %d\n", *(int*)addr);
    */


    *(int*)addr = 0xc3 ; // ret

    void (*fun_ptr)(void) = addr;
    fun_ptr();

    fprintf(stderr, "successfully executed mapped page\n");

    return 0;
}

