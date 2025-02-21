#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "slab_test.h"

void *kalloc(void) {
    void *addr;
    posix_memalign(&addr, PGSIZE, PGSIZE);
    return addr;
}

void kfree(void *buf) {
    free(buf);
}

void panic(char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

void constructor(void *buf, uint size) {
    // pass
}

#define NALLOC 6

int main() {
    struct kmem_cache *cache = kmem_cache_create("1", 2000, 8, constructor, 0);
    void *data[NALLOC];
    for (int i = 0; i < NALLOC; i++) {
        data[i] = kmem_cache_alloc(cache, KM_SLEEP);
        assert(data[i] != NULL);
    }
    kmem_cache_free(cache, data[0]);
    kmem_cache_free(cache, data[1]);
}

