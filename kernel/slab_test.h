typedef unsigned int uint;
typedef unsigned long long uint64;

#define PGSIZE 4096 // bytes per page
#define PGSHIFT 12  // bits of offset within a page

#define PGROUNDUP(sz)  (((sz)+PGSIZE-1) & ~(PGSIZE-1))
#define PGROUNDDOWN(a) (((a)) & ~(PGSIZE-1))

void *kalloc(void);
void kfree(void*);
void panic(char*);

#include <string.h>
#include <stdio.h>
#include "slab.h"

struct kmem_cache *kmem_cache_create(
  char *name,
  uint size,
  uint align,
  void (*constructor)(void*, uint),
  void (*destructor)(void*, uint)
);
void *kmem_cache_alloc(struct kmem_cache *cache, int flags);
void kmem_cache_free(struct kmem_cache *cache, void *buf);
void kmem_cache_destroy(struct kmem_cache *cache);
void kmem_cache_reap(struct kmem_cache *cache);
void debug_print_slab_chain(struct kmem_cache *cache);
