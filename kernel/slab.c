#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "slab.h"

// This uses Bonwick's naming scheme, even though I'm not a fan:
// - _empty_ slabs are those that are fully occupied
// - _partial_ slabs
// - _complete_ slabs are those without allocations
// alternative naming scheme in the future: occupied/partial/free

// hard coded value is ok because we're not worried about security
// 1 at the end so it's not aligned (illegal pointer value)
#define KMEM_CANARY ((struct kmem_bufctl*) 0xdeadcafecafedea1)

void cache_construct(void *ptr, uint size) {
  struct kmem_cache *cache = ptr;
  initlock(&cache->lock, "cache");
}

// this is also the head of the cache chain
struct kmem_cache cache_cache = {
  // TODO perhaps we should do this in a slabinit().
  .lock = { .name = "cache", .locked = 0, .cpu = 0 },
  .name = "cache",
  .size = sizeof(struct kmem_cache),
  .align = 8, // TODO
  .constructor = cache_construct,
  .destructor = 0,
  .head_empty = 0,
  .head_partial = 0,
  .head_complete = 0,
  .prev = &cache_cache,
  .next = &cache_cache,
};

int slab_is_empty(struct kmem_slab *slab) {
  return slab && slab->refcnt == slab->refcnt_max;
}

int slab_is_partial(struct kmem_slab *slab) {
  return slab && slab->refcnt > 0 && slab->refcnt < slab->refcnt_max;
}

int slab_is_complete(struct kmem_slab *slab) {
  return slab && slab->refcnt == 0;
}

void cache_queue_insert(struct kmem_cache *cache) {
  cache->next = &cache_cache;
  cache->prev = cache_cache.prev;
  cache_cache.prev->next = cache;
  cache_cache.prev = cache;
}

void cache_queue_remove(struct kmem_cache *cache) {
  cache->prev->next = cache->next;
  cache->next->prev = cache->prev;

  // this is only for security
  cache->prev = cache->next = 0;
}

void queue_remove(struct kmem_slab **head_ptr, struct kmem_slab *slab) {
  slab->prev->next = slab->next;
  slab->next->prev = slab->prev;

  if(slab->next == slab) {
    *head_ptr = 0;
  } else if(*head_ptr == slab) {
    *head_ptr = slab->next;
  }

  // this is only for security
  slab->prev = slab->next = 0;
}

void queue_insert(struct kmem_slab **head_ptr, struct kmem_slab *slab) {
    struct kmem_slab *head = *head_ptr;
    if(!head) {
      slab->prev = slab;
      slab->next = slab;
    } else {
      slab->prev = head->prev;
      slab->next = head;
      head->prev->next = slab;
      head->prev = slab;
    }
    *head_ptr = slab;
}

void slab_clear(struct kmem_cache *cache, struct kmem_slab *slab) {
  void *buf = (void *)PGROUNDDOWN((uint64)slab);
  void *end = (char*)slab - slab->buf_eff_size;
  while(buf <= end) {
    if(cache->destructor) {
      cache->destructor(buf, cache->size);
    }
    buf = (void*)((char*)buf + slab->buf_eff_size);
  }
}

void queue_clear(struct kmem_cache *cache, struct kmem_slab **head_ptr) {
  struct kmem_slab *start = *head_ptr;
  struct kmem_slab *current = *head_ptr;
  do {
    slab_clear(cache, current);
    kfree((void*)PGROUNDDOWN((uint64)current));
    current = current->next;
  } while(current != start);

  *head_ptr = 0;
}

struct kmem_cache *kmem_cache_create(
  char *name,
  uint size,
  uint align,
  void (*constructor)(void*, uint),
  void (*destructor)(void*, uint)
) {
  struct kmem_cache *cache = kmem_cache_alloc(&cache_cache, KM_SLEEP);
  if(!cache) {
    return 0;
  }
  cache->name = name;
  cache->size = size;
  cache->align = align;
  cache->constructor = constructor;
  cache->destructor = destructor;
  cache->head_empty = 0;
  cache->head_partial = 0;
  cache->head_complete = 0;
  cache->prev = 0;
  cache->next = 0;
  cache_queue_insert(cache);

  return cache;
}

void kmem_cache_grow(struct kmem_cache *cache) {
  // align cannot be bigger than 4096
  // TODO assert that align is reasonable, like 1,2,4,8,16
  // TODO assert that size is reasonable, like < PGSIZE/8

  void *page = kalloc();
  if(!page) {
    return;
  }
  struct kmem_slab *slab = (struct kmem_slab*)((char*)page + PGSIZE - sizeof(struct kmem_slab));
  memset(slab, 0, sizeof(struct kmem_slab));
  // initialize buffers

  // per buffer:
  // - `size` bytes for actual data
  // - pad to multiple of 8 bytes
  // - `sizeof(kmem_bufctl)` bytes for bufctl (could also be less with relative indexing)
  // - pad to satisfy alignment for next buffer (we ignore this for now because we have alignment 8 here)
  slab->bufctl_offset = ((cache->size + 7) & ~7u);
  slab->buf_eff_size = slab->bufctl_offset + sizeof(struct kmem_bufctl);
  slab->free_head = (struct kmem_bufctl*)((char*)page + slab->bufctl_offset);
  void *buf = page;
  void *end = (char*)slab - slab->buf_eff_size;
  struct kmem_bufctl *ctl;
  while(buf <= end) {
    slab->refcnt_max++; // TODO do this easier
    if(cache->constructor) {
      cache->constructor(buf, cache->size);
    }
    ctl = (struct kmem_bufctl*)((char*)buf + slab->bufctl_offset);
    ctl->next = (struct kmem_bufctl*)((char*)ctl + slab->buf_eff_size);

    buf = (void*)((char*)buf + slab->buf_eff_size);
  }
  // last freelist entry to NULL
  ctl = (struct kmem_bufctl*)((char*)buf - slab->buf_eff_size + slab->bufctl_offset);
  ctl->next = 0;

  // this is stupid because we immediately take something out again
  queue_insert(&cache->head_complete, slab);
}

void kmem_cache_reap(struct kmem_cache *cache) {
  acquire(&cache->lock);
  queue_clear(cache, &cache->head_complete);
  release(&cache->lock);
}

void *kmem_cache_alloc(struct kmem_cache *cache, int flags) {
  if(!cache->head_partial && !cache->head_complete) {
    kmem_cache_grow(cache);
    if(!cache->head_partial && !cache->head_complete) {
      return 0; // growing didn't work
    }
  }

  struct kmem_slab *slab = cache->head_partial ? cache->head_partial : cache->head_complete;
  struct kmem_bufctl *ctl = slab->free_head;
  slab->free_head = ctl->next;
  ctl->next = KMEM_CANARY;
  slab->refcnt++;

  if (slab->refcnt == 1) {
    queue_remove(&cache->head_complete, slab);
    queue_insert(&cache->head_partial, slab);
  } else if (slab->refcnt == slab->refcnt_max) {
    queue_remove(&cache->head_partial, slab);
    queue_insert(&cache->head_empty, slab);
  }

  return (void*)((char*)ctl - slab->bufctl_offset);
}

void kmem_cache_free(struct kmem_cache *cache, void *buf) {
  // TODO check if we are in the correct cache?
  // slab back pointer to cache?
  struct kmem_slab *slab = (struct kmem_slab*)((char*)PGROUNDDOWN((uint64)buf) + PGSIZE - sizeof(struct kmem_slab));
  struct kmem_bufctl *ctl = (struct kmem_bufctl*)((char*)buf + slab->bufctl_offset);
  if(ctl->next != KMEM_CANARY) {
    // this checks buffer overflow and double free
    panic("kmem_cache_free canary");
  }
  ctl->next = slab->free_head;
  slab->free_head = ctl;
  slab->refcnt--;

  if (slab->refcnt == slab->refcnt_max - 1) {
    queue_remove(&cache->head_empty, slab);
    queue_insert(&cache->head_partial, slab);
  } else if (slab->refcnt == 0) {
    queue_remove(&cache->head_partial, slab);
    queue_insert(&cache->head_complete, slab);
  }
}

void kmem_cache_destroy(struct kmem_cache *cache) {
  queue_clear(cache, &cache->head_empty);
  queue_clear(cache, &cache->head_partial);
  queue_clear(cache, &cache->head_complete);
  cache_queue_remove(cache);
  kmem_cache_free(&cache_cache, cache);
}
