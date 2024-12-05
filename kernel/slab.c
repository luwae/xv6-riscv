// This uses Bonwick's naming scheme, even though I'm not a fan:
// - _empty_ slabs are those that are fully occupied
// - _partial_ slabs
// - _complete_ slabs are those without allocations
// alternative naming scheme in the future: occupied/partial/free

// hard coded value is ok because we're not worried about security
// 1 at the end so it's not aligned (illegal pointer value)
#define KMEM_CANARY ((struct kmem_bufctl*) 0xdeadcafecafedea1)

struct kmem_cache cache_cache = {
  .name = "cache",
  .size = sizeof(struct kmem_cache),
  .align = 8, // TODO
  .constructor = 0,
  .destructor = 0,
  .head = 0,
  .complete_head = 0,
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

void queue_remove(struct kmem_cache *cache, struct kmem_slab *slab) {
  slab->prev->next = slab->next;
  slab->next->prev = slab->prev;

  if (cache->head == slab) {
    cache->head = slab->next;
  }
  if (cache->complete_head == slab) {
    cache->complete_head = slab->next;
  }

  // this is only for security
  slab->prev = slab->next = 0;
}

void queue_insert_before_head(struct kmem_slab **head, struct kmem_slab *slab) {
    struct kmem_slab *old_head = *head;
    if (!old_head) {
      slab->prev = slab;
      slab->next = slab;
    } else {
      slab->prev = old_head->prev;
      slab->next = old_head;
      old_head->prev->next = slab;
      old_head->prev = slab;
    }
    *head = slab;
}

// slab was fully occupied and we freed one allocation
void queue_on_empty_to_partial(struct kmem_cache *cache, struct kmem_slab *slab) {
  queue_remove(cache, slab);
  queue_insert_before_head(&cache->head, slab);
}

// slab was partial and now is fully occupied
void queue_on_partial_to_empty(struct kmem_cache *cache, struct kmem_slab *slab) {
  cache->head = cache->head->next;
}

// slab had one allocation and now 0
void queue_on_partial_to_complete(struct kmem_cache *cache, struct kmem_slab *slab) {
  queue_remove(cache, slab);
  queue_insert_before_head(&cache->complete_head, slab);
}

// queue had 0 allocations and now 1
void queue_on_complete_to_partial(struct kmem_cache *cache, struct kmem_slab *slab) {
  queue_remove(cache, slab);
  queue_insert_before_head(&cache->head, slab);
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
  cache->head = 0;
  cache->complete_head = 0;

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
    void *buf_next = (void*)((char*)buf + slab->buf_eff_size);
    ctl = (struct kmem_bufctl*)((char*)buf + slab->bufctl_offset);
    ctl->next = (struct kmem_bufctl*)((char*)ctl + slab->buf_eff_size);

    buf = (void*)((char*)buf + slab->buf_eff_size);
  }
  // last freelist entry to NULL
  ctl = (struct kmem_bufctl*)((char*)buf - slab->buf_eff_size + slab->bufctl_offset);
  ctl->next = NULL;

  queue_insert_before_head(&cache->head, slab);
}

void kmem_cache_reap(struct kmem_cache *cache) {
  int modify_head = slab_is_complete(cache->head);

  struct kmem_slab *start = cache->complete_head;
  while (slab_is_complete(cache->complete_head)) {
    struct kmem_slab *next = cache->complete_head->next;
    kfree((void*)PGROUNDDOWN((uint64)cache->complete_head));
    cache->complete_head = next;
    if (cache->complete_head == start) {
      break;
    }
  }

  if (modify_head) {
    cache->head = cache->complete_head;
  }
}

void *kmem_cache_alloc(struct kmem_cache *cache, int flags) {
  if(slab_is_empty(cache->head)) {
    kmem_cache_grow(cache);
  }
  if(slab_is_empty(cache->head)) {
    return 0; // growing didn't work
  }

  struct kmem_slab *slab = cache->head;
  struct kmem_bufctl *ctl = slab->free_head;
  slab->free_head = ctl->next;
  ctl->next = KMEM_CANARY;
  slab->refcnt++;

  if (slab->refcnt == 1) {
    queue_on_complete_to_partial(cache, slab);
  } else if (slab->refcnt == slab->refcnt_max) {
    queue_on_partial_to_empty(cache, slab);
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
    queue_on_empty_to_partial(cache, slab);
  } else if (slab->refcnt == 0) {
    queue_on_partial_to_complete(cache, slab);
  }
}

void kmem_cache_destroy(struct kmem_cache *cache) {
  cache->head->prev->next = NULL; // termination for iter
  struct kmem_slab *slab = cache->head;
  while(slab) {
    struct kmem_slab *next = slab->next;
    kfree((void*)PGROUNDDOWN((uint64)slab));
    slab = next;
  }   
  kmem_cache_free(&cache_cache, cache);
}

