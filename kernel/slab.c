// hard coded value is ok because we're not worried about security
// 1 at the end so it's not aligned (illegal pointer value)
#define KMEM_CANARY ((struct kmem_bufctl*) 0xdeadcafecafedea1)

struct kmem_cache cache_cache = {
  .name = "cache",
  .size = sizeof(struct kmem_cache),
  .align = 8, // TODO
  .constructor = 0,
  .destructor = 0
};

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

  return cache;
}

void *kmem_cache_alloc(struct kmem_cache *cache, int flags) {
  if(!cache->head) {
    struct kmem_slab *slab = kmem_slab_create(cache->size, cache->align, cache->constructor);
    if(!slab) {
      return 0;
    }
    // link it
    slab->prev = slab;
    slab->next = slab;
    cache->head = slab;
  }
  struct kmem_slab *head = cache->head;
  struct kmem_slab *current = cache->head;
  do {
    if(current->refcnt < current->refcnt_max){
      return kmem_slab_alloc(current);
    }
    current = current->next;
  } while (current != head);
  return 0; // TODO allocate new page here?
}

void *kmem_cache_free(struct kmem_cache *cache, void *buf) {
}

void *kmem_cache_destroy(struct kmem_cache *cache) {
    
}

void *kmem_slab_alloc(struct kmem_slab *slab) {
  struct kmem_bufctl *ctl = slab->free_head;
  if(!ctl) {
    panic("kmem_slab_alloc");
  }
  slab->free_head = ctl->next;
  ctl->next = KMEM_CANARY;
  slab->refcnt++;
  return (void*)((char*)ctl - slab->bufctl_offset);
}

void kmem_slab_free(void *buf) {
  struct kmem_slab *slab = (struct kmem_slab*)((char*)PGROUNDDOWN((unsigned long long) buf) + PGSIZE - sizeof(struct kmem_slab));
  struct kmem_bufctl *ctl = (struct kmem_bufctl*)((char*)buf + slab->bufctl_offset);
  if(ctl->next != KMEM_CANARY) {
    // this checks buffer overflow and double free
    panic("kmem_slab_free canary");
  }
  ctl->next = slab->free_head;
  slab->free_head = ctl;
  slab->refcnt--;
}

struct kmem_slab *kmem_slab_create(uint size, uint align, void (*constructor)(void*, uint)) {
  // align cannot be bigger than 4096
  // TODO assert that align is reasonable, like 1,2,4,8,16
  // TODO assert that size is reasonable, like < PGSIZE/8

  void *page = kalloc();
  if(!page) {
    return 0;
  }
  struct kmem_slab *slab = (struct kmem_slab*)((char*)page + PGSIZE - sizeof(struct kmem_slab));
  memset(slab, 0, sizeof(struct kmem_slab));
  // initialize buffers

  // per buffer:
  // - `size` bytes for actual data
  // - pad to multiple of 8 bytes
  // - `sizeof(kmem_bufctl)` bytes for bufctl (could also be less with relative indexing)
  // - pad to satisfy alignment for next buffer (we ignore this for now because we have alignment 8 here)
  slab->bufctl_offset = ((size + 7) & ~7u);
  slab->buf_eff_size = slab->bufctl_offset + sizeof(struct kmem_bufctl);
  slab->free_head = (struct kmem_bufctl*)((char*)page + slab->bufctl_offset);
  void *buf = page;
  void *end = (char*)slab - slab->buf_eff_size;
  struct kmem_bufctl *ctl;
  while(buf <= end) {
    slab->refcnt_max++; // TODO do this easier
    if(constructor) {
      constructor(buf, size);
    }
    void *buf_next = (void*)((char*)buf + slab->buf_eff_size);
    ctl = (struct kmem_bufctl*)((char*)buf + slab->bufctl_offset);
    ctl->next = (struct kmem_bufctl*)((char*)ctl + slab->buf_eff_size);

    buf = (void*)((char*)buf + slab->buf_eff_size);
  }
  // last freelist entry to NULL
  ctl = (struct kmem_bufctl*)((char*)buf - slab->buf_eff_size - sizeof(struct kmem_bufctl));
  ctl->next = NULL;

  return slab;
}
