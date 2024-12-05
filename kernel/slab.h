struct kmem_cache {
  // struct spinlock lock; // TODO
  char *name;
  uint size;
  uint align;
  void (*constructor)(void*, uint);
  void (*destructor)(void*, uint);
  struct kmem_slab *head;
  struct kmem_slab *complete_head;
};

struct kmem_slab {
  struct kmem_slab *prev;
  struct kmem_slab *next;
  struct kmem_bufctl *free_head;
  uint bufctl_offset;
  uint buf_eff_size;
  uint refcnt;
  uint refcnt_max;
};

struct kmem_bufctl {
  struct kmem_bufctl *next;
};

#define KM_NOSLEEP 0
#define KM_SLEEP 1
