struct kmem_cache {
  struct spinlock lock;
  char *name;
  uint size;
  uint align;
  void (*constructor)(void*, uint);
  void (*destructor)(void*, uint);
  struct kmem_slab *head_empty;
  struct kmem_slab *head_partial;
  struct kmem_slab *head_complete;
  struct kmem_cache *prev;
  struct kmem_cache *next;
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
