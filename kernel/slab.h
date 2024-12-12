#define KM_CFG_BUFCTL_INTERNAL 0x1

struct kmem_cfg {
  uint size;
  uint flags;
  uint bufctl_offset; // only used when KM_CFG_BUFCTL_INTERNAL is set
};

struct kmem_layout {
  int has_external_bufctl;
  uint bufctl_offset;
  uint buf_eff_size;
  uint refcnt_max;
};

struct kmem_cache {
  struct spinlock lock;
  char *name;
  void (*constructor)(void*, uint);
  void (*destructor)(void*, uint);
  struct kmem_layout layout;
  struct kmem_slab *head_empty;
  struct kmem_slab *head_partial;
  struct kmem_slab *head_complete;
  struct kmem_cache *prev;
  struct kmem_cache *next;
};

struct kmem_slab {
  // might be a little inefficient to keep the entire layout in the slab.
  // perhaps back pointer to cache?
  struct kmem_layout layout;
  uint refcnt;
  struct kmem_bufctl *free_head;
  struct kmem_slab *prev;
  struct kmem_slab *next;
};

struct kmem_bufctl {
  struct kmem_bufctl *next;
};

#define KM_NOSLEEP 0
#define KM_SLEEP 1
