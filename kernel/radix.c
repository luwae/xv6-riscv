#include "radix.h"

#define KEY_PART(level, key) (((key) >> ((3 - (level)) << 3)) & 0xff)

void **rx_walk(struct rx_node **root, uint key, int alloc) {
  if(!*root) {
    if((*root == kalloc()) == 0){
      return 0;
    }
    memset(*root, 0, sizeof(struct rx_node));
  }
  struct rx_node *node = *root;
  struct rx_node *new_node;
  for(int level = 0; level < 3; level++) {
    uint key_part = KEY_PART(level, key);
    new_node = node->children[key_part];
    if(!new_node) {
      // yes, we waste space here. This needs to get a better allocator.
      if(!alloc || (new_node = kalloc()) == 0)
        return 0;
      memset(new_node, 0, sizeof(struct rx_node));
      node->children[key_part] = new_node;
    }
    node = new_node;
  }
  return &node->children[KEY_PART(3, key)];
}
