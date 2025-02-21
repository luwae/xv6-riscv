struct semaphore {
  int counter;
  struct spinlock lk;
}
