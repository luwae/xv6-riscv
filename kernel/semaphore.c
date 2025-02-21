void semaphore_init(struct semaphore *sem, int counter) {
    sem->counter = counter;
    initlock(&sem->lk, "semaphore");
}

void wait(struct semaphore *sem) {
    acquire(&sem->lk);
    if (--sem->counter < 0) {
        sleep(sem, &sem->lk);
    }
    release(&sem->lk);
}

void signal(struct semaphore *sem) {
    acquire(&sem->lk);
    if (++sem->counter <= 0) {
        wakeup_single(sem);
    }
    release(&sem->lk);
}
