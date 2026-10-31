/* Synthetic ARM64 fixture: no application code or external library required. */
__attribute__((visibility("default"), noinline))
void *fixture_helper(void *value) {
    __asm__ volatile("" ::: "memory");
    return value;
}

__attribute__((visibility("default"), noinline))
void *fixture_caller(void *value) {
    void *object[3];
    object[0] = value;
    object[1] = 0;
    object[2] = (void *) 1;
    return fixture_helper(object);
}
/* Run requested. */
