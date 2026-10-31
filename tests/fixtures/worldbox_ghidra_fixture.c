/* Synthetic ARM64 fixture: no application code or external library required. */
__attribute__((visibility("default"), noinline))
void *fixture_helper(void *value) {
    __asm__ volatile("" ::: "memory");
    return value;
}

__attribute__((visibility("default"), noinline))
void *fixture_caller(void *value) {
    return fixture_helper(value);
}
