/* Synthetic 32-bit ARM fixture: validates JNI_OnLoad call discovery only. */
__attribute__((visibility("default"), noinline))
int RegisterNatives(void) {
    return 7;
}

__attribute__((visibility("default"), noinline))
int JNI_OnLoad(void *vm, void *reserved) {
    __asm__ volatile("" : : "r"(vm), "r"(reserved) : "memory");
    return RegisterNatives();
}
