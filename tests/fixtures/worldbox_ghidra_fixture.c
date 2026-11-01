/* Synthetic ARM64 fixture: no application code or external library required. */
__attribute__((visibility("default"), noinline))
void *fixture_helper(void *value, void *input) {
    __asm__ volatile("" : : "r"(input) : "memory");
    return value;
}

__attribute__((visibility("default"), noinline))
void *fixture_caller(void *value) {
    void *object[3];
    object[0] = value;
    object[1] = 0;
    object[2] = (void *) 1;
    return fixture_helper(object, value);
}
/* A separate known two-level pointer chain, used only to test provenance. */
struct fixture_inner { void *unused; void *value; };
struct fixture_outer { void *unused; struct fixture_inner *inner; };
__attribute__((visibility("default"), noinline))
void *fixture_chain(struct fixture_outer *outer) {
    void *object[3];
    object[0] = outer;
    object[1] = 0;
    object[2] = (void *) 1;
    return fixture_helper(object, outer->inner->value);
}
/* Run requested. */
/* Fixture-only exported JNI-shaped entry for testing symbol-to-FDE selection. */
__attribute__((visibility("default"), noinline))
void *JNI_OnLoad(void *value, void *reserved) {
    return fixture_helper(value, reserved);
}

/* Synthetic string-use fixture for bounded p-code argument tracing. */
__attribute__((visibility("default"), noinline))
void *fixture_string_caller(void) {
    return fixture_helper((void *)"UnityPurchasing", (void *)"UnityPurchasing");
}
