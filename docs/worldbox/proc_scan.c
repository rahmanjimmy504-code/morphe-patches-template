/*
 * Aggregate-only IL2CPP header heuristic for a disposable rooted emulator.
 * Scans two bounded, disjoint groups; never emits addresses or memory bytes.
 * The target's other threads can still run while the attached thread is stopped.
 */
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#define CHUNK (1024U * 1024U)
#define MAX_NEEDLE_BYTES 32U
#define MAX_STRING_OVERLAP (2U * MAX_NEEDLE_BYTES - 1U)
#ifndef GROUP_BUDGET
#define GROUP_BUDGET (UINT64_C(2) * 1024 * 1024 * 1024)
#endif
#define SMALL_RANGE (UINT64_C(128) * 1024 * 1024)
#define MAX_VALUE (512U * 1024U * 1024U)
#define MAX_RANGES 65536U
#define MAX_RESIDENT_RANGES 1000000U
#define MAX_PAGEMAP_PAGES (UINT64_C(20) * 1024 * 1024)
#define MAX_CHECKS 100000U

enum { MAP_ANONYMOUS, MAP_APK, MAP_SHARED_OBJECT, MAP_DATA_FILE, MAP_OTHER_FILE, MAP_SPECIAL, MAP_CLASS_COUNT };
static const char *const MAP_CLASS_LABELS[MAP_CLASS_COUNT] = {"anonymous", "apk", "sharedObject", "dataFile", "otherFile", "special"};

typedef struct { uint64_t start, end; int priority, map_class; } Range;
typedef struct {
    uint64_t eligible, attempted, bytes_read, ranges, read_errors, candidates, versions, checks;
    uint64_t mapped, nonresident, swapped, unknown;
    uint64_t string_hits[8][2];
    uint64_t class_string_hits[MAP_CLASS_COUNT][8][2];
} Stats;

typedef struct { const char *label; const unsigned char *bytes; size_t length; } Needle;
static const unsigned char N_UNITY_PURCHASING[] = "UnityPurchasing";
static const unsigned char N_UNITY_CALLBACK[] = "IUnityCallback";
static const unsigned char N_PURCHASE_SUCCEEDED[] = "OnPurchaseSucceeded";
static const unsigned char N_PRODUCTS_RETRIEVED[] = "OnProductsRetrieved";
static const unsigned char N_PURCHASE_FAILED[] = "OnPurchaseFailed";
static const unsigned char N_PREMIUM_ELEMENTS[] = "PremiumElementsChecker";
static const unsigned char N_PREMIUM_WINDOW[] = "PremiumWindow";
static const unsigned char N_PREMIUM_UNLOCK[] = "PremiumUnlockAnimation";
static const Needle NEEDLES[] = {
    {"unity_purchasing", N_UNITY_PURCHASING, sizeof(N_UNITY_PURCHASING) - 1},
    {"unity_callback", N_UNITY_CALLBACK, sizeof(N_UNITY_CALLBACK) - 1},
    {"purchase_succeeded", N_PURCHASE_SUCCEEDED, sizeof(N_PURCHASE_SUCCEEDED) - 1},
    {"products_retrieved", N_PRODUCTS_RETRIEVED, sizeof(N_PRODUCTS_RETRIEVED) - 1},
    {"purchase_failed", N_PURCHASE_FAILED, sizeof(N_PURCHASE_FAILED) - 1},
    {"premium_elements_checker", N_PREMIUM_ELEMENTS, sizeof(N_PREMIUM_ELEMENTS) - 1},
    {"premium_window", N_PREMIUM_WINDOW, sizeof(N_PREMIUM_WINDOW) - 1},
    {"premium_unlock_animation", N_PREMIUM_UNLOCK, sizeof(N_PREMIUM_UNLOCK) - 1},
};
#define NEEDLE_COUNT (sizeof(NEEDLES) / sizeof(NEEDLES[0]))

static uint32_t u32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int classify_mapping(const char *name) {
    if (*name == '[') return MAP_SPECIAL;
    if (*name == '\0' || *name == '\n' || !strncmp(name, "/dev/zero", 9) ||
        !strncmp(name, "/dev/ashmem", 11) || !strncmp(name, "/memfd:", 7))
        return MAP_ANONYMOUS;
    if (strstr(name, ".apk")) return MAP_APK;
    if (strstr(name, ".so")) return MAP_SHARED_OBJECT;
    if (strstr(name, ".dat")) return MAP_DATA_FILE;
    return MAP_OTHER_FILE;
}

static int plausible(int fd, uint64_t pos, uint32_t *version) {
    unsigned char h[64];
    if (pread(fd, h, sizeof(h), (off_t)pos) != (ssize_t)sizeof(h)) return 0;
    if (u32le(h) != 0xfab11bafU) return 0;
    *version = u32le(h + 4);
    if (*version < 16 || *version > 40) return 0;
    unsigned bounded = 0, nonzero = 0;
    for (unsigned i = 2; i < 16; i++) {
        uint32_t v = u32le(h + i * 4);
        if (v <= MAX_VALUE) bounded++;
        if (v > 0 && v <= MAX_VALUE) nonzero++;
    }
    return bounded == 14 && nonzero >= 4;
}

/* Search known bridge/script identifiers only; counts are aggregate and no
   addresses or candidate memory bytes are retained or emitted. */
static void scan_strings(const unsigned char *data, size_t have, size_t carry, int map_class, Stats *s) {
    for (size_t n = 0; n < NEEDLE_COUNT; n++) {
        const Needle *needle = &NEEDLES[n];
        size_t wide_length = needle->length * 2;
        for (size_t i = 0; i + needle->length <= have; i++) {
            if (i + needle->length > carry &&
                !memcmp(data + i, needle->bytes, needle->length))
                s->string_hits[n][0]++, s->class_string_hits[map_class][n][0]++;
        }
        for (size_t i = 0; i + wide_length <= have; i++) {
            if (i + wide_length <= carry) continue;
            size_t j = 0;
            for (; j < needle->length; j++) {
                if (data[i + 2 * j] != needle->bytes[j] || data[i + 2 * j + 1] != 0) break;
            }
            if (j == needle->length)
                s->string_hits[n][1]++, s->class_string_hits[map_class][n][1]++;
        }
    }
}

/* Keep overlap for header signatures and exact ASCII/UTF-16LE string leads. */
static void scan_range(int fd, unsigned char *buf, uint64_t start, uint64_t end, int map_class, Stats *s) {
    size_t carry = 0;
    s->ranges++;
    for (uint64_t pos = start; pos < end;) {
        uint64_t remaining = end - pos;
        size_t len = remaining < CHUNK ? (size_t)remaining : CHUNK;
        ssize_t n = pread(fd, buf + carry, len, (off_t)pos);
        s->attempted += len;
        if (n > 0) {
            s->bytes_read += (uint64_t)n;
            size_t have = carry + (size_t)n;
            scan_strings(buf, have, carry, map_class, s);
            for (size_t i = 0; i + 4 <= have; i++) {
                if (u32le(buf + i) == 0xfab11bafU && s->checks < MAX_CHECKS) {
                    uint32_t version;
                    s->checks++;
                    if (plausible(fd, pos - carry + i, &version)) {
                        s->candidates++;
                        s->versions |= UINT64_C(1) << version;
                    }
                }
            }
            if ((size_t)n == len) {
                carry = have < MAX_STRING_OVERLAP ? have : MAX_STRING_OVERLAP;
                memmove(buf, buf + have - carry, carry);
            } else {
                s->read_errors++;
                carry = 0; /* Don't bridge an unread portion. */
            }
        } else {
            s->read_errors++;
            carry = 0;
        }
        pos += len;
    }
}

/* Groups are disjoint. The tail pass selects the end of a partial range. */
static int select_window(const Range *r, int group, uint64_t budget,
                         uint64_t *start, uint64_t *end) {
    if ((r->priority ? 0 : 1) != group || !budget) return 0;
    uint64_t len = r->end - r->start;
    if (len > budget) len = budget;
    *start = group == 0 ? r->start : r->end - len;
    *end = *start + len;
    return 1;
}

/* The pagemap present bit is only a snapshot; it does not prove nonresident
   pages are uninteresting. Bound the pagemap work and flag all unknown bytes. */
static int resident_ranges(int pagemap, const Range *maps, size_t count, uint64_t page_size,
                           int include_swapped, Range **out, size_t *out_count, Stats group[2]) {
    Range *list = NULL;
    size_t used = 0, capacity = 0;
    uint64_t pages_seen = 0;
    uint64_t entries[4096];
    for (size_t m = 0; m < count; m++) {
        const Range *r = &maps[m];
        int g = r->priority ? 0 : 1;
        if (r->start % page_size || r->end % page_size) {
            fprintf(stderr, "unaligned memory mapping\n"); free(list); return -1;
        }
        size_t run_index = SIZE_MAX;
        for (uint64_t pos = r->start; pos < r->end;) {
            uint64_t pages = (r->end - pos) / page_size;
            if (pages_seen >= MAX_PAGEMAP_PAGES) {
                group[g].unknown += r->end - pos;
                break;
            }
            if (pages > 4096) pages = 4096;
            if (pages > MAX_PAGEMAP_PAGES - pages_seen) pages = MAX_PAGEMAP_PAGES - pages_seen;
            /* A position that cannot be represented as off_t is unknown, not absent. */
            uint64_t index = pos / page_size;
            ssize_t n = -1;
            if (index <= (uint64_t)INT64_MAX / sizeof(uint64_t))
                n = pread(pagemap, entries, (size_t)pages * sizeof(uint64_t),
                          (off_t)(index * sizeof(uint64_t)));
            size_t valid = n > 0 ? (size_t)n / sizeof(uint64_t) : 0;
            if (valid > pages) valid = (size_t)pages;
            for (size_t i = 0; i < valid; i++) {
                uint64_t page_start = pos + i * page_size;
                int present = !!(entries[i] & (UINT64_C(1) << 63));
                int swapped = !present && !!(entries[i] & (UINT64_C(1) << 62));
                if (!present) group[g].nonresident += page_size;
                if (swapped) group[g].swapped += page_size;
                if (present || (include_swapped && swapped)) {
                    group[g].eligible += page_size;
                    if (run_index != SIZE_MAX && list[run_index].end == page_start) {
                        list[run_index].end += page_size;
                    } else {
                        if (used == MAX_RESIDENT_RANGES) {
                            fprintf(stderr, "too many resident page ranges\n"); free(list); return -1;
                        }
                        if (used == capacity) {
                            size_t next = capacity ? capacity * 2 : 128;
                            if (next > MAX_RESIDENT_RANGES) next = MAX_RESIDENT_RANGES;
                            Range *p = realloc(list, next * sizeof(*p));
                            if (!p) { fprintf(stderr, "allocation failed\n"); free(list); return -1; }
                            list = p; capacity = next;
                        }
                        run_index = used;
                        list[used++] = (Range){page_start, page_start + page_size, r->priority, r->map_class};
                    }
                } else {
                    run_index = SIZE_MAX;
                }
            }
            if (valid < pages) {
                group[g].unknown += (pages - valid) * page_size;
                run_index = SIZE_MAX;
            }
            pages_seen += pages;
            pos += pages * page_size;
        }
    }
    *out = list; *out_count = used;
    return 0;
}

static void print_string_hits(const uint64_t hits[8][2]) {
    int first = 1;
    for (size_t i = 0; i < NEEDLE_COUNT; i++) {
        for (size_t encoding = 0; encoding < 2; encoding++) {
            if (!hits[i][encoding]) continue;
            printf("%s\"%s_%s\":%" PRIu64, first ? "" : ",", NEEDLES[i].label,
                   encoding ? "utf16le" : "ascii", hits[i][encoding]);
            first = 0;
        }
    }
}

static void print_stats(const Stats *s) {
    printf("{\"mappedBytes\":%" PRIu64 ",\"eligibleBytes\":%" PRIu64
           ",\"nonresidentBytes\":%" PRIu64 ",\"swappedBytes\":%" PRIu64
           ",\"pagemapUnknownBytes\":%" PRIu64 ",\"attemptedBytes\":%" PRIu64
           ",\"bytesRead\":%" PRIu64 ",\"rangesScanned\":%" PRIu64
           ",\"readErrors\":%" PRIu64 ",\"candidates\":%" PRIu64
           ",\"validationChecks\":%" PRIu64 ",\"stringHits\":{",
           s->mapped, s->eligible, s->nonresident, s->swapped, s->unknown,
           s->attempted, s->bytes_read, s->ranges, s->read_errors, s->candidates, s->checks);
    print_string_hits(s->string_hits);
    printf("},\"memoryClassStringHits\":{");
    for (int c = 0; c < MAP_CLASS_COUNT; c++) {
        printf("%s\"%s\":{", c ? "," : "", MAP_CLASS_LABELS[c]);
        print_string_hits(s->class_string_hits[c]);
        printf("}");
    }
    printf("}}");
}

int main(int argc, char **argv) {
    if (argc != 2 && !(argc == 3 && (!strcmp(argv[2], "--resident") ||
                                      !strcmp(argv[2], "--resident-and-swapped")))) {
        fprintf(stderr, "usage: proc_scan PID [--resident|--resident-and-swapped]\n"); return 2;
    }
    int resident = argc == 3;
    int include_swapped = resident && !strcmp(argv[2], "--resident-and-swapped");
    char *endptr = NULL;
    long parsed = strtol(argv[1], &endptr, 10);
    if (!endptr || *endptr || parsed <= 0 || parsed > INT32_MAX) {
        fprintf(stderr, "invalid PID\n"); return 2;
    }
    pid_t pid = (pid_t)parsed;
    char path[64];
    int status, attached = 0, mem = -1, pagemap = -1, exitcode = 1;
    FILE *maps = NULL;
    unsigned char *buf = NULL;
    Range *ranges = NULL;
    size_t count = 0, capacity = 0;
    Stats group[2] = {{0}, {0}};

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "ptrace attach failed: %s\n", strerror(errno)); goto done;
    }
    attached = 1;
    if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
        fprintf(stderr, "target did not stop for inspection\n"); goto done;
    }
    snprintf(path, sizeof(path), "/proc/%ld/maps", parsed);
    maps = fopen(path, "r");
    if (!maps) { fprintf(stderr, "open maps: %s\n", strerror(errno)); goto done; }
    snprintf(path, sizeof(path), "/proc/%ld/mem", parsed);
    mem = open(path, O_RDONLY | O_CLOEXEC);
    if (mem < 0) { fprintf(stderr, "open memory: %s\n", strerror(errno)); goto done; }
    buf = malloc(CHUNK + MAX_STRING_OVERLAP);
    if (!buf) { fprintf(stderr, "allocation failed\n"); goto done; }

    char line[4096];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start, end;
        char permissions[5] = {0};
        int name_pos = 0;
        if (sscanf(line, "%llx-%llx %4s %*s %*s %*s %n", &start, &end,
                   permissions, &name_pos) != 3 || !name_pos ||
            permissions[0] != 'r' || end <= start) continue;
        const char *name = line + name_pos;
        while (*name == ' ' || *name == '\t') name++;
        int map_class = classify_mapping(name);
        int anonymous = map_class == MAP_ANONYMOUS || map_class == MAP_SPECIAL;
        int priority = permissions[1] == 'w' && anonymous && end - start <= SMALL_RANGE;
        int g = priority ? 0 : 1;
        if (UINT64_MAX - group[g].eligible < end - start) {
            fprintf(stderr, "readable mapping size overflow\n"); goto done;
        }
        group[g].eligible += end - start;
        group[g].mapped += end - start;
        if (count == MAX_RANGES) { fprintf(stderr, "too many mappings\n"); goto done; }
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 128;
            Range *p = realloc(ranges, next * sizeof(*p));
            if (!p) { fprintf(stderr, "allocation failed\n"); goto done; }
            ranges = p; capacity = next;
        }
        ranges[count++] = (Range){start, end, priority, map_class};
    }
    if (ferror(maps)) { fprintf(stderr, "error reading mappings\n"); goto done; }
    if (resident) {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0) { fprintf(stderr, "cannot determine page size\n"); goto done; }
        snprintf(path, sizeof(path), "/proc/%ld/pagemap", parsed);
        pagemap = open(path, O_RDONLY | O_CLOEXEC);
        if (pagemap < 0) { fprintf(stderr, "open pagemap: %s\n", strerror(errno)); goto done; }
        group[0].eligible = group[1].eligible = 0;
        Range *present = NULL;
        size_t present_count = 0;
        if (resident_ranges(pagemap, ranges, count, (uint64_t)page_size,
                            include_swapped, &present, &present_count, group)) goto done;
        free(ranges); ranges = present; count = present_count;
    }

    /* Small writable anonymous allocations first, then other mappings from high addresses down.
       A partial high-address range is scanned from its end, not its beginning. */
    for (int g = 0; g < 2; g++) {
        for (size_t i = 0; i < count && group[g].attempted < GROUP_BUDGET; i++) {
            Range *r = &ranges[g == 0 ? i : count - 1 - i];
            uint64_t start, end;
            if (select_window(r, g, GROUP_BUDGET - group[g].attempted, &start, &end))
                scan_range(mem, buf, start, end, r->map_class, &group[g]);
        }
    }
    uint64_t versions = group[0].versions | group[1].versions;
    printf("{\"kind\":\"result\",\"mode\":\"%s\",\"candidates\":%" PRIu64 ",\"versions\":[",
           include_swapped ? "resident-and-swapped" : resident ? "resident" : "all", group[0].candidates + group[1].candidates);
    int first = 1;
    for (unsigned v = 16; v <= 40; v++) {
        if (versions & (UINT64_C(1) << v)) {
            printf("%s%u", first ? "" : ",", v); first = 0;
        }
    }
    printf("],\"priority\":"); print_stats(&group[0]);
    printf(",\"later\":"); print_stats(&group[1]);
    int incomplete = group[0].attempted < group[0].eligible || group[1].attempted < group[1].eligible ||
                     group[0].unknown || group[1].unknown;
    uint64_t skipped_nonresident = group[0].nonresident + group[1].nonresident;
    if (include_swapped) skipped_nonresident -= group[0].swapped + group[1].swapped;
    printf(",\"validationLimited\":%s,\"selectedTruncated\":%s,\"truncated\":%s}\n",
           group[0].checks == MAX_CHECKS || group[1].checks == MAX_CHECKS ? "true" : "false",
           incomplete ? "true" : "false",
           incomplete || (resident && skipped_nonresident) ? "true" : "false");
    exitcode = 0;
done:
    free(ranges);
    free(buf);
    if (mem >= 0) close(mem);
    if (pagemap >= 0) close(pagemap);
    if (maps) fclose(maps);
    if (attached && ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "ptrace detach failed: %s\n", strerror(errno));
        exitcode = 1;
    }
    return exitcode;
}
