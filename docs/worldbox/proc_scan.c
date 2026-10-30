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
#ifndef GROUP_BUDGET
#define GROUP_BUDGET (UINT64_C(2) * 1024 * 1024 * 1024)
#endif
#define SMALL_RANGE (UINT64_C(128) * 1024 * 1024)
#define MAX_VALUE (512U * 1024U * 1024U)
#define MAX_RANGES 65536U
#define MAX_CHECKS 100000U

typedef struct { uint64_t start, end; int priority; } Range;
typedef struct {
    uint64_t eligible, attempted, bytes_read, ranges, read_errors, candidates, versions, checks;
} Stats;

static uint32_t u32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
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

/* Keep three bytes between reads so magic crossing a chunk boundary is found. */
static void scan_range(int fd, unsigned char *buf, uint64_t start, uint64_t end, Stats *s) {
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
                carry = have < 3 ? have : 3;
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

static void print_stats(const Stats *s) {
    printf("{\"eligibleBytes\":%" PRIu64 ",\"attemptedBytes\":%" PRIu64
           ",\"bytesRead\":%" PRIu64 ",\"rangesScanned\":%" PRIu64
           ",\"readErrors\":%" PRIu64 ",\"candidates\":%" PRIu64
           ",\"validationChecks\":%" PRIu64 "}",
           s->eligible, s->attempted, s->bytes_read, s->ranges,
           s->read_errors, s->candidates, s->checks);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: proc_scan PID\n"); return 2; }
    char *endptr = NULL;
    long parsed = strtol(argv[1], &endptr, 10);
    if (!endptr || *endptr || parsed <= 0 || parsed > INT32_MAX) {
        fprintf(stderr, "invalid PID\n"); return 2;
    }
    pid_t pid = (pid_t)parsed;
    char path[64];
    int status, attached = 0, mem = -1, exitcode = 1;
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
    buf = malloc(CHUNK + 3);
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
        int anonymous = *name == '\0' || *name == '\n' || *name == '[' ||
                        !strncmp(name, "/dev/zero", 9) || !strncmp(name, "/dev/ashmem", 11) ||
                        !strncmp(name, "/memfd:", 7);
        int priority = permissions[1] == 'w' && anonymous && end - start <= SMALL_RANGE;
        int g = priority ? 0 : 1;
        if (UINT64_MAX - group[g].eligible < end - start) {
            fprintf(stderr, "readable mapping size overflow\n"); goto done;
        }
        group[g].eligible += end - start;
        if (count == MAX_RANGES) { fprintf(stderr, "too many mappings\n"); goto done; }
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 128;
            Range *p = realloc(ranges, next * sizeof(*p));
            if (!p) { fprintf(stderr, "allocation failed\n"); goto done; }
            ranges = p; capacity = next;
        }
        ranges[count++] = (Range){start, end, priority};
    }
    if (ferror(maps)) { fprintf(stderr, "error reading mappings\n"); goto done; }

    /* Small writable anonymous allocations first, then other mappings from high addresses down.
       A partial high-address range is scanned from its end, not its beginning. */
    for (int g = 0; g < 2; g++) {
        for (size_t i = 0; i < count && group[g].attempted < GROUP_BUDGET; i++) {
            Range *r = &ranges[g == 0 ? i : count - 1 - i];
            uint64_t start, end;
            if (select_window(r, g, GROUP_BUDGET - group[g].attempted, &start, &end))
                scan_range(mem, buf, start, end, &group[g]);
        }
    }
    uint64_t versions = group[0].versions | group[1].versions;
    printf("{\"kind\":\"result\",\"candidates\":%" PRIu64 ",\"versions\":[",
           group[0].candidates + group[1].candidates);
    int first = 1;
    for (unsigned v = 16; v <= 40; v++) {
        if (versions & (UINT64_C(1) << v)) {
            printf("%s%u", first ? "" : ",", v); first = 0;
        }
    }
    printf("],\"priority\":"); print_stats(&group[0]);
    printf(",\"later\":"); print_stats(&group[1]);
    printf(",\"validationLimited\":%s,\"truncated\":%s}\n",
           group[0].checks == MAX_CHECKS || group[1].checks == MAX_CHECKS ? "true" : "false",
           group[0].attempted < group[0].eligible || group[1].attempted < group[1].eligible ? "true" : "false");
    exitcode = 0;
done:
    free(ranges);
    free(buf);
    if (mem >= 0) close(mem);
    if (maps) fclose(maps);
    if (attached && ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "ptrace detach failed: %s\n", strerror(errno));
        exitcode = 1;
    }
    return exitcode;
}
