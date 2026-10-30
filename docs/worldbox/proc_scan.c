/*
 * Experimental, aggregate-only IL2CPP header scan for a disposable Android
 * emulator. Requires root/ptrace permission. Never emits or saves memory bytes.
 * A plausible header is only a lead, not proof of decrypted game metadata.
 */
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
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
#define MAX_BYTES (UINT64_C(2) * 1024 * 1024 * 1024)
#define MAX_VALUE (512U * 1024U * 1024U)

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
    uint64_t scanned = 0, ranges = 0, faults = 0, candidates = 0;
    uint64_t versions = 0;
    int truncated = 0;

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
        if (sscanf(line, "%llx-%llx %4s", &start, &end, permissions) != 3 ||
            permissions[0] != 'r' || end <= start) continue;
        ranges++;
        for (uint64_t pos = start; pos < end;) {
            if (scanned >= MAX_BYTES) { truncated = 1; goto finished; }
            uint64_t remaining = end - pos;
            size_t len = remaining < (CHUNK + 3U) ? (size_t)remaining : (CHUNK + 3U);
            if (len > MAX_BYTES - scanned) len = (size_t)(MAX_BYTES - scanned);
            ssize_t n = pread(mem, buf, len, (off_t)pos);
            scanned += len;
            if (n < 0) {
                faults++;
            } else {
                for (ssize_t i = 0; i + 4 <= n; i++) {
                    if (u32le(buf + i) == 0xfab11bafU) {
                        uint32_t v;
                        if (plausible(mem, pos + (uint64_t)i, &v)) {
                            candidates++;
                            versions |= UINT64_C(1) << v;
                        }
                    }
                }
            }
            if (remaining <= CHUNK) break;
            pos += CHUNK;
        }
    }
finished:
    printf("{\"kind\":\"result\",\"candidates\":%" PRIu64
           ",\"versions\":[", candidates);
    int first = 1;
    for (unsigned v = 16; v <= 40; v++) {
        if (versions & (UINT64_C(1) << v)) {
            printf("%s%u", first ? "" : ",", v); first = 0;
        }
    }
    printf("],\"scannedBytes\":%" PRIu64 ",\"ranges\":%" PRIu64
           ",\"readErrors\":%" PRIu64 ",\"truncated\":%s}\n",
           scanned, ranges, faults, truncated ? "true" : "false");
    exitcode = 0;
done:
    if (buf) free(buf);
    if (mem >= 0) close(mem);
    if (maps) fclose(maps);
    if (attached && ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "ptrace detach failed: %s\n", strerror(errno));
        /* Do not report success if we could not resume the target. */
        exitcode = 1;
    }
    return exitcode;
}
