// Experimental read-only scanner adapted from PR #1's dump-metadata.js.
// It reports aggregate results only; it does not transmit or save memory bytes.
'use strict';

const MAGIC = 'af 1b b1 fa';
const CHUNK_SIZE = 4 * 1024 * 1024;
const MAX_SCAN_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_RANGE_SIZE = 512 * 1024 * 1024;

function plausibleHeader(address) {
    try {
        if (address.readU32() !== 0xfab11baf) return null;
        const version = address.add(4).readU32();
        if (version < 16 || version > 40) return null;
        let bounded = 0;
        let nonzero = 0;
        for (let i = 2; i < 16; i++) {
            const value = address.add(i * 4).readU32();
            if (value <= MAX_RANGE_SIZE) bounded++;
            if (value > 0 && value <= MAX_RANGE_SIZE) nonzero++;
        }
        return bounded === 14 && nonzero >= 4 ? version : null;
    } catch (_) {
        return null;
    }
}

function scan() {
    const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true })
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }));
    let scanned = 0;
    let errors = 0;
    let candidates = 0;
    const versions = new Set();
    let truncated = false;
    for (const range of ranges) {
        // Scan in bounded chunks. Overlap by 3 bytes to catch a cross-boundary magic.
        for (let offset = 0; offset < range.size; offset += CHUNK_SIZE) {
            const length = Math.min(CHUNK_SIZE + 3, range.size - offset, MAX_SCAN_BYTES - scanned);
            if (length <= 0) { truncated = true; break; }
            let hits;
            try {
                hits = Memory.scanSync(range.base.add(offset), length, MAGIC);
            } catch (_) {
                errors++;
                scanned += length;
                continue;
            }
            scanned += length;
            for (const hit of hits) {
                // Ignore overlap hits already visited in the preceding chunk.
                if (offset > 0 && hit.address.compare(range.base.add(offset)) < 0) continue;
                const version = plausibleHeader(hit.address);
                if (version !== null) { candidates++; versions.add(version); }
            }
        }
        if (truncated) break;
    }
    send({ kind: 'result', candidates, versions: Array.from(versions), scannedBytes: scanned, errors, truncated });
}

setImmediate(() => {
    try { scan(); }
    catch (error) { send({ kind: 'error', message: String(error) }); }
});
