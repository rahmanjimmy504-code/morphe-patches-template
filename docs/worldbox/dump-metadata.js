// dump-metadata.js — find and dump an IL2CPP global-metadata.dat that has already
// been decrypted *in memory* by the running Unity/IL2CPP runtime.
//
// Why this exists: if the copy on disk has a non-standard magic, the runtime is
// decrypting it at startup. This script does not understand the cipher at all —
// it only looks for the decrypted header (0xFAB11BAF) in the process address
// space and copies out the bytes.
//
// IMPORTANT: this script only READS memory. It never hooks native code, so it
// also works on an x86_64 emulator running an ARM64/ARMv7 app through Android's
// native bridge (libndk_translation / libhoudini), where Frida's native agent
// cannot attach to translated ARM code but *can* still read its data.
//
// Usage (frida-server running as root on the device/emulator):
//   adb shell su -c '/data/local/tmp/frida-server &'
//   frida -U -f com.mkarpenko.worldbox -l dump-metadata.js --no-pause
// or attach to an already running instance:
//   frida -U -n WorldBox -l dump-metadata.js
//
// Output: files under /data/local/tmp/wb-meta/ — pull them with
//   adb pull /data/local/tmp/wb-meta ./wb-meta
//
// Everything written by this script is game data. Do not commit it, do not
// upload it to a public artifact store, do not paste it into web services.

'use strict';

const CONFIG = {
    magic: 0xFAB11BAF,          // Il2CppGlobalMetadataHeader::sanity
    outDir: '/data/local/tmp/wb-meta',
    chunk: 4 * 1024 * 1024,     // bytes read per iteration
    maxMetadataSize: 512 * 1024 * 1024,
    attempts: 20,               // scan passes...
    intervalMs: 5000,           // ...spaced this far apart
    minRangeSize: 64 * 1024
};

function log(msg) { console.log('[wb] ' + msg); }

function hexPtr(p) {
    return p.toString();
}

function u32(p) {
    try { return Memory.readU32(p); } catch (e) { return -1; }
}

// The header is a table of (offset, size) int32 pairs. If the magic matches but
// the offsets are nonsense we are looking at a coincidence, not real metadata.
function headerLooksSane(p, maxSize) {
    if (u32(p) !== CONFIG.magic) return false;
    const version = u32(p.add(4));
    const versionOk = (version >= 16 && version <= 40) || (version >= 100 && version <= 120);
    if (!versionOk) return false;

    let good = 0;
    for (let i = 2; i < 16; i++) {
        const v = u32(p.add(i * 4));
        if (v >= 0 && v <= maxSize) good++;
    }
    return good >= 14;
}

function findMagicInRange(range) {
    const hits = [];
    const step = CONFIG.chunk;
    for (let off = 0; off < range.size; off += step) {
        const len = Math.min(step + 4, range.size - off);
        let buf;
        try {
            buf = Memory.readByteArray(range.base.add(off), len);
        } catch (e) {
            continue;
        }
        const view = new Uint8Array(buf);
        for (let i = 0; i + 4 <= view.length; i += 4) {
            // little-endian 0xFAB11BAF => AF 1B B1 FA
            if (view[i] === 0xAF && view[i + 1] === 0x1B && view[i + 2] === 0xB1 && view[i + 3] === 0xFA) {
                hits.push(range.base.add(off + i));
            }
        }
    }
    return hits;
}

function trimTrailingZeros(p, size) {
    let end = size;
    while (end > 64) {
        const len = Math.min(4096, end);
        let buf;
        try {
            buf = new Uint8Array(Memory.readByteArray(p.add(end - len), len));
        } catch (e) {
            return end;
        }
        let i = buf.length - 1;
        while (i >= 0 && buf[i] === 0) i--;
        if (i >= 0) return end - (buf.length - 1 - i);
        end -= len;
    }
    return end;
}

function dumpCandidate(addr, containingRange, index) {
    // The metadata is normally one contiguous buffer inside a single mapping, so
    // the end of the containing range is a safe upper bound; trailing zero pages
    // are trimmed afterwards.
    const offsetInRange = addr.sub(containingRange.base);
    let available = containingRange.size - offsetInRange;
    if (available > CONFIG.maxMetadataSize) available = CONFIG.maxMetadataSize;
    const size = trimTrailingZeros(addr, available);
    const outPath = CONFIG.outDir + '/global-metadata.candidate' + index + '.dat';

    log('candidate #' + index + ' @ ' + hexPtr(addr) +
        '  version=' + u32(addr.add(4)) +
        '  range=' + hexPtr(containingRange.base) + '+' + containingRange.size +
        '  dump=' + size + ' bytes');

    const f = new File(outPath, 'wb');
    try {
        const CH = 1024 * 1024;
        for (let o = 0; o < size; o += CH) {
            const n = Math.min(CH, size - o);
            f.write(Memory.readByteArray(addr.add(o), n));
        }
    } finally {
        f.flush();
        f.close();
    }
    log('wrote ' + outPath);
    return outPath;
}

function scanOnce(pass) {
    let found = 0;
    const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true })
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: true }));

    for (const r of ranges) {
        if (r.size < CONFIG.minRangeSize) continue;
        const hits = findMagicInRange(r);
        if (!hits.length) continue;
        for (const h of hits) {
            if (!headerLooksSane(h, CONFIG.maxMetadataSize)) continue;
            dumpCandidate(h, r, pass + '_' + (found++));
        }
    }
    if (!found) log('pass ' + pass + ': no plausible metadata header yet');
    return found;
}

function loop(pass) {
    if (pass > CONFIG.attempts) {
        log('giving up after ' + CONFIG.attempts + ' passes; ' +
            'try again after the game reaches its main menu / a running world');
        return;
    }
    let found = 0;
    try { found = scanOnce(pass); } catch (e) { log('scan error: ' + e); }
    if (found > 0) {
        log('done. Pull with: adb pull ' + CONFIG.outDir);
        return;
    }
    setTimeout(() => loop(pass + 1), CONFIG.intervalMs);
}

Java.perform(function () {
    try { Java.enumerateClassLoadersSync(); } catch (e) { /* not a Java app yet: fine */ }
});

log('scanning for 0xFAB11BAF (decrypted global-metadata.dat), ' + CONFIG.attempts +
    ' passes every ' + (CONFIG.intervalMs / 1000) + 's');
log('arch=' + Process.arch + ' pointerSize=' + Process.pointerSize);
log('note: memory reads work even when the IL2CPP code is ARM and this agent is x86_64');
loop(0);
