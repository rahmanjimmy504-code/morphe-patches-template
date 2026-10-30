const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('docs/worldbox/scan-metadata.js', 'utf8');

function scan(bytes, options = {}) {
  class Pointer {
    constructor(offset) { this.offset = offset; }
    add(n) { return new Pointer(this.offset + n); }
    compare(other) { return Math.sign(this.offset - other.offset); }
    readU32() {
      if (this.offset < 0 || this.offset + 4 > bytes.length) throw Error('out of range');
      return bytes.readUInt32LE(this.offset);
    }
  }
  const messages = [];
  const range = {base: new Pointer(0), size: bytes.length};
  const context = {
    Process: {enumerateRanges: ({protection}) => protection === 'r--' ? [range] : []},
    Memory: {scanSync: (base, size) => {
      if (options.failRead) throw Error('unreadable');
      const found = [];
      for (let i = base.offset; i + 4 <= base.offset + size; i++)
        if (bytes.readUInt32LE(i) === 0xfab11baf) found.push({address: new Pointer(i)});
      return found;
    }},
    send: message => messages.push(message),
    setImmediate: fn => fn(),
  };
  vm.runInNewContext(source, context);
  assert.equal(messages.length, 1);
  return messages[0];
}

function candidate(offset, version = 29) {
  const bytes = Buffer.alloc(offset + 128);
  bytes.writeUInt32LE(0xfab11baf, offset);
  bytes.writeUInt32LE(version, offset + 4);
  for (let i = 2; i < 16; i++) bytes.writeUInt32LE(i * 16, offset + i * 4);
  return bytes;
}

let result = scan(candidate(64));
assert.equal(result.kind, 'result');
assert.equal(result.candidates, 1);
assert.equal(result.versions[0], 29);
assert.equal(scan(candidate(64, 99)).candidates, 0);
assert.equal(scan(Buffer.alloc(4096)).candidates, 0);
result = scan(candidate(4 * 1024 * 1024 - 2));
assert.equal(result.candidates, 1, 'finds magic crossing a chunk boundary exactly once');
result = scan(Buffer.alloc(4096), {failRead: true});
assert.equal(result.candidates, 0);
assert.equal(result.errors, 1);
assert.equal(Object.hasOwn(result, 'bytes'), false, 'never returns memory bytes');
console.log('WorldBox scanner synthetic tests passed.');
