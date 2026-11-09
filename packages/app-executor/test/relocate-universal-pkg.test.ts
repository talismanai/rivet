import { it } from 'node:test';
import { strict as assert } from 'node:assert';
import { relocateUniversalPkg, repairSignedUniversalPkg } from '../scripts/relocate-universal-pkg.mjs';

const prefix = '(function(process, require, console, EXECPATH_FD, PAYLOAD_POSITION, PAYLOAD_SIZE)';
const payload = Buffer.from('embedded JavaScript');
const prelude = Buffer.from(`${prefix} { return 'bootstrap'; })`);
const fields = ['PAYLOAD_POSITION', 'PAYLOAD_SIZE', 'PRELUDE_POSITION', 'PRELUDE_SIZE'] as const;

function fixture() {
  const runtime = Buffer.alloc(512);
  const values = [runtime.length, payload.length, runtime.length + payload.length, prelude.length];
  const thin = Buffer.alloc(runtime.length + payload.length + prelude.length);
  fields.forEach((field, index) => {
    const marker = `// ${field} //`;
    runtime.write(marker, 64 + index * 32, 'ascii');
    thin.write(String(values[index]).padEnd(marker.length, ' '), 64 + index * 32, 'ascii');
  });
  thin.set(payload, runtime.length);
  thin.set(prelude, runtime.length + payload.length);
  const offsets = [1024, 2048];
  const binary = Buffer.alloc(3072);
  binary.writeUInt32BE(0xcafebabe, 0);
  binary.writeUInt32BE(2, 4);
  [0x01000007, 0x0100000c].forEach((cpu, index) => {
    const header = 8 + index * 20;
    binary.writeUInt32BE(cpu, header);
    binary.writeUInt32BE(offsets[index]!, header + 8);
    binary.writeUInt32BE(thin.length, header + 12);
    binary.set(thin, offsets[index]);
  });
  return { binary, runtimes: { x64: runtime, arm64: runtime }, offsets, values };
}

void it('relocates both architectures so absolute reads retrieve the original payload and bootstrap', () => {
  const { binary, runtimes, offsets } = fixture();
  relocateUniversalPkg(binary, runtimes);
  for (const offset of offsets) {
    const values = fields.map((field, index) =>
      Number(binary.toString('ascii', offset + 64 + index * 32, offset + 64 + index * 32 + `// ${field} //`.length)),
    );
    assert.deepEqual(binary.subarray(values[0], values[0]! + values[1]!), payload);
    assert.deepEqual(binary.subarray(values[2], values[2]! + values[3]!), prelude);
    assert.equal(values[1], payload.length);
    assert.equal(values[3], prelude.length);
  }
});

void it('rejects thin binaries, truncated headers, and missing or duplicated architectures', () => {
  for (const invalid of [Buffer.alloc(4), Buffer.alloc(12)]) {
    assert.throws(() => relocateUniversalPkg(invalid, fixture().runtimes), /universal/);
  }
  const { binary, runtimes } = fixture();
  binary.writeUInt32BE(0x01000007, 28);
  assert.throws(() => relocateUniversalPkg(binary, runtimes), /architecture/);
});

void it('rejects slices outside the file', () => {
  const { binary, runtimes } = fixture();
  binary.writeUInt32BE(binary.length, 16);
  assert.throws(() => relocateUniversalPkg(binary, runtimes), /bounds/);
});

void it('fails closed if pkg changes its runtime fields', () => {
  const { binary, runtimes } = fixture();
  const runtime = Buffer.from(new Uint8Array(runtimes.arm64));
  runtime.fill(0, 64, 90);
  assert.throws(() => relocateUniversalPkg(binary, { ...runtimes, arm64: runtime }), /Cannot locate pkg/);
});

void it('validates every slice before making changes', () => {
  const { binary, runtimes, offsets } = fixture();
  binary.write('broken', offsets[1]! + 128, 'ascii');
  const original = Buffer.from(new Uint8Array(binary));
  assert.throws(() => relocateUniversalPkg(binary, runtimes), /Invalid pkg/);
  assert.deepEqual(binary, original);
});

void it('rejects corrupted or already relocated bootstrap offsets', () => {
  const { binary, runtimes, offsets, values } = fixture();
  binary.write('broken', offsets[1]! + values[2]!, 'ascii');
  assert.throws(() => relocateUniversalPkg(binary, runtimes), /layout/);
  const valid = fixture();
  relocateUniversalPkg(valid.binary, valid.runtimes);
  assert.throws(() => relocateUniversalPkg(valid.binary, valid.runtimes), /layout/);
});

void it('repairs payload movement during signing, including relocation of the next architecture', () => {
  const { binary, runtimes, offsets, values } = fixture();
  relocateUniversalPkg(binary, runtimes);
  for (let index = 0; index < 2; index++) {
    const start = offsets[index]! + values[0]!;
    const block = Buffer.from(new Uint8Array(binary.subarray(start, start + payload.length + prelude.length)));
    const movement = 32 * (index + 1);
    binary.fill(0, start, start + block.length + movement);
    binary.set(block, start + movement);
    binary.writeUInt32BE(values[0]! + block.length + movement, 8 + index * 20 + 12);
  }
  const old = offsets[1]!;
  const size = binary.readUInt32BE(40);
  const slice = Buffer.from(new Uint8Array(binary.subarray(old, old + size)));
  binary.fill(0, old, old + size);
  offsets[1] = old + 128;
  binary.writeUInt32BE(offsets[1], 36);
  binary.set(slice, offsets[1]);
  assert.equal(repairSignedUniversalPkg(binary, runtimes), true);
  for (const offset of offsets) {
    const position = Number(binary.toString('ascii', offset + 64, offset + 64 + '// PAYLOAD_POSITION //'.length));
    assert.deepEqual(binary.subarray(position, position + payload.length), payload);
    assert.deepEqual(binary.subarray(position + payload.length, position + payload.length + prelude.length), prelude);
  }
  assert.equal(repairSignedUniversalPkg(binary, runtimes), false);
});

void it('refuses to repair malformed signed payloads before modifying either architecture', () => {
  const { binary, runtimes, offsets, values } = fixture();
  relocateUniversalPkg(binary, runtimes);
  binary.write('broken', offsets[1]! + values[2]!, 'ascii');
  const original = Buffer.from(new Uint8Array(binary));
  assert.throws(() => repairSignedUniversalPkg(binary, runtimes), /layout/);
  assert.deepEqual(binary, original);
});
