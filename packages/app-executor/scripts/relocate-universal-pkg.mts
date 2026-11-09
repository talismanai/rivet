type Architecture = 'x64' | 'arm64';

const architectures = new Map<number, Architecture>([
  [0x01000007, 'x64'],
  [0x0100000c, 'arm64'],
]);
const fields = ['PAYLOAD_POSITION', 'PAYLOAD_SIZE', 'PRELUDE_POSITION', 'PRELUDE_SIZE'] as const;
const preludePrefix = '(function(process, require, console, EXECPATH_FD, PAYLOAD_POSITION, PAYLOAD_SIZE)';

/**
 * pkg's Node runtime reads its payload using absolute offsets in the executable.
 * lipo moves each thin executable into a fat slice without relocating those offsets.
 * Locate pkg's fields using the original runtimes, then relocate only the two positions.
 * Re-sign the resulting executable after calling this function.
 */
export function relocateUniversalPkg(binary: Buffer, runtimes: Record<Architecture, Buffer>): void {
  if (binary.length < 8 || binary.readUInt32BE(0) !== 0xcafebabe) {
    throw new Error('Expected a Mach-O universal executable from lipo');
  }
  const count = binary.readUInt32BE(4);
  if (count !== 2 || 8 + count * 20 > binary.length) {
    throw new Error('Expected Intel and Apple Silicon slices in the universal executor');
  }
  const seen = new Set<Architecture>();
  const patches: { offset: number; value: string }[] = [];
  for (let index = 0; index < count; index++) {
    const header = 8 + index * 20;
    const architecture = architectures.get(binary.readUInt32BE(header));
    if (!architecture || seen.has(architecture)) throw new Error('Unexpected universal executor architecture');
    seen.add(architecture);
    const offset = binary.readUInt32BE(header + 8);
    const size = binary.readUInt32BE(header + 12);
    const runtime = runtimes[architecture];
    if (offset < 8 + count * 20 || offset + size > binary.length || size < runtime.length) {
      throw new Error('Invalid universal executor slice bounds');
    }
    const values = {} as Record<(typeof fields)[number], number>;
    const positions = {} as Record<(typeof fields)[number], { offset: number; width: number }>;
    for (const field of fields) {
      const marker = `// ${field} //`;
      const position = runtime.indexOf(marker);
      if (position < 0 || runtime.indexOf(marker, position + 1) !== -1) {
        throw new Error(`Cannot locate pkg ${field} in the ${architecture} runtime`);
      }
      const value = binary.subarray(offset + position, offset + position + marker.length).toString('ascii');
      if (!/^\d+ *$/.test(value)) throw new Error(`Invalid pkg ${field} in the ${architecture} executor`);
      values[field] = Number(value);
      positions[field] = { offset: offset + position, width: marker.length };
    }
    if (
      values.PAYLOAD_POSITION < runtime.length ||
      values.PAYLOAD_SIZE <= 0 ||
      values.PRELUDE_POSITION !== values.PAYLOAD_POSITION + values.PAYLOAD_SIZE ||
      values.PRELUDE_SIZE < preludePrefix.length ||
      values.PRELUDE_POSITION + values.PRELUDE_SIZE > size ||
      binary.toString(
        'ascii',
        offset + values.PRELUDE_POSITION,
        offset + values.PRELUDE_POSITION + preludePrefix.length,
      ) !== preludePrefix
    ) {
      throw new Error(`Invalid pkg payload/prelude layout in the ${architecture} executor`);
    }
    for (const field of ['PAYLOAD_POSITION', 'PRELUDE_POSITION'] as const) {
      const location = positions[field];
      const value = String(values[field] + offset);
      if (value.length > location.width) throw new Error(`Relocated pkg ${field} exceeds its reserved space`);
      patches.push({ offset: location.offset, value: value.padEnd(location.width, ' ') });
    }
  }
  // Validate both slices before changing either one.
  for (const patch of patches) binary.write(patch.value, patch.offset, 'ascii');
}

/** codesign may move pkg's appended payload and the following fat slices when allocating signatures. */
export function repairSignedUniversalPkg(binary: Buffer, runtimes: Record<Architecture, Buffer>): boolean {
  if (binary.length < 48 || binary.readUInt32BE(0) !== 0xcafebabe || binary.readUInt32BE(4) !== 2)
    throw new Error('Expected a Mach-O universal executable after signing');
  const seen = new Set<Architecture>();
  const patches: { offset: number; width: number; value: number }[] = [];
  for (let index = 0; index < 2; index++) {
    const header = 8 + index * 20;
    const architecture = architectures.get(binary.readUInt32BE(header));
    if (!architecture || seen.has(architecture)) throw new Error('Unexpected signed executor architecture');
    seen.add(architecture);
    const offset = binary.readUInt32BE(header + 8);
    const size = binary.readUInt32BE(header + 12);
    if (offset < 48 || offset + size > binary.length) throw new Error('Invalid signed executor slice bounds');
    const positions = fields.map((field) => {
      const marker = `// ${field} //`;
      const position = runtimes[architecture].indexOf(marker);
      if (
        position < 0 ||
        runtimes[architecture].indexOf(marker, position + 1) !== -1 ||
        position + marker.length > size
      )
        throw new Error('Cannot locate signed pkg runtime fields');
      const text = binary.toString('ascii', offset + position, offset + position + marker.length);
      if (!/^\d+ *$/.test(text)) throw new Error('Invalid signed pkg runtime fields');
      return { offset: offset + position, width: marker.length, value: Number(text) };
    });
    const [payload, payloadSize, prelude, preludeSize] = positions;
    const actual = binary.indexOf(preludePrefix, offset);
    if (
      !payload ||
      !payloadSize ||
      !prelude ||
      !preludeSize ||
      payloadSize.value <= 0 ||
      prelude.value !== payload.value + payloadSize.value ||
      preludeSize.value < preludePrefix.length ||
      actual <
        offset + Math.max(...positions.map((field) => field.offset - offset + field.width)) + payloadSize.value ||
      actual + preludeSize.value > offset + size ||
      (binary.indexOf(preludePrefix, actual + preludePrefix.length) >= 0 &&
        binary.indexOf(preludePrefix, actual + preludePrefix.length) < offset + size)
    )
      throw new Error('Invalid signed pkg payload/prelude layout');
    if (prelude.value !== actual) {
      patches.push({ ...payload, value: actual - payloadSize.value }, { ...prelude, value: actual });
    }
  }
  for (const patch of patches) {
    if (String(patch.value).length > patch.width) throw new Error('Signed pkg position exceeds its reserved space');
  }
  for (const patch of patches) binary.write(String(patch.value).padEnd(patch.width, ' '), patch.offset, 'ascii');
  return patches.length > 0;
}
