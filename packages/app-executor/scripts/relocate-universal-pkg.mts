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
