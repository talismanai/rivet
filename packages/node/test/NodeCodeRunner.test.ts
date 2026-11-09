import { strict as assert } from 'node:assert';
import { it } from 'node:test';
import { NodeCodeRunner } from '../src/native/NodeCodeRunner.js';

void it('provides a working require function to Code nodes in ESM', async () => {
  const result = await new NodeCodeRunner().runCode(
    'return { value: { type: "string", value: require("node:path").basename("/example/file.txt") } };',
    {},
    { includeRequire: true, includeFetch: false, includeRivet: false, includeProcess: false, includeConsole: false },
  );
  assert.equal(result.value?.value, 'file.txt');
});
