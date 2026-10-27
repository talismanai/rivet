import { it, mock } from 'node:test';
import { strict as assert } from 'node:assert';
import { EventEmitter } from 'node:events';
import type { Command } from '@tauri-apps/api/shell';
import { runOAuthSidecar } from '../src/utils/oauthSidecar';

const request = {
  requestUrl: 'https://api.example.com/private',
  authenticationUrl: 'https://auth.example.com/login',
  callbackUrl: 'https://api.example.com/callback',
  status: 401,
};
function setup() {
  const events = new EventEmitter();
  const stdout = new EventEmitter();
  const child = { pid: 1, write: mock.fn(async (_data: string) => {}), kill: mock.fn(async () => {}) };
  const command = Object.assign(events, { stdout, spawn: async () => child });
  const controller = new AbortController();
  const pending = runOAuthSidecar(
    request,
    controller.signal,
    command as unknown as Pick<Command, 'stdout' | 'on' | 'spawn'>,
  );
  return { events, stdout, child, controller, pending };
}

it('returns the private helper JWT and passes configuration over stdin', async () => {
  const { stdout, child, pending } = setup();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(JSON.parse(child.write.mock.calls[0]!.arguments[0]), request);
  const result = { accessToken: 'fixture.jwt.token', expiresIn: 3600 };
  stdout.emit('data', JSON.stringify({ result }));
  assert.deepEqual(await pending, result);
});

it('cancels the helper gracefully and ignores late token output', async () => {
  const { stdout, events, child, controller, pending } = setup();
  await new Promise((resolve) => setImmediate(resolve));
  const rejected = assert.rejects(pending, /aborted/);
  controller.abort();
  await rejected;
  assert.deepEqual(JSON.parse(child.write.mock.calls[1]!.arguments[0]), { cancel: true });
  stdout.emit('data', JSON.stringify({ result: { accessToken: 'late.jwt.token' } }));
  events.emit('close', { code: 0 });
  assert.equal(child.kill.mock.callCount(), 0);
});

it('preserves the original response when the browser is closed without authentication', async () => {
  const { stdout, events, pending } = setup();
  stdout.emit('data', '{"result":false}');
  assert.equal(await pending, false);
  events.emit('close', { code: 0 });
});

it('rejects invalid helper output without including credentials in the error', async () => {
  for (const output of ['secret not json', '{"result":{"accessToken":"secret\\r\\nHeader: injected"}}']) {
    const { stdout, events, pending } = setup();
    stdout.emit('data', output);
    await assert.rejects(pending, (error: Error) => !error.message.includes('secret'));
    events.emit('close', { code: 0 });
  }
});

it('reports a callback error without cancelling the browser left open for inspection', async () => {
  const { stdout, events, child, pending } = setup();
  await new Promise((resolve) => setImmediate(resolve));
  stdout.emit('data', JSON.stringify({ error: 'Callback did not return JSON. Chrome left open.', browserOpen: true }));
  await assert.rejects(pending, /Chrome left open/);
  assert.equal(child.write.mock.callCount(), 1);
  assert.equal(child.kill.mock.callCount(), 0);
  events.emit('close', { code: 0 });
});
