import { strict as assert } from 'node:assert';
import { it } from 'node:test';
import { createStore } from 'jotai/vanilla';
import { atomWithStorage } from 'jotai/utils';
import type { RemoteDebuggerState } from '../src/state/execution';
import { createRemoteDebuggerStorage } from '../src/utils/remoteDebuggerStorage';

const connected: RemoteDebuggerState = {
  socket: {} as WebSocket, // What JSON restores from the previously persisted live WebSocket.
  started: true,
  reconnecting: true,
  url: 'ws://localhost:21889/internal',
  remoteUploadAllowed: true,
  isInternalExecutor: true,
};

it('restores legacy saved debugger state without treating its JSON socket as a live connection', () => {
  const storage = createRemoteDebuggerStorage({
    getItem: () => JSON.parse(JSON.stringify(connected)),
    setItem: () => {},
    removeItem: () => {},
  });
  assert.deepEqual(storage.getItem('debugger', connected), {
    socket: null,
    started: false,
    reconnecting: false,
    url: connected.url,
    remoteUploadAllowed: false,
    isInternalExecutor: false,
  });
});

it('persists the debugger URL without serializing the live socket or changing the current connection', () => {
  const socket = { addEventListener() {}, removeEventListener() {}, send() {} } as unknown as WebSocket;
  const live = { ...connected, socket };
  let saved: RemoteDebuggerState | undefined;
  const storage = createRemoteDebuggerStorage({
    getItem: (_key, initial) => saved ?? initial,
    setItem: (_key, value) => {
      saved = value;
    },
    removeItem: () => {
      saved = undefined;
    },
  });
  storage.setItem('debugger', live);
  assert.equal(saved?.socket, null);
  assert.equal(saved?.url, live.url);
  assert.equal(saved?.started, false);
  assert.equal(saved?.remoteUploadAllowed, false);
  assert.equal(live.socket, socket);
  assert.equal(live.started, true);
  assert.equal(live.remoteUploadAllowed, true);
  storage.removeItem('debugger');
  assert.equal(saved, undefined);
});

it('keeps a live connection in Jotai while a new app store restores only its preferences', () => {
  let saved = JSON.parse(JSON.stringify(connected)) as RemoteDebuggerState;
  const storage = createRemoteDebuggerStorage({
    getItem: () => saved,
    setItem: (_key, value) => {
      saved = JSON.parse(JSON.stringify(value));
    },
    removeItem: () => {},
  });
  const state = atomWithStorage('debugger', { ...connected, socket: null }, storage);
  const first = createStore();
  const unsubscribe = first.sub(state, () => {});
  assert.equal(first.get(state).socket, null);
  const socket = { addEventListener() {} } as unknown as WebSocket;
  first.set(state, { ...connected, socket });
  assert.equal(first.get(state).socket, socket);
  assert.equal(first.get(state).started, true);
  assert.equal(saved.socket, null);

  const second = createStore();
  const unsubscribeSecond = second.sub(state, () => {});
  assert.equal(second.get(state).socket, null);
  assert.equal(second.get(state).started, false);
  assert.equal(second.get(state).url, connected.url);
  unsubscribe();
  unsubscribeSecond();
});
