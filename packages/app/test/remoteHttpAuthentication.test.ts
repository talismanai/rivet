import { describe, it, mock } from 'node:test';
import { strict as assert } from 'node:assert';
import { RemoteHttpAuthentication } from '../src/utils/remoteHttpAuthentication';
import type { HttpAuthenticationRequest } from '@ironclad/rivet-core';

const request: HttpAuthenticationRequest = {
  requestUrl: 'https://api.example.com/private',
  authenticationUrl: 'https://login.example.com/oauth2/authorize',
  status: 302,
};

function setup() {
  const respond = mock.fn((_requestId: string, _result: import('@ironclad/rivet-core').HttpAuthenticationResult) => {});
  const onError = mock.fn((_error: unknown) => {});
  const windows: { signal: AbortSignal; close: () => void }[] = [];
  const owner = new RemoteHttpAuthentication(
    (_request, signal) =>
      new Promise<import('@ironclad/rivet-core').HttpAuthenticationResult>((resolve, reject) => {
        const abort = () => reject(new Error('Authentication cancelled'));
        signal.addEventListener('abort', abort, { once: true });
        windows.push({
          signal,
          close: () => {
            signal.removeEventListener('abort', abort);
            resolve({ accessToken: 'test.jwt.token', expiresIn: 3600 });
          },
        });
      }),
    respond,
    onError,
  );
  return { owner, respond, onError, windows };
}

describe('Debugger connection authentication ownership', () => {
  it('acknowledges a locally cancelled window so the server can release the pending graph', async () => {
    const { owner, respond, onError, windows } = setup();
    const pending = owner.start('request', request);
    owner.cancel('request');
    await pending;
    assert.equal(windows[0]!.signal.aborted, true);
    assert.equal(respond.mock.callCount(), 1);
    assert.equal(respond.mock.calls[0]!.arguments[0], 'request');
    assert.equal(onError.mock.callCount(), 0);
  });

  it('does not cancel windows owned by another connection', async () => {
    const first = setup();
    const second = setup();
    const firstPending = first.owner.start('first', request);
    const secondPending = second.owner.start('second', request);
    first.owner.dispose();
    await firstPending;
    assert.equal(second.windows[0]!.signal.aborted, false);
    assert.equal(second.respond.mock.callCount(), 0);
    second.windows[0]!.close();
    await secondPending;
    assert.equal(second.respond.mock.callCount(), 1);
  });

  it('acknowledges each pending window when the owning connection is disposed', async () => {
    const { owner, respond, windows } = setup();
    const pending = [owner.start('first', request), owner.start('second', request)];
    owner.dispose();
    await Promise.all(pending);
    assert.ok(windows.every(({ signal }) => signal.aborted));
    assert.equal(respond.mock.callCount(), 2);
  });

  it('acknowledges successful completion and window errors', async () => {
    const { owner, respond, windows } = setup();
    const pending = owner.start('request', request);
    windows[0]!.close();
    await pending;
    assert.equal(respond.mock.callCount(), 1);
    assert.deepEqual(respond.mock.calls[0]!.arguments[1], { accessToken: 'test.jwt.token', expiresIn: 3600 });

    const onError = mock.fn();
    const failed = new RemoteHttpAuthentication(
      async () => {
        throw new Error('Window failed');
      },
      respond,
      onError,
    );
    await failed.start('failed', request);
    assert.equal(respond.mock.callCount(), 2);
    assert.equal(onError.mock.callCount(), 1);
  });

  it('ignores duplicate in-flight messages and late cancellation', async () => {
    const { owner, respond, windows } = setup();
    const pending = owner.start('request', request);
    await owner.start('request', request);
    assert.equal(windows.length, 1);
    windows[0]!.close();
    await pending;
    owner.cancel('request');
    assert.equal(respond.mock.callCount(), 1);
  });
});
