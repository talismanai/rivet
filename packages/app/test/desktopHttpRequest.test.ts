import { describe, it, mock } from 'node:test';
import { strict as assert } from 'node:assert';
import { type Client, type ClientOptions, type HttpOptions, ResponseType } from '@tauri-apps/api/http';
import { createDesktopHttpRequest } from '../src/utils/desktopHttpRequest';

function setup(status = 302, headers = { location: 'https://login.example.com/oauth2/authorize' }, data = [1, 2, 3]) {
  const send = mock.fn(async (_options: HttpOptions) => ({
    status,
    headers,
    data,
    url: 'https://api.example.com/private',
  }));
  const drop = mock.fn(async () => {});
  const createClient = mock.fn(
    async (_options: ClientOptions) => ({ request: send, drop }) as unknown as Pick<Client, 'request' | 'drop'>,
  );
  return { request: createDesktopHttpRequest(createClient), createClient, send, drop };
}

describe('Desktop HTTP redirect transport', () => {
  it('disables native redirects and exposes status, Location, URL and binary body', async () => {
    const { request, createClient, send, drop } = setup();
    const response = await request('https://api.example.com/private', {});
    assert.deepEqual(createClient.mock.calls[0]!.arguments[0], { maxRedirections: 0 });
    assert.equal(send.mock.calls[0]!.arguments[0].responseType, ResponseType.Binary);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), 'https://login.example.com/oauth2/authorize');
    assert.equal(response.url, 'https://api.example.com/private');
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new Uint8Array([1, 2, 3]));
    assert.equal(drop.mock.callCount(), 1);
  });

  it('preserves the HTTP method, headers and exact request body', async () => {
    const { request, send } = setup(200);
    await request('https://api.example.com/private', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token' },
      body: '{"test":true}',
    });
    const options = send.mock.calls[0]!.arguments[0];
    assert.equal(options.method, 'POST');
    assert.equal(options.headers!.authorization, 'Bearer token');
    assert.equal(options.headers!['content-type'], 'application/json');
    assert.deepEqual(options.body!.payload, Array.from(new TextEncoder().encode('{"test":true}')));
  });

  it('preserves responses that cannot have a body', async () => {
    for (const status of [204, 205, 304]) {
      const { request } = setup(status);
      const response = await request('https://api.example.com/private', {});
      assert.equal(response.status, status);
      assert.equal(response.body, null);
    }
    const { request } = setup(200);
    assert.equal((await request('https://api.example.com/private', { method: 'HEAD' })).body, null);
  });

  it('does not send an already aborted request', async () => {
    const { request, createClient } = setup();
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(request('https://api.example.com/private', { signal: controller.signal }), /abort/i);
    assert.equal(createClient.mock.callCount(), 0);
  });

  it('releases the caller and native client when aborted during a pending HTTP request', async () => {
    const controller = new AbortController();
    const drop = mock.fn(async () => {});
    let started!: () => void;
    const sent = new Promise<void>((resolve) => {
      started = resolve;
    });
    const client = {
      request: () => {
        started();
        return new Promise(() => {});
      },
      drop,
    } as unknown as Pick<Client, 'request' | 'drop'>;
    const request = createDesktopHttpRequest(async () => client);
    const pending = request('https://api.example.com/private', { signal: controller.signal });
    await sent;
    controller.abort();
    await assert.rejects(pending, /abort/i);
    assert.equal(drop.mock.callCount(), 1);
  });
});
