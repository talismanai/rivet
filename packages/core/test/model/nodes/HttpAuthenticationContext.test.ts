import { strict as assert } from 'node:assert';
import { it, mock } from 'node:test';
import { fetchWithHttpAuthentication } from '../../../src/utils/httpAuthentication.js';
import type { DataValue } from '../../../src/model/DataValue.js';

function fixture() {
  const contextValues: Record<string, DataValue> = { other: { type: 'string', value: 'keep' } };
  const onHttpAuthenticationToken = mock.fn((_key: string, _token: { accessToken: string }) => {});
  let token = 'first.jwt.token';
  const ctx = {
    executor: 'nodejs' as const,
    signal: new AbortController().signal,
    httpAuthenticationCache: new Map<string, unknown>(),
    contextValues,
    onHttpAuthenticationToken,
    requestHttpAuthentication: mock.fn(async () => ({ accessToken: token, expiresIn: 3600 })),
    httpRequest: mock.fn(async (_url: string, init: RequestInit) =>
      new Headers(init.headers).get('authorization') === `Bearer ${token}`
        ? Response.json({ ok: true })
        : new Response('', { status: 403 }),
    ),
  };
  const run = (key?: string) =>
    fetchWithHttpAuthentication('https://api.example.com/private', {}, ctx, {
      loginUrl: 'https://login.example.com',
      tokenContextKey: key,
    });
  return {
    ctx,
    run,
    changeToken: () => {
      token = 'new.jwt.token';
    },
  };
}

void it('copies the Bearer JWT before retrying and republishes it on cache reuse under a newly configured key', async () => {
  const { ctx, run } = fixture();
  await run(' jwt ');
  assert.deepEqual(ctx.contextValues.jwt, { type: 'string', value: 'Bearer first.jwt.token' });
  assert.equal(ctx.contextValues.other!.value, 'keep');
  assert.equal(ctx.onHttpAuthenticationToken.mock.calls[0]!.arguments[0], 'jwt');
  await run('newKey');
  assert.equal(ctx.contextValues.newKey!.value, 'Bearer first.jwt.token');
  assert.equal(ctx.requestHttpAuthentication.mock.callCount(), 1);
  assert.equal(ctx.onHttpAuthenticationToken.mock.callCount(), 2);
});

void it('replaces the mirrored token when a cached JWT is rejected and a new login succeeds', async () => {
  const { ctx, run, changeToken } = fixture();
  await run('jwt');
  changeToken();
  await run('jwt');
  assert.equal(ctx.contextValues.jwt!.value, 'Bearer new.jwt.token');
  assert.equal(ctx.requestHttpAuthentication.mock.callCount(), 2);
  assert.equal(ctx.onHttpAuthenticationToken.mock.calls.at(-1)!.arguments[1].accessToken, 'new.jwt.token');
});

void it('leaves context unchanged when the key is blank or authentication is cancelled', async () => {
  const { ctx, run } = fixture();
  await run('  ');
  assert.deepEqual(Object.keys(ctx.contextValues), ['other']);
  assert.equal(ctx.onHttpAuthenticationToken.mock.callCount(), 0);
  ctx.httpAuthenticationCache.clear();
  await fetchWithHttpAuthentication(
    'https://api.example.com/private',
    {},
    {
      ...ctx,
      requestHttpAuthentication: async () => false,
    },
    { loginUrl: 'https://login.example.com', tokenContextKey: 'jwt' },
  );
  assert.deepEqual(Object.keys(ctx.contextValues), ['other']);
  assert.equal(ctx.onHttpAuthenticationToken.mock.callCount(), 0);
});

void it('supports context names like __proto__ without modifying the context prototype', async () => {
  const { ctx, run } = fixture();
  const prototype = Object.getPrototypeOf(ctx.contextValues);
  await run('__proto__');
  assert.equal(Object.getPrototypeOf(ctx.contextValues), prototype);
  assert.equal(Object.getOwnPropertyDescriptor(ctx.contextValues, '__proto__')!.value.value, 'Bearer first.jwt.token');
});
