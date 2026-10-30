import { strict as assert } from 'node:assert';
import { it, mock } from 'node:test';
import {
  fetchWithHttpAuthentication,
  getHttpAuthenticationCacheKey,
  signInWithHttpAuthentication,
} from '../../../src/utils/httpAuthentication.js';
import type { DataValue } from '../../../src/model/DataValue.js';
import type { HttpAuthenticationRequest } from '../../../src/model/ProcessContext.js';

const url = 'https://api.example.com';
const init = { headers: { authorization: 'configured-api-key' } };
const options = {
  loginUrl: 'https://login.example.com/login',
  tokenSource: 'authorization-header' as const,
  tokenContextKey: 'jwt',
  preferCachedToken: true,
};
function fixture() {
  const contextValues: Record<string, DataValue> = {};
  const ctx = {
    signal: new AbortController().signal,
    executor: 'nodejs' as const,
    httpAuthenticationCache: new Map<string, unknown>(),
    contextValues,
    requestHttpAuthentication: mock.fn(async () => ({ accessToken: 'first.jwt.token', expiresIn: 3600 })),
    onHttpAuthenticationToken: mock.fn((_key: string, _token: { accessToken: string }) => {}),
    httpRequest: mock.fn(async (_url: string, request: RequestInit) => {
      assert.equal(new Headers(request.headers).get('authorization'), 'Bearer first.jwt.token');
      return Response.json({ ok: true });
    }),
  };
  return ctx;
}

void it('manual sign-in copies context and prepares the exact node cache without making an API request', async () => {
  const ctx = fixture();
  await signInWithHttpAuthentication(url, init, ctx, options);
  assert.equal(ctx.httpRequest.mock.callCount(), 0);
  assert.deepEqual(ctx.contextValues.jwt, { type: 'string', value: 'Bearer first.jwt.token' });
  assert.equal(ctx.onHttpAuthenticationToken.mock.callCount(), 1);
  const key = getHttpAuthenticationCacheKey(url, init, options);
  const session = ctx.httpAuthenticationCache.get(key);
  await fetchWithHttpAuthentication(`${url}/private`, init, ctx, options);
  assert.equal(ctx.requestHttpAuthentication.mock.callCount(), 1);
  assert.equal(ctx.httpRequest.mock.callCount(), 1);
  assert.equal(ctx.httpAuthenticationCache.get(key), session);
});

void it('manual and node-triggered login need only the login URL, independently of the API origin', async () => {
  const ctx = fixture();
  const requests: HttpAuthenticationRequest[] = [];
  const authenticate = async (request: (typeof requests)[number]) => {
    requests.push(request);
    return { accessToken: 'first.jwt.token' };
  };
  // Ignore obsolete fields retained in an older settings/project file.
  const configured = { ...options, tokenCaptureUrl: 'https://obsolete.example' };
  await signInWithHttpAuthentication(url, init, { ...ctx, requestHttpAuthentication: authenticate }, configured);
  await fetchWithHttpAuthentication(
    url,
    init,
    { ...ctx, httpAuthenticationCache: new Map(), requestHttpAuthentication: authenticate },
    { ...configured, authenticateBeforeRequest: true },
  );
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(new URL(request.requestUrl).origin, url);
    assert.equal(request.authenticationUrl, options.loginUrl);
    assert.equal('tokenCaptureUrl' in request, false);
  }
  assert.equal(getHttpAuthenticationCacheKey(url, init, configured), getHttpAuthenticationCacheKey(url, init, options));
});

void it('manual sign-in forces a fresh login even when a reusable session exists', async () => {
  const ctx = fixture();
  await signInWithHttpAuthentication(url, init, ctx, options);
  const login = mock.fn(async () => ({ accessToken: 'second.jwt.token', expiresIn: 3600 }));
  await signInWithHttpAuthentication(url, init, { ...ctx, requestHttpAuthentication: login }, options);
  assert.equal(login.mock.callCount(), 1);
  assert.equal(ctx.contextValues.jwt!.value, 'Bearer second.jwt.token');
  assert.equal(ctx.httpRequest.mock.callCount(), 0);
});

void it('cancelling or failing manual login preserves the previous session and context', async () => {
  const ctx = fixture();
  await signInWithHttpAuthentication(url, init, ctx, options);
  const key = getHttpAuthenticationCacheKey(url, init, options);
  const session = ctx.httpAuthenticationCache.get(key);
  assert.equal(
    await signInWithHttpAuthentication(url, init, { ...ctx, requestHttpAuthentication: async () => false }, options),
    false,
  );
  await assert.rejects(
    signInWithHttpAuthentication(
      url,
      init,
      {
        ...ctx,
        requestHttpAuthentication: async () => {
          throw new Error('Login failed');
        },
      },
      options,
    ),
    /Login failed/,
  );
  assert.equal(ctx.httpAuthenticationCache.get(key), session);
  assert.equal(ctx.contextValues.jwt!.value, 'Bearer first.jwt.token');
});

void it('aborting manual login cancels the helper and does not cache a late token', async () => {
  const ctx = fixture();
  const controller = new AbortController();
  let helperSignal: AbortSignal | undefined;
  const pending = signInWithHttpAuthentication(
    url,
    init,
    {
      ...ctx,
      signal: controller.signal,
      requestHttpAuthentication: async (_request, signal) => {
        helperSignal = signal;
        return new Promise(() => {});
      },
    },
    options,
  );
  await Promise.resolve();
  controller.abort();
  await assert.rejects(pending, /abort/i);
  assert.equal(helperSignal!.aborted, true);
  assert.equal(ctx.httpAuthenticationCache.size, 0);
  assert.deepEqual(ctx.contextValues, {});
});

void it('validates required URLs and host support before starting manual login', async () => {
  const ctx = fixture();
  await assert.rejects(signInWithHttpAuthentication(url, init, ctx, {}), /valid API URL and OAuth login URL/);
  await assert.rejects(signInWithHttpAuthentication('file:///private', init, ctx, options), /valid API URL/);
  await assert.rejects(
    signInWithHttpAuthentication(url, init, { ...ctx, requestHttpAuthentication: undefined }, options),
    /interactive host/,
  );
  assert.equal(ctx.requestHttpAuthentication.mock.callCount(), 0);
});
