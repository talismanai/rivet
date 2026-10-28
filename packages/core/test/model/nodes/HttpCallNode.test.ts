import { describe, it, mock, afterEach } from 'node:test';
import { strict as assert } from 'node:assert';
import { HttpCallNodeImpl, type InternalProcessContext, type HttpAuthenticationRequest } from '../../../src/index.js';
import {
  fetchWithHttpAuthentication as performAuthenticatedRequest,
  isOAuthAuthorizationUrl,
  getAuthenticationUrl,
} from '../../../src/utils/httpAuthentication.js';

/* eslint-disable @typescript-eslint/no-floating-promises */

const endpoint = 'https://api.example.com/private';
const authorizationUrl =
  'https://login.example.com/oauth2/authorize?client_id=rivet&response_type=code&redirect_uri=https%3A%2F%2Fapi.example.com%2Fcallback';
const callbackUrl = 'https://api.example.com/callback';
function fetchWithHttpAuthentication(
  url: string,
  init: RequestInit,
  ctx: Parameters<typeof performAuthenticatedRequest>[2],
  options: Parameters<typeof performAuthenticatedRequest>[3] = {},
) {
  return performAuthenticatedRequest(url, init, ctx, { loginUrl: authorizationUrl, ...options });
}
const context = (overrides: Partial<InternalProcessContext> = {}) =>
  ({
    executor: 'nodejs',
    signal: new AbortController().signal,
    ...overrides,
  }) as InternalProcessContext;

function mockResponses(...responses: Response[]) {
  return mock.method(globalThis, 'fetch', async (_input: string | URL | Request, _init?: RequestInit) => {
    assert.ok(responses.length > 0, 'Unexpected extra HTTP request');
    return responses.shift()!;
  });
}

function mockAuthentication(retry: boolean) {
  return mock.fn(async (_request: HttpAuthenticationRequest, _signal: AbortSignal) =>
    retry ? { accessToken: 'test.jwt.token', expiresIn: 3600 } : false,
  );
}

afterEach(() => mock.restoreAll());

describe('HTTP Call authentication', () => {
  it('keeps the existing fetch behavior when no interactive host is available', async () => {
    const response = new Response('Unauthorized', { status: 401 });
    const fetch = mockResponses(response);
    const ctx = context();
    assert.equal(await fetchWithHttpAuthentication(endpoint, {}, ctx), response);
    assert.deepEqual(fetch.mock.calls[0]!.arguments, [endpoint, { signal: ctx.signal }]);
  });

  it('does not send a non-interactive request after execution was aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const fetch = mockResponses();
    await assert.rejects(fetchWithHttpAuthentication(endpoint, {}, context({ signal: controller.signal })), /abort/i);
    assert.equal(fetch.mock.callCount(), 0);
  });

  it('opens a 401 sign-in page and preserves the response when the host declines retry', async () => {
    const response = new Response('Unauthorized', { status: 401 });
    const fetch = mockResponses(response);
    const authenticate = mockAuthentication(false);
    assert.equal(
      await fetchWithHttpAuthentication(endpoint, {}, context({ requestHttpAuthentication: authenticate })),
      response,
    );
    assert.deepEqual(authenticate.mock.calls[0]!.arguments[0], {
      requestUrl: endpoint,
      authenticationUrl: authorizationUrl,
      status: 401,
      callbackUrl,
    });
    assert.equal(fetch.mock.callCount(), 1);
  });

  it('uses a relative sign-in Location on a 401', async () => {
    mockResponses(new Response('', { status: 401, headers: { location: '/login' } }));
    const authenticate = mockAuthentication(false);
    await fetchWithHttpAuthentication(endpoint, {}, context({ requestHttpAuthentication: authenticate }), {
      loginUrl: undefined,
    });
    assert.equal(authenticate.mock.calls[0]!.arguments[0].authenticationUrl, 'https://api.example.com/login');
  });

  it('stops at a 302 OAuth page before following it in Node', async () => {
    const response = new Response('', { status: 302, headers: { location: authorizationUrl } });
    const fetch = mockResponses(response);
    const authenticate = mockAuthentication(false);
    await fetchWithHttpAuthentication(endpoint, {}, context({ requestHttpAuthentication: authenticate }));
    assert.equal(authenticate.mock.calls[0]!.arguments[0].authenticationUrl, authorizationUrl);
    assert.equal(fetch.mock.callCount(), 1);
    assert.equal((fetch.mock.calls[0]!.arguments[1] as RequestInit).redirect, 'manual');
  });

  it('follows ordinary redirects and detects authentication later in the chain', async () => {
    const fetch = mockResponses(
      new Response('', { status: 302, headers: { location: '/next' } }),
      new Response('', { status: 302, headers: { location: authorizationUrl } }),
    );
    const authenticate = mockAuthentication(false);
    await fetchWithHttpAuthentication(endpoint, {}, context({ requestHttpAuthentication: authenticate }));
    assert.equal(fetch.mock.calls[1]!.arguments[0], 'https://api.example.com/next');
    assert.equal(authenticate.mock.callCount(), 1);
  });

  it('drops sensitive headers on cross-origin redirects and changes POST to GET on 302', async () => {
    const fetch = mockResponses(
      new Response('', { status: 302, headers: { location: 'https://other.example.com/result' } }),
      new Response('ok'),
    );
    await fetchWithHttpAuthentication(
      endpoint,
      {
        method: 'POST',
        body: 'payload',
        headers: {
          authorization: 'Bearer secret',
          cookie: 'session=secret',
          'content-type': 'text/plain',
          'x-request-id': 'id',
        },
      },
      context({ requestHttpAuthentication: async () => false }),
    );
    const init = fetch.mock.calls[1]!.arguments[1] as RequestInit;
    assert.equal(init.method, 'GET');
    assert.equal(init.body, undefined);
    assert.deepEqual(Object.fromEntries(new Headers(init.headers)), { 'x-request-id': 'id' });
  });

  it('preserves method and body on a 307 redirect', async () => {
    const fetch = mockResponses(new Response('', { status: 307, headers: { location: '/next' } }), new Response('ok'));
    await fetchWithHttpAuthentication(
      endpoint,
      { method: 'POST', body: 'payload' },
      context({ requestHttpAuthentication: async () => false }),
    );
    const init = fetch.mock.calls[1]!.arguments[1] as RequestInit;
    assert.equal(init.method, 'POST');
    assert.equal(init.body, 'payload');
  });

  it('limits redirect loops', async () => {
    const fetch = mock.method(
      globalThis,
      'fetch',
      async () => new Response('', { status: 302, headers: { location: '/loop' } }),
    );
    await assert.rejects(
      fetchWithHttpAuthentication(endpoint, {}, context({ requestHttpAuthentication: async () => false })),
      /redirect limit/,
    );
    assert.equal(fetch.mock.callCount(), 21);
  });

  it('retries browser requests once with a Bearer token and keeps JSON node outputs', async () => {
    const fetch = mockResponses(new Response('', { status: 401 }), Response.json({ authenticated: true }));
    const authenticate = mockAuthentication(true);
    const node = HttpCallNodeImpl.create();
    node.data.url = endpoint;
    node.data.authenticationUrl = authorizationUrl;
    const outputs = await new HttpCallNodeImpl(node).process(
      {},
      context({ executor: 'browser', requestHttpAuthentication: authenticate }),
    );
    assert.deepEqual(outputs['json']!.value, { authenticated: true });
    assert.equal(outputs['statusCode']!.value, 200);
    assert.equal(
      new Headers((fetch.mock.calls[1]!.arguments[1] as RequestInit).headers).get('authorization'),
      'Bearer test.jwt.token',
    );
    assert.equal(authenticate.mock.callCount(), 1);
  });

  it('does not repeat the dialog if the retried request is still unauthorized', async () => {
    const fetch = mockResponses(new Response('', { status: 401 }), new Response('still unauthorized', { status: 401 }));
    const authenticate = mockAuthentication(true);
    const response = await fetchWithHttpAuthentication(
      endpoint,
      {},
      context({ executor: 'browser', requestHttpAuthentication: authenticate }),
    );
    assert.equal(response.status, 401);
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(fetch.mock.callCount(), 2);
  });

  it('recognizes a visible OAuth URL after the browser has followed redirects', async () => {
    const response = new Response('Login');
    Object.defineProperties(response, { redirected: { value: true }, url: { value: authorizationUrl } });
    mockResponses(response);
    const authenticate = mockAuthentication(false);
    await fetchWithHttpAuthentication(
      endpoint,
      {},
      context({ executor: 'browser', requestHttpAuthentication: authenticate }),
    );
    assert.equal(authenticate.mock.calls[0]!.arguments[0].authenticationUrl, authorizationUrl);
  });

  it('detects OAuth redirects through the desktop transport without fetching the CORS-blocked provider', async () => {
    const browserFetch = mock.method(globalThis, 'fetch', async () => {
      throw new TypeError('Failed to fetch: CORS');
    });
    const nativeResponse = new Response('', { status: 302, headers: { location: authorizationUrl } });
    const httpRequest = mock.fn(async (_url: string, _init: RequestInit) => nativeResponse);
    const authenticate = mockAuthentication(false);
    const response = await fetchWithHttpAuthentication(
      endpoint,
      {},
      context({ executor: 'browser', httpRequest, requestHttpAuthentication: authenticate }),
    );
    assert.equal(response.status, 302);
    assert.equal(authenticate.mock.calls[0]!.arguments[0].authenticationUrl, authorizationUrl);
    assert.equal(httpRequest.mock.calls[0]!.arguments[1].redirect, 'manual');
    assert.equal(browserFetch.mock.callCount(), 0);
  });

  it('retries with the platform JWT through the native transport without browser CORS', async () => {
    const browserFetch = mock.method(globalThis, 'fetch', async () => {
      throw new TypeError('CORS');
    });
    const httpRequest = mock.fn(async (_url: string, init: RequestInit) =>
      new Headers(init.headers).has('authorization')
        ? Response.json({ authenticated: true })
        : new Response('', { status: 302, headers: { location: authorizationUrl } }),
    );
    const response = await fetchWithHttpAuthentication(
      endpoint,
      {},
      context({
        executor: 'browser',
        httpRequest,
        requestHttpAuthentication: mockAuthentication(true),
      }),
    );
    assert.deepEqual(await response.json(), { authenticated: true });
    assert.equal(httpRequest.mock.callCount(), 2);
    assert.equal(browserFetch.mock.callCount(), 0);
    assert.equal(
      new Headers(httpRequest.mock.calls[1]!.arguments[1].headers).get('authorization'),
      'Bearer test.jwt.token',
    );
  });

  it('follows ordinary redirects manually with the desktop browser transport', async () => {
    const httpRequest = mock.fn(async (url: string, _init: RequestInit) =>
      url === endpoint ? new Response('', { status: 302, headers: { location: '/next' } }) : new Response('ok'),
    );
    const authenticate = mockAuthentication(false);
    const response = await fetchWithHttpAuthentication(
      endpoint,
      { method: 'POST', body: 'payload' },
      context({ executor: 'browser', httpRequest, requestHttpAuthentication: authenticate }),
    );
    assert.equal(await response.text(), 'ok');
    assert.equal(httpRequest.mock.calls[1]!.arguments[0], 'https://api.example.com/next');
    assert.equal(httpRequest.mock.calls[1]!.arguments[1].method, 'GET');
    assert.equal(httpRequest.mock.calls[1]!.arguments[1].body, undefined);
    assert.equal(authenticate.mock.callCount(), 0);
  });

  it('keeps 401 node outputs intact in a browser without an interactive host', async () => {
    const fetch = mockResponses(Response.json({ error: 'unauthorized' }, { status: 401 }));
    const node = HttpCallNodeImpl.create();
    node.data.url = endpoint;
    node.data.authenticationUrl = authorizationUrl;
    const outputs = await new HttpCallNodeImpl(node).process({}, context({ executor: 'browser' }));
    assert.equal(outputs['statusCode']!.value, 401);
    assert.deepEqual(outputs['json']!.value, { error: 'unauthorized' });
    assert.equal(fetch.mock.callCount(), 1);
  });

  it('ignores successful and unrelated error responses', async () => {
    for (const status of [200, 404, 500]) {
      mockResponses(new Response('response', { status }));
      const authenticate = mockAuthentication(true);
      const response = await fetchWithHttpAuthentication(
        endpoint,
        {},
        context({ requestHttpAuthentication: authenticate }),
      );
      assert.equal(response.status, status);
      assert.equal(authenticate.mock.callCount(), 0);
    }
  });

  it('stops if execution is aborted while the sign-in page is open', async () => {
    const controller = new AbortController();
    const fetch = mockResponses(new Response('', { status: 401 }));
    await assert.rejects(
      fetchWithHttpAuthentication(
        endpoint,
        {},
        context({
          signal: controller.signal,
          requestHttpAuthentication: async () => {
            controller.abort();
            return { accessToken: 'test.jwt.token' };
          },
        }),
      ),
      /abort/i,
    );
    assert.equal(fetch.mock.callCount(), 1);
  });

  it('rejects non-web authentication URLs and credentials embedded in URLs', () => {
    for (const url of ['javascript:alert(1)', 'file:///etc/passwd', 'https://user:secret@example.com']) {
      assert.equal(getAuthenticationUrl(url, endpoint), undefined);
    }
    assert.equal(isOAuthAuthorizationUrl(new URL('https://example.com/download')), false);
    assert.equal(isOAuthAuthorizationUrl(new URL('https://example.com/oauth2/v2.0/authorize')), true);
    assert.equal(isOAuthAuthorizationUrl(new URL('https://accounts.google.com/o/oauth2/v2/auth')), true);
  });

  it('preserves a 401 without trying to open an API URL when no login URL is configured', async () => {
    mockResponses(new Response('', { status: 401 }));
    const authenticate = mockAuthentication(false);
    const response = await performAuthenticatedRequest(
      endpoint,
      {},
      context({ requestHttpAuthentication: authenticate }),
    );
    assert.equal(response.status, 401);
    assert.equal(authenticate.mock.callCount(), 0);
  });

  it('replays the original POST body and headers with the JWT, replacing an expired Authorization value', async () => {
    const fetch = mockResponses(new Response('', { status: 401 }), Response.json({ ok: true }));
    await fetchWithHttpAuthentication(
      endpoint,
      {
        method: 'POST',
        body: '{"payload":true}',
        headers: { Authorization: 'Bearer expired', 'content-type': 'application/json', 'x-request-id': 'id' },
      },
      context({ requestHttpAuthentication: mockAuthentication(true) }),
    );
    const init = fetch.mock.calls[1]!.arguments[1] as RequestInit;
    assert.equal(fetch.mock.calls[1]!.arguments[0], endpoint);
    assert.equal(init.method, 'POST');
    assert.equal(init.body, '{"payload":true}');
    assert.deepEqual(Object.fromEntries(new Headers(init.headers)), {
      authorization: 'Bearer test.jwt.token',
      'content-type': 'application/json',
      'x-request-id': 'id',
    });
  });

  it('reuses unexpired tokens only in memory for the same API and authentication configuration', async () => {
    const fetch = mockResponses(new Response('', { status: 401 }), new Response('ok'), new Response('cached'));
    const authenticate = mockAuthentication(true);
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: new Map() });
    await fetchWithHttpAuthentication(endpoint, {}, ctx);
    await fetchWithHttpAuthentication('https://api.example.com/another', {}, ctx);
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(
      new Headers((fetch.mock.calls[2]!.arguments[1] as RequestInit).headers).get('authorization'),
      'Bearer test.jwt.token',
    );
  });

  it('lets plugins reuse a session in place of their API key without changing the default header precedence', async () => {
    const fetch = mockResponses(
      new Response('', { status: 401 }),
      new Response('ok'),
      new Response('cached'),
      new Response('explicit'),
    );
    const authenticate = mockAuthentication(true);
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: new Map() });
    const init = { headers: { Authorization: 'api-key' } };
    await fetchWithHttpAuthentication(endpoint, init, ctx, { preferCachedToken: true });
    await fetchWithHttpAuthentication(endpoint, init, ctx, { preferCachedToken: true });
    await fetchWithHttpAuthentication(endpoint, init, ctx);
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(
      new Headers((fetch.mock.calls[2]!.arguments[1] as RequestInit).headers).get('authorization'),
      'Bearer test.jwt.token',
    );
    assert.equal(
      new Headers((fetch.mock.calls[3]!.arguments[1] as RequestInit).headers).get('authorization'),
      'api-key',
    );
  });

  it('authenticates before sending a request and reuses the session until it expires', async () => {
    const authenticate = mockAuthentication(true);
    const cache = new Map();
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: cache });
    const fetch = mock.method(globalThis, 'fetch', async (_url: string, init: RequestInit) => {
      assert.ok(authenticate.mock.callCount() > 0);
      assert.equal(new Headers(init.headers).get('authorization'), 'Bearer test.jwt.token');
      return new Response('ok');
    });
    const options = { authenticateBeforeRequest: true };
    await fetchWithHttpAuthentication(endpoint, {}, ctx, options);
    await fetchWithHttpAuthentication(endpoint, {}, ctx, options);
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(authenticate.mock.calls[0]!.arguments[0].status, 0);
    for (const entry of cache.values()) entry.expiresAt = 0;
    await fetchWithHttpAuthentication(endpoint, {}, ctx, options);
    assert.equal(authenticate.mock.callCount(), 2);
    assert.equal(fetch.mock.callCount(), 3);
  });

  it('shares one login between concurrent nodes with separate cancellation signals', async () => {
    let finishLogin!: (token: { accessToken: string; expiresIn: number }) => void;
    const authenticate = mock.fn(
      () =>
        new Promise<{ accessToken: string; expiresIn: number }>((resolve) => {
          finishLogin = resolve;
        }),
    );
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: new Map() });
    const fetch = mockResponses(new Response('first'), new Response('second'));
    const requests = [
      fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true }),
      fetchWithHttpAuthentication(
        `${endpoint}/second`,
        {},
        { ...ctx, signal: new AbortController().signal },
        { authenticateBeforeRequest: true },
      ),
    ];
    await Promise.resolve();
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(fetch.mock.callCount(), 0);
    finishLogin({ accessToken: 'shared.jwt', expiresIn: 3600 });
    await Promise.all(requests);
    assert.equal(fetch.mock.callCount(), 2);
  });

  it('keeps a shared login open when only one node is cancelled', async () => {
    let finishLogin!: (token: { accessToken: string }) => void;
    let loginSignal!: AbortSignal;
    const authenticate = mock.fn((_request: HttpAuthenticationRequest, signal: AbortSignal) => {
      loginSignal = signal;
      return new Promise<{ accessToken: string }>((resolve) => {
        finishLogin = resolve;
      });
    });
    const cache = new Map();
    const firstController = new AbortController();
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: cache });
    const fetch = mockResponses(new Response('ok'));
    const first = assert.rejects(
      fetchWithHttpAuthentication(
        endpoint,
        {},
        { ...ctx, signal: firstController.signal },
        { authenticateBeforeRequest: true },
      ),
      /abort/i,
    );
    const second = fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true });
    await Promise.resolve();
    firstController.abort();
    await first;
    assert.equal(loginSignal.aborted, false);
    assert.equal(authenticate.mock.callCount(), 1);
    finishLogin({ accessToken: 'shared.jwt' });
    assert.equal((await second).status, 200);
    assert.equal(fetch.mock.callCount(), 1);
  });

  it('closes a shared login when all waiting nodes are cancelled', async () => {
    let loginSignal!: AbortSignal;
    const authenticate = mock.fn((_request: HttpAuthenticationRequest, signal: AbortSignal) => {
      loginSignal = signal;
      return new Promise<false>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      });
    });
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: new Map() });
    const controllers = [new AbortController(), new AbortController()];
    const requests = controllers.map((controller) =>
      assert.rejects(
        fetchWithHttpAuthentication(
          endpoint,
          {},
          { ...ctx, signal: controller.signal },
          { authenticateBeforeRequest: true },
        ),
        /abort/i,
      ),
    );
    await Promise.resolve();
    for (const controller of controllers) controller.abort();
    await Promise.all(requests);
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(loginSignal.aborted, true);
  });

  it('reuses a token without a declared lifetime within an execution', async () => {
    const authenticate = mock.fn(async () => ({ accessToken: 'shared.jwt' }));
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: new Map() });
    mockResponses(new Response('first'), new Response('second'));
    await fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true });
    await fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true });
    assert.equal(authenticate.mock.callCount(), 1);
  });

  it('reuses the host project session across new execution caches without extending token expiry', async () => {
    const authenticate = mockAuthentication(true);
    const httpAuthenticationCache = new Map();
    const ctx = () =>
      context({ httpAuthenticationCache, executionCache: new Map(), requestHttpAuthentication: authenticate });
    const fetch = mockResponses(new Response('first'), new Response('second'));
    const first = ctx();
    await fetchWithHttpAuthentication(endpoint, {}, first, { authenticateBeforeRequest: true });
    const session = [...httpAuthenticationCache.values()][0];
    const second = ctx();
    await fetchWithHttpAuthentication(endpoint, {}, second, { authenticateBeforeRequest: true });
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(first.executionCache.size, 0);
    assert.equal(second.executionCache.size, 0);
    assert.equal([...httpAuthenticationCache.values()][0], session);
    assert.equal(
      new Headers((fetch.mock.calls[1]!.arguments[1] as RequestInit).headers).get('authorization'),
      'Bearer test.jwt.token',
    );
  });

  it('requests a new login on a later execution when the shared token has expired', async () => {
    const authenticate = mockAuthentication(true);
    const httpAuthenticationCache = new Map();
    const ctx = () =>
      context({ httpAuthenticationCache, executionCache: new Map(), requestHttpAuthentication: authenticate });
    mockResponses(new Response('first'), new Response('second'));
    await fetchWithHttpAuthentication(endpoint, {}, ctx(), { authenticateBeforeRequest: true });
    for (const session of httpAuthenticationCache.values()) session.expiresAt = 0;
    await fetchWithHttpAuthentication(endpoint, {}, ctx(), { authenticateBeforeRequest: true });
    assert.equal(authenticate.mock.callCount(), 2);
  });

  for (const status of [401, 403]) {
    it(`replaces a session rejected with ${status} on a later run and reuses the replacement`, async () => {
      let logins = 0;
      const authenticate = mock.fn(async () => ({ accessToken: `jwt.${++logins}`, expiresIn: 3600 }));
      const httpAuthenticationCache = new Map();
      const ctx = () =>
        context({ httpAuthenticationCache, executionCache: new Map(), requestHttpAuthentication: authenticate });
      const fetch = mockResponses(
        new Response('first'),
        new Response('rejected', { status }),
        new Response('refreshed'),
        new Response('third'),
      );
      for (let run = 0; run < 3; run++) {
        assert.equal(
          (await fetchWithHttpAuthentication(endpoint, {}, ctx(), { authenticateBeforeRequest: true })).status,
          200,
        );
      }
      assert.equal(authenticate.mock.callCount(), 2);
      assert.equal(
        new Headers((fetch.mock.calls[3]!.arguments[1] as RequestInit).headers).get('authorization'),
        'Bearer jwt.2',
      );
    });
  }

  it('does not reuse a project session after its API origin, login configuration, or API key changes', async () => {
    const authenticate = mockAuthentication(true);
    const httpAuthenticationCache = new Map();
    const ctx = () =>
      context({ httpAuthenticationCache, executionCache: new Map(), requestHttpAuthentication: authenticate });
    mockResponses(new Response('one'), new Response('two'), new Response('three'), new Response('four'));
    await fetchWithHttpAuthentication(endpoint, {}, ctx(), { authenticateBeforeRequest: true });
    await fetchWithHttpAuthentication('https://other.example.com/private', {}, ctx(), {
      authenticateBeforeRequest: true,
    });
    await fetchWithHttpAuthentication(endpoint, {}, ctx(), {
      authenticateBeforeRequest: true,
      loginUrl: 'https://other.example.com/login',
    });
    await fetchWithHttpAuthentication(endpoint, { headers: { Authorization: 'different-api-key' } }, ctx(), {
      authenticateBeforeRequest: true,
    });
    assert.equal(authenticate.mock.callCount(), 4);
  });

  it('uses a newly configured API key instead of overriding it with a previous key session', async () => {
    const httpAuthenticationCache = new Map();
    const ctx = () =>
      context({
        httpAuthenticationCache,
        executionCache: new Map(),
        requestHttpAuthentication: mockAuthentication(true),
      });
    const fetch = mockResponses(
      new Response('expired key', { status: 401 }),
      new Response('authenticated'),
      new Response('new key'),
    );
    await fetchWithHttpAuthentication(endpoint, { headers: { Authorization: 'old-key' } }, ctx(), {
      preferCachedToken: true,
    });
    await fetchWithHttpAuthentication(endpoint, { headers: { Authorization: 'new-key' } }, ctx(), {
      preferCachedToken: true,
    });
    assert.equal(
      new Headers((fetch.mock.calls[2]!.arguments[1] as RequestInit).headers).get('authorization'),
      'new-key',
    );
  });

  for (const status of [401, 403]) {
    for (const initiallyCached of [false, true]) {
      it(`reuses a refreshed JWT after a late ${status} with ${initiallyCached ? 'an old' : 'no'} cached session`, async () => {
        let releaseFailure!: (response: Response) => void;
        let holdRequest = false;
        let held = false;
        let logins = 0;
        const cache = new Map();
        const authenticate = mock.fn(async () => ({ accessToken: `jwt.${++logins}`, expiresIn: 3600 }));
        const ctx = context({
          executionCache: cache,
          requestHttpAuthentication: authenticate,
          httpRequest: async (url, init) => {
            if (!holdRequest) return new Response('ok');
            if (url.endsWith('/slow') && !held) {
              held = true;
              return new Promise<Response>((resolve) => {
                releaseFailure = resolve;
              });
            }
            return new Headers(init.headers).get('authorization') === `Bearer jwt.${initiallyCached ? 2 : 1}`
              ? new Response('ok')
              : new Response('unauthorized', { status });
          },
        });
        if (initiallyCached) await fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true });
        holdRequest = true;
        // Hold one old request until its peer has completed sign-in and cached the replacement.
        const slow = fetchWithHttpAuthentication(`${endpoint}/slow`, {}, ctx);
        await fetchWithHttpAuthentication(endpoint, {}, ctx);
        const session = [...cache.values()][0];
        releaseFailure(new Response('late failure', { status }));
        assert.equal((await slow).status, 200);
        assert.equal(authenticate.mock.callCount(), initiallyCached ? 2 : 1);
        assert.equal([...cache.values()][0], session, 'retain the refreshed session and its original expiry');
      });
    }
  }

  it('shares the JWT while the challenged response body is still being released', async () => {
    let releaseBody!: () => void;
    let cancelStarted!: () => void;
    const cancelling = new Promise<void>((resolve) => {
      cancelStarted = resolve;
    });
    const body = new ReadableStream({
      cancel: () => {
        cancelStarted();
        return new Promise<void>((resolve) => {
          releaseBody = resolve;
        });
      },
    });
    const authenticate = mockAuthentication(true);
    const ctx = context({
      executionCache: new Map(),
      requestHttpAuthentication: authenticate,
      httpRequest: async (_url, init) =>
        new Headers(init.headers).has('authorization') ? new Response('ok') : new Response(body, { status: 401 }),
    });
    const first = fetchWithHttpAuthentication(endpoint, {}, ctx);
    await cancelling;
    try {
      assert.equal(
        (await fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true })).status,
        200,
      );
      assert.equal(authenticate.mock.callCount(), 1);
    } finally {
      releaseBody();
      await first;
    }
  });

  it('clears a cancelled shared login so a later request can authenticate', async () => {
    let attempts = 0;
    const authenticate = mock.fn(async () => (++attempts === 1 ? false : { accessToken: 'new.jwt' }));
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: new Map() });
    const fetch = mockResponses(new Response('ok'));
    await assert.rejects(
      fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true }),
      /cancelled/,
    );
    assert.equal(fetch.mock.callCount(), 0);
    await fetchWithHttpAuthentication(endpoint, {}, ctx, { authenticateBeforeRequest: true });
    assert.equal(authenticate.mock.callCount(), 2);
  });

  it('uses the configured login URL on 403 and retries the original request with the JWT', async () => {
    const fetch = mockResponses(new Response('Forbidden', { status: 403 }), Response.json({ ok: true }));
    const authenticate = mockAuthentication(true);
    const response = await fetchWithHttpAuthentication(
      endpoint,
      { method: 'POST', body: 'payload', headers: { 'x-request-id': 'id' } },
      context({ requestHttpAuthentication: authenticate }),
    );
    assert.deepEqual(authenticate.mock.calls[0]!.arguments[0], {
      requestUrl: endpoint,
      authenticationUrl: authorizationUrl,
      status: 403,
      callbackUrl,
    });
    const init = fetch.mock.calls[1]!.arguments[1] as RequestInit;
    assert.equal(fetch.mock.calls[1]!.arguments[0], endpoint);
    assert.equal(init.method, 'POST');
    assert.equal(init.body, 'payload');
    assert.deepEqual(Object.fromEntries(new Headers(init.headers)), {
      authorization: 'Bearer test.jwt.token',
      'x-request-id': 'id',
    });
    assert.equal(response.status, 200);
  });

  it('does not repeat login or retain a rejected cached token when the retry is still 403', async () => {
    const fetch = mockResponses(
      new Response('', { status: 401 }),
      new Response('ok'),
      new Response('', { status: 403 }),
      new Response('still forbidden', { status: 403 }),
    );
    const authenticate = mockAuthentication(true);
    const ctx = context({ requestHttpAuthentication: authenticate, executionCache: new Map() });
    await fetchWithHttpAuthentication(endpoint, {}, ctx);
    assert.equal(ctx.executionCache.size, 1);
    const response = await fetchWithHttpAuthentication(endpoint, {}, ctx);
    assert.equal(response.status, 403);
    assert.equal(fetch.mock.callCount(), 4);
    assert.equal(authenticate.mock.callCount(), 2);
    assert.equal(ctx.executionCache.size, 0);
  });

  it('preserves 403 outputs when no OAuth login URL or interactive host is available', async () => {
    const authenticate = mockAuthentication(true);
    mockResponses(new Response('Forbidden', { status: 403 }));
    const response = await performAuthenticatedRequest(
      endpoint,
      {},
      context({ requestHttpAuthentication: authenticate }),
    );
    assert.equal(response.status, 403);
    assert.equal(authenticate.mock.callCount(), 0);

    mockResponses(Response.json({ error: 'forbidden' }, { status: 403 }));
    const node = HttpCallNodeImpl.create();
    node.data.url = endpoint;
    node.data.authenticationUrl = authorizationUrl;
    const outputs = await new HttpCallNodeImpl(node).process({}, context({ executor: 'browser' }));
    assert.equal(outputs['statusCode']!.value, 403);
    assert.deepEqual(outputs['json']!.value, { error: 'forbidden' });
  });
});
