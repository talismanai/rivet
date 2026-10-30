import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { PassThrough } from 'node:stream';
import { createServer } from 'node:http';
import {
  ChromeDebuggingPipe,
  matchesOAuthCallback,
  authenticateInChrome,
  OAuthAuthenticationError,
  getOAuthAuthenticationErrorMessage,
  bearerTokenFromHeaders,
} from '../src/auth/ChromeAuthentication.js';

void describe('Chrome OAuth interception', () => {
  void it('frames CDP commands over private pipes and correlates responses', async () => {
    const output = new PassThrough();
    const input = new PassThrough();
    const pipe = new ChromeDebuggingPipe(output, input);
    let sent = '';
    output.on('data', (chunk) => {
      sent += chunk.toString();
    });
    const result = pipe.command('Network.enable', {}, 'session');
    assert.deepEqual(JSON.parse(sent.slice(0, -1)), {
      id: 1,
      method: 'Network.enable',
      params: {},
      sessionId: 'session',
    });
    input.write('{"id":1,"result":');
    input.write('{"ok":true}}\0');
    assert.deepEqual(await result, { ok: true });
    pipe.dispose();
  });

  void it('rejects pending requests when Chrome closes the debugging pipe', async () => {
    const output = new PassThrough();
    const input = new PassThrough();
    const pipe = new ChromeDebuggingPipe(output, input);
    const pending = assert.rejects(pipe.command('Network.enable'), /closed/);
    pipe.dispose();
    await pending;
    await assert.rejects(pipe.command('Page.navigate'), /closed/);
  });

  void it('reports a lost debugging connection even when no command is pending', () => {
    const input = new PassThrough();
    const pipe = new ChromeDebuggingPipe(new PassThrough(), input);
    let closed = 0;
    pipe.onClose = () => closed++;
    input.emit('close');
    pipe.dispose();
    assert.equal(closed, 1);
  });

  void it('matches only the configured callback origin and path, retaining configured query constraints', () => {
    const callback = 'https://api.example.com/api/callback?tenant=one';
    assert.ok(matchesOAuthCallback(callback + '&code=code&state=state', callback));
    for (const url of [
      'https://evil.example/api/callback?tenant=one',
      'https://api.example.com/api/callback/other?tenant=one',
      'https://api.example.com/api/callback?tenant=two',
      'not a url',
    ]) {
      assert.equal(matchesOAuthCallback(url, callback), false);
    }
  });

  void it(
    'captures a JSON platform callback in a real isolated browser',
    { skip: process.env.RIVET_TEST_CHROME !== '1', timeout: 30000 },
    async () => {
      const token = { accessToken: 'fixture.jwt.token', expiresIn: 3600 };
      const server = createServer((request, response) => {
        if (request.url === '/login') {
          response.writeHead(302, { location: '/callback?code=fixture' });
          response.end();
        } else {
          response.writeHead(200, { 'content-type': 'application/json' });
          response.end(
            JSON.stringify({
              data: {
                access_token: token.accessToken,
                expires_in: token.expiresIn,
                user: { email: 'fixture@example.com' },
              },
            }),
          );
        }
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const base = `http://127.0.0.1:${address.port}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      try {
        const result = await authenticateInChrome(
          {
            requestUrl: base + '/private',
            authenticationUrl: base + '/login',
            callbackUrl: base + '/callback',
            status: 401,
          },
          controller.signal,
        );
        assert.deepEqual(result, token);
      } finally {
        clearTimeout(timer);
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    },
  );
});

void describe('OAuth callback diagnostics', () => {
  void it('only exposes predefined errors and never raw callback bodies or credentials', () => {
    assert.match(getOAuthAuthenticationErrorMessage(new OAuthAuthenticationError('callbackStatus', 403)), /HTTP 403/);
    assert.match(getOAuthAuthenticationErrorMessage(new OAuthAuthenticationError('callbackJson')), /valid JSON/);
    const secret = 'secret.jwt.token';
    assert.ok(!getOAuthAuthenticationErrorMessage(new Error(secret)).includes(secret));
  });

  for (const fixture of [
    {
      name: 'captures JSON after cross-site navigation',
      status: 200,
      body: JSON.stringify({ data: { access_token: 'fixture.jwt.token', expires_in: 3600 } }),
      error: undefined,
    },
    { name: 'reports the callback HTTP status', status: 403, body: 'private error body', error: 'callbackStatus' },
    {
      name: 'reports non-JSON callback responses',
      status: 200,
      body: '<html>private response</html>',
      error: 'callbackJson',
    },
    {
      name: 'reports callback JSON without a token',
      status: 200,
      body: '{"data":{"private":"details"}}',
      error: 'callbackToken',
    },
  ] as const) {
    void it(fixture.name, { skip: process.env.RIVET_TEST_CHROME !== '1', timeout: 30000 }, async () => {
      let base = '';
      const server = createServer((request, response) => {
        if (request.url === '/login') {
          response.writeHead(302, { location: base.replace('127.0.0.1', 'localhost') + '/provider' });
          response.end();
        } else if (request.url === '/provider') {
          response.writeHead(200, { 'content-type': 'text/html' });
          response.end(`<script>location.href=${JSON.stringify(base + '/callback?code=fixture')}</script>`);
        } else {
          response.writeHead(fixture.status, { 'content-type': 'application/json' });
          response.end(fixture.body);
        }
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      base = `http://127.0.0.1:${address.port}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      try {
        const result = authenticateInChrome(
          {
            requestUrl: base + '/private',
            authenticationUrl: base + '/login',
            callbackUrl: base + '/callback',
            status: 0,
          },
          controller.signal,
        );
        if (fixture.error) {
          await assert.rejects(
            result,
            (error: unknown) => error instanceof OAuthAuthenticationError && error.code === fixture.error,
          );
        } else {
          assert.deepEqual(await result, { accessToken: 'fixture.jwt.token', expiresIn: 3600 });
        }
      } finally {
        clearTimeout(timer);
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });
  }
});

void it(
  'leaves the original callback open for inspection until cancelled',
  { skip: process.env.RIVET_TEST_CHROME !== '1', timeout: 30000 },
  async () => {
    let callbacks = 0;
    const server = createServer((request, response) => {
      if (request.url !== '/callback') {
        response.writeHead(204);
        response.end();
        return;
      }
      callbacks++;
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<html><body>Platform diagnostic page</body></html>');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const callbackUrl = `http://127.0.0.1:${address.port}/callback`;
    const controller = new AbortController();
    let reported!: () => void;
    const diagnostic = new Promise<void>((resolve) => {
      reported = resolve;
    });
    let settled = false;
    const timeout = setTimeout(() => controller.abort(), 20000);
    const pending = authenticateInChrome(
      { requestUrl: callbackUrl, authenticationUrl: callbackUrl, callbackUrl, status: 0 },
      controller.signal,
      {
        onCallbackError(error) {
          assert.equal(error.code, 'callbackJson');
          reported();
        },
      },
    ).finally(() => {
      settled = true;
    });
    const rejected = assert.rejects(pending, /valid JSON/);
    try {
      await diagnostic;
      await new Promise((resolve) => setTimeout(resolve, 300));
      assert.equal(settled, false, 'helper stays alive while the diagnostic browser is open');
      assert.equal(callbacks, 1, 'the one-use OAuth callback is not fetched again');
      controller.abort();
      await rejected;
    } finally {
      clearTimeout(timeout);
      controller.abort();
      await rejected;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);

void describe('Official login Authorization header capture', () => {
  const jwt = (claims: object) => `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;
  for (const fixture of [
    { name: 'made by login page workers', worker: true, cors: true, redirect: false },
    { name: 'whose successful responses are blocked by CORS', worker: false, cors: false, redirect: false },
    { name: 'after ignoring a JWT stripped by a cross-origin redirect', worker: false, cors: true, redirect: true },
  ]) {
    void it(
      `captures authorized requests ${fixture.name}`,
      { skip: process.env.RIVET_TEST_CHROME !== '1', timeout: 30000 },
      async () => {
        const token = jwt({ exp: Math.floor(Date.now() / 1000) + 3600, source: 'worker' });
        let login = '';
        let capture = '';
        let verified = false;
        const server = createServer((request, response) => {
          if (fixture.cors || request.method === 'OPTIONS') response.setHeader('Access-Control-Allow-Origin', login);
          response.setHeader('Access-Control-Allow-Headers', 'Authorization');
          if (request.method === 'OPTIONS') {
            response.writeHead(204);
            response.end();
            return;
          }
          if (request.url === '/login') {
            response.writeHead(200, { 'content-type': 'text/html' });
            response.end(
              fixture.worker
                ? '<script>new Worker("/auth-worker.js")</script>'
                : `<script>(async()=>{
                    ${fixture.redirect ? `await fetch('/redirect',{headers:{Authorization:${JSON.stringify('Bearer ' + jwt({ source: 'stripped', exp: Math.floor(Date.now() / 1000) + 3600 }))}}});` : ''}
                    await fetch(${JSON.stringify(capture + '/verified')},{headers:{Authorization:${JSON.stringify('Bearer ' + token)}}});
                  })()</script>`,
            );
          } else if (request.url === '/redirect') {
            response.writeHead(302, { location: capture + '/public' });
            response.end();
          } else if (request.url === '/auth-worker.js') {
            response.writeHead(200, { 'content-type': 'text/javascript' });
            response.end(
              `fetch(${JSON.stringify(capture + '/verified')},{headers:{Authorization:${JSON.stringify('Bearer ' + token)}}});`,
            );
          } else {
            if (request.url === '/public') assert.equal(request.headers.authorization, undefined);
            verified ||= request.url === '/verified';
            response.writeHead(200, { 'content-type': 'application/json' });
            response.end('{}');
          }
        });
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
        const address = server.address();
        assert.ok(address && typeof address === 'object');
        login = `http://127.0.0.1:${address.port}`;
        capture = `http://localhost:${address.port}`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        const progress: unknown[] = [];
        try {
          const result = await authenticateInChrome(
            {
              requestUrl: 'https://destination.example.invalid/private',
              authenticationUrl: login + '/login',
              tokenSource: 'authorization-header',
              status: 0,
            },
            controller.signal,
            { onProgress: (event) => progress.push(event) },
          ).catch((error: Error) => {
            throw new Error(`${error.message}; capture progress: ${JSON.stringify(progress)}`);
          });
          assert.ok(verified);
          assert.ok(result);
          assert.equal(result.accessToken, token);
          assert.ok(
            progress.some(
              (event: any) => event.stage === 'request' && event.authorization === 'valid' && event.status === 200,
            ),
          );
          assert.ok(!JSON.stringify(progress).includes(token));
        } finally {
          clearTimeout(timeout);
          controller.abort();
          await new Promise<void>((resolve) => server.close(() => resolve()));
          assert.ok(verified, 'the browser actually sent the authorized request');
        }
      },
    );
  }
  void it(
    'discovers the API origin and ignores JWTs sent by unrelated provider frames',
    { skip: process.env.RIVET_TEST_CHROME !== '1', timeout: 30000 },
    async () => {
      const token = jwt({ exp: Math.floor(Date.now() / 1000) + 3600, source: 'capture' });
      const unrelated = jwt({ exp: Math.floor(Date.now() / 1000) + 3600, source: 'provider-frame' });
      let login = '';
      let capture = '';
      const server = createServer((request, response) => {
        response.setHeader('Access-Control-Allow-Origin', login);
        response.setHeader('Access-Control-Allow-Headers', 'Authorization');
        if (request.method === 'OPTIONS') {
          response.writeHead(204);
          response.end();
          return;
        }
        if (request.url === '/login') {
          response.writeHead(200, { 'content-type': 'text/html' });
          response.end(`<script>window.addEventListener('message', async (event)=>{
            if(event.origin !== ${JSON.stringify(capture)} || event.data !== 'provider-ready') return;
            await fetch(${JSON.stringify(capture + '/verified')},{headers:{Authorization:${JSON.stringify('Bearer ' + token)}}});
          });</script><iframe src="${capture}/provider"></iframe>`);
        } else if (request.url === '/provider') {
          response.writeHead(200, { 'content-type': 'text/html' });
          response.end(`<script>(async()=>{
            await fetch('/provider-api',{headers:{Authorization:${JSON.stringify('Bearer ' + unrelated)}}});
            parent.postMessage('provider-ready', ${JSON.stringify(login)});
          })()</script>`);
        } else {
          response.writeHead(200, { 'content-type': 'application/json' });
          response.end('{}');
        }
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      login = `http://127.0.0.1:${address.port}`;
      capture = `http://localhost:${address.port}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);
      try {
        const result = await authenticateInChrome(
          {
            requestUrl: 'https://destination.example.invalid/private',
            authenticationUrl: login + '/login',
            tokenSource: 'authorization-header',
            status: 0,
          },
          controller.signal,
        );
        assert.ok(result);
        assert.equal(result.accessToken, token);
      } finally {
        clearTimeout(timeout);
        controller.abort();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    },
  );
  void it('parses a Bearer JWT and its expiry without requiring an access-token token_use', () => {
    const token = jwt({ token_use: 'id', aud: 'admin-client', exp: Math.floor(Date.now() / 1000) + 3600 });
    const result = bearerTokenFromHeaders({ AUTHORIZATION: `Bearer ${token}` });
    assert.equal(result?.accessToken, token);
    assert.ok(result?.expiresIn && result.expiresIn > 3500 && result.expiresIn <= 3600);
  });
  void it('ignores expired tokens, malformed JWTs and other authorization schemes', () => {
    for (const authorization of [
      'Basic abc',
      'Bearer opaque',
      'Bearer invalid.jwt.token',
      `Bearer ${jwt({ exp: 1 })}`,
      `Bearer ${jwt({ exp: 'invalid' })}`,
    ]) {
      assert.equal(bearerTokenFromHeaders({ authorization }), undefined);
    }
  });
  void it(
    'captures only a valid JWT accepted by a login-page API request',
    { skip: process.env.RIVET_TEST_CHROME !== '1', timeout: 30000 },
    async () => {
      const token = jwt({ token_use: 'id', aud: 'admin-client', exp: Math.floor(Date.now() / 1000) + 3600 });
      const rejected = jwt({ exp: Math.floor(Date.now() / 1000) + 3600, source: 'rejected' });
      const unrelated = 'opaque-session-token';
      let base = '';
      let api = '';
      const seen: string[] = [];
      const server = createServer((request, response) => {
        response.setHeader('Access-Control-Allow-Origin', base);
        response.setHeader('Access-Control-Allow-Headers', 'Authorization');
        if (request.method === 'OPTIONS') {
          response.writeHead(204);
          response.end();
          return;
        }
        if (request.url === '/login') {
          response.writeHead(200, { 'content-type': 'text/html' });
          response.end(`<script>(async()=>{
          await fetch(${JSON.stringify(api + '/rejected')}, {headers:{Authorization:${JSON.stringify('Bearer ' + rejected)}}});
          await fetch('/unrelated', {headers:{Authorization:${JSON.stringify('Bearer ' + unrelated)}}});
          await fetch(${JSON.stringify(api + '/verified')}, {headers:{Authorization:${JSON.stringify('Bearer ' + token)}}});
        })()</script>`);
        } else {
          seen.push(request.url!);
          response.writeHead(request.url === '/rejected' ? 401 : 200, { 'content-type': 'application/json' });
          response.end('{}');
        }
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      base = `http://127.0.0.1:${address.port}`;
      api = `http://localhost:${address.port}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);
      try {
        const result = await authenticateInChrome(
          {
            requestUrl: api + '/private',
            authenticationUrl: base + '/login',
            callbackUrl: base + '/unused-legacy-callback',
            tokenSource: 'authorization-header',
            status: 0,
          },
          controller.signal,
        );
        assert.ok(result);
        assert.equal(result.accessToken, token);
        assert.ok(seen.includes('/rejected') && seen.includes('/unrelated') && seen.includes('/verified'));
      } finally {
        clearTimeout(timeout);
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    },
  );
});
