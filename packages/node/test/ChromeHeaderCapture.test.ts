import { strict as assert } from 'node:assert';
import { it } from 'node:test';
import { ChromeHeaderCapture } from '../src/auth/ChromeHeaderCapture.js';

const login = 'https://platform.example';
const jwt = (source: string) =>
  `e30.${Buffer.from(JSON.stringify({ source, exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url')}.signature`;
const token = jwt('platform');
const otherToken = jwt('other');
const headers = (value = token) => ({ Authorization: `Bearer ${value}` });
const request = (values: object = {}) => ({
  requestId: 'request',
  documentURL: login + '/home',
  request: { url: 'https://api.dynamic.example/profile', headers: headers() },
  ...values,
});
const response = (values: object = {}) => ({
  requestId: 'request',
  response: { status: 200 },
  hasExtraInfo: true,
  ...values,
});

void it('captures main request headers when Chrome explicitly reports no ExtraInfo', () => {
  const capture = new ChromeHeaderCapture(new Set([login]), () => {});
  assert.equal(capture.capture('page', 'Network.requestWillBeSent', request()), undefined);
  assert.equal(
    capture.capture('page', 'Network.responseReceived', response({ hasExtraInfo: false }))?.accessToken,
    token,
  );
});

function permutations<T>(items: T[]): T[][] {
  return items.flatMap((item, index) =>
    items.length === 1
      ? [[item]]
      : permutations(items.filter((_, other) => other !== index)).map((rest) => [item, ...rest]),
  );
}

void it('correlates independent ExtraInfo events before or after their main request and response', () => {
  const events = [
    ['Network.requestWillBeSent', request()],
    ['Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() }],
    ['Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 200 }],
    ['Network.responseReceived', response()],
  ] as const;
  for (const order of permutations([...events])) {
    // CDP's main request precedes its main response; ExtraInfo has no such ordering guarantee.
    if (
      order.findIndex(([method]) => method === 'Network.requestWillBeSent') >
      order.findIndex(([method]) => method === 'Network.responseReceived')
    )
      continue;
    const capture = new ChromeHeaderCapture(new Set([login]), () => {});
    const captured = order.map(([method, params]) => capture.capture('page', method, params)).filter(Boolean);
    assert.ok(captured.length > 0);
    assert.ok(captured.every((value) => value && value.accessToken === token));
  }
});

for (const finalToken of [undefined, otherToken]) {
  void it(`keeps late redirect metadata separate from the final hop ${finalToken ? 'with a different JWT' : 'without a JWT'}`, () => {
    const capture = new ChromeHeaderCapture(new Set([login]), () => {});
    assert.equal(capture.capture('page', 'Network.requestWillBeSent', request()), undefined);
    assert.equal(
      capture.capture(
        'page',
        'Network.requestWillBeSent',
        request({
          redirectResponse: { status: 302 },
          redirectHasExtraInfo: true,
          // The main event can contain provisional headers. Actual wire headers take precedence.
          request: { url: 'https://another-api.example/final', headers: headers() },
        }),
      ),
      undefined,
    );
    assert.equal(
      capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() }),
      undefined,
    );
    assert.equal(
      capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 302 }),
      undefined,
    );
    assert.equal(capture.capture('page', 'Network.responseReceived', response()), undefined);
    assert.equal(
      capture.capture('page', 'Network.requestWillBeSentExtraInfo', {
        requestId: 'request',
        headers: finalToken ? headers(finalToken) : {},
      }),
      undefined,
    );
    assert.equal(
      capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 200 })
        ?.accessToken,
      finalToken,
    );
  });
}

void it('accounts for redirect hops that do not emit ExtraInfo', () => {
  const capture = new ChromeHeaderCapture(new Set([login]), () => {});
  capture.capture('page', 'Network.requestWillBeSent', request());
  capture.capture(
    'page',
    'Network.requestWillBeSent',
    request({ redirectResponse: { status: 302 }, redirectHasExtraInfo: false }),
  );
  capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() });
  capture.capture('page', 'Network.responseReceived', response());
  assert.equal(
    capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 200 })
      ?.accessToken,
    token,
  );
});

void it('does not associate a final response with the earlier hop when its ExtraInfo arrives before the redirect event', () => {
  const capture = new ChromeHeaderCapture(new Set([login]), () => {});
  capture.capture('page', 'Network.requestWillBeSent', request());
  capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers(otherToken) });
  assert.equal(
    capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 200 }),
    undefined,
  );
  assert.equal(
    capture.capture(
      'page',
      'Network.requestWillBeSent',
      request({
        redirectResponse: { status: 302 },
        redirectHasExtraInfo: false,
        request: { url: 'https://another-api.example/final', headers: headers(otherToken) },
      }),
    ),
    undefined,
  );
  assert.equal(capture.capture('page', 'Network.responseReceived', response())?.accessToken, otherToken);
});

for (const status of [401, 403]) {
  void it(`does not capture a JWT rejected with HTTP ${status}`, () => {
    const capture = new ChromeHeaderCapture(new Set([login]), () => {});
    capture.capture('page', 'Network.requestWillBeSent', request());
    capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() });
    assert.equal(capture.capture('page', 'Network.responseReceived', response({ response: { status } })), undefined);
    assert.equal(
      capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: status }),
      undefined,
    );
  });
}

void it('keeps requests in separate browser sessions isolated and releases detached sessions', () => {
  const capture = new ChromeHeaderCapture(new Set([login]), () => {});
  capture.capture('worker', 'Network.requestWillBeSent', request());
  assert.equal(capture.capture('page', 'Network.responseReceived', response({ hasExtraInfo: false })), undefined);
  capture.forgetSession('worker');
  assert.equal(capture.capture('worker', 'Network.responseReceived', response({ hasExtraInfo: false })), undefined);
});

void it('matches worker responses with wire headers emitted by their registered parent page', () => {
  for (const early of [true, false]) {
    const capture = new ChromeHeaderCapture(new Set([login]), () => {});
    capture.registerSession('worker', 'page');
    const wireHeaders = () =>
      capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() });
    const wireStatus = () =>
      capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 200 });
    if (early) {
      wireHeaders();
      wireStatus();
    }
    assert.equal(capture.capture('worker', 'Network.requestWillBeSent', request()), undefined);
    const result = capture.capture('worker', 'Network.responseReceived', response());
    if (early) assert.equal(result?.accessToken, token);
    else {
      assert.equal(result, undefined);
      wireHeaders();
      assert.equal(wireStatus()?.accessToken, token);
    }
  }
});

void it('does not correlate ambiguous worker IDs or a parent page request with the same ID', () => {
  for (const collision of ['sibling', 'page']) {
    const capture = new ChromeHeaderCapture(new Set([login]), () => {});
    capture.registerSession('worker', 'page');
    capture.registerSession('sibling', 'page');
    capture.capture('worker', 'Network.requestWillBeSent', request());
    capture.capture(
      collision,
      'Network.requestWillBeSent',
      request({ request: { url: login + '/other', headers: {} } }),
    );
    capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() });
    capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 200 });
    assert.equal(capture.capture('worker', 'Network.responseReceived', response()), undefined);
  }
});

void it('ignores JWTs initiated by unrelated pages even when their API request succeeds', () => {
  const capture = new ChromeHeaderCapture(new Set([login]), () => {});
  capture.capture('provider', 'Network.requestWillBeSent', request({ documentURL: 'https://accounts.example/login' }));
  assert.equal(capture.capture('provider', 'Network.responseReceived', response({ hasExtraInfo: false })), undefined);
});

void it('accepts a cached HTTP 200 revalidated with 304 only after confirming the actual headers', () => {
  const capture = new ChromeHeaderCapture(new Set([login]), () => {});
  capture.capture('page', 'Network.requestWillBeSent', request());
  capture.capture('page', 'Network.responseReceived', response());
  capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 304 });
  assert.equal(
    capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() })
      ?.accessToken,
    token,
  );
});

void it('captures CORS-blocked HTTP 200 responses but ignores unrelated network failures', () => {
  for (const cors of [true, false]) {
    const capture = new ChromeHeaderCapture(new Set([login]), () => {});
    capture.capture('page', 'Network.requestWillBeSent', request());
    capture.capture('page', 'Network.loadingFailed', {
      requestId: 'request',
      ...(cors ? { corsErrorStatus: { corsError: 'MissingAllowOriginHeader' } } : {}),
    });
    capture.capture('page', 'Network.requestWillBeSentExtraInfo', { requestId: 'request', headers: headers() });
    assert.equal(
      capture.capture('page', 'Network.responseReceivedExtraInfo', { requestId: 'request', statusCode: 200 })
        ?.accessToken,
      cors ? token : undefined,
    );
  }
});
