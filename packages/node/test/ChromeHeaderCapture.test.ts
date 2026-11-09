import { strict as assert } from 'node:assert';
import { it } from 'node:test';
import { ChromeHeaderCapture } from '../src/auth/ChromeHeaderCapture.js';

const jwt = (source: string) =>
  `e30.${Buffer.from(JSON.stringify({ source, exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url')}.signature`;
const first = jwt('first');
const second = jwt('second');
const headers = (value = first) => ({ Authorization: `Bearer ${value}` });

void it('captures a JWT immediately without a response, request ID, URL, or initiating page', () => {
  const capture = new ChromeHeaderCapture(() => {});
  assert.equal(capture.capture('Network.requestWillBeSent', { request: { headers: headers() } })?.accessToken, first);
});

void it('captures wire headers even before the main request event, including worker requests', () => {
  const capture = new ChromeHeaderCapture(() => {});
  assert.equal(
    capture.capture('Network.requestWillBeSentExtraInfo', { headers: { authorization: `bearer ${first}` } })
      ?.accessToken,
    first,
  );
});

void it('keeps the first JWT and never replaces it with tokens from later requests or redirects', () => {
  for (const method of ['Network.requestWillBeSent', 'Network.requestWillBeSentExtraInfo']) {
    const capture = new ChromeHeaderCapture(() => {});
    const params = method.endsWith('ExtraInfo') ? { headers: headers() } : { request: { headers: headers() } };
    assert.equal(capture.capture(method, params)?.accessToken, first);
    assert.equal(capture.capture('Network.requestWillBeSentExtraInfo', { headers: headers(second) }), undefined);
    assert.equal(capture.capture('Network.requestWillBeSent', { request: { headers: headers(second) } }), undefined);
  }
});

void it('does not let failed responses or CORS errors prevent later header capture', () => {
  const capture = new ChromeHeaderCapture(() => {});
  for (const method of ['Network.responseReceived', 'Network.responseReceivedExtraInfo', 'Network.loadingFailed']) {
    assert.equal(capture.capture(method, {}), undefined);
  }
  assert.equal(capture.capture('Network.requestWillBeSentExtraInfo', { headers: headers() })?.accessToken, first);
});

void it('skips malformed or expired credentials and captures the first valid JWT afterward', () => {
  const progress: unknown[] = [];
  const capture = new ChromeHeaderCapture((event) => progress.push(event));
  for (const value of [
    '',
    'Basic abc',
    'Bearer opaque',
    'Bearer invalid.jwt.token',
    'Bearer e30.eyJleHAiOjF9.signature',
  ]) {
    assert.equal(
      capture.capture('Network.requestWillBeSentExtraInfo', { headers: { Authorization: value } }),
      undefined,
    );
  }
  assert.equal(capture.capture('Network.requestWillBeSent', { request: { headers: headers() } })?.accessToken, first);
  assert.ok(!JSON.stringify(progress).includes(first));
});

void it('also captures outgoing WebSocket handshake Authorization headers', () => {
  const capture = new ChromeHeaderCapture(() => {});
  assert.equal(
    capture.capture('Network.webSocketWillSendHandshakeRequest', { request: { headers: headers() } })?.accessToken,
    first,
  );
});

void it('ignores unrelated events and response headers', () => {
  const capture = new ChromeHeaderCapture(() => {});
  assert.equal(capture.capture('Network.responseReceivedExtraInfo', { headers: headers() }), undefined);
  assert.equal(capture.capture('Page.frameNavigated', { headers: headers() }), undefined);
  assert.equal(capture.capture('Network.requestWillBeSent', {}), undefined);
});
