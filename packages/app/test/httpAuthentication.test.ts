import { it } from 'node:test';
import { strict as assert } from 'node:assert';

it('declines authentication outside Tauri instead of turning a 401 response into an error', async () => {
  // The Tauri v1 window module expects a browser global even when the native bridge is unavailable.
  const previousWindow = globalThis.window;
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'window', { value: {}, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'navigator', {
    value: { appVersion: 'Linux', userAgent: 'Browser' },
    configurable: true,
  });
  try {
    const { requestHttpAuthentication } = await import('../src/utils/httpAuthentication');
    assert.equal(
      await requestHttpAuthentication(
        { requestUrl: 'https://example.com', authenticationUrl: 'https://example.com/login', status: 401 },
        new AbortController().signal,
      ),
      false,
    );
  } finally {
    if (previousWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
    else globalThis.window = previousWindow;
    if (previousNavigator) Object.defineProperty(globalThis, 'navigator', previousNavigator);
    else Reflect.deleteProperty(globalThis, 'navigator');
  }
});
