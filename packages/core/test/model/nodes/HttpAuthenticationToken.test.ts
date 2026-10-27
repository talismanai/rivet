import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { parseHttpAuthenticationToken, isHttpAuthenticationToken } from '../../../src/utils/httpAuthenticationToken.js';

void describe('Platform JWT callback', () => {
  void it('extracts only the platform token and expiry from the supplied JSON format', () => {
    assert.deepEqual(
      parseHttpAuthenticationToken({
        data: { access_token: 'fixture.jwt.token', expires_in: 3600, user: { email: 'fixture@example.com' } },
      }),
      { accessToken: 'fixture.jwt.token', expiresIn: 3600 },
    );
  });
  void it('rejects missing tokens, invalid expiry and header injection without exposing secrets in errors', () => {
    for (const body of [
      null,
      {},
      { data: {} },
      { data: { access_token: '' } },
      { data: { access_token: 'secret\r\nHeader: injected' } },
      { data: { access_token: 'secret', expires_in: -1 } },
    ]) {
      assert.throws(
        () => parseHttpAuthenticationToken(body),
        (error: Error) => !error.message.includes('secret'),
      );
    }
    assert.equal(isHttpAuthenticationToken({ accessToken: 'abc', expiresIn: Infinity }), false);
  });
});
