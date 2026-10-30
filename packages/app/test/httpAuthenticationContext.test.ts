import { strict as assert } from 'node:assert';
import { it } from 'node:test';
import { withHttpAuthenticationToken } from '../src/utils/httpAuthenticationContext';

it('copies a JWT as a secret string while preserving other context entries and replacing the chosen key', () => {
  const other = { value: { type: 'string' as const, value: 'keep' }, secret: false };
  const current = { other, jwt: { value: { type: 'number' as const, value: 3 }, secret: false } };
  const result = withHttpAuthenticationToken(current, ' jwt ', { accessToken: 'fixture.jwt.token' });
  assert.deepEqual(result.jwt, { value: { type: 'string', value: 'Bearer fixture.jwt.token' }, secret: true });
  assert.equal(result.other, other);
  assert.equal(current.jwt.value.value, 3);
  assert.equal(withHttpAuthenticationToken(result, 'jwt', { accessToken: 'fixture.jwt.token' }), result);
  assert.equal(
    withHttpAuthenticationToken(result, 'jwt', { accessToken: 'new.jwt.token' }).jwt!.value.value,
    'Bearer new.jwt.token',
  );
});

it('ignores missing keys and invalid token messages without writing credentials', () => {
  const current = {};
  for (const [key, token] of [
    [undefined, { accessToken: 'fixture.jwt.token' }],
    [' ', { accessToken: 'fixture.jwt.token' }],
    ['jwt', false],
    ['jwt', { accessToken: 'bad\ntoken' }],
  ]) {
    assert.equal(withHttpAuthenticationToken(current, key, token), current);
  }
});
