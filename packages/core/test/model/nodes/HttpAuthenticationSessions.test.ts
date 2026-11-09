import { it } from 'node:test';
import { strict as assert } from 'node:assert';
import { HttpAuthenticationSessions } from '../../../src/utils/HttpAuthenticationSessions.js';

void it('retains the same in-memory cache across executions and isolates projects', () => {
  const sessions = new HttpAuthenticationSessions();
  const cache = sessions.forProject('one');
  cache.set('session', { token: 'fixture' });
  assert.equal(sessions.forProject('one'), cache);
  assert.equal(sessions.forProject('two').size, 0);
});

void it('clears references to closed projects and does not reuse them on reopen', () => {
  const sessions = new HttpAuthenticationSessions();
  const closed = sessions.forProject('one');
  const open = sessions.forProject('two');
  closed.set('session', 'fixture');
  open.set('session', 'other');
  sessions.retain(['two']);
  assert.equal(closed.size, 0);
  assert.notEqual(sessions.forProject('one'), closed);
  assert.equal(sessions.forProject('one').size, 0);
  assert.equal(sessions.forProject('two'), open);
  assert.equal(open.get('session'), 'other');
});

void it('clears all cached credentials when the host session ends', () => {
  const sessions = new HttpAuthenticationSessions();
  const cache = sessions.forProject('one');
  cache.set('session', 'fixture');
  sessions.clear();
  assert.equal(cache.size, 0);
  assert.notEqual(sessions.forProject('one'), cache);
});
