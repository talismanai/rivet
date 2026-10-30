import { strict as assert } from 'node:assert';
import { it } from 'node:test';
import { HttpAuthenticationSessions } from '@ironclad/rivet-core';
import { syncHttpAuthenticationSessions } from '../src/utils/syncHttpAuthenticationSessions';

it('sends only live sessions for the selected project and preserves their original expiry', () => {
  const sessions = new HttpAuthenticationSessions();
  const expiresAt = Date.now() + 60000;
  const token = { accessToken: 'fixture.jwt.token', expiresIn: 60 };
  sessions.forProject('one').set('httpAuthentication:fixture', { token, expiresAt });
  sessions.forProject('one').set('httpAuthentication:expired', { token, expiresAt: Date.now() - 1 });
  sessions.forProject('one').set('other-execution-data', { token, expiresAt });
  sessions.forProject('two').set('httpAuthentication:other', { token, expiresAt });
  const messages: unknown[] = [];
  const socket = {
    readyState: 1,
    send: (value: string) => {
      messages.push(JSON.parse(value));
    },
  };
  syncHttpAuthenticationSessions(socket, sessions, ['one']);
  assert.deepEqual(messages, [
    {
      type: 'http-authentication-session',
      data: { projectId: 'one', cacheKey: 'httpAuthentication:fixture', token, expiresAt },
    },
  ]);
  socket.readyState = 3;
  syncHttpAuthenticationSessions(socket, sessions, ['one']);
  assert.equal(messages.length, 1);
});

it('represents sessions without a declared lifetime explicitly without extending an expiry', () => {
  const sessions = new HttpAuthenticationSessions();
  sessions
    .forProject('one')
    .set('httpAuthentication:fixture', { token: { accessToken: 'fixture.jwt.token' }, expiresAt: Infinity });
  let message: any;
  syncHttpAuthenticationSessions(
    {
      readyState: 1,
      send: (value) => {
        message = JSON.parse(value);
      },
    },
    sessions,
    ['one'],
  );
  assert.equal(message.data.expiresAt, null);
});

it('keeps a successful local session when the debugger fails during synchronization', () => {
  const sessions = new HttpAuthenticationSessions();
  const session = { token: { accessToken: 'fixture.jwt.token' }, expiresAt: Infinity };
  sessions.forProject('one').set('httpAuthentication:fixture', session);
  assert.doesNotThrow(() =>
    syncHttpAuthenticationSessions(
      {
        readyState: 1,
        send: () => {
          throw new Error('Connection closed');
        },
      },
      sessions,
      ['one'],
    ),
  );
  assert.equal(sessions.forProject('one').get('httpAuthentication:fixture'), session);
});
