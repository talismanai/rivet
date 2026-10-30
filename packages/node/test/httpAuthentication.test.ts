import { it, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { EventEmitter } from 'node:events';
import { type WebSocketServer, type WebSocket } from 'ws';
import {
  type GraphProcessor,
  HttpAuthenticationSessions,
  signInWithHttpAuthentication,
  fetchWithHttpAuthentication,
} from '@ironclad/rivet-core';
import { syncHttpAuthenticationSessions } from '../../app/src/utils/syncHttpAuthenticationSessions';
import { startDebuggerServer } from '../src/debugger.js';

/* eslint-disable @typescript-eslint/no-floating-promises */

class Client extends EventEmitter {
  readyState = 1;
  messages: { message: string; data: { requestId: string } }[] = [];
  send(data: string) {
    this.messages.push(JSON.parse(data));
  }
  respond(requestId: string, result: unknown = false) {
    this.emit(
      'message',
      Buffer.from(JSON.stringify({ type: 'http-authentication-response', data: { requestId, result } })),
    );
  }
}

function setup(options: NonNullable<Parameters<typeof startDebuggerServer>[0]> = {}) {
  const server = Object.assign(new EventEmitter(), { clients: new Set<WebSocket>() });
  const debuggerServer = startDebuggerServer({ ...options, server: server as unknown as WebSocketServer });
  const connect = (supportsAuthentication = true) => {
    const client = new Client();
    server.clients.add(client as unknown as WebSocket);
    server.emit('connection', client);
    if (supportsAuthentication) {
      client.emit('message', Buffer.from(JSON.stringify({ type: 'http-authentication-supported', data: {} })));
    }
    client.messages = [];
    return client;
  };
  const controller = new AbortController();
  const request = () =>
    debuggerServer.requestHttpAuthentication!(
      {} as GraphProcessor,
      {
        requestUrl: 'https://api.example.com/private',
        authenticationUrl: 'https://api.example.com/login',
        status: 401,
      },
      controller.signal,
    );
  return { connect, request, controller, debuggerServer };
}

describe('Debugger HTTP authentication', () => {
  it('reuses a settings login on a Node connection established later without another prompt', async () => {
    const sessions = new HttpAuthenticationSessions();
    const url = 'https://api.example.com';
    const init = { headers: { authorization: 'configured-api-key' } };
    const options = {
      loginUrl: 'https://login.example.com',
      tokenSource: 'authorization-header' as const,
      tokenContextKey: 'jwt',
      preferCachedToken: true,
    };
    await signInWithHttpAuthentication(
      url,
      init,
      {
        signal: new AbortController().signal,
        httpAuthenticationCache: sessions.forProject('one'),
        requestHttpAuthentication: async () => ({ accessToken: 'manual.jwt.token', expiresIn: 60 }),
      },
      options,
    );
    const { connect, debuggerServer } = setup();
    const client = connect();
    syncHttpAuthenticationSessions(
      {
        readyState: 1,
        send: (value) => {
          client.emit('message', Buffer.from(value));
        },
      },
      sessions,
      ['one'],
    );
    const contextValues = {};
    const response = await fetchWithHttpAuthentication(
      `${url}/private`,
      init,
      {
        executor: 'nodejs',
        signal: new AbortController().signal,
        contextValues,
        httpAuthenticationCache: debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'one'),
        requestHttpAuthentication: async () => {
          assert.fail('A manually authenticated session must not prompt again');
        },
        httpRequest: async (_url, request) => {
          assert.equal(new Headers(request.headers).get('authorization'), 'Bearer manual.jwt.token');
          return Response.json({ ok: true });
        },
      },
      options,
    );
    assert.equal(response.status, 200);
    assert.deepEqual(contextValues, { jwt: { type: 'string', value: 'Bearer manual.jwt.token' } });
  });

  it('imports manually authenticated sessions only into the owning client and preserves expiry', () => {
    const { connect, debuggerServer } = setup({
      getClientsForProcessor: (processor) => [(processor as unknown as { client: WebSocket }).client],
    });
    const owner = connect();
    const other = connect();
    const token = { accessToken: 'manual.jwt.token', expiresIn: 60 };
    const data = { projectId: 'one', cacheKey: 'httpAuthentication:fixture', token, expiresAt: Date.now() + 60000 };
    owner.emit('message', Buffer.from(JSON.stringify({ type: 'http-authentication-session', data })));
    const cache = debuggerServer.getHttpAuthenticationCache!({ client: owner } as unknown as GraphProcessor, 'one')!;
    assert.deepEqual(cache.get(data.cacheKey), { token, expiresAt: data.expiresAt });
    assert.equal(
      debuggerServer.getHttpAuthenticationCache!({ client: other } as unknown as GraphProcessor, 'one')!.size,
      0,
    );
    owner.emit(
      'message',
      Buffer.from(
        JSON.stringify({
          type: 'http-authentication-session',
          data: { ...data, cacheKey: 'httpAuthentication:expired', expiresAt: Date.now() - 1 },
        }),
      ),
    );
    owner.emit(
      'message',
      Buffer.from(
        JSON.stringify({
          type: 'http-authentication-session',
          data: { ...data, cacheKey: 'httpAuthentication:invalid', token: { accessToken: 'bad\ntoken' } },
        }),
      ),
    );
    assert.equal(cache.size, 1);
    owner.emit(
      'message',
      Buffer.from(
        JSON.stringify({
          type: 'http-authentication-session',
          data: {
            ...data,
            cacheKey: 'httpAuthentication:unlimited',
            token: { accessToken: 'no.expiry.token' },
            expiresAt: null,
          },
        }),
      ),
    );
    assert.equal((cache.get('httpAuthentication:unlimited') as { expiresAt: number }).expiresAt, Infinity);
    other.readyState = 3;
  });

  it('sends mirrored JWTs only to the processor owner, without broadcasting to other clients', () => {
    const { connect, debuggerServer } = setup({
      getClientsForProcessor: (processor) => [(processor as unknown as { client: WebSocket }).client],
    });
    const owner = connect();
    const other = connect();
    const processor = { client: owner } as unknown as GraphProcessor;
    debuggerServer.publishHttpAuthenticationToken!(processor, 'project-one', 'jwt', {
      accessToken: 'fixture.jwt.token',
    });
    assert.deepEqual(owner.messages, [
      {
        message: 'http-authentication-token',
        data: {
          projectId: 'project-one',
          contextKey: 'jwt',
          token: { accessToken: 'fixture.jwt.token' },
        },
      },
    ]);
    assert.equal(other.messages.length, 0);
    owner.readyState = 3;
    debuggerServer.publishHttpAuthenticationToken!(processor, 'project-one', 'jwt', {
      accessToken: 'fixture.jwt.token',
    });
    assert.equal(owner.messages.length, 1);
    assert.equal(other.messages.length, 0);
  });
  it('reuses a project cache for new processors on the same connection', () => {
    const { connect, debuggerServer } = setup();
    connect();
    const first = debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'one');
    const second = debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'one');
    assert.ok(first);
    first.set('token', 'fixture');
    assert.equal(second, first);
    assert.equal(debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'two')!.size, 0);
  });

  it('does not transfer a running processor token or login prompt to another client after disconnect', async () => {
    const { connect, debuggerServer, controller } = setup();
    const owner = connect();
    const other = connect();
    const processor = {} as GraphProcessor;
    assert.ok(debuggerServer.getHttpAuthenticationCache!(processor, 'one'));
    owner.readyState = 3;
    owner.emit('close');
    debuggerServer.publishHttpAuthenticationToken!(processor, 'one', 'jwt', { accessToken: 'owner.jwt.token' });
    assert.equal(
      await debuggerServer.requestHttpAuthentication!(
        processor,
        {
          requestUrl: 'https://api.example/private',
          authenticationUrl: 'https://platform.example/login',
          status: 401,
        },
        controller.signal,
      ),
      false,
    );
    assert.equal(other.messages.length, 0);
    // A later run may explicitly select the currently connected client.
    assert.ok(debuggerServer.getHttpAuthenticationCache!(processor, 'one'));
    debuggerServer.publishHttpAuthenticationToken!(processor, 'one', 'jwt', { accessToken: 'new.jwt.token' });
    assert.equal(other.messages.length, 1);
  });

  it('clears closed projects while keeping sessions for other open projects', () => {
    const { connect, debuggerServer } = setup();
    const client = connect();
    const cache = debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'one')!;
    const other = debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'two')!;
    cache.set('token', 'fixture');
    other.set('token', 'other');
    client.emit(
      'message',
      Buffer.from(JSON.stringify({ type: 'http-authentication-projects', data: { projectIds: ['two'] } })),
    );
    assert.equal(cache.size, 0);
    assert.equal(other.get('token'), 'other');
    assert.notEqual(debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'one'), cache);
  });

  it('isolates session credentials between debugger clients and clears disconnected owners', () => {
    const { connect, debuggerServer } = setup({
      getClientsForProcessor: (processor) => [(processor as unknown as { client: WebSocket }).client],
    });
    const first = connect();
    const second = connect();
    const processor = (client: Client) => ({ client }) as unknown as GraphProcessor;
    const cache = debuggerServer.getHttpAuthenticationCache!(processor(first), 'one')!;
    const other = debuggerServer.getHttpAuthenticationCache!(processor(second), 'one')!;
    cache.set('token', 'fixture');
    other.set('token', 'other');
    assert.notEqual(cache, other);
    first.readyState = 3;
    first.emit('close');
    assert.equal(cache.size, 0);
    assert.equal(other.get('token'), 'other');
    assert.equal(debuggerServer.getHttpAuthenticationCache!(processor(first), 'one'), undefined);
  });

  it('does not retain sessions for clients without interactive authentication support', () => {
    const { connect, debuggerServer } = setup();
    connect(false);
    assert.equal(debuggerServer.getHttpAuthenticationCache!({} as GraphProcessor, 'one'), undefined);
  });

  it('preserves the original response when no desktop client is connected', async () => {
    assert.equal(await setup().request(), false);
  });

  it('does not wait for older debugger clients that cannot display a sign-in window', async () => {
    const { connect, request } = setup();
    const client = connect(false);
    assert.equal(await request(), false);
    assert.equal(client.messages.length, 0);
  });

  it('waits for the selected client to close the dialog, without claiming Node has browser cookies', async () => {
    const { connect, request } = setup();
    const client = connect();
    const completion = request();
    assert.equal(client.messages[0]!.message, 'http-authentication');
    client.respond(client.messages[0]!.data.requestId);
    assert.equal(await completion, false);
  });

  it('does not allow another debugger client to complete an authentication request', async () => {
    const { connect, request } = setup();
    const selected = connect();
    const other = connect();
    let completed = false;
    const completion = request().then(() => {
      completed = true;
    });
    const requestId = selected.messages[0]!.data.requestId;
    other.respond(requestId);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(completed, false);
    assert.equal(other.messages.length, 0);
    selected.respond(requestId);
    await completion;
    assert.equal(completed, true);
  });

  it('returns the captured platform token to the requesting Node executor', async () => {
    const { connect, request } = setup();
    const client = connect();
    const completion = request();
    const token = { accessToken: 'test.jwt.token', expiresIn: 3600 };
    client.respond(client.messages[0]!.data.requestId, token);
    assert.deepEqual(await completion, token);
  });

  it('rejects malformed bearer credentials received from a debugger client', async () => {
    const { connect, request } = setup();
    const client = connect();
    const completion = request();
    client.respond(client.messages[0]!.data.requestId, { accessToken: 'bad\r\nHeader: value' });
    assert.equal(await completion, false);
  });

  it('releases a request when the selected client disconnects', async () => {
    const { connect, request } = setup();
    const client = connect();
    const completion = request();
    client.emit('close');
    assert.equal(await completion, false);
  });

  it('closes the remote dialog when graph execution is aborted', async () => {
    const { connect, request, controller } = setup();
    const client = connect();
    const completion = assert.rejects(request(), /abort/i);
    controller.abort();
    await completion;
    assert.deepEqual(client.messages[1], {
      message: 'http-authentication-cancel',
      data: { requestId: client.messages[0]!.data.requestId },
    });
    // Late responses are harmless after cancellation has removed the pending request.
    client.respond(client.messages[0]!.data.requestId);
  });
});
