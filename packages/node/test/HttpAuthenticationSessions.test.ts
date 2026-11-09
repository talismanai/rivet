import { it, mock } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  emptyNodeGraph,
  HttpCallNodeImpl,
  ContextNodeImpl,
  type Project,
  type ProjectId,
  type PortId,
} from '@ironclad/rivet-core';
import { coreCreateProcessor } from '../../core/src/api/createProcessor.js';
import { createProcessor } from '../src/api.js';
import type { RivetDebuggerServer } from '../src/debugger.js';

function projectFixture(): Project {
  const node = HttpCallNodeImpl.create();
  node.data.url = 'https://api.example.com/private';
  node.data.authenticationUrl = 'https://login.example.com/login';
  const graph = emptyNodeGraph();
  graph.nodes.push(node);
  return {
    metadata: { id: 'fixture-project' as ProjectId, title: 'Fixture', description: '' },
    graphs: { [graph.metadata!.id!]: graph },
  };
}

for (const [name, create] of [
  ['core', coreCreateProcessor],
  ['node', createProcessor],
] as const) {
  void it(`${name} mirrors fresh and cached JWTs into the running context and notifies the host`, async () => {
    const project = projectFixture();
    const graph = Object.values(project.graphs)[0]!;
    const http = graph.nodes[0] as ReturnType<typeof HttpCallNodeImpl.create>;
    http.data.authenticationTokenContextKey = 'jwt';
    const reader = ContextNodeImpl.create();
    reader.data.id = 'jwt';
    reader.data.useDefaultValueInput = true;
    graph.nodes.push(reader);
    graph.connections.push({
      outputNodeId: http.id,
      outputId: 'res_body' as PortId,
      inputNodeId: reader.id,
      inputId: 'default' as PortId,
    });
    const authenticate = mock.fn(async () => ({ accessToken: 'fixture.jwt.token', expiresIn: 3600 }));
    const notify = mock.fn((_key: string, _token: { accessToken: string }) => {});
    const options = {
      graph: graph.metadata!.id!,
      requestHttpAuthentication: authenticate,
      onHttpAuthenticationToken: notify,
      httpAuthenticationCache: new Map<string, unknown>(),
      httpRequest: async (_url: string, init: RequestInit) =>
        new Headers(init.headers).has('authorization')
          ? Response.json({ ok: true })
          : new Response('', { status: 401 }),
    };
    for (let i = 0; i < 2; i++) {
      const instance = create(project, options);
      let read: unknown;
      instance.processor.on('nodeFinish', ({ node, outputs }) => {
        if (node.id === reader.id) read = outputs.data;
      });
      await instance.run();
      assert.deepEqual(read, { type: 'string', value: 'Bearer fixture.jwt.token' });
      assert.equal(instance.contextValues.jwt!.value, 'Bearer fixture.jwt.token');
    }
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(notify.mock.callCount(), 2);
    assert.equal(notify.mock.calls[0]!.arguments[0], 'jwt');
  });

  void it(`${name} processors reuse a host OAuth session after graph edits and a new run`, async () => {
    const project = projectFixture();
    const authenticate = mock.fn(async () => ({ accessToken: 'fixture.jwt.token', expiresIn: 3600 }));
    const httpRequest = mock.fn(async (_url: string, init: RequestInit) =>
      new Headers(init.headers).get('authorization') === 'Bearer fixture.jwt.token'
        ? Response.json({ ok: true })
        : new Response('Sign in', { status: 401 }),
    );
    const options = {
      graph: Object.keys(project.graphs)[0],
      requestHttpAuthentication: authenticate,
      httpAuthenticationCache: new Map<string, unknown>(),
      httpRequest,
    };
    await create(project, options).run();
    const edited = { ...project, graphs: { ...project.graphs } };
    await create(edited, options).run();
    assert.equal(authenticate.mock.callCount(), 1);
    assert.equal(httpRequest.mock.callCount(), 3);
    assert.equal(
      new Headers(httpRequest.mock.calls[2]!.arguments[1].headers).get('authorization'),
      'Bearer fixture.jwt.token',
    );
  });
}

void it('Node processors obtain the persistent project session from their debugger automatically', async () => {
  const project = projectFixture();
  (
    Object.values(project.graphs)[0]!.nodes[0] as ReturnType<typeof HttpCallNodeImpl.create>
  ).data.authenticationTokenContextKey = 'jwt';
  const cache = new Map<string, unknown>();
  const authenticate = mock.fn(async () => ({ accessToken: 'fixture.jwt.token', expiresIn: 3600 }));
  const getCache = mock.fn((_processor: unknown, projectId: string) => {
    assert.equal(projectId, project.metadata.id);
    return cache;
  });
  const debuggerServer = {
    attach: () => {},
    requestHttpAuthentication: authenticate,
    getHttpAuthenticationCache: getCache,
    publishHttpAuthenticationToken: mock.fn(
      (_processor: unknown, projectId: string, key: string, token: { accessToken: string }) => {
        assert.equal(projectId, project.metadata.id);
        assert.equal(key, 'jwt');
        assert.equal(token.accessToken, 'fixture.jwt.token');
      },
    ),
  } as unknown as RivetDebuggerServer;
  const httpRequest = mock.fn(async (_url: string, init: RequestInit) =>
    new Headers(init.headers).get('authorization') === 'Bearer fixture.jwt.token'
      ? Response.json({ ok: true })
      : new Response('Sign in', { status: 401 }),
  );
  const options = { graph: Object.keys(project.graphs)[0], remoteDebugger: debuggerServer, httpRequest };
  await createProcessor(project, options).run();
  await createProcessor({ ...project, graphs: { ...project.graphs } }, options).run();
  assert.equal(getCache.mock.callCount(), 2);
  assert.equal(authenticate.mock.callCount(), 1);
  assert.equal(httpRequest.mock.callCount(), 3);
  assert.equal((debuggerServer.publishHttpAuthenticationToken as ReturnType<typeof mock.fn>).mock.callCount(), 2);
});
