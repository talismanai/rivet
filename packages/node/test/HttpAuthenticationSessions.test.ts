import { it, mock } from 'node:test';
import { strict as assert } from 'node:assert';
import { emptyNodeGraph, HttpCallNodeImpl, type Project, type ProjectId } from '@ironclad/rivet-core';
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
});
