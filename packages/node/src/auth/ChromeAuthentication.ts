import { spawn, type ChildProcess } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { delimiter, join, isAbsolute } from 'node:path';
import { tmpdir, platform } from 'node:os';
import type { Readable, Writable } from 'node:stream';
import {
  parseHttpAuthenticationToken,
  isHttpAuthenticationToken,
  type HttpAuthenticationToken,
  type HttpAuthenticationRequest,
  type HttpAuthenticationResult,
} from '@ironclad/rivet-core';

const oauthErrors = {
  browser: 'Could not launch Chrome/Chromium.',
  connection: 'Chrome closed its debugging connection before authentication completed.',
  command: 'Chrome could not complete an OAuth response interception command.',
  timeout: 'OAuth sign-in timed out after 10 minutes.',
  callbackStatus: 'The platform OAuth callback returned an unsuccessful HTTP status.',
  callbackLoad: 'The platform OAuth callback response could not be loaded.',
  callbackSize: 'The platform OAuth callback response exceeds the 1 MiB limit.',
  callbackJson: 'The platform OAuth callback did not return valid JSON.',
  callbackToken:
    'The platform OAuth callback JSON must contain a valid data.access_token and optional positive expires_in.',
} as const;

export class OAuthAuthenticationError extends Error {
  constructor(
    readonly code: keyof typeof oauthErrors,
    status?: number,
  ) {
    super(
      `${oauthErrors[code]}${Number.isInteger(status) && status! >= 100 && status! <= 599 ? ` HTTP ${status}.` : ''}`,
    );
  }
}

/** Only predefined messages may cross the helper boundary; never include callback bodies or URLs. */
export function getOAuthAuthenticationErrorMessage(error: unknown): string {
  return error instanceof OAuthAuthenticationError
    ? error.message
    : 'OAuth sign-in failed before Rivet could capture an authentication token. Verify the configured login and API or callback URLs.';
}

// CDP is carried over private inherited pipes, never an exposed debugging port.
type Message = { id?: number; sessionId?: string; method?: string; params?: any; result?: any; error?: unknown };

export class ChromeDebuggingPipe {
  private disposed = false;
  private nextId = 1;
  private buffer = '';
  private readonly pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>();
  onEvent: (message: Message) => void = () => {};
  private readonly read = (chunk: string) => {
    this.buffer += chunk;
    if (this.buffer.length > 4 * 1024 * 1024) {
      this.dispose();
      return;
    }
    let boundary;
    while ((boundary = this.buffer.indexOf('\0')) >= 0) {
      const raw = this.buffer.slice(0, boundary);
      this.buffer = this.buffer.slice(boundary + 1);
      if (!raw) continue;
      let message: Message;
      try {
        message = JSON.parse(raw);
      } catch {
        continue;
      }
      if (message.id !== undefined) {
        const pending = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) pending?.reject(new OAuthAuthenticationError('command'));
        else pending?.resolve(message.result);
      } else this.onEvent(message);
    }
  };
  private readonly close = () => this.dispose();

  constructor(
    private readonly output: Writable,
    private readonly input: Readable,
  ) {
    input.setEncoding('utf8');
    input.on('data', this.read);
    input.on('close', this.close);
    input.on('error', this.close);
    output.on('error', this.close);
  }

  command(method: string, params: object = {}, sessionId?: string): Promise<any> {
    if (this.disposed) return Promise.reject(new OAuthAuthenticationError('connection'));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.output.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0', (error) => {
        if (error) {
          this.pending.delete(id);
          reject(new OAuthAuthenticationError('connection'));
        }
      });
    });
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.input.off('data', this.read);
    for (const pending of this.pending.values()) pending.reject(new OAuthAuthenticationError('connection'));
    this.pending.clear();
  }
}

export function matchesOAuthCallback(actual: string, expected: string): boolean {
  try {
    const url = new URL(actual);
    const callback = new URL(expected);
    return (
      url.origin === callback.origin &&
      url.pathname === callback.pathname &&
      [...callback.searchParams].every(([key, value]) => url.searchParams.get(key) === value)
    );
  } catch {
    return false;
  }
}

/** Inspect only request headers; JWT signature validation remains the destination API's responsibility. */
export function bearerTokenFromHeaders(headers: Record<string, unknown>): HttpAuthenticationToken | undefined {
  const authorization = Object.entries(headers).find(([key]) => key.toLowerCase() === 'authorization')?.[1];
  if (typeof authorization !== 'string') return undefined;
  const accessToken = /^Bearer\s+(\S+)\s*$/i.exec(authorization)?.[1];
  if (!accessToken || accessToken.split('.').length !== 3 || !isHttpAuthenticationToken({ accessToken }))
    return undefined;
  try {
    const claims = JSON.parse(Buffer.from(accessToken.split('.')[1]!, 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object') return undefined;
    if (claims.exp !== undefined) {
      if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) return undefined;
      const expiresIn = Math.floor(claims.exp - Date.now() / 1000);
      return expiresIn > 0 ? { accessToken, expiresIn } : undefined;
    }
    return { accessToken };
  } catch {
    return undefined;
  }
}

function webUrl(value: string): URL {
  const url = new URL(value);
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password)
    throw new Error('OAuth URLs must be HTTP or HTTPS URLs without embedded credentials');
  return url;
}

async function findChrome(): Promise<string> {
  const override = process.env.RIVET_CHROME_PATH;
  if (override && !isAbsolute(override)) throw new Error('RIVET_CHROME_PATH must be an absolute executable path');
  const candidates = override
    ? [override]
    : [
        ...(platform() === 'darwin'
          ? [
              '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
              '/Applications/Chromium.app/Contents/MacOS/Chromium',
            ]
          : []),
        ...(platform() === 'win32'
          ? [process.env.PROGRAMFILES, process.env['PROGRAMFILES(X86)'], process.env.LOCALAPPDATA]
              .filter((path): path is string => !!path)
              .map((path) => join(path, 'Google', 'Chrome', 'Application', 'chrome.exe'))
          : []),
        ...(process.env.PATH ?? '')
          .split(delimiter)
          .filter(Boolean)
          .flatMap((path) =>
            ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'].map((name) => join(path, name)),
          ),
      ];
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      /* try the next installation */
    }
  }
  throw new Error('Chrome/Chromium was not found. Install it or set RIVET_CHROME_PATH.');
}

async function waitForExit(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const finish = () => {
      clearTimeout(timer);
      child.off('exit', finish);
      resolve();
    };
    const timer = setTimeout(finish, 2000);
    child.once('exit', finish);
  });
}

/** Launch an isolated browser and capture a callback JSON token or a Bearer header sent to the exact API origin. */
export async function authenticateInChrome(
  request: HttpAuthenticationRequest,
  signal: AbortSignal,
  options: { onCallbackError?: (error: OAuthAuthenticationError) => void } = {},
): Promise<HttpAuthenticationResult> {
  signal.throwIfAborted();
  const login = webUrl(request.authenticationUrl);
  const callbackUrl = request.callbackUrl || login.searchParams.get('redirect_uri');
  const headerCapture = request.tokenSource === 'authorization-header' || (!request.tokenSource && !callbackUrl);
  const callback = headerCapture ? undefined : webUrl(callbackUrl || '');
  const apiOrigin = webUrl(request.requestUrl).origin;
  const executable = await findChrome();
  signal.throwIfAborted();
  const profile = await mkdtemp(join(tmpdir(), 'rivet-oauth-'));
  let child: ChildProcess | undefined;
  let pipe: ChromeDebuggingPipe | undefined;
  let sessionId: string | undefined;
  let loginWindowClosed = false;
  let diagnosticClosed: (() => void) | undefined;
  let abort = () => {};
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    signal.throwIfAborted();
    child = spawn(
      executable,
      [
        '--remote-debugging-pipe',
        `--user-data-dir=${profile}`,
        '--no-first-run',
        '--no-default-browser-check',
        'about:blank',
      ],
      {
        stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'],
      },
    );
    // Register before constructing the pipes, including failed-spawn paths.
    child.on('error', () => {});
    pipe = new ChromeDebuggingPipe(child.stdio[3] as Writable, child.stdio[4] as Readable);
    const cdp = pipe;
    let frameId: string | undefined;
    let loginTargetId: string | undefined;
    const apiRequests = new Set<string>();
    const successfulRequests = new Set<string>();
    const headerTokens = new Map<string, HttpAuthenticationToken>();
    const completion = new Promise<HttpAuthenticationResult>((resolve, reject) => {
      abort = () => reject(new Error('OAuth authentication aborted'));
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
      timer = setTimeout(() => reject(new OAuthAuthenticationError('timeout')), 10 * 60 * 1000);
      child!.once('error', () => reject(new OAuthAuthenticationError('browser')));
      child!.once('exit', () => resolve(false));
      cdp.onEvent = (message) => {
        if (
          (message.method === 'Target.targetDestroyed' && message.params?.targetId === loginTargetId) ||
          (message.method === 'Target.detachedFromTarget' && message.params?.sessionId === sessionId)
        ) {
          loginWindowClosed = true;
          diagnosticClosed?.();
          resolve(false);
          return;
        }
        if (message.sessionId !== sessionId) return;
        const params = message.params;
        if (headerCapture) {
          const accept = (id: string) => {
            const token = headerTokens.get(id);
            if (token && apiRequests.has(id) && successfulRequests.has(id)) resolve(token);
          };
          if (message.method === 'Network.requestWillBeSent') {
            try {
              if (new URL(params.request.url).origin === apiOrigin) {
                apiRequests.add(params.requestId);
                const token = bearerTokenFromHeaders(params.request.headers ?? {});
                if (token) headerTokens.set(params.requestId, token);
                accept(params.requestId);
              } else {
                apiRequests.delete(params.requestId);
                successfulRequests.delete(params.requestId);
                headerTokens.delete(params.requestId);
              }
            } catch {
              /* ignore non-web requests */
            }
          }
          if (message.method === 'Network.requestWillBeSentExtraInfo') {
            const token = bearerTokenFromHeaders(params.headers ?? {});
            if (token) headerTokens.set(params.requestId, token);
            accept(params.requestId);
          }
          if (message.method === 'Network.responseReceived') {
            try {
              if (
                new URL(params.response.url).origin === apiOrigin &&
                params.response.status >= 200 &&
                params.response.status < 300
              ) {
                successfulRequests.add(params.requestId);
                accept(params.requestId);
              }
            } catch {
              /* ignore non-web responses */
            }
          }
          if (message.method === 'Network.loadingFailed') {
            apiRequests.delete(params.requestId);
            successfulRequests.delete(params.requestId);
            headerTokens.delete(params.requestId);
          }
          // Bound metadata collected during long interactive logins.
          if (headerTokens.size > 512) headerTokens.delete(headerTokens.keys().next().value!);
          if (apiRequests.size > 512) apiRequests.delete(apiRequests.values().next().value!);
          if (successfulRequests.size > 512) successfulRequests.delete(successfulRequests.values().next().value!);
          return;
        }
        if (message.method === 'Page.frameNavigated' && !params.frame?.parentId) {
          frameId = params.frame.id;
        }
        if (message.method === 'Fetch.requestPaused') {
          let capturedBody: { body: string; base64Encoded: boolean } | undefined;
          const capture = async () => {
            const matches =
              params.resourceType === 'Document' &&
              params.frameId === frameId &&
              matchesOAuthCallback(params.request.url, callback!.href);
            if (!matches || (params.responseStatusCode >= 300 && params.responseStatusCode < 400)) {
              await cdp.command('Fetch.continueRequest', { requestId: params.requestId }, sessionId);
              return;
            }
            if (params.responseErrorReason) throw new OAuthAuthenticationError('callbackLoad');
            if (params.responseStatusCode < 200 || params.responseStatusCode >= 300) {
              throw new OAuthAuthenticationError('callbackStatus', params.responseStatusCode);
            }
            // Read while paused at the response stage, before a cross-site renderer swap
            // can discard the body from Network.getResponseBody's renderer-side cache.
            const result = await cdp.command('Fetch.getResponseBody', { requestId: params.requestId }, sessionId);
            capturedBody = result;
            const body = result.base64Encoded ? Buffer.from(result.body, 'base64').toString('utf8') : result.body;
            if (typeof body !== 'string' || body.length > 1024 * 1024)
              throw new OAuthAuthenticationError('callbackSize');
            let parsed: unknown;
            try {
              parsed = JSON.parse(body);
            } catch {
              throw new OAuthAuthenticationError('callbackJson');
            }
            let token;
            try {
              token = parseHttpAuthenticationToken(parsed);
            } catch {
              throw new OAuthAuthenticationError('callbackToken');
            }
            resolve(token);
          };
          void capture().catch(async (error: unknown) => {
            if (options.onCallbackError && params.responseStatusCode && !params.responseErrorReason) {
              try {
                const body =
                  capturedBody ??
                  (await cdp.command('Fetch.getResponseBody', { requestId: params.requestId }, sessionId));
                // Render the exact intercepted bytes without navigating to the one-use callback again.
                await cdp.command(
                  'Fetch.fulfillRequest',
                  {
                    requestId: params.requestId,
                    responseCode: params.responseStatusCode,
                    responseHeaders: (params.responseHeaders ?? []).filter(
                      (header: { name: string }) =>
                        !['content-encoding', 'content-length', 'transfer-encoding'].includes(
                          header.name.toLowerCase(),
                        ),
                    ),
                    body: body.base64Encoded ? body.body : Buffer.from(body.body, 'utf8').toString('base64'),
                  },
                  sessionId,
                );
              } catch {
                await cdp
                  .command('Fetch.failRequest', { requestId: params.requestId, errorReason: 'Failed' }, sessionId)
                  .catch(() => {});
              }
            }
            reject(error);
          });
        }
      };
    });
    const start = async () => {
      await cdp.command('Target.setDiscoverTargets', { discover: true });
      const { targetId } = await cdp.command('Target.createTarget', { url: 'about:blank' });
      loginTargetId = targetId;
      sessionId = (await cdp.command('Target.attachToTarget', { targetId, flatten: true })).sessionId;
      const { targetInfos } = await cdp.command('Target.getTargets');
      for (const target of targetInfos) {
        if (target.type === 'page' && target.url === 'about:blank' && target.targetId !== targetId) {
          await cdp.command('Target.closeTarget', { targetId: target.targetId });
        }
      }
      if (headerCapture) {
        await cdp.command('Network.enable', {}, sessionId);
      } else {
        await cdp.command(
          'Fetch.enable',
          {
            patterns: [
              {
                urlPattern: `${callback!.origin}${callback!.pathname.replace(/[\\*?]/g, '\\$&')}*`,
                resourceType: 'Document',
                requestStage: 'Response',
              },
            ],
          },
          sessionId,
        );
      }
      await cdp.command('Page.enable', {}, sessionId);
      frameId = (await cdp.command('Page.getFrameTree', {}, sessionId)).frameTree.frame.id;
      await cdp.command('Page.navigate', { url: login.href }, sessionId);
      return completion;
    };
    return await Promise.race([completion, start()]);
  } catch (error) {
    if (
      options.onCallbackError &&
      !signal.aborted &&
      error instanceof OAuthAuthenticationError &&
      error.code.startsWith('callback') &&
      child &&
      child.exitCode === null &&
      child.signalCode === null &&
      pipe
    ) {
      if (timer) clearTimeout(timer);
      await pipe.command('Fetch.disable', {}, sessionId).catch(() => {});
      options.onCallbackError(error);
      // Keep the debugging pipe and helper alive until the user closes Chrome.
      // App shutdown/cancellation still releases the browser and temporary profile.
      await new Promise<void>((resolve) => {
        const done = () => {
          diagnosticClosed = undefined;
          child!.off('exit', done);
          signal.removeEventListener('abort', done);
          resolve();
        };
        diagnosticClosed = done;
        child!.once('exit', done);
        signal.addEventListener('abort', done, { once: true });
        if (signal.aborted || loginWindowClosed || child!.exitCode !== null || child!.signalCode !== null) done();
      });
    }
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
    signal.removeEventListener('abort', abort);
    pipe?.dispose();
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill();
      await waitForExit(child);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await waitForExit(child);
      }
    }
    await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
