import { spawn, type ChildProcess } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { delimiter, join, isAbsolute } from 'node:path';
import { tmpdir, platform } from 'node:os';
import type { Readable, Writable } from 'node:stream';
import {
  parseHttpAuthenticationToken,
  type HttpAuthenticationRequest,
  type HttpAuthenticationResult,
  type HttpAuthenticationProgress,
} from '@ironclad/rivet-core';

import { ChromeHeaderCapture } from './ChromeHeaderCapture.js';
export { bearerTokenFromHeaders } from './ChromeHeaderCapture.js';

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
  onClose: () => void = () => {};
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
    this.onClose();
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

/** Capture callback JSON or discover the Bearer JWT used by the configured login page. */
export async function authenticateInChrome(
  request: HttpAuthenticationRequest,
  signal: AbortSignal,
  options: {
    onCallbackError?: (error: OAuthAuthenticationError) => void;
    onProgress?: (progress: HttpAuthenticationProgress) => void;
  } = {},
): Promise<HttpAuthenticationResult> {
  signal.throwIfAborted();
  const login = webUrl(request.authenticationUrl);
  const callbackUrl = request.callbackUrl || login.searchParams.get('redirect_uri');
  const headerCapture = request.tokenSource === 'authorization-header' || (!request.tokenSource && !callbackUrl);
  const callback = headerCapture ? undefined : webUrl(callbackUrl || '');
  webUrl(request.requestUrl);
  // Trust the page initiating the request, rather than a separately configured API hostname.
  // This excludes Google/provider frames while allowing the platform to change its API endpoints.
  const pageOrigins = new Set([login.origin, ...(callbackUrl ? [webUrl(callbackUrl).origin] : [])]);
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
    let lastProgress = '';
    const report = (progress: HttpAuthenticationProgress) => {
      const serialized = JSON.stringify(progress);
      if (serialized === lastProgress) return;
      lastProgress = serialized;
      options.onProgress?.(progress);
    };
    const headerCaptureState = new ChromeHeaderCapture(pageOrigins, report);
    const captureSessions = new Map<string, { targetId: string; type: string }>();
    const autoAttach = {
      autoAttach: true,
      waitForDebuggerOnStart: true,
      flatten: true,
      filter: [
        ...['page', 'iframe', 'worker', 'service_worker', 'shared_worker'].map((type) => ({
          type,
          exclude: false,
        })),
        { exclude: true },
      ],
    };
    const enableCapture = async (id: string) => {
      await cdp.command('Network.enable', {}, id);
      // Workers can spawn further workers; attach recursively before resuming their JavaScript.
      await cdp.command('Target.setAutoAttach', autoAttach, id);
    };
    const completion = new Promise<HttpAuthenticationResult>((resolve, reject) => {
      cdp.onClose = () => reject(new OAuthAuthenticationError('connection'));
      abort = () => reject(new Error('OAuth authentication aborted'));
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
      timer = setTimeout(() => reject(new OAuthAuthenticationError('timeout')), 10 * 60 * 1000);
      child!.once('error', () => reject(new OAuthAuthenticationError('browser')));
      child!.once('exit', () => resolve(false));
      cdp.onEvent = (message) => {
        if (headerCapture && message.method === 'Target.attachedToTarget') {
          const { sessionId: id, targetInfo } = message.params ?? {};
          if (typeof id !== 'string' || !targetInfo?.targetId) return;
          captureSessions.set(id, { targetId: targetInfo.targetId, type: targetInfo.type });
          headerCaptureState.registerSession(id, message.sessionId);
          void enableCapture(id)
            .catch(() => report({ stage: 'capture-error' }))
            .finally(() => {
              // Always resume a target, including unsupported/detached worker domains.
              void cdp.command('Runtime.runIfWaitingForDebugger', {}, id).catch(() => {});
            });
          return;
        }
        if (
          headerCapture &&
          (message.method === 'Target.targetDestroyed' || message.method === 'Target.detachedFromTarget')
        ) {
          let pageRemoved = false;
          for (const [id, target] of captureSessions) {
            if (target.targetId === message.params?.targetId || id === message.params?.sessionId) {
              pageRemoved ||= target.type === 'page';
              captureSessions.delete(id);
              headerCaptureState.forgetSession(id);
            }
          }
          if (pageRemoved && ![...captureSessions.values()].some((target) => target.type === 'page')) {
            loginWindowClosed = true;
            resolve(false);
          }
          return;
        }
        if (
          !headerCapture &&
          ((message.method === 'Target.targetDestroyed' && message.params?.targetId === loginTargetId) ||
            (message.method === 'Target.detachedFromTarget' && message.params?.sessionId === sessionId))
        ) {
          loginWindowClosed = true;
          diagnosticClosed?.();
          resolve(false);
          return;
        }
        if (headerCapture ? !captureSessions.has(message.sessionId ?? '') : message.sessionId !== sessionId) return;
        const params = message.params;
        if (headerCapture) {
          const token = headerCaptureState.capture(message.sessionId!, message.method ?? '', params ?? {});
          if (token) resolve(token);
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
        captureSessions.set(sessionId!, { targetId, type: 'page' });
        await enableCapture(sessionId!);
        await cdp.command('Target.setAutoAttach', autoAttach);
        report({ stage: 'waiting' });
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
