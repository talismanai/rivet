import {
  isHttpAuthenticationToken,
  type HttpAuthenticationRequest,
  type HttpAuthenticationResult,
  type HttpAuthenticationProgress,
} from '@ironclad/rivet-core';
import type { Command, Child } from '@tauri-apps/api/shell';

/** Private helper output contains a bearer credential: never log stdout or include it in errors. */
export function runOAuthSidecar(
  request: HttpAuthenticationRequest,
  signal: AbortSignal,
  command: Pick<Command, 'stdout' | 'stderr' | 'on' | 'spawn'>,
  onProgress?: (message: string) => void,
): Promise<HttpAuthenticationResult> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    let child: Child | undefined;
    let settled = false;
    let closed = false;
    let invalidPkgPayload = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: HttpAuthenticationResult, error?: Error, keepBrowserOpen = false) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', abort);
      if (error) {
        if (!keepBrowserOpen) cancel();
        reject(error);
      } else resolve(result);
    };
    const cancel = () => {
      if (!child || closed || killTimer) return;
      void child.write('{"cancel":true}\n').catch(() => {});
      killTimer = setTimeout(() => {
        void child?.kill().catch(() => {});
      }, 10000);
    };
    const abort = () => {
      finish(false, new Error('OAuth authentication aborted'));
    };
    command.stdout.on('data', (line) => {
      if (settled) return;
      try {
        const message = JSON.parse(line) as {
          result?: unknown;
          error?: unknown;
          browserOpen?: unknown;
          progress?: unknown;
        };
        if ('progress' in message) {
          const progress = message.progress as Partial<HttpAuthenticationProgress> | null;
          if (progress?.stage === 'waiting') {
            onProgress?.(
              `Waiting for a Bearer JWT in requests initiated by ${new URL(request.authenticationUrl).origin}.`,
            );
          } else if (progress?.stage === 'capture-error') {
            onProgress?.('Chrome could not enable network capture for a browser target.');
          } else if (
            progress?.stage === 'request' &&
            ['missing', 'invalid', 'valid'].includes(progress.authorization ?? '')
          ) {
            const header = {
              missing: 'no Authorization header detected',
              invalid: 'Authorization detected, but it is not a valid, unexpired Bearer JWT',
              valid: 'Bearer JWT detected',
            }[progress.authorization!];
            const status =
              typeof progress.status === 'number' &&
              Number.isInteger(progress.status) &&
              progress.status >= 100 &&
              progress.status <= 599
                ? `HTTP ${progress.status}`
                : 'waiting for response';
            onProgress?.(`Login-page request: ${header}; ${status}.`);
          }
          return;
        }
        if (typeof message.error === 'string') finish(false, new Error(message.error), message.browserOpen === true);
        else if (message.result === false || isHttpAuthenticationToken(message.result)) finish(message.result);
        else finish(false, new Error('OAuth helper returned an invalid access token'));
      } catch {
        finish(false, new Error('OAuth helper returned an invalid response'));
      }
    });
    command.stderr.on('data', (line) => {
      // Classify a known startup failure without retaining or exposing arbitrary stderr or credentials.
      if (!settled && /pkg\/prelude\/bootstrap|node:internal\/bootstrap\/pkg/.test(line.slice(0, 4096))) {
        invalidPkgPayload = true;
      }
    });
    command.on('close', ({ code, signal: exitSignal }) => {
      closed = true;
      if (killTimer) clearTimeout(killTimer);
      const details = [
        typeof code === 'number' ? `exit code ${code}` : undefined,
        typeof exitSignal === 'number' ? `signal ${exitSignal}` : undefined,
      ].filter(Boolean);
      const hint = invalidPkgPayload
        ? ' The packaged executor could not load its embedded Node.js payload. Rebuild the sidecar and installer.'
        : ' The helper did not return an authentication result. Check the installed executor sidecar.';
      finish(
        false,
        new Error(
          `OAuth browser helper exited unexpectedly${details.length ? ` (${details.join(', ')})` : ''}.${hint}`,
        ),
      );
    });
    command.on('error', () => finish(false, new Error('OAuth browser helper failed')));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    void command
      .spawn()
      .then(async (process) => {
        child = process;
        if (signal.aborted || settled) {
          cancel();
          return;
        }
        await child.write(JSON.stringify(request) + '\n');
      })
      .catch(() => finish(false, new Error('Could not start the OAuth browser helper. Rebuild the Rivet sidecar.')));
  });
}
