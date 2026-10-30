import {
  authenticateInChrome,
  getOAuthAuthenticationErrorMessage,
  type HttpAuthenticationRequest,
} from '@ironclad/rivet-node';
import { createInterface } from 'node:readline';

/** A one-shot private stdin/stdout protocol. Never route this output to executor logs. */
export function runOAuthLogin(): void {
  const controller = new AbortController();
  const input = createInterface({ input: process.stdin });
  let started = false;
  let diagnosticReported = false;
  const cancel = () => controller.abort();
  process.once('SIGTERM', cancel);
  input.once('close', cancel);
  const finish = (message: object) => {
    process.stdout.write(JSON.stringify(message) + '\n', () => process.exit(0));
  };
  input.on('line', (line) => {
    if (line.length > 65536) {
      finish({ error: 'OAuth configuration is too large' });
      return;
    }
    let message: HttpAuthenticationRequest | { cancel: true };
    try {
      const parsed: unknown = JSON.parse(line);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid configuration');
      message = parsed as typeof message;
    } catch {
      finish({ error: 'Invalid OAuth configuration' });
      return;
    }
    if ('cancel' in message && message.cancel === true) {
      cancel();
      if (!started) finish({ result: false });
      return;
    }
    if (started) return;
    started = true;
    void authenticateInChrome(message as HttpAuthenticationRequest, controller.signal, {
      onProgress(progress) {
        process.stdout.write(JSON.stringify({ progress }) + '\n');
      },
      onCallbackError(error) {
        diagnosticReported = true;
        process.stdout.write(
          JSON.stringify({
            error: `${getOAuthAuthenticationErrorMessage(error)} Chrome has been left open so you can inspect the callback page. Close Chrome when finished.`,
            browserOpen: true,
          }) + '\n',
        );
      },
    })
      .then((result) => finish({ result }))
      .catch((error: unknown) => {
        if (diagnosticReported) {
          process.exit(0);
          return;
        }
        finish({
          error: controller.signal.aborted
            ? 'OAuth authentication cancelled'
            : getOAuthAuthenticationErrorMessage(error),
        });
      });
  });
}
