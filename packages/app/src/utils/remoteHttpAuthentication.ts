import type { HttpAuthenticationRequest, HttpAuthenticationResult } from '@ironclad/rivet-core';

/** Own sign-in windows for one debugger connection, independently of mounted React hook instances. */
export class RemoteHttpAuthentication {
  private readonly pending = new Map<string, AbortController>();

  constructor(
    private readonly open: (
      request: HttpAuthenticationRequest,
      signal: AbortSignal,
    ) => Promise<HttpAuthenticationResult>,
    private readonly respond: (requestId: string, result: HttpAuthenticationResult) => void,
    private readonly onError: (error: unknown) => void,
  ) {}

  async start(requestId: string, request: HttpAuthenticationRequest): Promise<void> {
    if (this.pending.has(requestId)) return;
    const controller = new AbortController();
    this.pending.set(requestId, controller);
    let result: HttpAuthenticationResult = false;
    try {
      result = await this.open(request, controller.signal);
    } catch (error) {
      if (!controller.signal.aborted) this.onError(error);
    } finally {
      this.pending.delete(requestId);
      // A locally cancelled window must still release the server's pending request.
      this.respond(requestId, controller.signal.aborted ? false : result);
    }
  }

  cancel(requestId: string): void {
    this.pending.get(requestId)?.abort();
  }

  dispose(): void {
    for (const controller of this.pending.values()) controller.abort();
  }
}
