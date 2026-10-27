import { Body, getClient, ResponseType, type Client, type ClientOptions } from '@tauri-apps/api/http';

type CreateClient = (options: ClientOptions) => Promise<Pick<Client, 'request' | 'drop'>>;

/** Use Tauri's native HTTP transport so OAuth redirect inspection does not depend on provider CORS support. */
export function createDesktopHttpRequest(createClient: CreateClient = getClient) {
  return async (url: string, init: RequestInit): Promise<Response> => {
    const request = new Request(url, init);
    request.signal.throwIfAborted();
    const body = request.body ? Body.bytes(await request.arrayBuffer()) : undefined;
    request.signal.throwIfAborted();
    const client = await createClient({ maxRedirections: 0 });
    let abort: (() => void) | undefined;
    try {
      request.signal.throwIfAborted();
      const response = await new Promise<Awaited<ReturnType<typeof client.request<number[]>>>>((resolve, reject) => {
        abort = () => reject(request.signal.reason ?? new Error('HTTP request aborted'));
        request.signal.addEventListener('abort', abort, { once: true });
        void client
          .request<number[]>({
            url: request.url,
            method: request.method as Parameters<Client['request']>[0]['method'],
            headers: Object.fromEntries(request.headers),
            body,
            responseType: ResponseType.Binary,
          })
          .then(resolve, reject);
        if (request.signal.aborted) abort();
      });
      request.signal.throwIfAborted();
      const result = new Response(
        request.method === 'HEAD' || [204, 205, 304].includes(response.status) ? null : new Uint8Array(response.data),
        { status: response.status, headers: response.headers },
      );
      Object.defineProperty(result, 'url', { value: response.url });
      return result;
    } finally {
      if (abort) request.signal.removeEventListener('abort', abort);
      await client.drop();
    }
  };
}

export const desktopHttpRequest = createDesktopHttpRequest();
