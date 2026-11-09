import {
  isHttpAuthenticationToken,
  type HttpAuthenticationProgress,
  type HttpAuthenticationToken,
} from '@ironclad/rivet-core';

type Headers = Record<string, unknown>;
type NetworkParams = { request?: { headers?: Headers }; headers?: Headers };

/** Inspect only request headers; JWT signature validation remains the destination API's responsibility. */
export function bearerTokenFromHeaders(headers: Headers): HttpAuthenticationToken | undefined {
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

/** Capture the first Bearer JWT observed anywhere in the dedicated login browser. */
export class ChromeHeaderCapture {
  private captured = false;

  constructor(private readonly report: (progress: HttpAuthenticationProgress) => void) {}

  capture(method: string, params: NetworkParams): HttpAuthenticationToken | undefined {
    if (this.captured) return undefined;
    let headers: Headers | undefined;
    if (method === 'Network.requestWillBeSent' || method === 'Network.webSocketWillSendHandshakeRequest') {
      headers = params.request?.headers;
    } else if (method === 'Network.requestWillBeSentExtraInfo') {
      headers = params.headers;
    }
    if (!headers) return undefined;
    const token = bearerTokenFromHeaders(headers);
    if (token) this.captured = true;
    this.report({
      stage: 'request',
      authorization: token
        ? 'valid'
        : Object.keys(headers).some((key) => key.toLowerCase() === 'authorization')
          ? 'invalid'
          : 'missing',
    });
    return token;
  }
}
