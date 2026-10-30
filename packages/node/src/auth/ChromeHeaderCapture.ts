import {
  isHttpAuthenticationToken,
  type HttpAuthenticationProgress,
  type HttpAuthenticationToken,
} from '@ironclad/rivet-core';

type Headers = Record<string, unknown>;
type CapturedHeaders = {
  token?: HttpAuthenticationToken;
  authorization: 'missing' | 'invalid' | 'valid';
};
type Hop = {
  trusted: boolean;
  headers: CapturedHeaders;
  status?: number;
  hasExtraInfo?: boolean;
  failed?: boolean;
  corsFailed?: boolean;
};
type Exchange = {
  sessionId: string;
  requestId: string;
  hops: Hop[];
  requestExtras: CapturedHeaders[];
  responseExtras: number[];
};
type NetworkParams = {
  requestId?: string;
  type?: string;
  documentURL?: string;
  request?: { url: string; headers?: Headers };
  response?: { status: number };
  redirectResponse?: { status: number };
  redirectHasExtraInfo?: boolean;
  hasExtraInfo?: boolean;
  headers?: Headers;
  statusCode?: number;
  corsErrorStatus?: unknown;
};

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

function captureHeaders(headers: Headers = {}): CapturedHeaders {
  const token = bearerTokenFromHeaders(headers);
  return {
    token,
    authorization: token
      ? 'valid'
      : Object.keys(headers).some((key) => key.toLowerCase() === 'authorization')
        ? 'invalid'
        : 'missing',
  };
}

const successful = (status?: number) => status !== undefined && status >= 200 && status < 300;

/** CDP reuses request IDs across redirects and delivers ExtraInfo independently of the main events. */
export class ChromeHeaderCapture {
  private readonly exchanges = new Map<string, Exchange>();
  private readonly parents = new Map<string, string>();

  constructor(
    private readonly pageOrigins: ReadonlySet<string>,
    private readonly report: (progress: HttpAuthenticationProgress) => void,
  ) {}

  registerSession(sessionId: string, parentSessionId?: string): void {
    if (parentSessionId) this.parents.set(sessionId, parentSessionId);
  }

  forgetSession(sessionId: string): void {
    this.parents.delete(sessionId);
    for (const [key, exchange] of this.exchanges) {
      if (exchange.sessionId === sessionId) this.exchanges.delete(key);
    }
  }

  capture(sessionId: string, method: string, params: NetworkParams): HttpAuthenticationToken | undefined {
    if (!params.requestId || !method.startsWith('Network.') || params.type === 'Preflight') return undefined;
    if (
      ![
        'Network.requestWillBeSent',
        'Network.requestWillBeSentExtraInfo',
        'Network.responseReceived',
        'Network.responseReceivedExtraInfo',
        'Network.loadingFailed',
      ].includes(method)
    )
      return undefined;
    const key = JSON.stringify([sessionId, params.requestId]);
    let exchange = this.exchanges.get(key);
    if (!exchange) {
      exchange = { sessionId, requestId: params.requestId, hops: [], requestExtras: [], responseExtras: [] };
      this.exchanges.set(key, exchange);
      if (this.exchanges.size > 512) this.exchanges.delete(this.exchanges.keys().next().value!);
    }
    const previous = exchange.hops.at(-1);
    switch (method) {
      case 'Network.requestWillBeSent': {
        if (!params.request) return undefined;
        if (previous && params.redirectResponse) {
          previous.status = params.redirectResponse.status;
          previous.hasExtraInfo = params.redirectHasExtraInfo === true;
        }
        let trusted = false;
        try {
          const target = new URL(params.request.url);
          trusted =
            ['http:', 'https:'].includes(target.protocol) &&
            !target.username &&
            !target.password &&
            this.pageOrigins.has(new URL(params.documentURL ?? '').origin);
        } catch {
          /* ignore non-web requests and unknown initiators */
        }
        exchange.hops.push({ trusted, headers: captureHeaders(params.request.headers) });
        break;
      }
      case 'Network.requestWillBeSentExtraInfo':
        exchange.requestExtras.push(captureHeaders(params.headers));
        break;
      case 'Network.responseReceivedExtraInfo':
        if (typeof params.statusCode === 'number') exchange.responseExtras.push(params.statusCode);
        break;
      case 'Network.responseReceived':
        if (previous && params.response) {
          previous.status = params.response.status;
          previous.hasExtraInfo = params.hasExtraInfo === true;
        }
        break;
      case 'Network.loadingFailed':
        // A CORS failure can precede ExtraInfo confirming HTTP 200; retain that exchange.
        if (previous) {
          if (params.corsErrorStatus) previous.corsFailed = true;
          else previous.failed = true;
        }
        break;
    }
    // Chrome limits redirects itself; bound every collection even for malformed event streams.
    if (exchange.hops.length > 32 || exchange.requestExtras.length > 32 || exchange.responseExtras.length > 32) {
      this.exchanges.delete(key);
      return undefined;
    }
    const token = this.inspect(exchange);
    if (token) return token;
    if (method.endsWith('ExtraInfo')) {
      // Chrome sends a worker's main events to the worker session, but its wire
      // headers/status to the owning page session. Never match unrelated targets.
      for (const candidate of this.exchanges.values()) {
        if (candidate.requestId !== params.requestId || !this.isChildOf(candidate.sessionId, sessionId)) continue;
        const captured = this.inspect(candidate);
        if (captured) return captured;
      }
    }
    return undefined;
  }

  private isChildOf(sessionId: string, parent: string): boolean {
    const visited = new Set<string>();
    let current = this.parents.get(sessionId);
    while (current && !visited.has(current)) {
      if (current === parent) return true;
      visited.add(current);
      current = this.parents.get(current);
    }
    return false;
  }

  private extraInfo(exchange: Exchange): Exchange {
    if (exchange.requestExtras.length || exchange.responseExtras.length) return exchange;
    const visited = new Set<string>();
    let parent = this.parents.get(exchange.sessionId);
    while (parent && !visited.has(parent)) {
      visited.add(parent);
      const candidate = this.exchanges.get(JSON.stringify([parent, exchange.requestId]));
      if (candidate) {
        // A page request or two workers using the same ID makes ownership ambiguous.
        const owners = [...this.exchanges.values()].filter(
          (other) =>
            other.requestId === exchange.requestId && other.hops.length && this.isChildOf(other.sessionId, parent!),
        );
        if (candidate.hops.length || owners.length !== 1) return exchange;
        if (candidate.requestExtras.length || candidate.responseExtras.length) return candidate;
      }
      parent = this.parents.get(parent);
    }
    return exchange;
  }

  private inspect(exchange: Exchange): HttpAuthenticationToken | undefined {
    const extras = this.extraInfo(exchange);
    let extraIndex = 0;
    for (const [index, hop] of exchange.hops.entries()) {
      let headers = hop.headers;
      let status = hop.status;
      let complete = hop.hasExtraInfo === false;
      if (hop.hasExtraInfo !== false) {
        const actualHeaders = extras.requestExtras[extraIndex];
        const actualStatus = extras.responseExtras[extraIndex];
        if (actualHeaders) headers = actualHeaders;
        if (actualStatus !== undefined) {
          // Chrome exposes a cached response as 200 even when the network revalidation returned 304.
          status = actualStatus === 304 && successful(hop.status) ? hop.status : actualStatus;
        }
        // A final hop's ExtraInfo can arrive before its main redirect event. Wait for
        // a main response or CORS failure before associating those headers with this hop.
        complete =
          actualHeaders !== undefined &&
          actualStatus !== undefined &&
          (hop.status !== undefined || hop.corsFailed === true);
        extraIndex++;
      }
      if (index !== exchange.hops.length - 1 || !hop.trusted || hop.failed) continue;
      this.report({
        stage: 'request',
        authorization: headers.authorization,
        ...(status !== undefined ? { status } : {}),
      });
      if (complete && successful(status) && headers.token) return headers.token;
    }
    return undefined;
  }
}
