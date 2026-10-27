import type {
  InternalProcessContext,
  HttpAuthenticationRequest,
  HttpAuthenticationResult,
  HttpAuthenticationToken,
} from '../model/ProcessContext.js';
import { isHttpAuthenticationToken } from './httpAuthenticationToken.js';

export type HttpAuthenticationOptions = {
  loginUrl?: string;
  callbackUrl?: string;
  tokenSource?: 'callback' | 'authorization-header';
  /** Let a previously authenticated session supersede a plugin's configured API key. */
  preferCachedToken?: boolean;
  /** Sign in before sending a request when no reusable session is available. */
  authenticateBeforeRequest?: boolean;
};

type CachedSession = { token: HttpAuthenticationToken; expiresAt: number };

function isReusableSession(value: unknown): value is CachedSession {
  const session = value as Partial<CachedSession> | undefined;
  return (
    !!session &&
    isHttpAuthenticationToken(session.token) &&
    typeof session.expiresAt === 'number' &&
    session.expiresAt > Date.now()
  );
}

type PendingLogin = {
  controller: AbortController;
  promise: Promise<HttpAuthenticationResult>;
  consumers: number;
  settled: boolean;
};

const pendingLogins = new WeakMap<object, Map<string, PendingLogin>>();

/** Nodes have separate abort signals; close a shared window only when its last caller cancels. */
async function shareLogin(
  owner: object,
  cacheKey: string,
  authenticate: NonNullable<InternalProcessContext['requestHttpAuthentication']>,
  challenge: HttpAuthenticationRequest,
  signal: AbortSignal,
): Promise<HttpAuthenticationResult> {
  signal.throwIfAborted();
  let pending = pendingLogins.get(owner);
  if (!pending) {
    pending = new Map();
    pendingLogins.set(owner, pending);
  }
  let login = pending.get(cacheKey);
  if (!login || login.controller.signal.aborted) {
    const controller = new AbortController();
    const entry: PendingLogin = {
      controller,
      consumers: 0,
      settled: false,
      promise: Promise.resolve().then(() => authenticate(challenge, controller.signal)),
    };
    entry.promise = entry.promise.finally(() => {
      entry.settled = true;
      if (pending.get(cacheKey) === entry) pending.delete(cacheKey);
    });
    pending.set(cacheKey, entry);
    login = entry;
  }
  const shared = login;
  shared.consumers++;
  let abort: (() => void) | undefined;
  try {
    return await new Promise<HttpAuthenticationResult>((resolve, reject) => {
      abort = () => reject(signal.reason ?? new Error('OAuth authentication aborted'));
      signal.addEventListener('abort', abort, { once: true });
      void shared.promise.then(resolve, reject);
      if (signal.aborted) abort();
    });
  } finally {
    if (abort) signal.removeEventListener('abort', abort);
    shared.consumers--;
    if (!shared.consumers && !shared.settled) {
      shared.controller.abort();
      if (pending.get(cacheKey) === shared) pending.delete(cacheKey);
    }
  }
}

function isAuthenticationFailure(status: number): boolean {
  return status === 401 || status === 403;
}

/** Only web URLs may be opened by an external authentication response. */
export function getAuthenticationUrl(value: string, base: string): URL | undefined {
  try {
    const url = new URL(value, base);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url : undefined;
  } catch {
    return undefined;
  }
}

export function isOAuthAuthorizationUrl(url: URL): boolean {
  return (
    (url.searchParams.has('client_id') && url.searchParams.has('response_type')) ||
    /\/(?:oauth2?|oidc)(?:\/[^/?#]+)*\/(?:authorize|auth)\/?$/i.test(url.pathname) ||
    (/\/authorize\/?$/i.test(url.pathname) && url.searchParams.has('client_id'))
  );
}

function getChallenge(
  response: Response,
  requestUrl: string,
  responseUrl: string,
  options: HttpAuthenticationOptions,
): HttpAuthenticationRequest | undefined {
  const location = response.headers.get('location');
  const candidate = isAuthenticationFailure(response.status)
    ? options.loginUrl?.trim() || location
    : location ?? responseUrl;
  if (!candidate) return undefined;
  const target = getAuthenticationUrl(candidate, responseUrl);
  if (!target) {
    return undefined;
  }
  if (
    isAuthenticationFailure(response.status) ||
    (response.status === 302 && location && isOAuthAuthorizationUrl(target)) ||
    (response.redirected && isOAuthAuthorizationUrl(target))
  ) {
    const callback = options.callbackUrl?.trim() || target.searchParams.get('redirect_uri');
    return {
      requestUrl,
      authenticationUrl: target.href,
      status: response.status,
      ...(options.tokenSource ? { tokenSource: options.tokenSource } : {}),
      ...(callback ? { callbackUrl: getAuthenticationUrl(callback, target.href)?.href } : {}),
    };
  }
  return undefined;
}

/** Inspect redirects with a host transport when available, before visiting an OAuth provider. */
export async function fetchWithHttpAuthentication(
  url: string,
  init: RequestInit,
  context: Pick<InternalProcessContext, 'executor' | 'signal' | 'requestHttpAuthentication' | 'httpRequest'> &
    Partial<Pick<InternalProcessContext, 'executionCache'>>,
  options: HttpAuthenticationOptions = {},
): Promise<Response> {
  context.signal.throwIfAborted();
  const authenticate = context.requestHttpAuthentication;
  if (!authenticate) {
    if (options.authenticateBeforeRequest) throw new Error('OAuth authentication requires an interactive host');
    return (context.httpRequest ?? fetch)(url, { ...init, signal: context.signal });
  }

  const cacheKey = `httpAuthentication:${JSON.stringify([new URL(url).origin, options.loginUrl ?? '', options.callbackUrl ?? '', options.tokenSource ?? 'auto'])}`;
  const cached = context.executionCache?.get(cacheKey);
  let usedCachedToken = false;
  if (isReusableSession(cached) && (options.preferCachedToken || !new Headers(init.headers).has('authorization'))) {
    const headers = new Headers(init.headers);
    headers.set('authorization', `Bearer ${cached.token.accessToken}`);
    init = { ...init, headers };
    usedCachedToken = true;
  }

  const perform = async (
    request: (url: string, init: RequestInit) => Promise<Response>,
    inspectRedirects: boolean,
  ): Promise<{ response: Response; challenge?: HttpAuthenticationRequest }> => {
    let currentUrl = url;
    let currentInit = { ...init };
    for (let redirects = 0; ; redirects++) {
      context.signal.throwIfAborted();
      const response = await request(currentUrl, {
        ...currentInit,
        signal: context.signal,
        redirect: inspectRedirects ? 'manual' : 'follow',
      });
      const challenge = getChallenge(response, url, response.url || currentUrl, options);
      if (challenge) {
        return { response, challenge };
      }
      const location = response.headers.get('location');
      if (!inspectRedirects || ![301, 302, 303, 307, 308].includes(response.status) || !location) {
        return { response };
      }
      const nextUrl = new URL(location, currentUrl);
      if (redirects >= 20 || !['http:', 'https:'].includes(nextUrl.protocol) || nextUrl.username || nextUrl.password) {
        await response.body?.cancel();
        throw new Error('HTTP redirect limit exceeded or invalid redirect URL');
      }
      const headers = new Headers(currentInit.headers);
      if (nextUrl.origin !== new URL(currentUrl).origin) {
        headers.delete('authorization');
        headers.delete('proxy-authorization');
        headers.delete('cookie');
      }
      const method = (currentInit.method ?? 'GET').toUpperCase();
      if (
        ((response.status === 301 || response.status === 302) && method === 'POST') ||
        (response.status === 303 && method !== 'GET' && method !== 'HEAD')
      ) {
        currentInit = { ...currentInit, method: 'GET', body: undefined };
        for (const header of [
          'content-type',
          'content-length',
          'content-encoding',
          'content-language',
          'content-location',
        ]) {
          headers.delete(header);
        }
      }
      await response.body?.cancel();
      currentInit.headers = headers;
      currentUrl = nextUrl.href;
    }
  };

  const request = context.httpRequest ?? fetch;
  const inspectRedirects = context.httpRequest !== undefined || context.executor === 'nodejs';
  let response: Response | undefined;
  let challenge: HttpAuthenticationRequest | undefined;
  if (options.authenticateBeforeRequest && !usedCachedToken) {
    context.signal.throwIfAborted();
    const loginUrl = options.loginUrl?.trim();
    const target = loginUrl ? getAuthenticationUrl(loginUrl, url) : undefined;
    if (!target) throw new Error('A valid OAuth login URL is required before sending the request');
    const callback = options.callbackUrl?.trim() || target.searchParams.get('redirect_uri');
    challenge = {
      requestUrl: url,
      authenticationUrl: target.href,
      status: 0,
      ...(options.tokenSource ? { tokenSource: options.tokenSource } : {}),
      ...(callback ? { callbackUrl: getAuthenticationUrl(callback, target.href)?.href } : {}),
    };
  } else {
    ({ response, challenge } = await perform(request, inspectRedirects));
  }
  // A late failure must not invalidate a session refreshed by another concurrent request.
  const current = context.executionCache?.get(cacheKey);
  const refreshed = current !== cached && isReusableSession(current) ? current : undefined;
  if ((challenge || (response && isAuthenticationFailure(response.status))) && current === cached) {
    context.executionCache?.delete(cacheKey);
  }
  let token;
  try {
    if (challenge && refreshed) {
      token = refreshed.token;
    } else if (challenge) {
      token = await shareLogin(
        context.executionCache ?? context.signal,
        cacheKey,
        authenticate,
        challenge,
        context.signal,
      );
    } else {
      token = false;
    }
    if (!token) {
      context.signal.throwIfAborted();
      if (!response) throw new Error('OAuth authentication was cancelled');
      return response;
    }
    if (!isHttpAuthenticationToken(token)) throw new Error('Authentication did not return a valid access token');
    context.signal.throwIfAborted();
  } catch (error) {
    await response?.body?.cancel();
    throw error;
  }
  const headers = new Headers(init.headers);
  headers.set('authorization', `Bearer ${token.accessToken}`);
  init = { ...init, headers };
  // Share a valid session immediately with other nodes, even if this API request is still in flight.
  // Without a supplied lifetime it lasts only for this execution, or until the API rejects it.
  const expiresAt = token.expiresIn ? Date.now() + token.expiresIn * 1000 : Infinity;
  if (!refreshed) context.executionCache?.set(cacheKey, { token, expiresAt });
  await response?.body?.cancel();
  context.signal.throwIfAborted();
  // Re-send the original method/body once. Cross-origin redirects still strip the token.
  const retry = await perform(request, inspectRedirects);
  if (retry.challenge || isAuthenticationFailure(retry.response.status)) {
    const current = context.executionCache?.get(cacheKey) as { token?: unknown } | undefined;
    if (current?.token === token) context.executionCache?.delete(cacheKey);
  }
  return retry.response;
}
