import type { HttpAuthenticationToken } from '../model/ProcessContext.js';

export function isHttpAuthenticationToken(value: unknown): value is HttpAuthenticationToken {
  if (!value || typeof value !== 'object' || !('accessToken' in value)) return false;
  return (
    typeof value.accessToken === 'string' &&
    value.accessToken.length <= 32768 &&
    /^[A-Za-z0-9._~+/-]+=*$/.test(value.accessToken) &&
    (!('expiresIn' in value) ||
      (typeof value.expiresIn === 'number' && Number.isFinite(value.expiresIn) && value.expiresIn > 0))
  );
}

/** Parse the platform callback without retaining its user details or exposing its body in errors. */
export function parseHttpAuthenticationToken(body: unknown): HttpAuthenticationToken {
  const data = body && typeof body === 'object' && 'data' in body ? body.data : undefined;
  if (!data || typeof data !== 'object' || !('access_token' in data)) {
    throw new Error('OAuth callback response must contain data.access_token');
  }
  const token = {
    accessToken: data.access_token,
    ...('expires_in' in data ? { expiresIn: data.expires_in } : {}),
  };
  if (!isHttpAuthenticationToken(token)) throw new Error('OAuth callback returned an invalid access token or expiry');
  return token;
}
