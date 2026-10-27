import type { HttpAuthenticationRequest, HttpAuthenticationResult } from '@ironclad/rivet-core';
import { Command } from '@tauri-apps/api/shell';
import { isInTauri } from './tauri';
import { runOAuthSidecar } from './oauthSidecar';

/** Google sign-in runs in a real Chrome window; no platform callback changes are required. */
export async function requestHttpAuthentication(
  request: HttpAuthenticationRequest,
  signal: AbortSignal,
): Promise<HttpAuthenticationResult> {
  signal.throwIfAborted();
  if (!isInTauri()) return false;
  const login = new URL(request.authenticationUrl);
  const callbackUrl = request.callbackUrl || login.searchParams.get('redirect_uri');
  const tokenSource = request.tokenSource ?? (callbackUrl ? 'callback' : 'authorization-header');
  if (tokenSource === 'callback' && !callbackUrl)
    throw new Error('Set the OAuth callback URL, or include redirect_uri in the OAuth login URL.');
  const callback = tokenSource === 'callback' && callbackUrl ? new URL(callbackUrl) : undefined;
  for (const url of [login, new URL(request.requestUrl), ...(callback ? [callback] : [])]) {
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)
      throw new Error('Unsupported OAuth login or callback URL');
  }
  return runOAuthSidecar(
    { ...request, tokenSource, ...(callback ? { callbackUrl: callback.href } : {}) },
    signal,
    Command.sidecar('../../app-executor/dist/app-executor', ['--oauth-login']),
  );
}
