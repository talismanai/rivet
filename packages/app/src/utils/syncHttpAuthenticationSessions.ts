import { isReusableHttpAuthenticationSession, type HttpAuthenticationSessions } from '@ironclad/rivet-core';

/** Credentials travel only over the owning debugger connection; never serialize them to settings. */
export function syncHttpAuthenticationSessions(
  socket: { readyState: number; send: (message: string) => void } | null,
  sessions: HttpAuthenticationSessions,
  projectIds: Iterable<string>,
): void {
  if (socket?.readyState !== 1) return;
  for (const projectId of new Set(projectIds)) {
    for (const [cacheKey, session] of sessions.forProject(projectId)) {
      if (!cacheKey.startsWith('httpAuthentication:') || !isReusableHttpAuthenticationSession(session)) continue;
      try {
        socket.send(
          JSON.stringify({
            type: 'http-authentication-session',
            data: {
              projectId,
              cacheKey,
              token: session.token,
              expiresAt: Number.isFinite(session.expiresAt) ? session.expiresAt : null,
            },
          }),
        );
      } catch {
        // A debugger disconnect must not turn a successful local sign-in into a failure.
        // Live sessions are sent again when the debugger reconnects.
        return;
      }
    }
  }
}
