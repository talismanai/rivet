import { isHttpAuthenticationToken } from '@ironclad/rivet-core';
import type { ProjectContext } from '../state/savedGraphs';

/** User-configured JWT mirroring uses the same storage as other secret project context values. */
export function withHttpAuthenticationToken(
  current: ProjectContext,
  contextKey: unknown,
  token: unknown,
): ProjectContext {
  if (typeof contextKey !== 'string' || !contextKey.trim() || !isHttpAuthenticationToken(token)) return current;
  const key = contextKey.trim();
  const value = `Bearer ${token.accessToken}`;
  const previous = Object.hasOwn(current, key) ? current[key] : undefined;
  if (previous?.secret && previous.value.type === 'string' && previous.value.value === value) return current;
  return { ...current, [key]: { value: { type: 'string', value }, secret: true } };
}
