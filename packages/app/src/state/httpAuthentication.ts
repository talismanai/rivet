import { atom } from 'jotai';
import { HttpAuthenticationSessions } from '@ironclad/rivet-core';

// Deliberately excluded from atomWithStorage: JWTs must remain in memory only.
export const httpAuthenticationSessionsState = atom(() => new HttpAuthenticationSessions());
