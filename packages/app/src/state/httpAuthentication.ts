import { atom } from 'jotai';
import { HttpAuthenticationSessions } from '@ironclad/rivet-core';

// The session cache is transient. An explicitly configured context mirror is stored separately.
export const httpAuthenticationSessionsState = atom(() => new HttpAuthenticationSessions());
