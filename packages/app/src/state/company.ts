import { atom } from 'jotai';
import { atomWithStorage } from 'jotai/utils';
import { createHybridStorage } from './storage.js';

const { storage } = createHybridStorage('companyUi');

/** Whether the user has an active company session (cookie). Undefined until first check. */
export const isLoggedInToCompanyState = atom<boolean | undefined>(undefined);

/** Deploy API key issued by your backend after login (stored locally). */
export const companyDeployApiKeyState = atomWithStorage<string>('companyDeployApiKey', '', storage);
