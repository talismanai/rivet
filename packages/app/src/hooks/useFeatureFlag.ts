import { match } from 'ts-pattern';

export type FeatureFlag = 'community' | 'company';

export function useFeatureFlag(flag: FeatureFlag): boolean {
  return match(flag)
    .with('community', () => import.meta.env.MODE === 'development')
    .with('company', () => Boolean(import.meta.env.VITE_COMPANY_API_BASE?.trim()))
    .otherwise(() => false);
}
