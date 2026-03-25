import join from 'url-join';

export function getCompanyApiBaseUrl(): string | undefined {
  const base = import.meta.env.VITE_COMPANY_API_BASE?.trim();
  return base && base.length > 0 ? base.replace(/\/$/, '') : undefined;
}

export function getCompanyApi(path?: string): string | undefined {
  const base = getCompanyApiBaseUrl();
  if (!base) {
    return undefined;
  }
  return join(base, 'api', path || '');
}

export function getCompanyLoginUrl(): string | undefined {
  const base = getCompanyApiBaseUrl();
  if (!base) {
    return undefined;
  }
  return join(base, 'auth', 'signin');
}
