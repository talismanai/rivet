import { useQuery } from '@tanstack/react-query';
import { useAtom } from 'jotai';
import { useEffect } from 'react';
import { isLoggedInToCompanyState } from '../state/company';
import { getCompanyApi } from '../utils/getCompanyApi';

function isCompanyProfilePayload(data: unknown): data is { user: Record<string, unknown> } {
  return typeof data === 'object' && data != null && 'user' in data && (data as { user?: unknown }).user != null;
}

export function useCompanySession() {
  const profileUrl = getCompanyApi('profile');
  const [isLoggedInToCompany, setIsLoggedInToCompany] = useAtom(isLoggedInToCompanyState);

  useEffect(() => {
    if (!profileUrl) {
      setIsLoggedInToCompany(false);
    }
  }, [profileUrl, setIsLoggedInToCompany]);

  const { refetch } = useQuery({
    queryKey: ['company-profile', profileUrl],
    enabled: profileUrl != null,
    retry: false,
    queryFn: async () => {
      if (!profileUrl) {
        setIsLoggedInToCompany(false);
        return { user: null };
      }

      try {
        const response = await fetch(profileUrl, {
          credentials: 'include',
        });

        if (response.status !== 200) {
          setIsLoggedInToCompany(false);
          return { user: null };
        }

        const data: unknown = await response.json();

        if (!isCompanyProfilePayload(data)) {
          setIsLoggedInToCompany(false);
          return { user: null };
        }

        setIsLoggedInToCompany(true);
        return data;
      } catch {
        setIsLoggedInToCompany(false);
        return { user: null };
      }
    },
  });

  useEffect(() => {
    if (profileUrl && isLoggedInToCompany === undefined) {
      refetch();
    }
  }, [isLoggedInToCompany, profileUrl, refetch]);

  return isLoggedInToCompany;
}
