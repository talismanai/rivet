import Button from '@atlaskit/button';
import { WebviewWindow } from '@tauri-apps/api/window';
import { type FC } from 'react';
import { useSetAtom } from 'jotai';
import { getCompanyLoginUrl } from '../../utils/getCompanyApi';
import { isLoggedInToCompanyState } from '../../state/company';

export const CompanyNeedsLoginPage: FC = () => {
  const loginUrl = getCompanyLoginUrl();
  const setIsLoggedInToCompany = useSetAtom(isLoggedInToCompanyState);

  const handleLogInClick = () => {
    if (!loginUrl) {
      return;
    }
    const window = new WebviewWindow('company-login', { alwaysOnTop: true, center: true, url: loginUrl });

    window.once('tauri://created', () => {
      console.log('company login window created');
    });

    window.once('tauri://error', (e) => {
      console.error(e);
    });

    window.onCloseRequested(() => {
      setIsLoggedInToCompany(undefined);
    });
  };

  if (!loginUrl) {
    return (
      <div className="needs-login">
        <h1>Company login</h1>
        <p>Company API base URL is not configured. Set VITE_COMPANY_API_BASE when building the app.</p>
      </div>
    );
  }

  return (
    <div className="needs-login">
      <h1>Sign in with Google</h1>
      <p>Use your company Google account. After you finish signing in, close the login window to refresh your session.</p>
      <p>
        <Button appearance="primary" onClick={handleLogInClick}>
          Log in
        </Button>
      </p>
    </div>
  );
};
