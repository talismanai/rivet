import { css } from '@emotion/react';
import { useState, type FC, type ReactNode } from 'react';
import { useAtomValue } from 'jotai';
import { overlayOpenState } from '../../state/ui';
import { ErrorBoundary } from 'react-error-boundary';
import { SideNavigation, ButtonItem, Section } from '@atlaskit/side-navigation';
import { match } from 'ts-pattern';
import { useCompanySession } from '../../hooks/useCompanySession';
import { CompanyNeedsLoginPage } from './CompanyNeedsLoginPage';
import { CompanyDeployPanel } from './CompanyDeployPanel';

const styles = css`
  position: fixed;
  left: 250px;
  top: var(--project-selector-height);
  right: 0;
  bottom: 0;
  background: var(--grey-darker);
  padding: 64px 32px 0 32px;
  z-index: 150;

  display: flex;
  flex-direction: column;
  gap: 16px;
  padding-bottom: 16px;

  .main {
    display: grid;
    grid-template-columns: 250px 1fr;
    flex: 1 1 auto;
    column-gap: 16px;
    min-height: 0;
    overflow: hidden;
  }

  .selected-nav-area {
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-height: 0;
    overflow: auto;
  }

  .company-info {
    max-width: 720px;
    color: var(--grey-light);
    line-height: 1.5;
  }
`;

export const CompanyOverlayRenderer: FC = () => {
  const openOverlay = useAtomValue(overlayOpenState);

  if (openOverlay !== 'company') return null;

  return (
    <ErrorBoundary fallbackRender={() => 'Failed to render Company overlay'}>
      <CompanyOverlay />
    </ErrorBoundary>
  );
};

export const CompanyOverlay: FC = () => {
  const [selectedNav, setSelectedNav] = useState('deploy');

  return (
    <div css={styles}>
      <h1>Company</h1>
      <p className="company-info">
        Sign in with your company Google account (session cookie). Use the deploy key from your backend to publish
        project metadata to your company API. For Google Workspace, AWS, and internal APIs, your backend should issue
        short-lived tokens after OAuth — the desktop app does not store Google or AWS secrets.
      </p>
      <div className="main">
        <SideNavigation label="Company">
          <Section title="Actions">
            <ButtonItem isSelected={selectedNav === 'deploy'} onClick={() => setSelectedNav('deploy')}>
              Deploy
            </ButtonItem>
          </Section>
        </SideNavigation>
        <div className="selected-nav-area">
          {match(selectedNav)
            .with('deploy', () => (
              <NeedsCompanyLogin>
                <CompanyDeployPanel />
              </NeedsCompanyLogin>
            ))
            .otherwise(() => `Unknown nav: ${selectedNav}`)}
        </div>
      </div>
    </div>
  );
};

const NeedsCompanyLogin: FC<{ children: ReactNode }> = ({ children }) => {
  const isLoggedIn = useCompanySession();

  if (isLoggedIn === undefined) {
    return null;
  }

  if (!isLoggedIn) return <CompanyNeedsLoginPage />;

  return <>{children}</>;
};
