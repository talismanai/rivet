/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL for company auth and APIs (e.g. https://rivet.mycompany.com). No trailing slash. */
  readonly VITE_COMPANY_API_BASE?: string;
  /** Optional full URL for deploy POST (overrides `${VITE_COMPANY_API_BASE}/api/deploy`). */
  readonly VITE_COMPANY_DEPLOY_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
