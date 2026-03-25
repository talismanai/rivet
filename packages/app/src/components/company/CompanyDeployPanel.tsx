import Button from '@atlaskit/button';
import Textfield from '@atlaskit/textfield';
import { type FC, useState } from 'react';
import { useCompanyDeploy } from '../../hooks/useCompanyDeploy';
import Checkbox from '@atlaskit/checkbox';

export const CompanyDeployPanel: FC = () => {
  const { deployApiKey, setDeployApiKey, deploy, isDeploying } = useCompanyDeploy();
  const [includeProjectJson, setIncludeProjectJson] = useState(false);

  return (
    <div className="company-deploy">
      <h2>Deploy to company</h2>
      <p>
        Sends metadata about the current project to your company deploy API. Paste the API key issued when you signed in
        (or from your account page). The key is stored only on this device.
      </p>
      <label htmlFor="company-deploy-key">Deploy API key</label>
      <Textfield
        id="company-deploy-key"
        name="company-deploy-key"
        type="password"
        value={deployApiKey}
        onChange={(e) => setDeployApiKey(e.currentTarget.value)}
        placeholder="Paste key from your company session"
        isRequired
      />
      <div style={{ marginTop: 12 }}>
        <Checkbox
          isChecked={includeProjectJson}
          onChange={() => setIncludeProjectJson((v) => !v)}
          label="Include full project JSON in the request (can be large)"
        />
      </div>
      <p style={{ marginTop: 16 }}>
        <Button
          appearance="primary"
          onClick={() => deploy({ includeSerializedProject: includeProjectJson })}
          isDisabled={isDeploying}
        >
          {isDeploying ? 'Deploying…' : 'Deploy'}
        </Button>
      </p>
    </div>
  );
};
