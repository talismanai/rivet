import { type NodeGraph } from '@ironclad/rivet-core';
import { useMutation } from '@tanstack/react-query';
import { useAtom, useAtomValue } from 'jotai';
import { useCallback } from 'react';
import { toast } from 'react-toastify';
import { companyDeployApiKeyState } from '../state/company';
import { loadedProjectState, projectState } from '../state/savedGraphs';
import { getCompanyApi } from '../utils/getCompanyApi';

function getDeployUrl(): string | undefined {
  const fromEnv = import.meta.env.VITE_COMPANY_DEPLOY_URL?.trim();
  if (fromEnv) {
    return fromEnv;
  }
  return getCompanyApi('deploy');
}

export type CompanyDeployPayload = {
  projectFilePath: string | null;
  projectTitle: string;
  projectId: string;
  graphCount: number;
  graphNames: string[];
  /** Optional: set when the deploy endpoint accepts a serialized project snapshot */
  serializedProject?: string;
};

export function useCompanyDeploy() {
  const project = useAtomValue(projectState);
  const loadedProject = useAtomValue(loadedProjectState);
  const [deployApiKey, setDeployApiKey] = useAtom(companyDeployApiKeyState);

  const mutation = useMutation({
    mutationFn: async (payload: CompanyDeployPayload) => {
      const url = getDeployUrl();
      if (!url) {
        throw new Error('Company deploy is not configured (set VITE_COMPANY_API_BASE or VITE_COMPANY_DEPLOY_URL).');
      }
      if (!deployApiKey.trim()) {
        throw new Error('Enter a deploy API key from your company session.');
      }

      const response = await fetch(url, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${deployApiKey.trim()}`,
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `Deploy failed (${response.status})`);
      }

      return response.json().catch(() => ({}));
    },
    onSuccess: () => {
      toast.success('Deploy request sent');
    },
    onError: (err: Error) => {
      toast.error(err.message);
    },
  });

  const deploy = useCallback(
    (options?: { includeSerializedProject?: boolean }) => {
      const graphNames = Object.values(project.graphs).map((g: NodeGraph) => g.metadata?.name ?? 'Untitled');
      const payload: CompanyDeployPayload = {
        projectFilePath: loadedProject.path,
        projectTitle: project.metadata.title,
        projectId: project.metadata.id,
        graphCount: Object.keys(project.graphs).length,
        graphNames,
      };
      if (options?.includeSerializedProject) {
        payload.serializedProject = JSON.stringify(project);
      }
      mutation.mutate(payload);
    },
    [loadedProject.path, mutation, project],
  );

  return {
    deployApiKey,
    setDeployApiKey,
    deploy,
    isDeploying: mutation.isPending,
  };
}
