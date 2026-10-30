import { useStore } from 'jotai';
import { useCallback } from 'react';
import type { HttpAuthenticationToken, ProjectId } from '@ironclad/rivet-core';
import { openedProjectsSortedIdsState, projectContextState, projectState } from '../state/savedGraphs';
import { withHttpAuthenticationToken } from '../utils/httpAuthenticationContext';

export function useHttpAuthenticationContext() {
  const store = useStore();
  return useCallback(
    (projectId: ProjectId, contextKey: string, token: HttpAuthenticationToken) => {
      // An authentication may finish after switching projects. Update its owner, never the active project by default.
      if (
        store.get(projectState).metadata.id !== projectId &&
        !store.get(openedProjectsSortedIdsState).includes(projectId)
      )
        return;
      store.set(projectContextState(projectId), (current) => withHttpAuthenticationToken(current, contextKey, token));
    },
    [store],
  );
}
