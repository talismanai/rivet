import { useEffect, useRef, useState } from 'react';
import { useAtomValue, useStore } from 'jotai';
import Button from '@atlaskit/button';
import { toast } from 'react-toastify';
import { getPluginConfig, signInWithHttpAuthentication, type RivetPlugin } from '@ironclad/rivet-core';
import { settingsState } from '../state/settings';
import { openedProjectsSortedIdsState, projectState } from '../state/savedGraphs';
import { httpAuthenticationSessionsState } from '../state/httpAuthentication';
import { remoteDebuggerState } from '../state/execution';
import { useHttpAuthenticationContext } from '../hooks/useHttpAuthenticationContext';
import { fillMissingSettingsFromEnvironmentVariables, isInTauri } from '../utils/tauri';
import { requestHttpAuthentication } from '../utils/httpAuthentication';
import { syncHttpAuthenticationSessions } from '../utils/syncHttpAuthenticationSessions';

export function PluginOAuthSignIn({ plugin }: { plugin: RivetPlugin }) {
  const settings = useAtomValue(settingsState);
  const project = useAtomValue(projectState);
  const openProjects = useAtomValue(openedProjectsSortedIdsState);
  const sessions = useAtomValue(httpAuthenticationSessionsState);
  const publish = useHttpAuthenticationContext();
  const store = useStore();
  const controller = useRef<AbortController>();
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState('');
  const desktop = isInTauri();
  const projectOpen = openProjects.includes(project.metadata.id);

  useEffect(() => {
    setBusy(false);
    setProgress('');
    return () => {
      controller.current?.abort();
      controller.current = undefined;
    };
  }, [project.metadata.id]);

  const signIn = async () => {
    if (controller.current || !plugin.httpAuthentication || !desktop || !projectOpen) return;
    const abort = new AbortController();
    controller.current = abort;
    setBusy(true);
    setProgress('Starting Chrome…');
    try {
      const config = plugin.httpAuthentication;
      const resolved = await fillMissingSettingsFromEnvironmentVariables(settings, [plugin]);
      abort.signal.throwIfAborted();
      const read = (key?: string) => (key ? getPluginConfig(plugin, resolved, key)?.trim() : undefined);
      const apiUrl = read(config.requestUrlConfigKey) ?? '';
      const authorization = read(config.authorizationConfigKey);
      const result = await signInWithHttpAuthentication(
        apiUrl,
        { headers: authorization ? { authorization } : {} },
        {
          signal: abort.signal,
          requestHttpAuthentication: (request, signal) =>
            requestHttpAuthentication(request, signal, (message) => {
              if (controller.current === abort && !abort.signal.aborted) setProgress(message);
            }),
          httpAuthenticationCache: sessions.forProject(project.metadata.id),
          onHttpAuthenticationToken: (key, token) => publish(project.metadata.id, key, token),
        },
        {
          loginUrl: read(config.loginUrlConfigKey),
          tokenContextKey: read(config.tokenContextKeyConfigKey),
          tokenSource: config.tokenSource,
        },
      );
      if (controller.current !== abort || abort.signal.aborted) return;
      if (result) {
        setProgress('JWT captured. Authentication is ready for this project.');
        syncHttpAuthenticationSessions(store.get(remoteDebuggerState).socket, sessions, [project.metadata.id]);
        toast.success('Signed in. Authentication is ready for this project.');
      } else {
        toast.info('Chrome closed before Rivet captured a token. See the capture status below.');
      }
    } catch (error) {
      if (controller.current === abort) {
        if (abort.signal.aborted) setProgress('Sign-in cancelled.');
        else {
          setProgress('Sign-in did not complete.');
          toast.error(String(error));
        }
      }
    } finally {
      if (controller.current === abort) {
        controller.current = undefined;
        setBusy(false);
      }
    }
  };

  return (
    <div>
      <Button
        onClick={() => {
          void signIn();
        }}
        isDisabled={!desktop || !projectOpen || busy}
      >
        {busy ? 'Signing in…' : 'Sign in'}
      </Button>
      {busy && <Button onClick={() => controller.current?.abort()}>Cancel sign-in</Button>}
      {progress && <p role="status">{progress}</p>}
      <p>
        {!desktop
          ? 'Sign-in requires the Rivet desktop app.'
          : !projectOpen
            ? 'Open a project before signing in.'
            : 'Opens a fresh login and updates this project’s authentication session and configured context value.'}
      </p>
    </div>
  );
}
