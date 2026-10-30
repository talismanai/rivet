import type { SyncStorage } from 'jotai/vanilla/utils/atomWithStorage';
import type { RemoteDebuggerState } from '../state/execution';

function disconnected(state: RemoteDebuggerState): RemoteDebuggerState {
  return {
    ...state,
    socket: null,
    started: false,
    reconnecting: false,
    remoteUploadAllowed: false,
    isInternalExecutor: false,
  };
}

/** Persist debugger preferences, never a WebSocket or a previous connection's capabilities. */
export function createRemoteDebuggerStorage(
  storage: SyncStorage<RemoteDebuggerState>,
): SyncStorage<RemoteDebuggerState> {
  return {
    // Older versions serialized WebSocket as {}. Discard it when restoring saved state.
    getItem: (key, initialValue) => disconnected(storage.getItem(key, initialValue)),
    setItem: (key, value) => storage.setItem(key, disconnected(value)),
    removeItem: (key) => storage.removeItem(key),
  };
}
