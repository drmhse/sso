import { inject, ref } from 'vue';

export function useWorkspaceRuntime() {
  return {
    refreshVersion: inject('workspaceRefreshVersion', ref(0)),
    reload: inject('workspaceReload', async () => {}),
    openFullClient: inject('workspaceOpenFullClient', () => {}),
  };
}
