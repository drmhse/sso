import { inject, computed } from 'vue';
import type { AuthOSContext } from '../types';
import { AUTH_OS_INJECTION_KEY } from '../types';
import { SsoClient, MemoryStorage } from '@drmhse/sso-sdk';

export function useAuthOS() {
  const context = inject<AuthOSContext>(AUTH_OS_INJECTION_KEY);

  if (!context) {
    // Return a default client when not wrapped in provider (e.g., in tests)
    // This allows components to render without requiring AuthOSProvider wrapper
    const defaultClient = new SsoClient({
      baseURL: 'http://localhost:3001',
      storage: new MemoryStorage(),
    });
    return {
      client: defaultClient,
      isLoading: computed(() => false),
      isAuthenticated: computed(() => false),
    };
  }

  const isLoading = computed(() => context.state.isLoading);
  const isAuthenticated = computed(() => context.state.isAuthenticated);

  return {
    client: context.client,
    isLoading,
    isAuthenticated,
  };
}
