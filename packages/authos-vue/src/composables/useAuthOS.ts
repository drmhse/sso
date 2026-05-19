import { inject, computed } from 'vue';
import type { AuthOSContext, AuthOSPluginOptions } from '../types';
import { AUTH_OS_INJECTION_KEY } from '../types';
import { SsoClient, MemoryStorage } from '@drmhse/sso-sdk';

/**
 * Access the AuthOS client, state, and configuration.
 *
 * @example
 * ```vue
 * <script setup>
 * import { useAuthOS } from '@drmhse/authos-vue';
 *
 * const { client, isAuthenticated, isLoading, options } = useAuthOS();
 *
 * async function handleLogout() {
 *   await client.auth.logout();
 * }
 * </script>
 * ```
 */
export function useAuthOS() {
  const context = inject<AuthOSContext>(AUTH_OS_INJECTION_KEY);

  if (!context) {
    // Return a default client when not wrapped in provider (e.g., in tests)
    // This allows components to render without requiring AuthOSProvider wrapper
    const defaultOptions: AuthOSPluginOptions = {
      baseURL: 'http://localhost:3001',
    };
    const defaultClient = new SsoClient({
      baseURL: defaultOptions.baseURL,
      storage: new MemoryStorage(),
    });
    return {
      client: defaultClient,
      options: defaultOptions,
      isLoading: computed(() => false),
      isAuthenticated: computed(() => false),
    };
  }

  const isLoading = computed(() => context.state.isLoading);
  const isAuthenticated = computed(() => context.state.isAuthenticated);

  return {
    client: context.client,
    options: context.options,
    isLoading,
    isAuthenticated,
  };
}
