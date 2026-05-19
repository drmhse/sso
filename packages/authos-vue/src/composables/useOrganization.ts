import { inject, computed, ref } from 'vue';
import type { AuthOSContext } from '../types';
import { AUTH_OS_INJECTION_KEY } from '../types';

/**
 * Composable to access the current organization context and switch between organizations.
 *
 * When switching organizations, this calls the backend to issue new JWT tokens
 * with the organization context, enabling seamless organization switching without
 * requiring re-authentication.
 *
 * @returns The current organization and a function to switch organizations
 *
 * @example
 * ```vue
 * <script setup>
 * import { useOrganization } from '@drmhse/authos-vue';
 *
 * const { currentOrganization, switchOrganization, isSwitching } = useOrganization();
 * </script>
 * ```
 */
export function useOrganization() {
  const context = inject<AuthOSContext>(AUTH_OS_INJECTION_KEY);

  if (!context) {
    // Return default values when not wrapped in provider (e.g., in tests)
    return {
      currentOrganization: ref(null),
      organizations: ref([]),
      switchOrganization: async () => null,
      isSwitching: ref(false),
    };
  }

  const currentOrganization = computed(() => context.state.currentOrganization);
  const organizations = computed(() => context.state.organizations);
  const isSwitching = ref(false);

  async function switchOrganization(slug: string) {
    if (!context) return;
    isSwitching.value = true;
    try {
      // Call the backend to issue new org-scoped tokens
      const result = await context.client.organizations.select(slug);

      // Update the SDK session with the new tokens
      await context.client.setSession({
        access_token: result.access_token,
        refresh_token: result.refresh_token,
      });

      // Update the local organization state with full response
      const orgResponse = await context.client.organizations.get(slug);
      context.state.currentOrganization = orgResponse;

      return orgResponse;
    } finally {
      isSwitching.value = false;
    }
  }

  return {
    currentOrganization,
    organizations,
    switchOrganization,
    isSwitching,
  };
}
