import { inject, computed, ref } from 'vue';
import type { AuthOSContext } from '../types';
import { AUTH_OS_INJECTION_KEY } from '../types';

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
