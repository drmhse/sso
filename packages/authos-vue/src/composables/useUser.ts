import { inject, computed, ref } from 'vue';
import type { AuthOSContext } from '../types';
import { AUTH_OS_INJECTION_KEY } from '../types';

export function useUser() {
  const context = inject<AuthOSContext>(AUTH_OS_INJECTION_KEY);

  if (!context) {
    // Return default values when not wrapped in provider (e.g., in tests)
    return {
      user: ref(null),
      isLoading: computed(() => false),
    };
  }

  const user = computed(() => context.state.user);
  const isLoading = computed(() => context.state.isLoading);

  return {
    user,
    isLoading,
  };
}
