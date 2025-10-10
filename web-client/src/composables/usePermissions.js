import { computed } from 'vue';
import { useAuthStore } from '@/stores/auth';

/**
 * Composable for checking user permissions and roles.
 * Provides convenient boolean flags for authorization logic.
 */
export function usePermissions() {
  const authStore = useAuthStore();

  const isPlatformOwner = computed(() => authStore.isPlatformOwner);

  const isOrgOwner = computed(() => authStore.currentRole === 'owner');

  const isOrgAdmin = computed(() => ['owner', 'admin'].includes(authStore.currentRole));

  const isOrgMember = computed(() =>
    ['owner', 'admin', 'member'].includes(authStore.currentRole)
  );

  const canManageTeam = computed(() => isOrgAdmin.value);

  const canManageServices = computed(() => isOrgAdmin.value);

  const canManageBilling = computed(() => isOrgOwner.value);

  return {
    isPlatformOwner,
    isOrgOwner,
    isOrgAdmin,
    isOrgMember,
    canManageTeam,
    canManageServices,
    canManageBilling,
  };
}
