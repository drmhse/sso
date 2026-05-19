import { computed, type ComputedRef } from 'vue';
import { useUser } from './useUser';

/**
 * Check if the current user has a specific permission.
 *
 * @param permission The permission to check
 * @returns A computed ref that is true if the user has the permission
 *
 * @example
 * ```vue
 * <script setup>
 * import { usePermission } from '@drmhse/authos-vue';
 *
 * const canAccessAdmin = usePermission('admin:access');
 * </script>
 *
 * <template>
 *   <button v-if="canAccessAdmin">Admin Panel</button>
 * </template>
 * ```
 */
export function usePermission(permission: string): ComputedRef<boolean> {
  const { user } = useUser();

  return computed(() => {
    if (!user.value || !permission) return false;
    return user.value.permissions?.includes(permission) ?? false;
  });
}

/**
 * Check if the current user has any of the specified permissions.
 *
 * @param permissions The permissions to check
 * @returns A computed ref that is true if the user has any of the permissions
 *
 * @example
 * ```vue
 * <script setup>
 * import { useAnyPermission } from '@drmhse/authos-vue';
 *
 * const canAccessReports = useAnyPermission(['reports:read', 'admin:access']);
 * </script>
 * ```
 */
export function useAnyPermission(permissions: string[]): ComputedRef<boolean> {
  const { user } = useUser();

  return computed(() => {
    if (!user.value || permissions.length === 0) return false;
    return permissions.some((p) => user.value?.permissions?.includes(p));
  });
}

/**
 * Check if the current user has all of the specified permissions.
 *
 * @param permissions The permissions to check
 * @returns A computed ref that is true if the user has all of the permissions
 *
 * @example
 * ```vue
 * <script setup>
 * import { useAllPermissions } from '@drmhse/authos-vue';
 *
 * const canManageBilling = useAllPermissions(['billing:read', 'billing:write']);
 * </script>
 * ```
 */
export function useAllPermissions(permissions: string[]): ComputedRef<boolean> {
  const { user } = useUser();

  return computed(() => {
    if (!user.value || permissions.length === 0) return false;
    return permissions.every((p) => user.value?.permissions?.includes(p));
  });
}
