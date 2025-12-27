import { useMemo } from 'react';
import { useAuthOSContext } from '../context';

/**
 * Hook to check if the current user has a specific permission.
 *
 * @param permission - The permission string to check for
 * @returns True if the user has the permission, false otherwise
 *
 * @example
 * ```tsx
 * function AdminPanel() {
 *   const canManageUsers = usePermission('users:manage');
 *
 *   if (!canManageUsers) {
 *     return <div>Access denied</div>;
 *   }
 *
 *   return <div>Admin Panel Content</div>;
 * }
 * ```
 */
export function usePermission(permission: string): boolean {
  const { user } = useAuthOSContext();

  return useMemo(() => {
    if (!user?.permissions) return false;
    return user.permissions.includes(permission);
  }, [user?.permissions, permission]);
}

/**
 * Hook to check if the current user has any of the specified permissions.
 *
 * @param permissions - Array of permission strings to check
 * @returns True if the user has at least one of the permissions
 *
 * @example
 * ```tsx
 * function EditButton() {
 *   const canEdit = useAnyPermission(['posts:edit', 'posts:manage']);
 *
 *   if (!canEdit) return null;
 *
 *   return <button>Edit</button>;
 * }
 * ```
 */
export function useAnyPermission(permissions: string[]): boolean {
  const { user } = useAuthOSContext();

  return useMemo(() => {
    if (!user?.permissions) return false;
    return permissions.some((perm) => user.permissions.includes(perm));
  }, [user?.permissions, permissions]);
}

/**
 * Hook to check if the current user has all of the specified permissions.
 *
 * @param permissions - Array of permission strings that are all required
 * @returns True only if the user has all of the permissions
 *
 * @example
 * ```tsx
 * function AdvancedSettings() {
 *   const hasAccess = useAllPermissions(['settings:view', 'settings:edit']);
 *
 *   if (!hasAccess) return <div>Insufficient permissions</div>;
 *
 *   return <SettingsForm />;
 * }
 * ```
 */
export function useAllPermissions(permissions: string[]): boolean {
  const { user } = useAuthOSContext();

  return useMemo(() => {
    if (!user?.permissions) return false;
    return permissions.every((perm) => user.permissions.includes(perm));
  }, [user?.permissions, permissions]);
}
