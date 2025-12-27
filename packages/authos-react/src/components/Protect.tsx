import { useAuthOSContext } from '../context';
import { usePermission } from '../hooks/usePermission';
import type { ProtectProps } from '../types';

/**
 * Component that conditionally renders children based on permission or role.
 *
 * @example
 * ```tsx
 * import { Protect } from '@drmhse/authos-react';
 *
 * function AdminPage() {
 *   return (
 *     <Protect
 *       permission="admin:access"
 *       fallback={<div>Access denied</div>}
 *     >
 *       <AdminDashboard />
 *     </Protect>
 *   );
 * }
 *
 * // Or using role
 * function OwnerSettings() {
 *   return (
 *     <Protect role="owner">
 *       <DangerZone />
 *     </Protect>
 *   );
 * }
 * ```
 */
export function Protect({ permission, role, fallback = null, children }: ProtectProps) {
  const { user, isLoading } = useAuthOSContext();
  const hasPermission = usePermission(permission ?? '');

  // Determine what to render
  const renderContent = () => {
    // While loading, show nothing inside the container
    if (isLoading) {
      return null;
    }

    // If not authenticated, show fallback
    if (!user) {
      return fallback;
    }

    // Check permission if provided
    if (permission && !hasPermission) {
      return fallback;
    }

    // Check role if provided
    if (role) {
      // Get the user's role from their permissions
      // Convention: role permissions are prefixed with "role:"
      const userRoles = user.permissions
        .filter((p) => p.startsWith('role:'))
        .map((p) => p.replace('role:', ''));

      const roleHierarchy = ['member', 'admin', 'owner'];
      const requiredRoleIndex = roleHierarchy.indexOf(role);
      const hasRole = userRoles.some((userRole) => {
        const userRoleIndex = roleHierarchy.indexOf(userRole);
        return userRoleIndex >= requiredRoleIndex;
      });

      if (!hasRole) {
        return fallback;
      }
    }

    return children;
  };

  return <div data-authos-protect>{renderContent()}</div>;
}
