import { useState, useCallback } from 'react';
import { useAuthOSContext } from '../context';
import type { UserButtonProps } from '../types';

/**
 * Component for displaying user info and handling logout.
 *
 * @example
 * ```tsx
 * import { UserButton } from '@drmhse/authos-react';
 *
 * function Header() {
 *   return (
 *     <UserButton
 *       showEmail
 *       onLogout={() => window.location.href = '/'}
 *     />
 *   );
 * }
 * ```
 */
export function UserButton({ className, showEmail = false, onLogout }: UserButtonProps) {
  const { client, user, setUser, setOrganization } = useAuthOSContext();
  const [isOpen, setIsOpen] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const handleLogout = useCallback(async () => {
    setIsLoggingOut(true);
    try {
      await client.auth.logout();
    } catch {
      // Logout may fail if token is already invalid, that's fine
    } finally {
      setUser(null);
      setOrganization(null);
      setIsLoggingOut(false);
      setIsOpen(false);
      onLogout?.();
    }
  }, [client, setUser, setOrganization, onLogout]);

  if (!user) {
    return (
      <div className={className} data-authos-userbutton data-state="signed-out">
        <span data-authos-user-placeholder>Not signed in</span>
      </div>
    );
  }

  // Generate initials from email
  const initials = user.email
    .split('@')[0]
    .split('.')
    .map((part) => part[0]?.toUpperCase() ?? '')
    .slice(0, 2)
    .join('');

  return (
    <div className={className} data-authos-userbutton="" data-state={isOpen ? 'open' : 'closed'}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        disabled={isLoggingOut}
        data-authos-user-trigger=""
      >
        <span data-authos-avatar="" aria-hidden="true">
          {initials}
        </span>
        {showEmail && <span data-authos-email="">{user.email}</span>}
      </button>

      {isOpen && (
        <div data-authos-user-menu="">
          <div data-authos-user-info="">
            <span data-authos-email="">{user.email}</span>
            {user.is_platform_owner && (
              <span data-authos-badge="">Platform Owner</span>
            )}
          </div>

          <div data-authos-divider=""></div>

          <button
            type="button"
            onClick={handleLogout}
            disabled={isLoggingOut}
            data-authos-logout=""
          >
            {isLoggingOut ? 'Signing out...' : 'Sign out'}
          </button>
        </div>
      )}
    </div>
  );
}
