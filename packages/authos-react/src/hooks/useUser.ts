import { useAuthOSContext } from '../context';
import type { UserProfile } from '@drmhse/sso-sdk';

/**
 * Hook to access the current authenticated user.
 *
 * @returns The current user profile or null if not authenticated
 *
 * @example
 * ```tsx
 * function ProfilePage() {
 *   const user = useUser();
 *
 *   if (!user) return <div>Please sign in</div>;
 *
 *   return <div>Welcome, {user.email}!</div>;
 * }
 * ```
 */
export function useUser(): UserProfile | null {
  const { user } = useAuthOSContext();
  return user;
}
