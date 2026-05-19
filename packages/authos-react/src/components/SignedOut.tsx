import { useAuthOSContext } from '../context';
import type { SignedOutProps } from '../types';

/**
 * Renders children only when the user is NOT authenticated.
 * Use with SignedIn to create conditional UI based on auth state.
 *
 * @example
 * ```tsx
 * import { SignedIn, SignedOut, UserButton, SignIn } from '@drmhse/authos-react';
 *
 * function Header() {
 *   return (
 *     <header>
 *       <SignedIn>
 *         <UserButton />
 *       </SignedIn>
 *       <SignedOut>
 *         <SignIn />
 *       </SignedOut>
 *     </header>
 *   );
 * }
 * ```
 */
export function SignedOut({ children }: SignedOutProps) {
  const { isAuthenticated, isLoading } = useAuthOSContext();

  // Don't render while loading to prevent flash of content
  if (isLoading) {
    return null;
  }

  // Only render when NOT authenticated
  if (isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
