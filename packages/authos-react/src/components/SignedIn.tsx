import { useAuthOSContext } from '../context';
import type { SignedInProps } from '../types';

/**
 * Renders children only when the user is authenticated.
 * Use with SignedOut to create conditional UI based on auth state.
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
export function SignedIn({ children }: SignedInProps) {
  const { isAuthenticated, isLoading } = useAuthOSContext();

  // Don't render while loading to prevent flash of content
  if (isLoading) {
    return null;
  }

  // Only render when authenticated
  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
