import { useAuthOSContext } from '../context';

/**
 * Hook to access the AuthOS client and loading status.
 *
 * @returns The SDK client instance and loading state
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { client, isLoading } = useAuthOS();
 *
 *   if (isLoading) return <div>Loading...</div>;
 *
 *   const handleLogin = async () => {
 *     await client.auth.login({ email, password });
 *   };
 * }
 * ```
 */
export function useAuthOS() {
  const { client, isLoading, isAuthenticated } = useAuthOSContext();
  return { client, isLoading, isAuthenticated };
}
