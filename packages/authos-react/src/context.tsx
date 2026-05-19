import { createContext, useContext, useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { SsoClient, UserProfile, Organization } from '@drmhse/sso-sdk';
import type { AuthOSContextState, AuthOSProviderProps } from './types';
import { injectStyles, applyVariables } from './styles';

const AuthOSContext = createContext<AuthOSContextState | null>(null);

/**
 * Provider component that wraps your app and provides AuthOS context.
 *
 * @example Basic usage
 * ```tsx
 * import { AuthOSProvider, SignIn, SignedOut } from '@drmhse/authos-react';
 *
 * function App() {
 *   return (
 *     <AuthOSProvider config={{ baseURL: 'https://sso.example.com' }}>
 *       <SignedOut>
 *         <SignIn />
 *       </SignedOut>
 *     </AuthOSProvider>
 *   );
 * }
 * ```
 *
 * @example With OAuth (requires org and service)
 * ```tsx
 * <AuthOSProvider config={{
 *   baseURL: 'https://sso.example.com',
 *   org: 'my-org',
 *   service: 'my-app',
 * }}>
 *   <SignIn providers={['github', 'google']} />
 * </AuthOSProvider>
 * ```
 *
 * @example With SSR token (Next.js App Router)
 * ```tsx
 * import { cookies } from 'next/headers';
 * import { AuthOSProvider } from '@drmhse/authos-react';
 *
 * export default async function RootLayout({ children }) {
 *   const cookieStore = cookies();
 *   const token = cookieStore.get('authos_token')?.value;
 *
 *   return (
 *     <AuthOSProvider
 *       config={{ baseURL: 'https://sso.example.com' }}
 *       initialSessionToken={token}
 *     >
 *       {children}
 *     </AuthOSProvider>
 *   );
 * }
 * ```
 */
export function AuthOSProvider({ config, children, client: externalClient, initialSessionToken }: AuthOSProviderProps) {
  const clientRef = useRef<SsoClient | null>(null);

  // Create or use the provided client
  if (!clientRef.current) {
    clientRef.current = externalClient ?? new SsoClient(config);
  }


  const client = clientRef.current;

  // Inject styles on mount
  useEffect(() => {
    injectStyles();

    // Apply custom appearance variables if provided
    if (config.appearance?.variables) {
      applyVariables(config.appearance.variables as Record<string, string>);
    }

    // Runtime validation for OAuth configuration
    if (config.org && !config.service) {
      console.warn(
        '[AuthOS] You provided "org" but not "service". OAuth flows may not work correctly.'
      );
    }
    if (!config.org && config.service) {
      console.warn(
        '[AuthOS] You provided "service" but not "org". OAuth flows may not work correctly.'
      );
    }
  }, [config.appearance]);

  // If we have an initial token from SSR, set it on the client immediately
  // This prevents the loading flash and enables immediate auth state
  const hasInitialToken = useRef(!!initialSessionToken);
  useEffect(() => {
    if (initialSessionToken && hasInitialToken.current) {
      client.setSession({ access_token: initialSessionToken });
      hasInitialToken.current = false; // Only set once
    }
  }, [client, initialSessionToken]);

  const [user, setUser] = useState<UserProfile | null>(null);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [isLoading, setIsLoading] = useState(!initialSessionToken);

  const refreshUser = useCallback(async () => {
    try {
      const profile = await client.user.getProfile();
      setUser(profile);
    } catch {
      setUser(null);
    }
  }, [client]);

  useEffect(() => {
    // Subscribe to auth state changes
    const unsubscribe = client.onAuthStateChange(async (isAuthenticated) => {
      if (isAuthenticated) {
        try {
          const profile = await client.user.getProfile();
          setUser(profile);
        } catch {
          setUser(null);
        }
      } else {
        setUser(null);
        setOrganization(null);
      }
      setIsLoading(false);
    });

    return unsubscribe;
  }, [client]);

  const contextValue = useMemo<AuthOSContextState>(
    () => ({
      client,
      config,
      user,
      isAuthenticated: !!user,
      isLoading,
      organization,
      setUser,
      setOrganization,
      refreshUser,
    }),
    [client, config, user, isLoading, organization, refreshUser]
  );

  return <AuthOSContext.Provider value={contextValue}>{children}</AuthOSContext.Provider>;
}

/**
 * Hook to access the AuthOS context.
 * Must be used within an AuthOSProvider.
 *
 * @throws Error if used outside of AuthOSProvider
 */
export function useAuthOSContext(): AuthOSContextState {
  const context = useContext(AuthOSContext);
  if (!context) {
    throw new Error('useAuthOSContext must be used within an AuthOSProvider');
  }
  return context;
}
