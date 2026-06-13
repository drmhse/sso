import { useState, useCallback, FormEvent, useEffect } from 'react';
import { SsoApiError } from '@drmhse/sso-sdk';
import { useAuthOSContext } from '../context';

export interface PasskeySignInProps {
  /** Callback when passkey sign-in is successful */
  onSuccess?: () => void;
  /** Callback when sign-in fails */
  onError?: (error: Error) => void;
  /** Organization slug for B2B service-scoped passkey sign-in. Defaults to provider config org. */
  orgSlug?: string;
  /** Service slug for B2B service-scoped passkey sign-in. Defaults to provider config service. */
  serviceSlug?: string;
  /** Redirect URI to validate for service-scoped passkey sign-in. Defaults to provider config redirectUri. */
  redirectUri?: string;
  /** Caller state to preserve through service-scoped passkey sign-in. */
  state?: string;
  /** Custom class name */
  className?: string;
  /** Show sign in with password link */
  showPasswordSignIn?: boolean;
}

/**
 * Passkey (WebAuthn) sign-in component.
 * 
 * Uses the Web Authentication API for passwordless authentication
 * via biometrics, security keys, or platform authenticators.
 * 
 * @example
 * ```tsx
 * import { PasskeySignIn } from '@drmhse/authos-react';
 * 
 * function LoginPage() {
 *   return (
 *     <PasskeySignIn
 *       onSuccess={() => router.push('/dashboard')}
 *       onError={(err) => console.error(err)}
 *     />
 *   );
 * }
 * ```
 */
export function PasskeySignIn({
  onSuccess,
  onError,
  orgSlug,
  serviceSlug,
  redirectUri,
  state: authState,
  className,
  showPasswordSignIn = true,
}: PasskeySignInProps) {
  const { client, config, setUser } = useAuthOSContext();
  
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSupported, setIsSupported] = useState(true);

  // Check WebAuthn support
  useEffect(() => {
    setIsSupported(client.passkeys.isSupported());
  }, [client]);

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setError(null);
      setIsLoading(true);

      try {
        const org = orgSlug ?? config.org;
        const service = serviceSlug ?? config.service;
        const passkeyContext = org && service
          ? {
              org_slug: org,
              service_slug: service,
              redirect_uri: redirectUri ?? config.redirectUri,
              state: authState,
            }
          : undefined;

        // Use the SDK's convenient login method which handles the full WebAuthn flow
        await client.passkeys.login(email, passkeyContext);

        // Refresh user profile
        const profile = await client.user.getProfile();
        setUser(profile);
        onSuccess?.();
      } catch (err) {
        const message = err instanceof SsoApiError 
          ? err.message 
          : err instanceof Error 
            ? err.message 
            : 'Passkey authentication failed';
        setError(message);
        onError?.(err instanceof Error ? err : new Error(message));
      } finally {
        setIsLoading(false);
      }
    },
    [client, email, orgSlug, serviceSlug, redirectUri, authState, config.org, config.service, config.redirectUri, setUser, onSuccess, onError]
  );

  if (!isSupported) {
    return (
      <div className={className} data-authos-passkey="" data-state="unsupported">
        <div data-authos-error="">
          Passkeys are not supported in this browser.
        </div>
        {showPasswordSignIn && (
          <a href="/signin" data-authos-link="signin">Sign in with password</a>
        )}
      </div>
    );
  }

  return (
    <div className={className} data-authos-passkey="">
      <form onSubmit={handleSubmit}>
        <div data-authos-field="email">
          <label htmlFor="authos-passkey-email">Email</label>
          <input
            id="authos-passkey-email"
            type="email"
            autoComplete="email webauthn"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            required
            disabled={isLoading}
          />
        </div>

        {error && <div data-authos-error="">{error}</div>}

        <button type="submit" disabled={isLoading} data-authos-submit="">
          {isLoading ? 'Authenticating...' : 'Sign in with Passkey'}
        </button>

        {showPasswordSignIn && (
          <div data-authos-signin-prompt="">
            <a href="/signin" data-authos-link="signin">Sign in with password</a>
          </div>
        )}
      </form>
    </div>
  );
}
