import { useState, useCallback, FormEvent } from 'react';
import { SsoApiError } from '@drmhse/sso-sdk';
import { useAuthOSContext } from '../context';
import { OAuthButton } from './OAuthButton';
import type { SignUpProps, SupportedOAuthProvider } from '../types';

/**
 * Headless SignUp component that handles user registration.
 *
 * @example
 * ```tsx
 * import { SignUp } from '@drmhse/authos-react';
 *
 * function RegisterPage() {
 *   return (
 *     <SignUp
 *       onSuccess={() => console.log('Registration successful!')}
 *       onError={(error) => console.error('Registration failed:', error)}
 *       providers={['github', 'google']}
 *     />
 *   );
 * }
 * ```
 */
export function SignUp({
  onSuccess,
  onError,
  orgSlug,
  serviceSlug,
  showSignIn = true,
  className,
  providers = false,
  showDivider = true,
}: SignUpProps) {
  const { client, config } = useAuthOSContext();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  // Determine if we have OAuth configured
  const hasOAuthConfig = !!(config.org && config.service);
  const oauthProviders = providers && Array.isArray(providers) ? providers : [];

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setError(null);

      // Client-side validation
      if (password !== confirmPassword) {
        setError('Passwords do not match');
        return;
      }

      if (password.length < 8) {
        setError('Password must be at least 8 characters');
        return;
      }

      setIsLoading(true);

      try {
        await client.auth.register({
          email,
          password,
          org_slug: orgSlug ?? config.org,
          service_slug: serviceSlug ?? config.service,
        } as any);

        setIsSuccess(true);
        onSuccess?.();
      } catch (err) {
        const message = err instanceof SsoApiError ? err.message : 'Registration failed';
        setError(message);
        onError?.(err instanceof Error ? err : new Error(message));
      } finally {
        setIsLoading(false);
      }
    },
    [client, email, password, confirmPassword, orgSlug, serviceSlug, onSuccess, onError]
  );

  if (isSuccess) {
    return (
      <div className={className} data-authos-signup data-state="success">
        <div data-authos-success>
          <h2>Check your email</h2>
          <p>We've sent a verification link to {email}. Please click the link to verify your account.</p>
        </div>
      </div>
    );
  }

  return (
    <div className={className} data-authos-signup data-state="form">
      {/* OAuth Buttons Section */}
      {oauthProviders.length > 0 && (
        <div data-authos-oauth-section="">
          {oauthProviders.map((provider: SupportedOAuthProvider) => (
            <OAuthButton
              key={provider}
              provider={provider}
              disabled={isLoading || !hasOAuthConfig}
            />
          ))}
          {!hasOAuthConfig && (
            <p data-authos-oauth-warning="" style={{ color: 'orange', fontSize: '0.875rem' }}>
              OAuth requires org and service in AuthOSProvider config
            </p>
          )}
        </div>
      )}

      {/* Divider */}
      {oauthProviders.length > 0 && showDivider && (
        <div data-authos-divider="">
          <span>or</span>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div data-authos-field="email">
          <label htmlFor="authos-signup-email">Email</label>
          <input
            id="authos-signup-email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            required
            disabled={isLoading}
          />
        </div>

        <div data-authos-field="password">
          <label htmlFor="authos-signup-password">Password</label>
          <input
            id="authos-signup-password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Create a password"
            required
            minLength={8}
            disabled={isLoading}
          />
        </div>

        <div data-authos-field="confirm-password">
          <label htmlFor="authos-signup-confirm">Confirm Password</label>
          <input
            id="authos-signup-confirm"
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Confirm your password"
            required
            disabled={isLoading}
          />
        </div>

        {error && <div data-authos-error>{error}</div>}

        <button type="submit" disabled={isLoading} data-authos-submit>
          {isLoading ? 'Creating account...' : 'Create Account'}
        </button>

        {showSignIn && (
          <div data-authos-signin-prompt>
            Already have an account? <a href="/signin" data-authos-link="signin">Sign in</a>
          </div>
        )}
      </form>
    </div>
  );
}
