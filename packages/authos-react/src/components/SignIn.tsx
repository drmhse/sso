import { useState, useCallback, FormEvent } from 'react';
import { SsoApiError } from '@drmhse/sso-sdk';
import { useAuthOSContext } from '../context';
import type { SignInProps } from '../types';

type SignInState = 'credentials' | 'mfa';

// MFA is required when expires_in is 300 seconds (5 minutes)
const MFA_PREAUTH_EXPIRY = 300;

/**
 * Headless SignIn component that handles email/password authentication with MFA support.
 *
 * @example
 * ```tsx
 * import { SignIn } from '@drmhse/authos-react';
 *
 * function LoginPage() {
 *   return (
 *     <SignIn
 *       onSuccess={(user) => console.log('Logged in:', user)}
 *       onError={(error) => console.error('Login failed:', error)}
 *     />
 *   );
 * }
 * ```
 */
export function SignIn({
  onSuccess,
  onError,
  showForgotPassword = true,
  showSignUp = true,
  className,
}: SignInProps) {
  const { client, setUser } = useAuthOSContext();

  const [state, setState] = useState<SignInState>('credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [preauthToken, setPreauthToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleCredentialsSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setError(null);
      setIsLoading(true);

      try {
        const result = await client.auth.login({ email, password });

        // Check if MFA is required (expires_in of 300 indicates pre-auth token)
        if (result.expires_in === MFA_PREAUTH_EXPIRY) {
          setPreauthToken(result.access_token);
          setState('mfa');
        } else {
          // Login successful - session is auto-saved by SDK
          const profile = await client.user.getProfile();
          setUser(profile);
          onSuccess?.(profile);
        }
      } catch (err) {
        const message = err instanceof SsoApiError ? err.message : 'Login failed';
        setError(message);
        onError?.(err instanceof Error ? err : new Error(message));
      } finally {
        setIsLoading(false);
      }
    },
    [client, email, password, setUser, onSuccess, onError]
  );

  const handleMfaSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setError(null);
      setIsLoading(true);

      try {
        // verifyMfa takes positional arguments: (preauthToken, code, deviceCodeId?)
        await client.auth.verifyMfa(preauthToken, mfaCode);

        // Session is auto-saved by SDK
        const profile = await client.user.getProfile();
        setUser(profile);
        onSuccess?.(profile);
      } catch (err) {
        const message = err instanceof SsoApiError ? err.message : 'Invalid MFA code';
        setError(message);
        onError?.(err instanceof Error ? err : new Error(message));
      } finally {
        setIsLoading(false);
      }
    },
    [client, preauthToken, mfaCode, setUser, onSuccess, onError]
  );

  const handleBackToCredentials = useCallback(() => {
    setState('credentials');
    setMfaCode('');
    setPreauthToken('');
    setError(null);
  }, []);

  if (state === 'mfa') {
    return (
      <div className={className} data-authos-signin="" data-state="mfa">
        <form onSubmit={handleMfaSubmit}>
          <div data-authos-field="mfa-code">
            <label htmlFor="authos-mfa-code">Verification Code</label>
            <input
              id="authos-mfa-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              placeholder="Enter 6-digit code"
              required
              disabled={isLoading}
            />
          </div>

          {error && <div data-authos-error>{error}</div>}

          <button type="submit" disabled={isLoading} data-authos-submit="">
            {isLoading ? 'Verifying...' : 'Verify'}
          </button>

          <button type="button" onClick={handleBackToCredentials} data-authos-back="">
            Back to login
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className={className} data-authos-signin="" data-state="credentials">
      <form onSubmit={handleCredentialsSubmit}>
        <div data-authos-field="email">
          <label htmlFor="authos-email">Email</label>
          <input
            id="authos-email"
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
          <label htmlFor="authos-password">Password</label>
          <input
            id="authos-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            required
            disabled={isLoading}
          />
        </div>

        {error && <div data-authos-error>{error}</div>}

        <button type="submit" disabled={isLoading} data-authos-submit="">
          {isLoading ? 'Signing in...' : 'Sign In'}
        </button>

        {showForgotPassword && (
          <a href="/forgot-password" data-authos-link="forgot-password">
            Forgot password?
          </a>
        )}

        {showSignUp && (
          <div data-authos-signup-prompt>
            Don't have an account? <a href="/signup" data-authos-link="signup">Sign up</a>
          </div>
        )}
      </form>
    </div>
  );
}
