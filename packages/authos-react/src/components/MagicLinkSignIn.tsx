import { useState, useCallback, FormEvent } from 'react';
import { SsoApiError } from '@drmhse/sso-sdk';
import { useAuthOSContext } from '../context';

export interface MagicLinkSignInProps {
  /** Callback when magic link is successfully sent */
  onSuccess?: () => void;
  /** Callback when sending fails */
  onError?: (error: Error) => void;
  /** Custom class name */
  className?: string;
  /** Show sign in with password link */
  showPasswordSignIn?: boolean;
}

/**
 * Passwordless sign-in via magic link (email).
 * 
 * Sends a one-time login link to the user's email address.
 * 
 * @example
 * ```tsx
 * import { MagicLinkSignIn } from '@drmhse/authos-react';
 * 
 * function LoginPage() {
 *   return (
 *     <MagicLinkSignIn
 *       onSuccess={() => alert('Check your email!')}
 *       onError={(err) => console.error(err)}
 *     />
 *   );
 * }
 * ```
 */
export function MagicLinkSignIn({
  onSuccess,
  onError,
  className,
  showPasswordSignIn = true,
}: MagicLinkSignInProps) {
  const { client } = useAuthOSContext();
  
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSent, setIsSent] = useState(false);

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setError(null);
      setIsLoading(true);

      try {
        await client.magicLinks.request({ email });
        setIsSent(true);
        onSuccess?.();
      } catch (err) {
        const message = err instanceof SsoApiError ? err.message : 'Failed to send magic link';
        setError(message);
        onError?.(err instanceof Error ? err : new Error(message));
      } finally {
        setIsLoading(false);
      }
    },
    [client, email, onSuccess, onError]
  );

  if (isSent) {
    return (
      <div className={className} data-authos-magic-link="" data-state="sent">
        <div data-authos-success="">
          <p>Check your email!</p>
          <p>We sent a login link to <strong>{email}</strong></p>
        </div>
        <button
          type="button"
          onClick={() => setIsSent(false)}
          data-authos-back=""
        >
          Use a different email
        </button>
      </div>
    );
  }

  return (
    <div className={className} data-authos-magic-link="" data-state="form">
      <form onSubmit={handleSubmit}>
        <div data-authos-field="email">
          <label htmlFor="authos-magic-email">Email</label>
          <input
            id="authos-magic-email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            required
            disabled={isLoading}
          />
        </div>

        {error && <div data-authos-error="">{error}</div>}

        <button type="submit" disabled={isLoading} data-authos-submit="">
          {isLoading ? 'Sending...' : 'Send Magic Link'}
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
