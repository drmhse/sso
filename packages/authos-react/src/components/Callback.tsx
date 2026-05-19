import React, { useEffect, useState, useRef } from 'react';
import { useAuthOSContext } from '../context';
import type { CallbackProps } from '../types';

export function Callback({ onSuccess, onError, children }: CallbackProps) {
  const { client } = useAuthOSContext();
  const [error, setError] = useState<string | null>(null);
  const processedRef = useRef(false);

  useEffect(() => {
    if (processedRef.current || !client) return;

    const processCallback = async () => {
      processedRef.current = true;

      // Parse callback parameters from URL hash first, then fall back to query params.
      const hashParams = new URLSearchParams(window.location.hash.substring(1));
      const queryParams = new URLSearchParams(window.location.search);

      const accessToken =
        hashParams.get('access_token') || queryParams.get('access_token');
      const refreshToken =
        hashParams.get('refresh_token') || queryParams.get('refresh_token');
      const errorParam = hashParams.get('error') || queryParams.get('error');
      const errorDescription =
        hashParams.get('error_description') || queryParams.get('error_description');

      if (errorParam) {
        const msg = errorDescription || errorParam;
        setError(msg);
        onError?.(new Error(msg));
        return;
      }

      if (accessToken) {
        try {
          // Set session using SDK
          await client.setSession({
            access_token: accessToken,
            refresh_token: refreshToken || undefined,
          });

          onSuccess?.();
        } catch (err: any) {
          const message = err.message || 'Failed to set session';
          setError(message);
          onError?.(err instanceof Error ? err : new Error(message));
        }
      } else {
        // No tokens found
        const message = 'No authentication tokens found in callback URL.';
        setError(message);
        onError?.(new Error(message));
      }
    };

    processCallback();
  }, [client, onSuccess, onError]);

  if (children) {
    return <>{children({ error })}</>;
  }

  // Default UI
  return (
    <div data-authos-callback="">
      {error ? (
        <div data-authos-error="">{error}</div>
      ) : (
        <div data-authos-loading="">Completing sign in...</div>
      )}
    </div>
  );
}
