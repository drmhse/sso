import { ssoBase } from './index';
import { useAuthStore } from '@/stores/auth';

// Refresh state management - prevents multiple concurrent refresh attempts
let isRefreshing = false;
let failedQueue = [];

/**
 * Process queued requests after token refresh completes
 * @param {Error|null} error - Error if refresh failed
 * @param {string|null} token - New access token if refresh succeeded
 */
const processQueue = (error, token = null) => {
  failedQueue.forEach(promise => {
    if (error) {
      promise.reject(error);
    } else {
      promise.resolve(token);
    }
  });
  failedQueue = [];
};

/**
 * Create an intercepted client that wraps SDK calls with automatic token refresh
 * This provides seamless session management by:
 * - Detecting 401 authentication errors
 * - Automatically refreshing expired tokens
 * - Queuing failed requests and retrying after refresh
 * - Handling auth errors gracefully
 */
const createInterceptedClient = (client) => {
  const handler = {
    get(target, prop) {
      const value = target[prop];

      // If it's a module (auth, user, organizations, etc.)
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return new Proxy(value, handler);
      }

      // If it's a method, wrap it with error handling and auto-refresh logic
      if (typeof value === 'function') {
        return async (...args) => {
          try {
            return await value.apply(target, args);
          } catch (error) {
            const authStore = useAuthStore();

            // Check if it's a 401 authentication error (token expired)
            // Note: We check statusCode on SsoApiError
            const is401 = error?.statusCode === 401 || error?.response?.status === 401;

            if (is401 && authStore.refreshToken) {
              // This is an expired token - attempt auto-refresh

              // If a refresh is already in progress, queue this request
              if (isRefreshing) {
                return new Promise((resolve, reject) => {
                  failedQueue.push({
                    resolve: async (newToken) => {
                      try {
                        // Retry the original request with new token
                        const result = await value.apply(target, args);
                        resolve(result);
                      } catch (retryError) {
                        reject(retryError);
                      }
                    },
                    reject,
                  });
                });
              }

              // Start refresh process
              isRefreshing = true;

              try {
                // Attempt to refresh the access token
                await authStore.refreshAccessToken();

                // Refresh successful - process queued requests
                processQueue(null, authStore.token);

                // Retry the original request with new token
                return await value.apply(target, args);
              } catch (refreshError) {
                // Refresh failed - session is invalid
                console.error('Token refresh failed:', refreshError);
                processQueue(refreshError, null);

                // Clear auth and redirect to login
                authStore.handleAuthError(error);
                throw error;
              } finally {
                isRefreshing = false;
              }
            }

            // For 403 or other auth errors, handle normally
            if (error?.statusCode === 403 || error?.response?.status === 403) {
              authStore.handleAuthError(error);
            }

            throw error;
          }
        };
      }

      return value;
    },
  };

  return new Proxy(client, handler);
};

export const ssoWithInterceptor = createInterceptedClient(ssoBase);
