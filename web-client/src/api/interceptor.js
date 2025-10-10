import { ssoBase } from './index';
import { useAuthStore } from '@/stores/auth';

/**
 * Create an intercepted client that wraps SDK calls with error handling
 * This adds automatic 401/403 detection and auth state cleanup
 */
const createInterceptedClient = (client) => {
  const handler = {
    get(target, prop) {
      const value = target[prop];

      // If it's a module (auth, user, organizations, etc.)
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return new Proxy(value, handler);
      }

      // If it's a method, wrap it with error handling
      if (typeof value === 'function') {
        return async (...args) => {
          try {
            return await value.apply(target, args);
          } catch (error) {
            const authStore = useAuthStore();

            // Check if it's an authentication error
            if (error?.response?.status === 401 || error?.response?.status === 403) {
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
