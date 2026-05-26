import { ssoBase } from './api';
import { useAuthStore } from '@/stores/auth';

let isRefreshing = false;
let failedQueue = [];

function processQueue(error, token = null) {
  for (const item of failedQueue) {
    if (error) item.reject(error);
    else item.resolve(token);
  }
  failedQueue = [];
}

function proxify(target) {
  return new Proxy(target, {
    get(current, prop) {
      const value = current[prop];

      if (value && typeof value === 'object' && !Array.isArray(value)) {
        return proxify(value);
      }

      if (typeof value !== 'function') {
        return value;
      }

      return async (...args) => {
        try {
          return await value.apply(current, args);
        } catch (error) {
          const authStore = useAuthStore();
          const is401 = error?.statusCode === 401 || error?.response?.status === 401;

          if (!is401 || !authStore.refreshToken) throw error;

          if (isRefreshing) {
            return new Promise((resolve, reject) => {
              failedQueue.push({
                resolve: async () => {
                  try {
                    resolve(await value.apply(current, args));
                  } catch (retryError) {
                    reject(retryError);
                  }
                },
                reject,
              });
            });
          }

          isRefreshing = true;

          try {
            await authStore.refreshAccessToken();
            processQueue(null, authStore.token);
            return await value.apply(current, args);
          } catch (refreshError) {
            processQueue(refreshError, null);
            authStore.handleAuthError(error);
            throw error;
          } finally {
            isRefreshing = false;
          }
        }
      };
    },
  });
}

export const ssoWithInterceptor = proxify(ssoBase);
