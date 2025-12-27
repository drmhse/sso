import { defineNuxtRouteMiddleware, navigateTo } from 'nuxt/app';
import { useAuthOS } from '../composables/useAuthOS';

export interface AuthMiddlewareOptions {
  redirectTo?: string;
}

export function createAuthMiddleware(options: AuthMiddlewareOptions = {}) {
  const { redirectTo = '/login' } = options;

  return defineNuxtRouteMiddleware(() => {
    const { isAuthenticated, isLoading } = useAuthOS();

    if (isLoading.value) {
      return;
    }

    if (!isAuthenticated.value) {
      return navigateTo(redirectTo, {
        redirectCode: 302,
        replace: true,
      });
    }
  });
}

export const authMiddleware = createAuthMiddleware();
