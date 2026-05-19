// Middleware
export { authMiddleware } from './middleware';
export type { AuthMiddlewareConfig } from './middleware';

// Server utilities
export { currentUser, auth, getToken } from './server';
export type { AuthUser, AuthState } from './server';

// Client utilities
export { createAuthOSClient, createServerClient } from './client';
export type { CreateAuthOSClientOptions } from './client';

// Helpers
export { getJwksUrl, normalizeBaseUrl } from './utils';
