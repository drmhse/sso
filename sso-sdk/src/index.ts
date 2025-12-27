/**
 * SSO Platform SDK
 *
 * A TypeScript SDK for interacting with the multi-tenant SSO Platform API.
 *
 * @packageDocumentation
 */

// Main client
export { SsoClient } from './client';
export type { SsoClientOptions } from './client';

// Storage (exported for custom implementations)
export type { TokenStorage } from './storage';
export { MemoryStorage, BrowserStorage, CookieStorage } from './storage';

// Session (exported for framework adapters)
export type { AuthSnapshot } from './session';

// Error handling
export { SsoApiError, AuthErrorCodes } from './errors';

// All types
export * from './types';

// Modules (exported for type references, but typically accessed via SsoClient instance)
export { AuthModule } from './modules/auth';
export { UserModule } from './modules/user';
export { OrganizationsModule } from './modules/organizations';
export { ServicesModule } from './modules/services';
export { InvitationsModule } from './modules/invitations';
export { PlatformModule } from './modules/platform';
export { ServiceApiModule } from './modules/serviceApi';
export { PermissionsModule } from './modules/permissions';
export { PasskeysModule } from './modules/passkeys';
export { MagicLinks } from './modules/magic';
