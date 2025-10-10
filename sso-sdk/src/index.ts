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

// Error handling
export { SsoApiError } from './errors';

// All types
export * from './types';

// Modules (exported for type references, but typically accessed via SsoClient instance)
export { AuthModule } from './modules/auth';
export { UserModule } from './modules/user';
export { OrganizationsModule } from './modules/organizations';
export { ServicesModule } from './modules/services';
export { InvitationsModule } from './modules/invitations';
export { PlatformModule } from './modules/platform';
