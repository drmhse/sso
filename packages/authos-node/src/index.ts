/**
 * AuthOS Node.js Server Adapter
 *
 * Provides utilities for backend frameworks including:
 * - JWT token verification with JWKS
 * - Webhook signature verification
 * - Express middleware (via '@drmhse/authos-node/express')
 *
 * @packageDocumentation
 */

// Token verification
export { createTokenVerifier, TokenVerificationError, clearJWKSCache } from './jwks';

// Webhook verification
export { verifyWebhookSignature, createWebhookSignature, WebhookVerificationError } from './webhook';

// Types
export type {
  AuthOSNodeOptions,
  JWK,
  JWKS,
  VerifiedToken,
  AuthenticatedRequest,
  VerifyTokenOptions,
  WebhookVerifyOptions,
  RequireAuthOptions,
  RequirePermissionOptions,
} from './types';

// Re-export useful types from the SDK
export type { JwtClaims } from '@drmhse/sso-sdk';
