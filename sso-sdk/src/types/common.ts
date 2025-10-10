/**
 * Common types used across the SDK
 */

/**
 * Represents a user in the system.
 */
export interface User {
  id: string;
  email: string;
  is_platform_owner: boolean;
  created_at: string;
}

/**
 * User profile response (includes context from JWT)
 */
export interface UserProfile {
  id: string;
  email: string;
  org?: string;
  service?: string;
}

/**
 * Paginated response wrapper
 */
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  has_more: boolean;
}

/**
 * Standard pagination parameters
 */
export interface PaginationParams {
  page?: number;
  limit?: number;
}

/**
 * OAuth provider types
 */
export type OAuthProvider = 'github' | 'google' | 'microsoft';

/**
 * Organization status types
 */
export type OrganizationStatus = 'pending' | 'active' | 'suspended' | 'rejected';

/**
 * Service types
 */
export type ServiceType = 'web' | 'mobile' | 'desktop' | 'api';

/**
 * Organization member roles
 */
export type MemberRole = 'owner' | 'admin' | 'member';

/**
 * Invitation status
 */
export type InvitationStatus = 'pending' | 'accepted' | 'declined' | 'cancelled';
