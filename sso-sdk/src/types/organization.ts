import { OrganizationStatus, MemberRole, OAuthProvider, PaginationParams } from './common';

/**
 * Organization entity
 */
export interface Organization {
  id: string;
  slug: string;
  name: string;
  owner_user_id: string;
  status: OrganizationStatus;
  tier_id: string;
  max_services?: number | null;
  max_users?: number | null;
  approved_by?: string | null;
  approved_at?: string | null;
  rejected_by?: string | null;
  rejected_at?: string | null;
  rejection_reason?: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Organization tier details
 */
export interface OrganizationTier {
  id: string;
  name: string;
  display_name?: string;
  default_max_services: number;
  default_max_users: number;
  features: string; // JSON string containing feature configuration
  price_cents?: number;
  currency?: string;
  created_at: string;
}

/**
 * Organization membership
 */
export interface Membership {
  id: string;
  org_id: string;
  user_id: string;
  role: MemberRole;
  created_at: string;
}

/**
 * Organization response with metadata
 */
export interface OrganizationResponse {
  organization: Organization;
  membership_count: number;
  service_count: number;
  tier: OrganizationTier;
}

/**
 * Organization member details
 */
export interface OrganizationMember {
  user_id: string;
  email: string;
  role: MemberRole;
  joined_at: string;
}

/**
 * Create organization payload (public endpoint)
 */
export interface CreateOrganizationPayload {
  slug: string;
  name: string;
  owner_email: string;
}

/**
 * Create organization response
 */
export interface CreateOrganizationResponse {
  organization: Organization;
  owner: {
    id: string;
    email: string;
    is_platform_owner: boolean;
    created_at: string;
  };
  membership: Membership;
}

/**
 * Update organization payload
 */
export interface UpdateOrganizationPayload {
  name?: string;
  max_services?: number;
  max_users?: number;
}

/**
 * Update member role payload
 */
export interface UpdateMemberRolePayload {
  role: MemberRole;
}

/**
 * Transfer ownership payload
 */
export interface TransferOwnershipPayload {
  new_owner_user_id: string;
}

/**
 * OAuth credentials payload
 */
export interface SetOAuthCredentialsPayload {
  client_id: string;
  client_secret: string;
}

/**
 * OAuth credentials response (secret never returned)
 */
export interface OAuthCredentials {
  id: string;
  org_id: string;
  provider: OAuthProvider;
  client_id: string;
  created_at: string;
}

/**
 * List organizations query params
 */
export interface ListOrganizationsParams extends PaginationParams {
  status?: OrganizationStatus;
}
