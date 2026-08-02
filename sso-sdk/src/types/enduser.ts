import { PaginationParams } from './common';
import type { OrganizationUser } from './organization';

/**
 * End-user subscription details
 */
export interface EndUserSubscription {
  service_id: string;
  service_slug: string;
  service_name: string;
  plan_id: string;
  plan_name: string;
  status: string;
  current_period_end: string;
  created_at: string;
}

/**
 * End-user identity (OAuth provider link)
 */
export interface EndUserIdentity {
  provider: string;
  provider_user_id: string;
  created_at: string;
}

export interface EndUserSession {
  id: string;
  service_id: string | null;
  service_name: string | null;
  org_slug: string | null;
  ip_address: string | null;
  user_agent: string | null;
  expires_at: string;
  refresh_token_expires_at: string | null;
  created_at: string;
}

export interface EndUserLoginEvent {
  id: string;
  service_id: string | null;
  service_name: string | null;
  provider: string;
  ip_address: string | null;
  user_agent: string | null;
  risk_score: number | null;
  risk_factors: string[];
  geo_country: string | null;
  geo_city: string | null;
  created_at: string;
}

/**
 * End-user with subscriptions and identities
 */
export interface EndUser {
  user: OrganizationUser;
  subscriptions: EndUserSubscription[];
  identities: EndUserIdentity[];
}

/**
 * End-user list response
 */
export interface EndUserListResponse {
  users: EndUser[];
  total: number;
  page: number;
  limit: number;
}

/**
 * End-user detail response with session info
 */
export interface EndUserDetailResponse {
  user: OrganizationUser;
  subscriptions: EndUserSubscription[];
  identities: EndUserIdentity[];
  session_count: number;
  sessions: EndUserSession[];
  recent_logins: EndUserLoginEvent[];
}

/**
 * List end-users query params
 */
export interface ListEndUsersParams extends PaginationParams {
  /**
   * Optional service slug to filter users by a specific service
   */
  service_slug?: string;
}

/**
 * Revoke sessions response
 */
export interface RevokeSessionsResponse {
  message: string;
  revoked_count: number;
}
