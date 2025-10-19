import { PaginationParams } from './common';

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

/**
 * End-user with subscriptions and identities
 */
export interface EndUser {
  user: {
    id: string;
    email: string;
    is_platform_owner: boolean;
    created_at: string;
  };
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
  user: {
    id: string;
    email: string;
    is_platform_owner: boolean;
    created_at: string;
  };
  subscriptions: EndUserSubscription[];
  identities: EndUserIdentity[];
  session_count: number;
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
