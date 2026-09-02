import { OrganizationStatus, PaginationParams, User } from './common';
import { OrganizationTier } from './organization';

/**
 * Platform organization response with additional metadata
 */
export interface PlatformOrganizationResponse {
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
  tier: OrganizationTier;
  owner: User;
}

/**
 * Platform organizations list response
 */
export interface PlatformOrganizationsListResponse {
  organizations: PlatformOrganizationResponse[];
  total: number;
}

/**
 * Approve organization payload
 */
export interface ApproveOrganizationPayload {
  tier_id: string;
}

/**
 * Reject organization payload
 */
export interface RejectOrganizationPayload {
  reason: string;
}

/**
 * Update organization tier payload
 */
export interface UpdateOrganizationTierPayload {
  tier_id: string;
  max_services?: number;
  max_users?: number;
}

/**
 * Promote user to platform owner payload
 */
export interface PromotePlatformOwnerPayload {
  user_id: string;
}

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  id: string;
  user_id: string;
  user_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details?: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

/**
 * List platform organizations params
 */
export interface ListPlatformOrganizationsParams extends PaginationParams {
  status?: OrganizationStatus;
  search?: string;
  tier_id?: string;
}

/**
 * Get audit log params
 */
export interface GetAuditLogParams extends PaginationParams {
  user_id?: string;
  action?: string;
  resource_type?: string;
  start_date?: string;
  end_date?: string;
}

/**
 * Platform overview metrics
 */
export interface PlatformOverviewMetrics {
  total_organizations: number;
  total_users: number;
  total_end_users: number;
  total_services: number;
  total_logins_24h: number;
  total_logins_30d: number;
}

/**
 * Organization status breakdown
 */
export interface OrganizationStatusBreakdown {
  pending: number;
  active: number;
  suspended: number;
  rejected: number;
}

/**
 * Growth trend data point
 */
export interface GrowthTrendPoint {
  date: string;
  new_organizations: number;
  new_users: number;
}

/**
 * Login activity data point
 */
export interface LoginActivityPoint {
  date: string;
  count: number;
}

/**
 * Top organization metrics
 */
export interface TopOrganization {
  id: string;
  name: string;
  slug: string;
  user_count: number;
  service_count: number;
  login_count_30d: number;
}

/**
 * Recent organization data
 */
export interface RecentOrganization {
  id: string;
  name: string;
  slug: string;
  status: OrganizationStatus;
  created_at: string;
}

/**
 * Platform analytics date range query params
 */
export interface PlatformAnalyticsDateRangeParams {
  start_date?: string;
  end_date?: string;
}

/**
 * Impersonation request payload
 */
export interface ImpersonateRequest {
  user_id: string;
  reason: string;
}

/**
 * User info for impersonation response
 */
export interface ImpersonationUserInfo {
  id: string;
  email: string;
  is_platform_owner: boolean;
  org_id?: string;
  org_name?: string;
}

/**
 * Impersonation response
 */
export interface ImpersonateResponse {
  token: string;
  target_user: ImpersonationUserInfo;
  actor_user: ImpersonationUserInfo;
}

/**
 * Platform user
 */
export interface PlatformUser {
  id: string;
  email: string;
  is_platform_owner: boolean;
  created_at: string;
}

/**
 * Platform user list response
 */
export interface PlatformUserListResponse {
  users: PlatformUser[];
  total: number;
}

/**
 * Managed-deployment configuration, as read from the operator-owned config file
 * on the AuthOS host. Only available when the deployment was installed with
 * managed paths configured.
 */
export interface ManagedConfigResponse {
  config: Record<string, unknown>;
  config_path: string;
  /** False when no apply command is configured, so {@link apply} cannot run. */
  apply_command_configured: boolean;
  status: Record<string, unknown> | null;
}

export interface ApplyManagedConfigResponse {
  scheduled: boolean;
  message: string;
}

/** One day's MFA rollup. `org_id` is null on the platform-wide row. */
export interface MfaMetricsSummary {
  org_id: string | null;
  /** `YYYY-MM-DD`. */
  date: string;
  total_users: number;
  mfa_enabled_users: number;
  new_mfa_setups: number;
  mfa_disabled: number;
  totp_verifications_total: number;
  totp_verifications_success: number;
  totp_verifications_failed: number;
  backup_codes_generated: number;
  backup_codes_used: number;
}

/**
 * Either supply `start_date` and `end_date` together, or `days`. Omit `org_id`
 * for the platform-wide rollup.
 */
export interface GetMfaMetricsParams {
  org_id?: string;
  /** Inclusive `YYYY-MM-DD`; must be paired with `end_date`. */
  start_date?: string;
  /** Inclusive `YYYY-MM-DD`; must be paired with `start_date`. */
  end_date?: string;
  /** Trailing window, 1-366. Defaults to 30. Ignored when a range is given. */
  days?: number;
}

/** A row from `mfa_failure_patterns`, flagged when it crosses the threshold. */
export interface SuspiciousActivityAlert {
  id: string;
  org_id: string | null;
  user_id: string | null;
  user_email: string | null;
  ip_address: string | null;
  failure_type: string;
  failure_count: number;
  is_suspicious: boolean;
  first_seen_at: string;
  last_seen_at: string;
  details: string | null;
}

/**
 * A stored `mfa_daily_metrics` row. The generate endpoint returns the persisted
 * record, so it carries the row identity that {@link MfaMetricsSummary} omits.
 */
export interface MfaDailyMetricsRow extends MfaMetricsSummary {
  id: string;
  created_at: string;
  updated_at: string;
}

export interface GenerateMfaMetricsParams {
  org_id?: string;
  /** `YYYY-MM-DD`. Defaults to today. */
  date?: string;
}
