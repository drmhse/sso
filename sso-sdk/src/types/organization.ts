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
  tier_id: string | null;
  max_services: number | null;
  max_users: number | null;
  approved_by: string | null;
  approved_at: string | null;
  rejected_by: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  custom_domain: string | null;
  domain_verified: boolean;
  brand_logo_url: string | null;
  brand_primary_color: string | null;
  feature_overrides: string | null;
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

/** User fields serialized by organization-management responses. */
export interface OrganizationUser {
  id: string;
  email: string;
  org_id: string | null;
  is_platform_owner: boolean;
  email_verified_at: string | null;
  created_at: string;
  updated_at: string | null;
  deleted_at: string | null;
}

/**
 * Organization response with metadata
 */
export interface OrganizationResponse {
  organization: Organization;
  membership_count: number;
  service_count: number;
  tier: OrganizationTier | null;
}

/**
 * Organization member details
 */
export interface OrganizationMember {
  user: OrganizationUser;
  membership: Membership;
}

export interface MemberServiceAccess {
  service_id: string;
  service_slug: string;
  service_name: string;
  access: 'viewer' | 'manager' | null;
}

export interface UpdateMemberServiceAccessPayload {
  grants: Array<{
    service_slug: string;
    access: 'viewer' | 'manager' | null;
  }>;
}

/**
 * Create organization payload (authenticated endpoint)
 */
export interface CreateOrganizationPayload {
  slug: string;
  name: string;
}

/**
 * Create organization response
 */
export interface CreateOrganizationResponse {
  organization: Organization;
  owner: OrganizationUser;
  membership: Membership;
  access_token: string;
  refresh_token: string;
}

/**
 * Select organization response - returned when switching org context
 */
export interface SelectOrganizationResponse {
  organization: Organization;
  membership: Membership;
  access_token: string;
  refresh_token: string;
  expires_in: number;
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
  new_owner_email: string;
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

/**
 * Member list response with pagination metadata
 */
export interface MemberListResponse {
  members: OrganizationMember[];
  total: number;
  limit: {
    current: number;
    max: number;
    source: string;
  };
}

/**
 * SMTP configuration request
 */
export interface SetSmtpRequest {
  host: string;
  port: number;
  username: string;
  password: string;
  from_email: string;
  from_name?: string;
}

/**
 * SMTP configuration response (without password)
 */
export interface SmtpConfigResponse {
  host: string;
  port: number;
  username: string;
  from_email: string;
  from_name?: string;
  configured: boolean;
}

// ============================================================================
// AUDIT LOGS
// ============================================================================

/**
 * Organization audit log entry
 * 
 * This type matches the API response from GET /api/organizations/:slug/audit-log
 * The API joins user information from the users table to provide actor details.
 */
export interface AuditLog {
  /** Unique identifier for the audit log entry */
  id: string;

  /** Organization ID this audit log belongs to */
  organization_id: string;

  /** User ID who performed the action */
  actor_id: string;

  /** Action that was performed (e.g., 'service.created', 'user.invited') */
  action: string;

  /** Type of resource that was targeted (e.g., 'service', 'user', 'organization') */
  target_type: string;

  /** ID of the resource that was targeted */
  target_id: string;

  /** IP address from which the action was performed */
  ip_address?: string;

  /** User agent string of the client */
  user_agent?: string;

  /** Whether the action was successful */
  success: boolean;

  /** Redacted structured event metadata, when present. */
  metadata?: Record<string, unknown>;

  /** Timestamp when the action was recorded */
  created_at: string;

  /**
   * Actor details (optional, joined from users table when available)
   * This field is populated by the API when fetching audit logs
   */
  actor?: {
    id: string;
    email: string;
  };
}

/**
 * Audit log response with pagination
 */
export interface AuditLogResponse {
  logs: AuditLog[];
  pagination: PaginationInfo;
}

/**
 * Event type information for filtering
 */
export interface EventTypeInfo {
  value: string;
  label: string;
  category: string;
}

/**
 * Audit log query parameters
 */
export interface AuditLogQueryParams extends PaginationParams {
  action?: string;
  target_type?: string;
  target_id?: string;
}

// ============================================================================
// WEBHOOKS
// ============================================================================

/**
 * Webhook configuration
 */
export interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * Webhook response
 */
export interface WebhookResponse {
  id: string;
  name: string;
  url: string;
  events: string[];
  is_active: boolean;
  secret?: string;
  created_at: string;
  updated_at: string;
}

/**
 * Webhook list response
 */
export interface WebhookListResponse {
  webhooks: WebhookResponse[];
  total: number;
}

/**
 * Create webhook request
 */
export interface CreateWebhookRequest {
  name: string;
  url: string;
  events: string[];
}

/**
 * Update webhook request
 */
export interface UpdateWebhookRequest {
  name?: string;
  url?: string;
  events?: string[];
  is_active?: boolean;
}

/**
 * Webhook delivery attempt
 */
export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  webhook_name: string;
  event_type: string;
  payload: any;
  response_status_code?: number;
  response_body?: string;
  attempt_count: number;
  max_attempts: number;
  next_retry_at?: string;
  delivered: boolean;
  delivery_error?: string;
  created_at: string;
  updated_at: string;
}

/**
 * Webhook delivery list response
 */
export interface WebhookDeliveryListResponse {
  deliveries: WebhookDelivery[];
  pagination: PaginationInfo;
}

/**
 * Webhook delivery query parameters
 */
export interface WebhookDeliveryQueryParams extends PaginationParams {
  event_type?: string;
  delivered?: boolean;
}

/**
 * Pagination information
 */
export interface PaginationInfo {
  page: number;
  limit: number;
  total: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

// ============================================================================
// CUSTOM DOMAINS & BRANDING
// ============================================================================

/**
 * Custom domain configuration
 */
export interface DomainConfiguration {
  custom_domain: string | null;
  domain_verified: boolean;
}

/**
 * Set custom domain request
 */
export interface SetCustomDomainRequest {
  domain: string;
}

/**
 * Domain verification method
 */
export interface DomainVerificationMethod {
  method: string;
  instructions: string;
  record_type?: string;
  record_name?: string;
  record_value?: string;
}

/**
 * Domain verification response
 */
export interface DomainVerificationResponse {
  verification_token: string;
  verification_methods: DomainVerificationMethod[];
}

/**
 * Domain verification result
 */
export interface DomainVerificationResult {
  verified: boolean;
  message: string;
}

/**
 * Branding configuration
 */
export interface BrandingConfiguration {
  logo_url: string | null;
  primary_color: string | null;
}

/**
 * Update branding request
 */
export interface UpdateBrandingRequest {
  logo_url?: string | null;
  primary_color?: string | null;
}

// ============================================================================
// RISK SETTINGS
// ============================================================================

/**
 * Risk settings response
 */
export interface GetRiskSettingsResponse {
  enforcement_mode: string;
  low_threshold: number;
  medium_threshold: number;
  new_device_score: number;
  impossible_travel_score: number;
  velocity_threshold: number;
  velocity_score: number;
}

/**
 * Update risk settings request
 */
export interface UpdateRiskSettingsRequest {
  enforcement_mode?: string;
  low_threshold?: number;
  medium_threshold?: number;
  new_device_score?: number;
  impossible_travel_score?: number;
  velocity_threshold?: number;
  velocity_score?: number;
}

/**
 * Update risk settings response
 */
export interface UpdateRiskSettingsResponse {
  message: string;
  settings: GetRiskSettingsResponse;
}

// ============================================================================
// SCIM TOKENS
// ============================================================================

/**
 * Create SCIM token request
 */
export interface CreateScimTokenRequest {
  name: string;
  /** RFC 3339 expiry timestamp. Omit for a non-expiring token. */
  expires_at?: string;
}

/**
 * SCIM token returned by list operations. Secret token material is never included.
 */
export interface ScimTokenResponse {
  id: string;
  name: string;
  prefix: string;
  active: boolean;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
}

/** SCIM token creation response. The plaintext token is returned only once. */
export interface CreateScimTokenResponse {
  id: string;
  name: string;
  token: string;
  prefix: string;
  created_at: string;
  expires_at: string | null;
}

/**
 * List SCIM tokens response
 */
export interface ListScimTokensResponse {
  tokens: ScimTokenResponse[];
}
