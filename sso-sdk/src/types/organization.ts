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
  custom_domain?: string | null;
  domain_verified?: boolean;
  domain_verification_token?: string | null;
  brand_logo_url?: string | null;
  brand_primary_color?: string | null;
  feature_overrides?: string | Record<string, unknown> | null;
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
  owner: {
    id: string;
    email: string;
    is_platform_owner: boolean;
    created_at: string;
  };
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
  org_id: string;

  /** User ID who performed the action */
  actor_user_id: string;

  /** Email of the user who performed the action (optional, joined from users table) */
  actor_user_email?: string;

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

  /** Additional details about the action (JSON string or object) */
  details?: string;

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

  /**
   * Organization ID (deprecated: use org_id)
   * @deprecated Use org_id instead for consistency with backend
   */
  organization_id?: string;

  /**
   * Actor ID (deprecated: use actor_user_id) 
   * @deprecated Use actor_user_id instead for consistency with backend
   */
  actor_id?: string;

  /**
   * Metadata about the action (optional)
   * Contains additional structured information about what changed
   */
  metadata?: Record<string, any> | null;
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
}

/**
 * SCIM token response
 */
export interface ScimTokenResponse {
  id: string;
  name: string;
  token?: string; // Only present on creation
  last_used_at?: string;
  created_at: string;
}

/**
 * List SCIM tokens response
 */
export interface ListScimTokensResponse {
  tokens: ScimTokenResponse[];
}
