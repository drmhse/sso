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
  user_email: string;
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
