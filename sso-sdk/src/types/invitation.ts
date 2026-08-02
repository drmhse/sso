import { InvitationStatus, MemberRole } from './common';

/**
 * Invitation entity
 */
export interface Invitation {
  id: string;
  org_id: string;
  email: string;
  invited_by: string;
  role: MemberRole | string;
  status: InvitationStatus;
  expires_at: string;
  created_at: string;
}

export interface InvitationInviter {
  id: string;
  email: string;
  created_at: string;
}

export interface CreateInvitationResponse {
  invitation: Invitation;
  inviter: InvitationInviter;
  /** Plaintext invitation token. Returned only at creation. */
  token: string;
}

export interface OrganizationInvitationListItem {
  invitation: Omit<Invitation, 'org_id' | 'invited_by'>;
  inviter: InvitationInviter;
}

/**
 * Create invitation payload
 */
export interface CreateInvitationPayload {
  email: string;
  role: MemberRole;
}

/**
 * Accept invitation payload
 */
export interface AcceptInvitationPayload {
  token: string;
}

/**
 * Decline invitation payload
 */
export interface DeclineInvitationPayload {
  token: string;
}

/**
 * Invitation with organization details
 */
export interface InvitationWithOrg {
  id: string;
  email: string;
  role: MemberRole | string;
  expires_at: string;
  created_at: string;
  organization_name: string;
  organization_slug: string;
}
