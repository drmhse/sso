import { InvitationStatus, MemberRole } from './common';

/**
 * Invitation entity
 */
export interface Invitation {
  id: string;
  org_id: string;
  inviter_user_id: string;
  invitee_email: string;
  role: MemberRole;
  token: string;
  status: InvitationStatus;
  expires_at: string;
  created_at: string;
}

/**
 * Create invitation payload
 */
export interface CreateInvitationPayload {
  invitee_email: string;
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
export interface InvitationWithOrg extends Invitation {
  organization_name: string;
  organization_slug: string;
  inviter_email: string;
}
