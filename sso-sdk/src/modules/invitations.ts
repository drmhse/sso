import { HttpClient } from '../http';
import {
  Invitation,
  InvitationWithOrg,
  CreateInvitationPayload,
  AcceptInvitationPayload,
  DeclineInvitationPayload,
} from '../types';

/**
 * Invitation management methods
 */
export class InvitationsModule {
  constructor(private http: HttpClient) {}

  /**
   * Create and send an invitation to join an organization.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param payload Invitation payload with email and role
   * @returns Created invitation
   *
   * @example
   * ```typescript
   * const invitation = await sso.invitations.create('acme-corp', {
   *   invitee_email: 'newuser@example.com',
   *   role: 'member'
   * });
   * ```
   */
  public async create(orgSlug: string, payload: CreateInvitationPayload): Promise<Invitation> {
    const response = await this.http.post<Invitation>(
      `/api/organizations/${orgSlug}/invitations`,
      payload
    );
    return response.data;
  }

  /**
   * List all invitations for an organization.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @returns Array of invitations
   *
   * @example
   * ```typescript
   * const invitations = await sso.invitations.listForOrg('acme-corp');
   * invitations.forEach(inv => console.log(inv.invitee_email, inv.status));
   * ```
   */
  public async listForOrg(orgSlug: string): Promise<Invitation[]> {
    const response = await this.http.get<Invitation[]>(
      `/api/organizations/${orgSlug}/invitations`
    );
    return response.data;
  }

  /**
   * Cancel a pending invitation.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param invitationId Invitation ID to cancel
   *
   * @example
   * ```typescript
   * await sso.invitations.cancel('acme-corp', 'invitation-id');
   * ```
   */
  public async cancel(orgSlug: string, invitationId: string): Promise<void> {
    await this.http.post(`/api/organizations/${orgSlug}/invitations/${invitationId}`);
  }

  /**
   * List invitations received by the current authenticated user.
   *
   * @returns Array of invitations with organization details
   *
   * @example
   * ```typescript
   * const myInvitations = await sso.invitations.listForUser();
   * myInvitations.forEach(inv => {
   *   console.log(`Invited to ${inv.organization_name} as ${inv.role}`);
   * });
   * ```
   */
  public async listForUser(): Promise<InvitationWithOrg[]> {
    const response = await this.http.get<InvitationWithOrg[]>('/api/invitations');
    return response.data;
  }

  /**
   * Accept an invitation using its token.
   *
   * @param token Invitation token
   *
   * @example
   * ```typescript
   * await sso.invitations.accept('invitation-token-from-email');
   * ```
   */
  public async accept(token: string): Promise<void> {
    const payload: AcceptInvitationPayload = { token };
    await this.http.post('/api/invitations/accept', payload);
  }

  /**
   * Decline an invitation using its token.
   *
   * @param token Invitation token
   *
   * @example
   * ```typescript
   * await sso.invitations.decline('invitation-token-from-email');
   * ```
   */
  public async decline(token: string): Promise<void> {
    const payload: DeclineInvitationPayload = { token };
    await this.http.post('/api/invitations/decline', payload);
  }
}
