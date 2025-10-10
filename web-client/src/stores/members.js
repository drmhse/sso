import { defineStore } from 'pinia';
import { sso } from '@/api';

export const useMembersStore = defineStore('members', {
  state: () => ({
    members: [],
    invitations: [],
    loading: false,
    error: null,
  }),

  getters: {
    owners: (state) => state.members.filter(m => m.role === 'owner'),

    admins: (state) => state.members.filter(m => m.role === 'admin'),

    regularMembers: (state) => state.members.filter(m => m.role === 'member'),

    pendingInvitations: (state) => state.invitations.filter(inv => inv.status === 'pending'),
  },

  actions: {
    /**
     * Fetch members for an organization
     */
    async fetchMembers(orgSlug) {
      this.loading = true;
      this.error = null;

      try {
        this.members = await sso.organizations.members.list(orgSlug);
      } catch (error) {
        console.error('Failed to fetch members:', error);
        this.error = error.message || 'Failed to fetch members';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Fetch invitations for an organization
     */
    async fetchInvitations(orgSlug) {
      try {
        this.invitations = await sso.invitations.listForOrg(orgSlug);
      } catch (error) {
        console.error('Failed to fetch invitations:', error);
        throw error;
      }
    },

    /**
     * Create a new invitation
     */
    async createInvitation(orgSlug, payload) {
      try {
        const invitation = await sso.invitations.create(orgSlug, payload);
        this.invitations.push(invitation);
        return invitation;
      } catch (error) {
        console.error('Failed to create invitation:', error);
        throw error;
      }
    },

    /**
     * Cancel an invitation
     */
    async cancelInvitation(orgSlug, invitationId) {
      try {
        await sso.invitations.cancel(orgSlug, invitationId);

        // Remove from local state
        const index = this.invitations.findIndex(inv => inv.id === invitationId);
        if (index !== -1) {
          this.invitations.splice(index, 1);
        }
      } catch (error) {
        console.error('Failed to cancel invitation:', error);
        throw error;
      }
    },

    /**
     * Update a member's role
     */
    async updateMemberRole(orgSlug, userId, role) {
      try {
        const updated = await sso.organizations.members.updateRole(orgSlug, userId, { role });

        // Update in local state
        const index = this.members.findIndex(m => m.user_id === userId);
        if (index !== -1) {
          this.members[index] = updated;
        }

        return updated;
      } catch (error) {
        console.error('Failed to update member role:', error);
        throw error;
      }
    },

    /**
     * Remove a member from the organization
     */
    async removeMember(orgSlug, userId) {
      try {
        await sso.organizations.members.remove(orgSlug, userId);

        // Remove from local state
        const index = this.members.findIndex(m => m.user_id === userId);
        if (index !== -1) {
          this.members.splice(index, 1);
        }
      } catch (error) {
        console.error('Failed to remove member:', error);
        throw error;
      }
    },

    /**
     * Transfer organization ownership
     */
    async transferOwnership(orgSlug, newOwnerUserId) {
      try {
        await sso.organizations.members.transferOwnership(orgSlug, {
          new_owner_user_id: newOwnerUserId,
        });

        // Refresh members list to reflect the change
        await this.fetchMembers(orgSlug);
      } catch (error) {
        console.error('Failed to transfer ownership:', error);
        throw error;
      }
    },

    /**
     * Clear state
     */
    clear() {
      this.members = [];
      this.invitations = [];
      this.error = null;
    },
  },
});
