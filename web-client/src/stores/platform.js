import { defineStore } from 'pinia';
import { sso } from '@/api';

export const usePlatformStore = defineStore('platform', {
  state: () => ({
    organizations: [],
    total: 0,
    loading: false,
    error: null,
    filters: {
      status: null, // 'pending', 'active', 'suspended', 'rejected'
      page: 1,
      limit: 50,
    },
  }),

  getters: {
    pendingOrganizations: (state) => {
      return state.organizations.filter(org => org.status === 'pending');
    },

    activeOrganizations: (state) => {
      return state.organizations.filter(org => org.status === 'active');
    },

    suspendedOrganizations: (state) => {
      return state.organizations.filter(org => org.status === 'suspended');
    },
  },

  actions: {
    /**
     * Fetch organizations with optional filters
     */
    async fetchOrganizations(params = {}) {
      this.loading = true;
      this.error = null;

      try {
        const filters = { ...this.filters, ...params };
        const response = await sso.platform.organizations.list(filters);

        this.organizations = response.organizations;
        this.total = response.total;
        this.filters = { ...this.filters, ...params };
      } catch (error) {
        console.error('Failed to fetch organizations:', error);
        this.error = error.message || 'Failed to fetch organizations';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Approve a pending organization
     */
    async approveOrganization(orgId, tierId) {
      try {
        const approved = await sso.platform.organizations.approve(orgId, { tier_id: tierId });

        // Update the organization in the list
        const index = this.organizations.findIndex(org => org.id === orgId);
        if (index !== -1) {
          this.organizations[index] = approved;
        }

        return approved;
      } catch (error) {
        console.error('Failed to approve organization:', error);
        throw error;
      }
    },

    /**
     * Reject a pending organization
     */
    async rejectOrganization(orgId, reason) {
      try {
        const rejected = await sso.platform.organizations.reject(orgId, { reason });

        // Update the organization in the list
        const index = this.organizations.findIndex(org => org.id === orgId);
        if (index !== -1) {
          this.organizations[index] = rejected;
        }

        return rejected;
      } catch (error) {
        console.error('Failed to reject organization:', error);
        throw error;
      }
    },

    /**
     * Suspend an active organization
     */
    async suspendOrganization(orgId) {
      try {
        const suspended = await sso.platform.organizations.suspend(orgId);

        // Update the organization in the list
        const index = this.organizations.findIndex(org => org.id === orgId);
        if (index !== -1) {
          this.organizations[index] = suspended;
        }

        return suspended;
      } catch (error) {
        console.error('Failed to suspend organization:', error);
        throw error;
      }
    },

    /**
     * Activate a suspended organization
     */
    async activateOrganization(orgId) {
      try {
        const activated = await sso.platform.organizations.activate(orgId);

        // Update the organization in the list
        const index = this.organizations.findIndex(org => org.id === orgId);
        if (index !== -1) {
          this.organizations[index] = activated;
        }

        return activated;
      } catch (error) {
        console.error('Failed to activate organization:', error);
        throw error;
      }
    },

    /**
     * Update an organization's tier
     */
    async updateOrganizationTier(orgId, payload) {
      try {
        const updated = await sso.platform.organizations.updateTier(orgId, payload);

        // Update the organization in the list
        const index = this.organizations.findIndex(org => org.id === orgId);
        if (index !== -1) {
          this.organizations[index] = updated;
        }

        return updated;
      } catch (error) {
        console.error('Failed to update organization tier:', error);
        throw error;
      }
    },

    /**
     * Clear filters and reload
     */
    clearFilters() {
      this.filters = {
        status: null,
        page: 1,
        limit: 50,
      };
      return this.fetchOrganizations();
    },
  },
});
