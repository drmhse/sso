import { defineStore } from 'pinia';
import { ssoWithInterceptor as sso } from '@/api/interceptor';

export const useOrganizationStore = defineStore('organization', {
  state: () => ({
    currentOrganization: null,
    organizations: [],
    loading: false,
    error: null,
  }),

  getters: {
    hasOrganization: (state) => state.currentOrganization !== null,

    currentOrgSlug: (state) => state.currentOrganization?.organization.slug,

    currentOrgId: (state) => state.currentOrganization?.organization.id,

    currentOrgName: (state) => state.currentOrganization?.organization.name,

    currentOrgStatus: (state) => state.currentOrganization?.organization.status,

    isActive: (state) => state.currentOrganization?.organization.status === 'active',
  },

  actions: {
    /**
     * Fetch the current user's organizations
     */
    async fetchUserOrganizations() {
      this.loading = true;
      this.error = null;

      try {
        this.organizations = await sso.organizations.list();
      } catch (error) {
        console.error('Failed to fetch organizations:', error);
        this.error = error.message || 'Failed to fetch organizations';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Fetch a specific organization by slug and set it as current
     */
    async fetchOrganization(orgSlug) {
      this.loading = true;
      this.error = null;

      try {
        this.currentOrganization = await sso.organizations.get(orgSlug);
      } catch (error) {
        console.error('Failed to fetch organization:', error);
        this.error = error.message || 'Failed to fetch organization';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Update the current organization
     */
    async updateOrganization(orgSlug, payload) {
      try {
        this.currentOrganization = await sso.organizations.update(orgSlug, payload);
        return this.currentOrganization;
      } catch (error) {
        console.error('Failed to update organization:', error);
        throw error;
      }
    },

    /**
     * Clear current organization state
     */
    clearCurrent() {
      this.currentOrganization = null;
    },
  },
});
