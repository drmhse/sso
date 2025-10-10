import { defineStore } from 'pinia';
import { sso } from '@/api';

export const useServicesStore = defineStore('services', {
  state: () => ({
    services: [],
    currentService: null,
    currentServicePlans: [],
    oauthCredentials: {
      github: null,
      google: null,
      microsoft: null,
    },
    loading: false,
    error: null,
  }),

  getters: {
    hasServices: (state) => state.services.length > 0,

    currentServiceSlug: (state) => state.currentService?.service?.slug,

    currentServiceId: (state) => state.currentService?.service?.id,

    currentServiceName: (state) => state.currentService?.service?.name,

    servicesCount: (state) => state.services.length,

    webServices: (state) => state.services.filter(s => s.service_type === 'web'),

    mobileServices: (state) => state.services.filter(s => s.service_type === 'mobile'),

    apiServices: (state) => state.services.filter(s => s.service_type === 'api'),
  },

  actions: {
    /**
     * Fetch all services for an organization
     */
    async fetchServices(orgSlug) {
      this.loading = true;
      this.error = null;

      try {
        this.services = await sso.services.list(orgSlug);
        return this.services;
      } catch (error) {
        console.error('Failed to fetch services:', error);
        this.error = error.message || 'Failed to fetch services';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Fetch a specific service by slug
     */
    async fetchService(orgSlug, serviceSlug) {
      this.loading = true;
      this.error = null;

      try {
        this.currentService = await sso.services.get(orgSlug, serviceSlug);
        this.currentServicePlans = this.currentService.plans || [];
        return this.currentService;
      } catch (error) {
        console.error('Failed to fetch service:', error);
        this.error = error.message || 'Failed to fetch service';
        throw error;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Create a new service
     */
    async createService(orgSlug, payload) {
      try {
        const result = await sso.services.create(orgSlug, payload);

        // Add the new service to the list
        this.services.push(result.service);

        return result;
      } catch (error) {
        console.error('Failed to create service:', error);
        throw error;
      }
    },

    /**
     * Update a service
     */
    async updateService(orgSlug, serviceSlug, payload) {
      try {
        const updated = await sso.services.update(orgSlug, serviceSlug, payload);

        // Update in local state
        const index = this.services.findIndex(s => s.slug === serviceSlug);
        if (index !== -1) {
          this.services[index] = updated;
        }

        // Update current service if it's the one being edited
        if (this.currentService?.service?.slug === serviceSlug) {
          this.currentService.service = updated;
        }

        return updated;
      } catch (error) {
        console.error('Failed to update service:', error);
        throw error;
      }
    },

    /**
     * Delete a service
     */
    async deleteService(orgSlug, serviceSlug) {
      try {
        await sso.services.delete(orgSlug, serviceSlug);

        // Remove from local state
        const index = this.services.findIndex(s => s.slug === serviceSlug);
        if (index !== -1) {
          this.services.splice(index, 1);
        }

        // Clear current service if it's the one being deleted
        if (this.currentService?.service?.slug === serviceSlug) {
          this.currentService = null;
          this.currentServicePlans = [];
        }
      } catch (error) {
        console.error('Failed to delete service:', error);
        throw error;
      }
    },

    /**
     * Fetch OAuth credentials for a specific provider
     */
    async fetchOAuthCredentials(orgSlug, provider) {
      try {
        const credentials = await sso.organizations.oauthCredentials.get(orgSlug, provider);
        this.oauthCredentials[provider] = credentials;
        return credentials;
      } catch (error) {
        // If credentials don't exist (404), that's okay - just return null
        if (error.status === 404 || error.response?.status === 404) {
          this.oauthCredentials[provider] = null;
          return null;
        }
        console.error(`Failed to fetch ${provider} credentials:`, error);
        throw error;
      }
    },

    /**
     * Fetch all OAuth credentials for the organization
     */
    async fetchAllOAuthCredentials(orgSlug) {
      const providers = ['github', 'google', 'microsoft'];

      try {
        await Promise.allSettled(
          providers.map(provider => this.fetchOAuthCredentials(orgSlug, provider))
        );
      } catch (error) {
        console.error('Failed to fetch OAuth credentials:', error);
      }
    },

    /**
     * Set or update OAuth credentials for a provider
     */
    async setOAuthCredentials(orgSlug, provider, payload) {
      try {
        const credentials = await sso.organizations.oauthCredentials.set(orgSlug, provider, payload);
        this.oauthCredentials[provider] = credentials;
        return credentials;
      } catch (error) {
        console.error(`Failed to set ${provider} credentials:`, error);
        throw error;
      }
    },

    /**
     * Fetch plans for the current service
     */
    async fetchPlans(orgSlug, serviceSlug) {
      try {
        this.currentServicePlans = await sso.services.plans.list(orgSlug, serviceSlug);
        return this.currentServicePlans;
      } catch (error) {
        console.error('Failed to fetch plans:', error);
        throw error;
      }
    },

    /**
     * Create a new plan for a service
     */
    async createPlan(orgSlug, serviceSlug, payload) {
      try {
        const plan = await sso.services.plans.create(orgSlug, serviceSlug, payload);
        this.currentServicePlans.push(plan);
        return plan;
      } catch (error) {
        console.error('Failed to create plan:', error);
        throw error;
      }
    },

    /**
     * Clear state
     */
    clear() {
      this.services = [];
      this.currentService = null;
      this.currentServicePlans = [];
      this.oauthCredentials = {
        github: null,
        google: null,
        microsoft: null,
      };
      this.error = null;
    },

    /**
     * Clear only the current service
     */
    clearCurrentService() {
      this.currentService = null;
      this.currentServicePlans = [];
    },
  },
});
