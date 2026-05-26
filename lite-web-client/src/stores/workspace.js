import { defineStore } from 'pinia';
import { ssoWithInterceptor as sso } from '@/lib/interceptor';
import { useAuthStore } from './auth';
import { buildFullClientUrl } from '@/utils/fullClient';

export const useWorkspaceStore = defineStore('workspace', {
  state: () => ({
    mode: 'idle',
    currentOrganization: null,
    organizations: [],
    clientConfig: null,
    error: '',
  }),

  getters: {
    fullClientUrl: (state) => state.clientConfig?.full_client_url || '',
    managedConfigEnabled: (state) => state.clientConfig?.managed_config_enabled === true,
    currentOrgSlug: (state) => state.currentOrganization?.organization?.slug || '',
    currentOrgName: (state) => state.currentOrganization?.organization?.name || '',
    currentOrgStatus: (state) => state.currentOrganization?.organization?.status || '',
  },

  actions: {
    async loadClientConfig() {
      if (this.clientConfig) return this.clientConfig;
      const response = await fetch('/api/public/web-config');
      this.clientConfig = await response.json();
      return this.clientConfig;
    },

    async resolveWorkspace() {
      const authStore = useAuthStore();
      this.mode = 'loading';
      this.error = '';

      await this.loadClientConfig();

      try {
        this.organizations = await sso.organizations.list();

        if (this.organizations.length > 1) {
          this.mode = 'handoff';
          return;
        }

        if (this.organizations.length === 0) {
          this.currentOrganization = null;
          this.mode = 'no-org';
          return;
        }

        const orgSlug = this.organizations[0].organization.slug;
        this.currentOrganization = await sso.organizations.get(orgSlug);

        if (this.currentOrganization.organization.status === 'active') {
          const selection = await sso.organizations.select(orgSlug);
          await authStore.updateTokens(
            selection.access_token,
            selection.refresh_token,
            selection.membership.role,
          );
          this.currentOrganization = await sso.organizations.get(orgSlug);
        }

        this.mode = 'ready';
      } catch (error) {
        console.error('Workspace resolution failed:', error);
        this.mode = 'error';
        this.error = error.message || 'Failed to load your AuthOS workspace.';
      }
    },

    async refreshOrganization() {
      if (!this.currentOrgSlug) return null;
      this.currentOrganization = await sso.organizations.get(this.currentOrgSlug);
      return this.currentOrganization;
    },

    async updateOrganization(payload) {
      if (!this.currentOrgSlug) throw new Error('No organization selected');
      this.currentOrganization = await sso.organizations.update(this.currentOrgSlug, payload);
      return this.currentOrganization;
    },

    redirectToFullClient(path = '/home') {
      const authStore = useAuthStore();
      const url = buildFullClientUrl(this.clientConfig, path, {
        accessToken: authStore.token,
        refreshToken: authStore.refreshToken,
      });

      if (!url) {
        throw new Error('No full client URL is configured');
      }

      window.location.href = url;
    },
  },
});
