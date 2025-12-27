import { HttpClient } from '../http';
import {
  Service,
  ServiceListResponse,
  CreateServicePayload,
  CreateServiceResponse,
  UpdateServicePayload,
  PlanResponse,
  CreatePlanPayload,
  UpdatePlanPayload,
  ApiKey,
  ApiKeyCreateResponse,
  CreateApiKeyPayload,
  ListApiKeysResponse,
  SamlConfig,
  ConfigureSamlPayload,
  ConfigureSamlResponse,
  SamlCertificate,
  CreateCheckoutPayload,
  CreateCheckoutResponse,
} from '../types';

/**
 * Service management methods
 */
export class ServicesModule {
  constructor(private http: HttpClient) { }

  /**
   * Create a new service for an organization.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param payload Service creation payload
   * @returns Created service with details
   *
   * @example
   * ```typescript
   * const result = await sso.services.create('acme-corp', {
   *   slug: 'main-app',
   *   name: 'Main Application',
   *   service_type: 'web',
   *   github_scopes: ['user:email', 'read:org'],
   *   redirect_uris: ['https://app.acme.com/callback']
   * });
   * console.log(result.service.client_id);
   * ```
   */
  public async create(orgSlug: string, payload: CreateServicePayload): Promise<CreateServiceResponse> {
    const response = await this.http.post<CreateServiceResponse>(
      `/api/organizations/${orgSlug}/services`,
      payload
    );
    return response.data;
  }

  /**
   * List all services for an organization.
   *
   * @param orgSlug Organization slug
   * @returns Service list response with usage metadata
   *
   * @example
   * ```typescript
   * const result = await sso.services.list('acme-corp');
   * console.log(`Using ${result.usage.current_services} of ${result.usage.max_services} services`);
   * result.services.forEach(svc => console.log(svc.name, svc.client_id));
   * ```
   */
  public async list(orgSlug: string): Promise<ServiceListResponse> {
    const response = await this.http.get<ServiceListResponse>(`/api/organizations/${orgSlug}/services`);
    return response.data;
  }

  /**
   * Get detailed information for a specific service.
   *
   * @param orgSlug Organization slug
   * @param serviceSlug Service slug
   * @returns Service with provider grants and plans
   *
   * @example
   * ```typescript
   * const service = await sso.services.get('acme-corp', 'main-app');
   * console.log(service.service.redirect_uris);
   * console.log(service.plans);
   * ```
   */
  public async get(orgSlug: string, serviceSlug: string): Promise<Service> {
    const response = await this.http.get<Service>(
      `/api/organizations/${orgSlug}/services/${serviceSlug}`
    );
    return response.data;
  }

  /**
   * Update service configuration.
   * Requires 'owner' or 'admin' role.
   *
   * @param orgSlug Organization slug
   * @param serviceSlug Service slug
   * @param payload Update payload
   * @returns Updated service
   *
   * @example
   * ```typescript
   * const updated = await sso.services.update('acme-corp', 'main-app', {
   *   name: 'Main Application v2',
   *   redirect_uris: ['https://app.acme.com/callback', 'https://app.acme.com/oauth']
   * });
   * ```
   */
  public async update(
    orgSlug: string,
    serviceSlug: string,
    payload: UpdateServicePayload
  ): Promise<Service> {
    const response = await this.http.patch<Service>(
      `/api/organizations/${orgSlug}/services/${serviceSlug}`,
      payload
    );
    return response.data;
  }

  /**
   * Delete a service.
   * Requires 'owner' role.
   *
   * @param orgSlug Organization slug
   * @param serviceSlug Service slug
   *
   * @example
   * ```typescript
   * await sso.services.delete('acme-corp', 'old-app');
   * ```
   */
  public async delete(orgSlug: string, serviceSlug: string): Promise<void> {
    await this.http.delete(`/api/organizations/${orgSlug}/services/${serviceSlug}`);
  }

  /**
   * Plan management methods
   */
  public plans = {
    /**
     * Create a new subscription plan for a service.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param payload Plan creation payload
     * @returns Created plan with subscription count
     *
     * @example
     * ```typescript
     * const result = await sso.services.plans.create('acme-corp', 'main-app', {
     *   name: 'pro',
     *   price_cents: 2999,
     *   currency: 'usd',
     *   features: ['api-access', 'advanced-analytics', 'priority-support']
     * });
     * console.log(result.plan.name, result.subscription_count);
     * ```
     */
    create: async (
      orgSlug: string,
      serviceSlug: string,
      payload: CreatePlanPayload
    ): Promise<PlanResponse> => {
      const response = await this.http.post<PlanResponse>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/plans`,
        payload
      );
      return response.data;
    },

    /**
     * List all plans for a service.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns Array of plans with subscription counts
     *
     * @example
     * ```typescript
     * const plans = await sso.services.plans.list('acme-corp', 'main-app');
     * plans.forEach(p => console.log(p.plan.name, p.subscription_count));
     * ```
     */
    list: async (orgSlug: string, serviceSlug: string): Promise<PlanResponse[]> => {
      const response = await this.http.get<PlanResponse[]>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/plans`
      );
      return response.data;
    },

    /**
     * Update a subscription plan.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param planId Plan ID
     * @param payload Plan update payload
     * @returns Updated plan with subscription count
     *
     * @example
     * ```typescript
     * const result = await sso.services.plans.update('acme-corp', 'main-app', 'plan_123', {
     *   name: 'Pro Plus',
     *   price_cents: 3999,
     *   currency: 'usd',
     *   features: ['api-access', 'advanced-analytics', 'priority-support', 'custom-integrations']
     * });
     * console.log('Updated plan:', result.plan.name);
     * ```
     */
    update: async (
      orgSlug: string,
      serviceSlug: string,
      planId: string,
      payload: UpdatePlanPayload
    ): Promise<PlanResponse> => {
      const response = await this.http.patch<PlanResponse>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/plans/${planId}`,
        payload
      );
      return response.data;
    },

    /**
     * Delete a subscription plan.
     * Requires 'owner' or 'admin' role.
     *
     * WARNING: This will fail if the plan has active subscriptions.
     * You must migrate or cancel all subscriptions before deleting a plan.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param planId Plan ID
     *
     * @example
     * ```typescript
     * try {
     *   await sso.services.plans.delete('acme-corp', 'main-app', 'plan_123');
     *   console.log('Plan deleted successfully');
     * } catch (error) {
     *   console.error('Cannot delete plan with active subscriptions');
     * }
     * ```
     */
    delete: async (orgSlug: string, serviceSlug: string, planId: string): Promise<void> => {
      await this.http.delete(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/plans/${planId}`
      );
    },
  };

  /**
   * API Key management methods for service-to-service authentication
   */
  public apiKeys = {
    /**
     * Create a new API key for a service.
     * Requires 'owner' or 'admin' role.
     *
     * IMPORTANT: The full API key is only returned once upon creation.
     * Store it securely as it cannot be retrieved again.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param payload API key creation payload
     * @returns Created API key with the full key value
     *
     * @example
     * ```typescript
     * const apiKey = await sso.services.apiKeys.create('acme-corp', 'main-app', {
     *   name: 'Production Backend',
     *   permissions: ['read:users', 'write:subscriptions'],
     *   expires_in_days: 90
     * });
     *
     * // IMPORTANT: Store this key securely - it won't be shown again
     * console.log('API Key:', apiKey.key);
     * console.log('Prefix:', apiKey.prefix);
     * ```
     */
    create: async (
      orgSlug: string,
      serviceSlug: string,
      payload: CreateApiKeyPayload
    ): Promise<ApiKeyCreateResponse> => {
      const response = await this.http.post<ApiKeyCreateResponse>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/api-keys`,
        payload
      );
      return response.data;
    },

    /**
     * List all API keys for a service.
     * Note: The full key values are not included in this response.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param options Optional query parameters for pagination
     * @returns List of API keys with metadata
     *
     * @example
     * ```typescript
     * const result = await sso.services.apiKeys.list('acme-corp', 'main-app', {
     *   limit: 50,
     *   offset: 0
     * });
     *
     * console.log(`Total API keys: ${result.total}`);
     * result.api_keys.forEach(key => {
     *   console.log(`${key.name} (${key.prefix})`);
     *   console.log(`Permissions: ${key.permissions.join(', ')}`);
     *   console.log(`Last used: ${key.last_used_at || 'Never'}`);
     * });
     * ```
     */
    list: async (
      orgSlug: string,
      serviceSlug: string,
      options?: { limit?: number; offset?: number }
    ): Promise<ListApiKeysResponse> => {
      const queryParams = new URLSearchParams();
      if (options?.limit) queryParams.set('limit', options.limit.toString());
      if (options?.offset) queryParams.set('offset', options.offset.toString());

      const query = queryParams.toString() ? `?${queryParams.toString()}` : '';
      const response = await this.http.get<ListApiKeysResponse>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/api-keys${query}`
      );
      return response.data;
    },

    /**
     * Get details for a specific API key.
     * Note: The full key value is not included in this response.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param apiKeyId API key ID
     * @returns API key details
     *
     * @example
     * ```typescript
     * const apiKey = await sso.services.apiKeys.get('acme-corp', 'main-app', 'key_abc123');
     * console.log(`Name: ${apiKey.name}`);
     * console.log(`Permissions: ${apiKey.permissions.join(', ')}`);
     * console.log(`Expires: ${apiKey.expires_at || 'Never'}`);
     * ```
     */
    get: async (
      orgSlug: string,
      serviceSlug: string,
      apiKeyId: string
    ): Promise<ApiKey> => {
      const response = await this.http.get<ApiKey>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/api-keys/${apiKeyId}`
      );
      return response.data;
    },

    /**
     * Delete an API key.
     * Requires 'owner' or 'admin' role.
     *
     * WARNING: This action is immediate and cannot be undone.
     * Any services using this key will lose access immediately.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param apiKeyId API key ID
     *
     * @example
     * ```typescript
     * await sso.services.apiKeys.delete('acme-corp', 'main-app', 'key_abc123');
     * console.log('API key deleted successfully');
     * ```
     */
    delete: async (
      orgSlug: string,
      serviceSlug: string,
      apiKeyId: string
    ): Promise<void> => {
      await this.http.delete(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/api-keys/${apiKeyId}`
      );
    },
  };

  /**
   * SAML 2.0 Identity Provider (IdP) management methods
   *
   * Configure your service as a SAML IdP to enable SSO into third-party applications
   * (Salesforce, AWS, Google Workspace, etc.)
   */
  public saml = {
    /**
     * Configure SAML IdP settings for a service.
     * Requires 'owner' or 'admin' role.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param payload SAML configuration payload
     * @returns Configuration success response
     *
     * @example
     * ```typescript
     * const result = await sso.services.saml.configure('acme-corp', 'main-app', {
     *   enabled: true,
     *   entity_id: 'https://salesforce.example.com',
     *   acs_url: 'https://salesforce.example.com/saml/acs',
     *   name_id_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
     *   attribute_mapping: {
     *     email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
     *   },
     *   sign_assertions: true,
     *   sign_response: true
     * });
     * ```
     */
    configure: async (
      orgSlug: string,
      serviceSlug: string,
      payload: ConfigureSamlPayload
    ): Promise<ConfigureSamlResponse> => {
      const response = await this.http.post<ConfigureSamlResponse>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/saml`,
        payload
      );
      return response.data;
    },

    /**
     * Get current SAML IdP configuration for a service.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns Current SAML configuration
     *
     * @example
     * ```typescript
     * const config = await sso.services.saml.getConfig('acme-corp', 'main-app');
     * if (config.enabled && config.has_certificate) {
     *   console.log('SAML IdP is ready');
     *   console.log('Entity ID:', config.entity_id);
     *   console.log('ACS URL:', config.acs_url);
     * }
     * ```
     */
    getConfig: async (orgSlug: string, serviceSlug: string): Promise<SamlConfig> => {
      const response = await this.http.get<SamlConfig>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/saml`
      );
      return response.data;
    },

    /**
     * Delete SAML IdP configuration and deactivate all certificates.
     * Requires 'owner' or 'admin' role.
     *
     * WARNING: This will break SSO for all third-party applications using this IdP.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     *
     * @example
     * ```typescript
     * await sso.services.saml.deleteConfig('acme-corp', 'main-app');
     * console.log('SAML IdP configuration deleted');
     * ```
     */
    deleteConfig: async (orgSlug: string, serviceSlug: string): Promise<ConfigureSamlResponse> => {
      const response = await this.http.delete<ConfigureSamlResponse>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/saml`
      );
      return response.data;
    },

    /**
     * Initiate an IdP-initiated SAML login.
     * Returns an HTML page with an auto-submitting form that POSTs the SAML assertion to the Service Provider.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns HTML page with auto-submitting form
     *
     * @example
     * ```typescript
     * const html = await sso.services.saml.initiateLogin('acme-corp', 'salesforce');
     * document.body.innerHTML = html; // Auto-submits
     * ```
     */
    initiateLogin: async (orgSlug: string, serviceSlug: string): Promise<string> => {
      const response = await this.http.get<string>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/saml/login`
      );
      return response.data;
    },

    /**
     * Generate a new SAML signing certificate for the IdP.
     * Requires 'owner' or 'admin' role.
     *
     * IMPORTANT: This automatically deactivates any existing active certificates.
     * Provide the returned certificate to your Service Provider during SAML setup.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns Certificate information including public key
     *
     * @example
     * ```typescript
     * const cert = await sso.services.saml.generateCertificate('acme-corp', 'main-app');
     * console.log('Certificate generated, valid until:', cert.valid_until);
     * console.log('Public certificate:\n', cert.public_key);
     * // Provide cert.public_key to your Service Provider
     * ```
     */
    generateCertificate: async (
      orgSlug: string,
      serviceSlug: string
    ): Promise<SamlCertificate> => {
      const response = await this.http.post<SamlCertificate>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/saml/certificate`,
        {}
      );
      return response.data;
    },

    /**
     * Get the active SAML signing certificate.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns Active certificate information
     *
     * @example
     * ```typescript
     * try {
     *   const cert = await sso.services.saml.getCertificate('acme-corp', 'main-app');
     *   console.log('Certificate expires:', cert.valid_until);
     * } catch (error) {
     *   console.log('No active certificate - generate one first');
     * }
     * ```
     */
    getCertificate: async (orgSlug: string, serviceSlug: string): Promise<SamlCertificate> => {
      const response = await this.http.get<SamlCertificate>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/saml/certificate`
      );
      return response.data;
    },

    /**
     * Get the SAML IdP metadata URL for this service.
     * This URL can be provided to Service Providers for automatic configuration.
     *
     * @param baseURL SSO platform base URL
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns Metadata URL
     *
     * @example
     * ```typescript
     * const metadataUrl = sso.services.saml.getMetadataUrl(
     *   'https://sso.example.com',
     *   'acme-corp',
     *   'main-app'
     * );
     * console.log('Provide this URL to your SP:', metadataUrl);
     * // https://sso.example.com/saml/acme-corp/main-app/metadata
     * ```
     */
    getMetadataUrl: (baseURL: string, orgSlug: string, serviceSlug: string): string => {
      return `${baseURL}/saml/${orgSlug}/${serviceSlug}/metadata`;
    },

    /**
     * Get the SAML SSO endpoint URL for this service.
     * This is where Service Providers should redirect users to initiate SSO.
     *
     * @param baseURL SSO platform base URL
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @returns SSO endpoint URL
     *
     * @example
     * ```typescript
     * const ssoUrl = sso.services.saml.getSsoUrl(
     *   'https://sso.example.com',
     *   'acme-corp',
     *   'main-app'
     * );
     * console.log('SSO endpoint:', ssoUrl);
     * // https://sso.example.com/saml/acme-corp/main-app/sso
     * ```
     */
    getSsoUrl: (baseURL: string, orgSlug: string, serviceSlug: string): string => {
      return `${baseURL}/saml/${orgSlug}/${serviceSlug}/sso`;
    },
  };

  /**
   * Stripe billing and checkout methods
   */
  public billing = {
    /**
     * Create a Stripe checkout session for the authenticated user to subscribe to a plan.
     * Requires organization membership.
     *
     * IMPORTANT: The plan must have a `stripe_price_id` configured to be available for purchase.
     *
     * @param orgSlug Organization slug
     * @param serviceSlug Service slug
     * @param payload Checkout payload containing plan_id and redirect URLs
     * @returns Checkout session with URL to redirect user to
     *
     * @example
     * ```typescript
     * const checkout = await sso.services.billing.createCheckout('acme-corp', 'main-app', {
     *   plan_id: 'plan_pro',
     *   success_url: 'https://app.acme.com/billing/success?session_id={CHECKOUT_SESSION_ID}',
     *   cancel_url: 'https://app.acme.com/billing/cancel'
     * });
     *
     * // Redirect user to Stripe checkout
     * window.location.href = checkout.checkout_url;
     * ```
     */
    createCheckout: async (
      orgSlug: string,
      serviceSlug: string,
      payload: CreateCheckoutPayload
    ): Promise<CreateCheckoutResponse> => {
      const response = await this.http.post<CreateCheckoutResponse>(
        `/api/organizations/${orgSlug}/services/${serviceSlug}/checkout`,
        payload
      );
      return response.data;
    },
  };
}
