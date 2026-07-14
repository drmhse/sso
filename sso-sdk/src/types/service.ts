import { ServiceType } from './common';

/**
 * Service entity
 */
export interface Service {
  id: string;
  org_id: string;
  slug: string;
  name: string;
  service_type: ServiceType;
  client_id: string;
  client_secret?: string | null; // Returned on creation, otherwise often null/omitted
  github_scopes: string[];
  microsoft_scopes: string[];
  google_scopes: string[];
  redirect_uris: string[];
  device_activation_uri?: string;
  resource_uris?: string[];
  saml_enabled: boolean;
  saml_entity_id?: string;
  saml_acs_url?: string;
  saml_slo_url?: string;
  saml_name_id_format?: string;
  saml_attribute_mapping?: Record<string, string>;
  saml_sign_assertions: boolean;
  saml_sign_response: boolean;
  created_at: string;
}

/**
 * Subscription plan
 */
export interface Plan {
  id: string;
  service_id: string;
  name: string;
  description?: string;
  price_cents: number;
  currency: string;
  features: string; // JSON string from API
  stripe_price_id?: string;
  is_default?: boolean;
  created_at: string;
}

/**
 * Plan response with metadata
 */
export interface PlanResponse {
  plan: Plan;
  subscription_count: number;
}

/**
 * Create plan payload
 */
export interface CreatePlanPayload {
  name: string;
  description?: string;
  price_cents: number;
  currency: string;
  features?: string[];
  stripe_price_id?: string;
  is_default?: boolean;
}

/**
 * Update plan payload
 */
export interface UpdatePlanPayload {
  name?: string;
  description?: string;
  price_cents?: number;
  currency?: string;
  features?: string[];
  stripe_price_id?: string | null;
  is_default?: boolean;
}

/**
 * Create service payload
 */
export interface CreateServicePayload {
  slug: string;
  name: string;
  service_type: ServiceType;
  github_scopes?: string[];
  microsoft_scopes?: string[];
  google_scopes?: string[];
  redirect_uris: string[];
  device_activation_uri?: string;
  resource_uris?: string[];
}

/**
 * Create service response
 */
export interface CreateServiceResponse {
  service: Service;
  default_plan: Plan;
  usage: {
    current_services: number;
    max_services: number;
    tier: string;
  };
}

export interface RotateServiceSecretResponse {
  service: Service;
  client_secret: string;
}

/**
 * Update service payload
 */
export interface UpdateServicePayload {
  name?: string;
  service_type?: ServiceType;
  github_scopes?: string[];
  microsoft_scopes?: string[];
  google_scopes?: string[];
  redirect_uris?: string[];
  device_activation_uri?: string;
  resource_uris?: string[];
}

/**
 * Service with aggregated details (for listing)
 */
export interface ServiceWithDetails {
  service: Service;
  plan_count: number;
  subscription_count: number;
}

/**
 * Service list response with usage metadata
 */
export interface ServiceListResponse {
  services: ServiceWithDetails[];
  usage: {
    current_services: number;
    max_services: number;
    tier: string;
  };
}

/**
 * API Key for service-to-service authentication
 */
export interface ApiKey {
  id: string;
  service_id: string;
  name: string;
  prefix: string;
  permissions: string[];
  last_used_at?: string;
  expires_at?: string;
  created_at: string;
  created_by: string;
}

/**
 * API Key creation response (includes the full key - only returned once)
 */
export interface ApiKeyCreateResponse {
  id: string;
  service_id: string;
  name: string;
  prefix: string;
  permissions: string[];
  expires_at?: string;
  created_at: string;
  created_by: string;
  key: string; // Full key is ONLY returned once upon creation
}

/**
 * Create API key payload
 */
export interface CreateApiKeyPayload {
  name: string;
  permissions: string[];
  expires_in_days?: number;
}

/**
 * List API keys response
 */
export interface ListApiKeysResponse {
  api_keys: ApiKey[];
  total: number;
}

/**
 * SAML configuration for a service (acting as Identity Provider)
 */
export interface SamlConfig {
  enabled: boolean;
  entity_id?: string;
  acs_url?: string;
  slo_url?: string;
  name_id_format?: string;
  attribute_mapping?: Record<string, string>;
  sign_assertions: boolean;
  sign_response: boolean;
  has_certificate: boolean;
}

/**
 * Configure SAML IdP payload
 */
export interface ConfigureSamlPayload {
  enabled: boolean;
  entity_id: string;
  acs_url: string;
  slo_url?: string;
  name_id_format?: string;
  attribute_mapping?: Record<string, string>;
  sign_assertions?: boolean;
  sign_response?: boolean;
}

/**
 * SAML configuration response
 */
export interface ConfigureSamlResponse {
  success: boolean;
  message: string;
}

/**
 * SAML signing certificate info
 */
export interface SamlCertificate {
  public_key: string;
  valid_from: string;
  valid_until: string;
  is_active: boolean;
  created_at: string;
  lifecycle_status: 'healthy' | 'expiring_soon' | 'expired' | 'not_yet_valid';
  expires_in_seconds: number;
  published_previous_certificates: SamlPublishedCertificate[];
}

export interface SamlPublishedCertificate {
  public_key: string;
  valid_from: string;
  valid_until: string;
  publish_until: string;
  created_at: string;
}

/**
 * Create checkout session payload
 */
export interface CreateCheckoutPayload {
  plan_id: string;
  success_url: string;
  cancel_url: string;
}

/**
 * Create checkout session response
 */
export interface CreateCheckoutResponse {
  checkout_url: string;
  session_id: string;
}
