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
  github_scopes: string[];
  microsoft_scopes: string[];
  google_scopes: string[];
  redirect_uris: string[];
  device_activation_uri?: string;
  created_at: string;
}

/**
 * Provider token grant configuration
 */
export interface ProviderTokenGrant {
  id: string;
  service_id: string;
  provider: string;
  scopes: string[];
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
  price_monthly?: number;
  features: string[];
  is_default: boolean;
  created_at: string;
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
}

/**
 * Create service response
 */
export interface CreateServiceResponse {
  service: Service;
  provider_grants: ProviderTokenGrant[];
  default_plan: Plan;
  usage: {
    current_services: number;
    max_services: number;
    tier: string;
  };
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
}

/**
 * Service response with details
 */
export interface ServiceResponse {
  service: Service;
  provider_grants: ProviderTokenGrant[];
  plans: Plan[];
}

/**
 * Create plan payload
 */
export interface CreatePlanPayload {
  name: string;
  description?: string;
  price_monthly?: number;
  features: string[];
  is_default?: boolean;
}

/**
 * Service with aggregated details
 */
export interface ServiceWithDetails extends Service {
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
