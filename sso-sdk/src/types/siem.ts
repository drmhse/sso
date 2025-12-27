/**
 * SIEM (Security Information and Event Management) types
 */

/**
 * SIEM provider types
 */
export type SiemProviderType = 'Datadog' | 'Splunk' | 'Elastic' | 'Custom';

/**
 * SIEM configuration response
 */
export interface SiemConfigResponse {
  id: string;
  org_id: string;
  name: string;
  provider_type: SiemProviderType;
  endpoint_url: string;
  batch_size: number;
  enabled: boolean;
  last_successful_batch_at: string | null;
  failure_count: number;
  created_at: string;
}

/**
 * Create SIEM configuration request
 */
export interface CreateSiemConfigRequest {
  name: string;
  provider_type: SiemProviderType;
  endpoint_url: string;
  api_key?: string;
  auth_header?: string;
  batch_size?: number;
}

/**
 * Update SIEM configuration request
 */
export interface UpdateSiemConfigRequest {
  name?: string;
  endpoint_url?: string;
  api_key?: string | null;
  auth_header?: string | null;
  batch_size?: number;
  enabled?: boolean;
}

/**
 * List SIEM configurations response
 */
export interface ListSiemConfigsResponse {
  siem_configs: SiemConfigResponse[];
  total: number;
}

/**
 * Test SIEM connection response
 */
export interface TestConnectionResponse {
  success: boolean;
  message: string;
}
