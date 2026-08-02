/**
 * Privacy and GDPR compliance types
 */

/**
 * User membership export data
 */
export interface MembershipExport {
  organization_id: string;
  organization_slug: string;
  role: string;
  joined_at: string;
}

/**
 * Login event export data
 */
export interface LoginEventExport {
  id: string;
  timestamp: string;
  ip_address: string | null;
  user_agent: string | null;
  provider: string | null;
  success: boolean;
  risk_score: number | null;
  risk_factors: string | null;
  geo_country: string | null;
  geo_city: string | null;
}

/**
 * OAuth identity export data
 */
export interface OAuthIdentityExport {
  provider: string;
  provider_user_id: string;
  linked_at: string;
}

/**
 * MFA event export data
 */
export interface MfaEventExport {
  event_type: string;
  timestamp: string;
  success: boolean;
  details: string | null;
}

/**
 * Passkey export data
 */
export interface PasskeyExport {
  id: string;
  name: string | null;
  aaguid: string | null;
  backup_eligible: boolean;
  created_at: string;
  last_used_at: string | null;
}

/**
 * Complete user data export response (GDPR Right to Access)
 */
export interface ExportUserDataResponse {
  user_id: string;
  email: string;
  created_at: string;
  memberships: MembershipExport[];
  login_events_count: number;
  login_events: LoginEventExport[];
  oauth_identities: OAuthIdentityExport[];
  mfa_events: MfaEventExport[];
  passkeys: PasskeyExport[];
}

/**
 * User anonymization confirmation payload.
 */
export interface ForgetUserRequest {
  current_password?: string;
  mfa_code?: string;
}

/**
 * User anonymization response (GDPR Right to be Forgotten)
 */
export interface ForgetUserResponse {
  success: boolean;
  message: string;
  user_id: string;
}
