/**
 * WebAuthn/Passkey authentication types
 */

/**
 * Request to start passkey registration
 */
export interface PasskeyRegisterStartRequest {
  name?: string;
}

/**
 * Response from starting passkey registration
 */
export interface PasskeyRegisterStartResponse {
  challenge_id: string;
  options: any; // PublicKeyCredentialCreationOptions from browser WebAuthn API
}

/**
 * Request to finish passkey registration
 */
export interface PasskeyRegisterFinishRequest {
  challenge_id: string;
  credential: RegistrationResponseJSON;
}

/**
 * Response from finishing passkey registration
 */
export interface PasskeyRegisterFinishResponse {
  success: boolean;
  passkey_id: string;
}

/**
 * Request to start passkey authentication
 */
export interface PasskeyAuthStartRequest {
  email: string;
  org_slug?: string;
  service_slug?: string;
  redirect_uri?: string;
}

/**
 * Response from starting passkey authentication
 */
export interface PasskeyAuthStartResponse {
  challenge_id: string;
  options: any; // PublicKeyCredentialRequestOptions from browser WebAuthn API
}

/**
 * Request to finish passkey authentication
 */
export interface PasskeyAuthFinishRequest {
  challenge_id: string;
  credential: AuthenticationResponseJSON;
}

/**
 * Response from finishing passkey authentication
 */
export interface PasskeyAuthFinishResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  /** Backward compatible alias for access_token. */
  token: string;
  user_id: string;
  device_trust_token?: string;
}

/**
 * JSON-serializable version of WebAuthn registration response
 */
export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
  authenticatorAttachment?: 'platform' | 'cross-platform';
  clientExtensionResults: Record<string, unknown>;
  type: 'public-key';
}

/**
 * JSON-serializable version of WebAuthn authentication response
 */
export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: 'platform' | 'cross-platform';
  clientExtensionResults: Record<string, unknown>;
  type: 'public-key';
}

/**
 * Passkey information
 */
export interface Passkey {
  id: string;
  user_id: string;
  credential_id: string;
  name: string;
  aaguid?: string;
  backup_eligible: boolean;
  backup_state: boolean;
  transports?: string;
  last_used_at?: string;
  created_at: string;
}

/**
 * Passkey shown in authenticated self-service settings.
 */
export interface UserPasskey {
  id: string;
  name: string;
  backup_eligible: boolean;
  backup_state: boolean;
  transports?: string | null;
  last_used_at?: string | null;
  created_at: string;
}

/**
 * Generic passkey action response.
 */
export interface PasskeyActionResponse {
  success: boolean;
  message: string;
}
