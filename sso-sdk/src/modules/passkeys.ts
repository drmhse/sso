import { HttpClient } from '../http';
import {
  PasskeyRegisterStartResponse,
  PasskeyRegisterFinishResponse,
  PasskeyAuthStartResponse,
  PasskeyAuthFinishResponse,
  UserPasskey,
  PasskeyActionResponse,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '../types/passkeys';

// WebAuthn types are only available in browser contexts
declare const window: any;
declare const PublicKeyCredential: any;
declare const navigator: any;
declare const AuthenticatorAttestationResponse: any;
declare const AuthenticatorAssertionResponse: any;
declare type CredentialCreationOptions = any;
declare type CredentialRequestOptions = any;

/**
 * WebAuthn/Passkey authentication module
 *
 * Provides methods for registering and authenticating with FIDO2 passkeys.
 * Requires a browser environment with WebAuthn support.
 *
 * @example
 * ```typescript
 * // Register a new passkey (requires authenticated session)
 * await sso.passkeys.register();
 *
 * // Login with passkey
 * const { token } = await sso.passkeys.login('user@example.com');
 * sso.setToken(token);
 * ```
 */
export class PasskeysModule {
  constructor(private http: HttpClient) { }

  /**
   * Check if WebAuthn is supported in the current browser
   */
  isSupported(): boolean {
    return (
      typeof window !== 'undefined' &&
      window.PublicKeyCredential !== undefined &&
      typeof window.PublicKeyCredential === 'function'
    );
  }

  /**
   * Check if platform authenticator (like Touch ID, Face ID, Windows Hello) is available
   */
  async isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (!this.isSupported()) {
      return false;
    }
    return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  }

  /**
   * Register a new passkey for the authenticated user
   *
   * This method requires an authenticated session (JWT token must be set).
   * It starts the WebAuthn registration ceremony, prompts the user to create
   * a passkey using their device's authenticator (e.g., Touch ID, Face ID,
   * Windows Hello, or hardware security key), and stores the credential.
   *
   * @param displayName Optional display name for the passkey
   * @returns Promise resolving to the registered passkey ID
   * @throws {Error} If WebAuthn is not supported or registration fails
   *
   * @example
   * ```typescript
   * try {
   *   const passkeyId = await sso.passkeys.register('My MacBook Pro');
   *   console.log('Passkey registered:', passkeyId);
   * } catch (error) {
   *   console.error('Passkey registration failed:', error);
   * }
   * ```
   */
  /**
   * Start the passkey registration ceremony.
   * returns the options required to create credentials in the browser.
   */
  async registerStart(displayName?: string): Promise<PasskeyRegisterStartResponse> {
    const response = await this.http.post<PasskeyRegisterStartResponse>(
      '/api/auth/passkeys/register/start',
      { name: displayName }
    );
    return response.data;
  }

  /**
   * List registered passkeys for the authenticated user.
   */
  async list(): Promise<UserPasskey[]> {
    const response = await this.http.get<UserPasskey[]>('/api/auth/passkeys');
    return response.data;
  }

  /**
   * Rename a passkey for the authenticated user.
   */
  async updateName(passkeyId: string, name: string): Promise<UserPasskey> {
    const response = await this.http.patch<UserPasskey>(`/api/auth/passkeys/${passkeyId}`, {
      name,
    });
    return response.data;
  }

  /**
   * Delete a passkey for the authenticated user.
   */
  async delete(passkeyId: string): Promise<PasskeyActionResponse> {
    const response = await this.http.delete<PasskeyActionResponse>(`/api/auth/passkeys/${passkeyId}`);
    return response.data;
  }

  /**
   * Finish the passkey registration ceremony.
   * Verifies the credential created by the browser.
   */
  async registerFinish(challengeId: string, credential: RegistrationResponseJSON): Promise<PasskeyRegisterFinishResponse> {
    const response = await this.http.post<PasskeyRegisterFinishResponse>(
      '/api/auth/passkeys/register/finish',
      {
        challenge_id: challengeId,
        credential,
      }
    );
    return response.data;
  }

  /**
   * Register a new passkey for the authenticated user
   * ...
   */
  async register(displayName?: string): Promise<string> {
    if (!this.isSupported()) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    // Start registration ceremony
    const startData = await this.registerStart(displayName);

    // Convert server options to browser format
    const createOptions: CredentialCreationOptions = {
      publicKey: {
        ...startData.options,
        challenge: this.base64UrlToUint8Array(startData.options.challenge as unknown as string),
        user: {
          ...startData.options.user,
          id: this.base64UrlToUint8Array(startData.options.user.id as unknown as string),
        },
        excludeCredentials: startData.options.excludeCredentials?.map((cred: any) => ({
          ...cred,
          id: this.base64UrlToUint8Array(cred.id as unknown as string),
        })),
      },
    };

    // Call WebAuthn API
    const credential = await navigator.credentials.create(createOptions);

    if (!credential || !(credential instanceof PublicKeyCredential)) {
      throw new Error('Failed to create passkey');
    }

    if (!(credential.response instanceof AuthenticatorAttestationResponse)) {
      throw new Error('Invalid credential response type');
    }

    // Convert credential to JSON
    const credentialJSON: RegistrationResponseJSON = {
      id: credential.id,
      rawId: this.uint8ArrayToBase64Url(new Uint8Array(credential.rawId)),
      response: {
        clientDataJSON: this.uint8ArrayToBase64Url(new Uint8Array(credential.response.clientDataJSON)),
        attestationObject: this.uint8ArrayToBase64Url(new Uint8Array(credential.response.attestationObject)),
        transports: credential.response.getTransports?.() as string[],
      },
      authenticatorAttachment: credential.authenticatorAttachment as ('platform' | 'cross-platform') | undefined,
      clientExtensionResults: credential.getClientExtensionResults(),
      type: credential.type as 'public-key',
    };

    // Finish registration
    const finishResponse = await this.registerFinish(startData.challenge_id, credentialJSON);

    return finishResponse.passkey_id;
  }

  /**
   * Authenticate with a passkey and obtain a JWT token
   *
   * This method prompts the user to authenticate using their passkey.
   * Upon successful authentication, a JWT token is returned which can
   * be used to make authenticated API requests.
   *
   * @param email User's email address
   * @returns Promise resolving to authentication response with JWT token
   * @throws {Error} If WebAuthn is not supported or authentication fails
   *
   * @example
   * ```typescript
   * try {
   *   const { token, user_id } = await sso.passkeys.login('user@example.com');
   *   sso.setToken(token);
   *   console.log('Logged in as:', user_id);
   * } catch (error) {
   *   console.error('Passkey login failed:', error);
   * }
   * ```
   */
  /**
   * Start the passkey authentication ceremony.
   * Returns the options required to get credentials from the browser.
   */
  async authenticateStart(email: string, context?: {
    org_slug?: string;
    service_slug?: string;
    redirect_uri?: string;
  }): Promise<PasskeyAuthStartResponse> {
    const response = await this.http.post<PasskeyAuthStartResponse>(
      '/api/auth/passkeys/authenticate/start',
      { email, ...context }
    );
    return response.data;
  }

  /**
   * Finish the passkey authentication ceremony.
   * Verifies the assertion returned by the browser.
   */
  async authenticateFinish(challengeId: string, credential: AuthenticationResponseJSON): Promise<PasskeyAuthFinishResponse> {
    const response = await this.http.post<PasskeyAuthFinishResponse>(
      '/api/auth/passkeys/authenticate/finish',
      {
        challenge_id: challengeId,
        credential,
      }
    );
    return response.data;
  }

  /**
   * Authenticate with a passkey and obtain a JWT token
   * ...
   */
  async login(email: string, context?: {
    org_slug?: string;
    service_slug?: string;
    redirect_uri?: string;
  }): Promise<PasskeyAuthFinishResponse> {
    if (!this.isSupported()) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    // Start authentication ceremony
    const startData = await this.authenticateStart(email, context);

    // Convert server options to browser format
    const getOptions: CredentialRequestOptions = {
      publicKey: {
        ...startData.options,
        challenge: this.base64UrlToUint8Array(startData.options.challenge as unknown as string),
        allowCredentials: startData.options.allowCredentials?.map((cred: any) => ({
          ...cred,
          id: this.base64UrlToUint8Array(cred.id as unknown as string),
        })),
      },
    };

    // Call WebAuthn API
    const credential = await navigator.credentials.get(getOptions);

    if (!credential || !(credential instanceof PublicKeyCredential)) {
      throw new Error('Failed to get passkey');
    }

    if (!(credential.response instanceof AuthenticatorAssertionResponse)) {
      throw new Error('Invalid credential response type');
    }

    // Convert credential to JSON
    const credentialJSON: AuthenticationResponseJSON = {
      id: credential.id,
      rawId: this.uint8ArrayToBase64Url(new Uint8Array(credential.rawId)),
      response: {
        clientDataJSON: this.uint8ArrayToBase64Url(new Uint8Array(credential.response.clientDataJSON)),
        authenticatorData: this.uint8ArrayToBase64Url(new Uint8Array(credential.response.authenticatorData)),
        signature: this.uint8ArrayToBase64Url(new Uint8Array(credential.response.signature)),
        userHandle: credential.response.userHandle
          ? this.uint8ArrayToBase64Url(new Uint8Array(credential.response.userHandle))
          : undefined,
      },
      authenticatorAttachment: credential.authenticatorAttachment as ('platform' | 'cross-platform') | undefined,
      clientExtensionResults: credential.getClientExtensionResults(),
      type: credential.type as 'public-key',
    };

    // Finish authentication
    return this.authenticateFinish(startData.challenge_id, credentialJSON);
  }

  /**
   * Convert Base64URL string to Uint8Array
   */
  private base64UrlToUint8Array(base64url: string): Uint8Array {
    // Add padding if needed
    const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;

    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }

    return outputArray;
  }

  /**
   * Convert Uint8Array to Base64URL string
   */
  private uint8ArrayToBase64Url(array: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < array.byteLength; i++) {
      binary += String.fromCharCode(array[i]);
    }

    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}
