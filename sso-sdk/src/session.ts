import { TokenStorage } from './storage';
import { RefreshTokenResponse } from './types';

interface SessionConfig {
  storageKeyPrefix?: string;
  autoRefresh?: boolean;
}

/**
 * Snapshot of the current authentication state.
 * Useful for hydration in SSR frameworks.
 */
export interface AuthSnapshot {
  isAuthenticated: boolean;
  token: string | null;
}

export class SessionManager {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private refreshPromise: Promise<string> | null = null;
  private listeners: Array<(isAuthenticated: boolean) => void> = [];

  constructor(
    private storage: TokenStorage,
    private refreshHandler: (token: string) => Promise<RefreshTokenResponse>,
    private config: SessionConfig = { storageKeyPrefix: 'sso_' }
  ) {}

  /**
   * Initialize session from storage
   */
  public async loadSession(): Promise<void> {
    this.accessToken = await this.storage.getItem(`${this.config.storageKeyPrefix}access_token`);
    this.refreshToken = await this.storage.getItem(`${this.config.storageKeyPrefix}refresh_token`);
  }

  /**
   * Set the session data (used after login/register)
   */
  public async setSession(tokens: { access_token: string; refresh_token?: string }) {
    this.accessToken = tokens.access_token;
    await this.storage.setItem(`${this.config.storageKeyPrefix}access_token`, tokens.access_token);

    if (tokens.refresh_token) {
      this.refreshToken = tokens.refresh_token;
      await this.storage.setItem(`${this.config.storageKeyPrefix}refresh_token`, tokens.refresh_token);
    }

    this.notifyListeners(true);
  }

  /**
   * Clear session (logout)
   */
  public async clearSession() {
    this.accessToken = null;
    this.refreshToken = null;
    await this.storage.removeItem(`${this.config.storageKeyPrefix}access_token`);
    await this.storage.removeItem(`${this.config.storageKeyPrefix}refresh_token`);
    this.notifyListeners(false);
  }

  /**
   * Get the current access token, refreshing it if necessary/possible
   */
  public async getToken(): Promise<string | null> {
    return this.accessToken;
  }

  /**
   * Handle logic for when a 401 occurs
   */
  public async refreshSession(): Promise<string> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    // Deduplicate refresh requests (mutex)
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      try {
        const tokens = await this.refreshHandler(this.refreshToken!);
        await this.setSession(tokens);
        return tokens.access_token;
      } catch (err) {
        await this.clearSession();
        throw err;
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  public isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  /**
   * Get a synchronous snapshot of the current auth state.
   * Useful for SSR hydration and initial state.
   */
  public getSnapshot(): AuthSnapshot {
    return {
      isAuthenticated: !!this.accessToken,
      token: this.accessToken,
    };
  }

  /**
   * Subscribe to auth state changes (useful for UI updates).
   * The listener is immediately called with the current state upon subscription.
   */
  public subscribe(listener: (isAuthenticated: boolean) => void) {
    this.listeners.push(listener);
    // Emit initial state immediately upon subscription
    listener(this.isAuthenticated());
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notifyListeners(isAuth: boolean) {
    this.listeners.forEach((l) => l(isAuth));
  }
}
