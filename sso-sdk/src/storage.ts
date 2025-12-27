/**
 * Abstract storage interface for persisting tokens
 */
export interface TokenStorage {
  getItem(key: string): Promise<string | null> | string | null;
  setItem(key: string, value: string): Promise<void> | void;
  removeItem(key: string): Promise<void> | void;
}

/**
 * In-memory storage (Default for Node/Server)
 */
export class MemoryStorage implements TokenStorage {
  private store = new Map<string, string>();

  getItem(key: string) {
    return this.store.get(key) || null;
  }

  setItem(key: string, value: string) {
    this.store.set(key, value);
  }

  removeItem(key: string) {
    this.store.delete(key);
  }
}

/**
 * Browser LocalStorage adapter
 */
export class BrowserStorage implements TokenStorage {
  getItem(key: string) {
    return typeof window !== 'undefined' ? window.localStorage.getItem(key) : null;
  }

  setItem(key: string, value: string) {
    if (typeof window !== 'undefined') window.localStorage.setItem(key, value);
  }

  removeItem(key: string) {
    if (typeof window !== 'undefined') window.localStorage.removeItem(key);
  }
}

/**
 * Browser Cookie adapter for SSR frameworks (Next.js, Nuxt, etc.)
 *
 * Uses document.cookie for client-side access. Works with server-side
 * middleware that can read the same cookies.
 *
 * For Next.js App Router, pair this with cookies() from 'next/headers'
 * in server components to pass the initial token.
 */
export class CookieStorage implements TokenStorage {
  constructor(
    private options: {
      domain?: string;
      path?: string;
      secure?: boolean;
      sameSite?: 'strict' | 'lax' | 'none';
      maxAge?: number; // In seconds
    } = {}
  ) {}

  private getCookie(name: string): string | null {
    if (typeof window === 'undefined') return null;

    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
      return parts.pop()?.split(';').shift() || null;
    }
    return null;
  }

  private setCookie(name: string, value: string): void {
    if (typeof window === 'undefined') return;

    let cookie = `${name}=${value}`;

    if (this.options.path) {
      cookie += `; Path=${this.options.path}`;
    }

    if (this.options.domain) {
      cookie += `; Domain=${this.options.domain}`;
    }

    if (this.options.secure !== false) {
      // Default to secure for auth tokens
      cookie += '; Secure';
    }

    if (this.options.sameSite ?? 'lax') {
      cookie += `; SameSite=${this.options.sameSite ?? 'lax'}`;
    }

    if (this.options.maxAge) {
      cookie += `; Max-Age=${this.options.maxAge}`;
    }

    document.cookie = cookie;
  }

  private deleteCookie(name: string): void {
    if (typeof window === 'undefined') return;

    let cookie = `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;

    if (this.options.path) {
      cookie += `; Path=${this.options.path}`;
    }

    if (this.options.domain) {
      cookie += `; Domain=${this.options.domain}`;
    }

    document.cookie = cookie;
  }

  getItem(key: string): string | null {
    return this.getCookie(key);
  }

  setItem(key: string, value: string): void {
    this.setCookie(key, value);
  }

  removeItem(key: string): void {
    this.deleteCookie(key);
  }
}

/**
 * Storage Factory
 */
export function resolveStorage(userStorage?: TokenStorage): TokenStorage {
  if (userStorage) return userStorage;
  if (typeof window !== 'undefined' && window.localStorage) return new BrowserStorage();
  return new MemoryStorage();
}
