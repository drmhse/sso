import type { NextRequest } from 'next/server.js';
import { NextResponse } from 'next/server.js';

export interface AuthMiddlewareConfig {
  /**
   * The JWKS URL for token verification
   */
  jwksUrl: string;
  /**
   * Protected routes that require authentication
   */
  protectedRoutes?: string[];
  /**
   * Public routes that don't require authentication
   */
  publicRoutes?: string[];
  /**
   * The URL to redirect to when not authenticated
   */
  signInUrl?: string;
  /**
   * Cookie name for the access token
   */
  tokenCookie?: string;
}

interface JWK {
  kty: string;
  use?: string;
  kid?: string;
  alg?: string;
  n?: string;
  e?: string;
}

interface JWKS {
  keys: JWK[];
}

// Cache for JWKS
let jwksCache: { keys: JWKS; expiry: number } | null = null;
const CACHE_DURATION = 3600000; // 1 hour

async function fetchJWKS(jwksUrl: string): Promise<JWKS> {
  const now = Date.now();

  if (jwksCache && jwksCache.expiry > now) {
    return jwksCache.keys;
  }

  const response = await fetch(jwksUrl, {
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS: ${response.status}`);
  }

  const jwks = (await response.json()) as JWKS;
  jwksCache = { keys: jwks, expiry: now + CACHE_DURATION };
  return jwks;
}

function base64UrlDecode(str: string): string {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  return atob(base64 + padding);
}

interface JWTHeader {
  alg: string;
  typ: string;
  kid?: string;
}

interface JWTPayload {
  sub: string;
  email: string;
  exp: number;
  iat: number;
  org?: string;
  permissions?: string[];
  [key: string]: unknown;
}

function parseJWT(token: string): { header: JWTHeader; payload: JWTPayload } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const header = JSON.parse(base64UrlDecode(parts[0])) as JWTHeader;
  const payload = JSON.parse(base64UrlDecode(parts[1])) as JWTPayload;

  return { header, payload };
}

async function importRSAPublicKey(jwk: JWK): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      alg: jwk.alg || 'RS256',
      use: 'sig',
    },
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['verify']
  );
}

async function verifyJWT(
  token: string,
  jwksUrl: string
): Promise<JWTPayload | null> {
  try {
    const { header, payload } = parseJWT(token);

    // Check expiration
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      return null;
    }

    // Fetch JWKS and find matching key
    const jwks = await fetchJWKS(jwksUrl);
    const key = header.kid
      ? jwks.keys.find((k) => k.kid === header.kid)
      : jwks.keys[0];

    if (!key) {
      return null;
    }

    // Import the public key
    const publicKey = await importRSAPublicKey(key);

    // Verify signature
    const parts = token.split('.');
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const signature = Uint8Array.from(
      base64UrlDecode(parts[2]),
      (c) => c.charCodeAt(0)
    );

    const isValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      publicKey,
      signature,
      data
    );

    return isValid ? payload : null;
  } catch {
    return null;
  }
}

function matchRoute(pathname: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    // Handle glob patterns
    if (pattern.includes('*')) {
      const regex = new RegExp(
        '^' + pattern.replace(/\*/g, '.*').replace(/\//g, '\\/') + '$'
      );
      return regex.test(pathname);
    }
    return pathname === pattern || pathname.startsWith(pattern + '/');
  });
}

/**
 * Creates an authentication middleware for Next.js Edge Runtime.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { authMiddleware } from '@drmhse/authos-react/nextjs';
 *
 * export default authMiddleware({
 *   jwksUrl: 'https://auth.example.com/.well-known/jwks.json',
 *   protectedRoutes: ['/dashboard/*', '/settings/*'],
 *   publicRoutes: ['/', '/about', '/pricing'],
 *   signInUrl: '/signin',
 * });
 *
 * export const config = {
 *   matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
 * };
 * ```
 */
export function authMiddleware(config: AuthMiddlewareConfig) {
  const {
    jwksUrl,
    protectedRoutes = [],
    publicRoutes = [],
    signInUrl = '/signin',
    tokenCookie = 'authos_token',
  } = config;

  return async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Always allow access to sign-in page
    if (pathname === signInUrl) {
      return NextResponse.next();
    }

    // Check if route is explicitly public
    if (publicRoutes.length > 0 && matchRoute(pathname, publicRoutes)) {
      return NextResponse.next();
    }

    // Check if route is protected
    const isProtected =
      protectedRoutes.length === 0 || matchRoute(pathname, protectedRoutes);

    if (!isProtected) {
      return NextResponse.next();
    }

    // Get token from cookie or authorization header
    const token =
      request.cookies.get(tokenCookie)?.value ??
      request.headers.get('authorization')?.replace('Bearer ', '');

    if (!token) {
      return NextResponse.redirect(new URL(signInUrl, request.url));
    }

    // Verify JWT
    const payload = await verifyJWT(token, jwksUrl);

    if (!payload) {
      // Token is invalid or expired
      const response = NextResponse.redirect(new URL(signInUrl, request.url));
      response.cookies.delete(tokenCookie);
      return response;
    }

    // Add user info to headers for server components
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-authos-user-id', payload.sub);
    requestHeaders.set('x-authos-user-email', payload.email);
    if (payload.org) {
      requestHeaders.set('x-authos-org', payload.org);
    }
    if (payload.permissions) {
      requestHeaders.set(
        'x-authos-permissions',
        JSON.stringify(payload.permissions)
      );
    }

    return NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
  };
}
