import * as crypto from 'crypto';
import type { JWK, JWKS, AuthOSNodeOptions, VerifyTokenOptions, VerifiedToken } from './types';
import type { JwtClaims } from '@drmhse/sso-sdk';

interface CachedJWKS {
  jwks: JWKS;
  fetchedAt: number;
}

const jwksCache = new Map<string, CachedJWKS>();
const DEFAULT_CACHE_TTL = 60 * 60 * 1000; // 1 hour

/**
 * Base64URL decode
 */
function base64UrlDecode(input: string): Buffer {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  return Buffer.from(padded, 'base64');
}

/**
 * Convert JWK to PEM public key format
 */
function jwkToPem(jwk: JWK): string {
  if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    throw new Error('Only RSA keys are supported');
  }

  const n = base64UrlDecode(jwk.n);
  const e = base64UrlDecode(jwk.e);

  // ASN.1 INTEGER encoding for n
  const nInt = encodeASN1Integer(n);
  // ASN.1 INTEGER encoding for e
  const eInt = encodeASN1Integer(e);

  // SEQUENCE containing n and e
  const rsaPublicKey = encodeASN1Sequence(Buffer.concat([nInt, eInt]));

  // BIT STRING wrapper
  const bitString = Buffer.concat([
    Buffer.from([0x03]),
    encodeASN1Length(rsaPublicKey.length + 1),
    Buffer.from([0x00]), // no unused bits
    rsaPublicKey,
  ]);

  // RSA algorithm identifier: OID 1.2.840.113549.1.1.1 (rsaEncryption) with NULL parameters
  const algorithmIdentifier = Buffer.from([
    0x30, 0x0d, // SEQUENCE
    0x06, 0x09, // OID
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1
    0x05, 0x00, // NULL
  ]);

  // Final SEQUENCE containing algorithm identifier and bit string
  const subjectPublicKeyInfo = encodeASN1Sequence(
    Buffer.concat([algorithmIdentifier, bitString])
  );

  // Convert to PEM
  const base64Key = subjectPublicKeyInfo.toString('base64');
  const lines = base64Key.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Encode ASN.1 length
 */
function encodeASN1Length(length: number): Buffer {
  if (length < 128) {
    return Buffer.from([length]);
  }
  const bytes: number[] = [];
  let len = length;
  while (len > 0) {
    bytes.unshift(len & 0xff);
    len = len >> 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/**
 * Encode ASN.1 INTEGER
 */
function encodeASN1Integer(value: Buffer): Buffer {
  // Add leading zero if high bit is set (to indicate positive number)
  const needsPadding = value[0] & 0x80;
  const content = needsPadding ? Buffer.concat([Buffer.from([0x00]), value]) : value;
  return Buffer.concat([
    Buffer.from([0x02]), // INTEGER tag
    encodeASN1Length(content.length),
    content,
  ]);
}

/**
 * Encode ASN.1 SEQUENCE
 */
function encodeASN1Sequence(content: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0x30]), // SEQUENCE tag
    encodeASN1Length(content.length),
    content,
  ]);
}

/**
 * Fetch JWKS from the AuthOS server
 */
async function fetchJWKS(baseURL: string): Promise<JWKS> {
  const url = `${baseURL.replace(/\/$/, '')}/.well-known/jwks.json`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<JWKS>;
}

/**
 * Get cached or fresh JWKS
 */
async function getJWKS(baseURL: string, cacheTTL: number): Promise<JWKS> {
  const cached = jwksCache.get(baseURL);
  const now = Date.now();

  if (cached && now - cached.fetchedAt < cacheTTL) {
    return cached.jwks;
  }

  const jwks = await fetchJWKS(baseURL);
  jwksCache.set(baseURL, { jwks, fetchedAt: now });
  return jwks;
}

/**
 * Find the appropriate key from JWKS
 */
function findKey(jwks: JWKS, kid: string): JWK | null {
  return jwks.keys.find((key) => key.kid === kid) || null;
}

/**
 * Error class for token verification failures
 */
export class TokenVerificationError extends Error {
  constructor(
    message: string,
    public readonly code: string
  ) {
    super(message);
    this.name = 'TokenVerificationError';
  }
}

/**
 * Parse JWT without verification
 */
function parseJWT(token: string): { header: { alg: string; kid?: string }; payload: JwtClaims } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new TokenVerificationError('Invalid JWT format', 'INVALID_TOKEN_FORMAT');
  }

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
    return { header, payload };
  } catch {
    throw new TokenVerificationError('Invalid JWT encoding', 'INVALID_TOKEN_FORMAT');
  }
}

/**
 * Create a token verifier instance
 */
export function createTokenVerifier(options: AuthOSNodeOptions) {
  const {
    baseURL,
    jwksCacheTTL = DEFAULT_CACHE_TTL,
    audience: defaultAudience,
    issuer: defaultIssuer = baseURL.replace(/\/+$/, ''),
  } = options;

  /**
   * Verify a JWT token using the JWKS from the AuthOS server
   */
  async function verifyToken(
    token: string,
    verifyOptions: VerifyTokenOptions = {}
  ): Promise<VerifiedToken> {
    const {
      audience = defaultAudience,
      issuer = defaultIssuer,
      clockTolerance = 0,
    } = verifyOptions;

    // Parse the token to get header and payload
    const { header, payload } = parseJWT(token);

    // Verify algorithm
    if (header.alg !== 'RS256') {
      throw new TokenVerificationError(
        `Unsupported algorithm: ${header.alg}. Only RS256 is supported.`,
        'INVALID_ALGORITHM'
      );
    }

    // Get the key ID from header
    const kid = header.kid;
    if (!kid) {
      throw new TokenVerificationError('Token missing kid header', 'MISSING_KID');
    }

    // Fetch JWKS and find the key
    const jwks = await getJWKS(baseURL, jwksCacheTTL);
    const jwk = findKey(jwks, kid);

    if (!jwk) {
      // Try refreshing the cache in case keys were rotated
      const freshJwks = await fetchJWKS(baseURL);
      jwksCache.set(baseURL, { jwks: freshJwks, fetchedAt: Date.now() });
      const freshJwk = findKey(freshJwks, kid);

      if (!freshJwk) {
        throw new TokenVerificationError(
          `No matching key found for kid: ${kid}`,
          'KEY_NOT_FOUND'
        );
      }

      return verifyWithKey(token, freshJwk, payload, { audience, issuer, clockTolerance });
    }

    return verifyWithKey(token, jwk, payload, { audience, issuer, clockTolerance });
  }

  return { verifyToken };
}

/**
 * Verify token with a specific JWK
 */
function verifyWithKey(
  token: string,
  jwk: JWK,
  payload: JwtClaims,
  options: { audience?: string; issuer?: string; clockTolerance: number }
): VerifiedToken {
  const { audience, issuer, clockTolerance } = options;

  // Convert JWK to PEM
  const pem = jwkToPem(jwk);

  // Verify signature
  const parts = token.split('.');
  const signatureInput = `${parts[0]}.${parts[1]}`;
  const signature = base64UrlDecode(parts[2]);

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(signatureInput);

  if (!verifier.verify(pem, signature)) {
    throw new TokenVerificationError('Invalid token signature', 'INVALID_SIGNATURE');
  }

  // Verify expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp + clockTolerance < now) {
    throw new TokenVerificationError('Token has expired', 'TOKEN_EXPIRED');
  }

  // Verify not before (iat)
  if (payload.iat && payload.iat - clockTolerance > now) {
    throw new TokenVerificationError('Token is not yet valid', 'TOKEN_NOT_YET_VALID');
  }

  // Verify audience if specified
  if (audience) {
    const tokenAud = (payload as unknown as { aud?: string | string[] }).aud;
    const validAud = Array.isArray(tokenAud) ? tokenAud.includes(audience) : tokenAud === audience;
    if (!validAud) {
      throw new TokenVerificationError('Invalid token audience', 'INVALID_AUDIENCE');
    }
  }

  // Verify issuer if specified
  if (issuer) {
    const tokenIss = (payload as unknown as { iss?: string }).iss;
    if (tokenIss !== issuer) {
      throw new TokenVerificationError('Invalid token issuer', 'INVALID_ISSUER');
    }
  }

  return { claims: payload, token };
}

/**
 * Clear the JWKS cache (useful for testing)
 */
export function clearJWKSCache(): void {
  jwksCache.clear();
}
