/**
 * Decodes a JWT token without verification (client-side use only).
 * @param {string} token - The JWT token to decode
 * @returns {object|null} The decoded payload or null if invalid
 */
export function decodeJwt(token) {
  if (!token) return null;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  } catch (error) {
    console.error('Failed to decode JWT:', error);
    return null;
  }
}

/**
 * Checks if a JWT token is expired.
 * @param {string} token - The JWT token to check
 * @returns {boolean} True if expired, false otherwise
 */
export function isTokenExpired(token) {
  const decoded = decodeJwt(token);
  if (!decoded || !decoded.exp) return true;

  return decoded.exp * 1000 < Date.now();
}
