import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AuthOSNodeOptions, RequireAuthOptions, RequirePermissionOptions, VerifiedToken } from '../types';
import { createTokenVerifier, TokenVerificationError } from '../jwks';

// Extend Express Request type to include auth
declare global {
  namespace Express {
    interface Request {
      auth?: VerifiedToken;
    }
  }
}

/**
 * Extract Bearer token from Authorization header
 */
function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice(7);
}

/**
 * Create Express middleware for AuthOS authentication
 */
export function createAuthMiddleware(options: AuthOSNodeOptions) {
  const verifier = createTokenVerifier(options);

  /**
   * Middleware that requires a valid JWT token
   *
   * @example
   * ```typescript
   * import { createAuthMiddleware } from '@drmhse/authos-node/express';
   *
   * const { requireAuth } = createAuthMiddleware({
   *   baseURL: process.env.AUTHOS_URL!,
   * });
   *
   * app.get('/protected', requireAuth(), (req, res) => {
   *   res.json({ user: req.auth?.claims });
   * });
   * ```
   */
  function requireAuth(authOptions: RequireAuthOptions = {}): RequestHandler {
    const { getToken, ...verifyOptions } = authOptions;

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const token = getToken ? getToken(req) : extractBearerToken(req);

        if (!token) {
          res.status(401).json({
            error: 'Unauthorized',
            message: 'Missing authentication token',
            code: 'MISSING_TOKEN',
          });
          return;
        }

        const verified = await verifier.verifyToken(token, verifyOptions);
        req.auth = verified;
        next();
      } catch (err) {
        if (err instanceof TokenVerificationError) {
          res.status(401).json({
            error: 'Unauthorized',
            message: err.message,
            code: err.code,
          });
          return;
        }

        // Unexpected error
        console.error('Auth middleware error:', err);
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Authentication verification failed',
        });
      }
    };
  }

  /**
   * Middleware that requires a specific permission
   * Must be used after requireAuth()
   *
   * @example
   * ```typescript
   * app.delete(
   *   '/users/:id',
   *   requireAuth(),
   *   requirePermission('users:delete'),
   *   (req, res) => {
   *     // User has the required permission
   *   }
   * );
   * ```
   */
  function requirePermission(
    permission: string,
    permOptions: RequirePermissionOptions = {}
  ): RequestHandler {
    const { message = 'Insufficient permissions' } = permOptions;

    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.auth) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const permissions = req.auth.claims.permissions || [];
      const hasPermission = permissions.includes(permission);

      if (!hasPermission) {
        res.status(403).json({
          error: 'Forbidden',
          message,
          code: 'PERMISSION_DENIED',
          required: permission,
        });
        return;
      }

      next();
    };
  }

  /**
   * Middleware that requires any of the specified permissions
   *
   * @example
   * ```typescript
   * app.get(
   *   '/reports',
   *   requireAuth(),
   *   requireAnyPermission(['reports:read', 'reports:admin']),
   *   (req, res) => { ... }
   * );
   * ```
   */
  function requireAnyPermission(
    permissions: string[],
    permOptions: RequirePermissionOptions = {}
  ): RequestHandler {
    const { message = 'Insufficient permissions' } = permOptions;

    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.auth) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const userPermissions = req.auth.claims.permissions || [];
      const hasAny = permissions.some((p) => userPermissions.includes(p));

      if (!hasAny) {
        res.status(403).json({
          error: 'Forbidden',
          message,
          code: 'PERMISSION_DENIED',
          required: permissions,
        });
        return;
      }

      next();
    };
  }

  /**
   * Middleware that requires all of the specified permissions
   *
   * @example
   * ```typescript
   * app.post(
   *   '/admin/users',
   *   requireAuth(),
   *   requireAllPermissions(['users:create', 'admin:access']),
   *   (req, res) => { ... }
   * );
   * ```
   */
  function requireAllPermissions(
    permissions: string[],
    permOptions: RequirePermissionOptions = {}
  ): RequestHandler {
    const { message = 'Insufficient permissions' } = permOptions;

    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.auth) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const userPermissions = req.auth.claims.permissions || [];
      const hasAll = permissions.every((p) => userPermissions.includes(p));

      if (!hasAll) {
        const missing = permissions.filter((p) => !userPermissions.includes(p));
        res.status(403).json({
          error: 'Forbidden',
          message,
          code: 'PERMISSION_DENIED',
          required: permissions,
          missing,
        });
        return;
      }

      next();
    };
  }

  /**
   * Middleware that requires the user to be a platform owner
   *
   * @example
   * ```typescript
   * app.get(
   *   '/platform/settings',
   *   requireAuth(),
   *   requirePlatformOwner(),
   *   (req, res) => { ... }
   * );
   * ```
   */
  function requirePlatformOwner(
    permOptions: RequirePermissionOptions = {}
  ): RequestHandler {
    const { message = 'Platform owner access required' } = permOptions;

    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.auth) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      if (!req.auth.claims.is_platform_owner) {
        res.status(403).json({
          error: 'Forbidden',
          message,
          code: 'NOT_PLATFORM_OWNER',
        });
        return;
      }

      next();
    };
  }

  /**
   * Middleware that requires the user to belong to a specific organization
   *
   * @example
   * ```typescript
   * app.get(
   *   '/org/:slug/data',
   *   requireAuth(),
   *   requireOrganization((req) => req.params.slug),
   *   (req, res) => { ... }
   * );
   * ```
   */
  function requireOrganization(
    getOrgSlug: string | ((req: Request) => string),
    permOptions: RequirePermissionOptions = {}
  ): RequestHandler {
    const { message = 'Organization access required' } = permOptions;

    return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.auth) {
        res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const requiredOrg = typeof getOrgSlug === 'function' ? getOrgSlug(req) : getOrgSlug;
      const userOrg = req.auth.claims.org;

      if (!userOrg || userOrg !== requiredOrg) {
        res.status(403).json({
          error: 'Forbidden',
          message,
          code: 'WRONG_ORGANIZATION',
          required: requiredOrg,
        });
        return;
      }

      next();
    };
  }

  return {
    requireAuth,
    requirePermission,
    requireAnyPermission,
    requireAllPermissions,
    requirePlatformOwner,
    requireOrganization,
  };
}
