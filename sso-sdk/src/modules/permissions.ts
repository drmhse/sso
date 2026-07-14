import { HttpClient } from '../http';
import { JwtClaims } from '../types';

/**
 * Permission checking and management methods
 *
 * This module provides utilities for working with ReBAC (Relationship-Based Access Control)
 * permissions. Permissions use Zanzibar-style relation tuples and are now fetched from the
 * API instead of being embedded in JWT tokens (for improved security and smaller token size).
 */
export class PermissionsModule {
  constructor(private http: HttpClient) {}

  /**
   * Check if user has a specific permission.
   * Fetches from user profile API (which uses cached permissions).
   *
   * @param permission Permission in format "namespace:object_id#relation"
   * @returns true if the permission is present
   *
   * @example
   * ```typescript
   * const hasAccess = await sso.permissions.hasPermission('organization:acme#owner');
   * ```
   */
  public async hasPermission(permission: string): Promise<boolean> {
    const response = await this.http.get<{ permissions: string[] }>('/api/user');
    return response.data.permissions.includes(permission);
  }

  /**
   * Get all user permissions.
   * Fetches from user profile API (which uses cached permissions).
   *
   * @returns Array of permission strings
   *
   * @example
   * ```typescript
   * const permissions = await sso.permissions.listPermissions();
   * // ["organization:acme#owner", "service:api#admin"]
   * ```
   */
  public async listPermissions(): Promise<string[]> {
    const response = await this.http.get<{ permissions: string[] }>('/api/user');
    return response.data.permissions;
  }

  /**
   * Check if user has access to a feature.
   *
   * @param feature Feature name to check
   * @returns true if the feature is available
   *
   * @example
   * ```typescript
   * const canExport = await sso.permissions.hasFeature('advanced-export');
   * ```
   */
  public async hasFeature(feature: string): Promise<boolean> {
    const response = await this.http.get<{ features: string[] | null }>('/api/user');
    return response.data.features?.includes(feature) ?? false;
  }

  /**
   * Get current plan name.
   *
   * @returns Current plan name or null if not in org/service context
   *
   * @example
   * ```typescript
   * const plan = await sso.permissions.getPlan();
   * console.log(plan); // "pro", "enterprise", etc.
   * ```
   */
  public async getPlan(): Promise<string | null> {
    const response = await this.http.get<{ plan: string | null }>('/api/user');
    return response.data.plan;
  }

  /**
   * Check if user has a specific permission on a resource.
   *
   * @param namespace The permission namespace (e.g., "organization", "service")
   * @param objectId The object ID (e.g., organization slug, service slug)
   * @param relation The relation type (e.g., "owner", "admin", "member")
   * @returns true if the user has the permission
   *
   * @example
   * ```typescript
   * const isOwner = await sso.permissions.can('organization', 'acme-corp', 'owner');
   * ```
   */
  public async can(namespace: string, objectId: string, relation: string): Promise<boolean> {
    return this.hasPermission(`${namespace}:${objectId}#${relation}`);
  }

  /**
   * Check if user is a member of an organization.
   *
   * @param orgId The organization ID or slug
   * @returns true if the user is a member
   *
   * @example
   * ```typescript
   * if (await sso.permissions.isOrgMember('acme-corp')) {
   *   // User is a member
   * }
   * ```
   */
  public async isOrgMember(orgId: string): Promise<boolean> {
    return this.hasPermission(`organization:${orgId}#member`);
  }

  /**
   * Check if user is an admin of an organization.
   *
   * @param orgId The organization ID or slug
   * @returns true if the user is an admin
   *
   * @example
   * ```typescript
   * if (await sso.permissions.isOrgAdmin('acme-corp')) {
   *   // User is an admin
   * }
   * ```
   */
  public async isOrgAdmin(orgId: string): Promise<boolean> {
    return this.hasPermission(`organization:${orgId}#admin`);
  }

  /**
   * Check if user is an owner of an organization.
   *
   * @param orgId The organization ID or slug
   * @returns true if the user is an owner
   *
   * @example
   * ```typescript
   * if (await sso.permissions.isOrgOwner('acme-corp')) {
   *   // User is an owner
   * }
   * ```
   */
  public async isOrgOwner(orgId: string): Promise<boolean> {
    return this.hasPermission(`organization:${orgId}#owner`);
  }

  /**
   * Check if user has access to a service.
   *
   * @param serviceId The service ID or slug
   * @returns true if the user has access
   *
   * @example
   * ```typescript
   * if (await sso.permissions.hasServiceAccess('api-service')) {
   *   // User has access to the service
   * }
   * ```
   */
  public async hasServiceAccess(serviceId: string): Promise<boolean> {
    return this.hasPermission(`service:${serviceId}#member`);
  }

  /**
   * Filter permissions by namespace.
   *
   * @param namespace The namespace to filter by (e.g., "organization", "service")
   * @returns Array of permissions matching the namespace
   *
   * @example
   * ```typescript
   * const orgPermissions = await sso.permissions.getPermissionsByNamespace('organization');
   * ```
   */
  public async getPermissionsByNamespace(namespace: string): Promise<string[]> {
    const allPermissions = await this.listPermissions();
    return allPermissions.filter((p) => p.startsWith(`${namespace}:`));
  }

  // ============================================================================
  // DEPRECATED METHODS - Token-based permission checking (legacy)
  // ============================================================================

  /**
   * @deprecated Use `hasPermission()` instead (without token parameter)
   * Decode a JWT token to extract claims (including permissions)
   * Note: This does NOT verify the signature - it only decodes the payload
   *
   * @param token The JWT access token
   * @returns The decoded JWT claims
   * @throws Error if the token is malformed
   */
  public decodeToken(token: string): JwtClaims {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      const payload = parts[1];
      const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded) as JwtClaims;
    } catch (error) {
      const wrappedError = new Error(
        `Failed to decode JWT: ${error instanceof Error ? error.message : 'Unknown error'}`,
      ) as Error & { cause?: unknown };
      wrappedError.cause = error;
      throw wrappedError;
    }
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `hasPermission(permission)` instead.
   * Check if a JWT token contains a specific permission
   *
   * @param token The JWT access token (ignored)
   * @param permission Permission in format "namespace:object_id#relation"
   * @returns true if the permission is present in the token
   */
  public hasPermissionFromToken(token: string, permission: string): boolean {
    const claims = this.decodeToken(token);
    return claims.permissions?.includes(permission) ?? false;
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `can(namespace, objectId, relation)` instead.
   * Check if a user has a specific permission on a resource
   *
   * @param token The JWT access token (ignored)
   * @param namespace The permission namespace (e.g., "organization", "service")
   * @param objectId The object ID (e.g., organization slug, service slug)
   * @param relation The relation type (e.g., "owner", "admin", "member")
   * @returns true if the user has the permission
   */
  public canFromToken(token: string, namespace: string, objectId: string, relation: string): boolean {
    return this.hasPermissionFromToken(token, `${namespace}:${objectId}#${relation}`);
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `isOrgMember(orgId)` instead.
   * Check if user is a member of an organization
   *
   * @param token The JWT access token (ignored)
   * @param orgId The organization ID or slug
   * @returns true if the user is a member
   */
  public isOrgMemberFromToken(token: string, orgId: string): boolean {
    return this.hasPermissionFromToken(token, `organization:${orgId}#member`);
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `isOrgAdmin(orgId)` instead.
   * Check if user is an admin of an organization
   *
   * @param token The JWT access token (ignored)
   * @param orgId The organization ID or slug
   * @returns true if the user is an admin
   */
  public isOrgAdminFromToken(token: string, orgId: string): boolean {
    return this.hasPermissionFromToken(token, `organization:${orgId}#admin`);
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `isOrgOwner(orgId)` instead.
   * Check if user is an owner of an organization
   *
   * @param token The JWT access token (ignored)
   * @param orgId The organization ID or slug
   * @returns true if the user is an owner
   */
  public isOrgOwnerFromToken(token: string, orgId: string): boolean {
    return this.hasPermissionFromToken(token, `organization:${orgId}#owner`);
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `hasServiceAccess(serviceId)` instead.
   * Check if user has access to a service
   *
   * @param token The JWT access token (ignored)
   * @param serviceId The service ID or slug
   * @returns true if the user has access
   */
  public hasServiceAccessFromToken(token: string, serviceId: string): boolean {
    return this.hasPermissionFromToken(token, `service:${serviceId}#member`);
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `listPermissions()` instead.
   * Get all permissions from a JWT token
   *
   * @param token The JWT access token
   * @returns Array of permission strings, or empty array if none
   */
  public getAllPermissionsFromToken(token: string): string[] {
    const claims = this.decodeToken(token);
    return claims.permissions ?? [];
  }

  /**
   * Parse a permission string into its components
   *
   * @param permission Permission string in format "namespace:object_id#relation"
   * @returns Parsed permission components or null if invalid format
   *
   * @example
   * ```typescript
   * const parsed = sso.permissions.parsePermission('organization:acme#owner');
   * // { namespace: 'organization', objectId: 'acme', relation: 'owner' }
   * ```
   */
  public parsePermission(permission: string): {
    namespace: string;
    objectId: string;
    relation: string;
  } | null {
    const match = permission.match(/^([^:]+):([^#]+)#(.+)$/);
    if (!match) {
      return null;
    }

    return {
      namespace: match[1],
      objectId: match[2],
      relation: match[3],
    };
  }

  /**
   * @deprecated JWT tokens no longer contain permissions. Use `getPermissionsByNamespace(namespace)` instead.
   * Filter permissions by namespace
   *
   * @param token The JWT access token (ignored)
   * @param namespace The namespace to filter by (e.g., "organization", "service")
   * @returns Array of permissions matching the namespace
   */
  public getPermissionsByNamespaceFromToken(token: string, namespace: string): string[] {
    const allPermissions = this.getAllPermissionsFromToken(token);
    return allPermissions.filter((p) => p.startsWith(`${namespace}:`));
  }
}
