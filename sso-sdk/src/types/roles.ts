export interface RoleResponse {
  id: string;
  org_id: string;
  slug: string;
  name: string;
  description?: string;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateRoleRequest {
  slug: string;
  name: string;
  description?: string;
  permissions: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  /**
   * Omit to leave the description unchanged, `null` to clear it, or a string to
   * set it. `undefined` and `null` mean different things here.
   */
  description?: string | null;
  permissions?: string[];
}
