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
  description?: string;
  permissions?: string[];
}
