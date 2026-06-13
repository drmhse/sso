# Organization Roles

AuthOS keeps organization roles tenant-local. Built-in roles are `owner`, `admin`, and `member`; custom roles belong to one organization and are addressed by their `slug`.

## Lifecycle

Create custom roles with `POST /api/organizations/{org_slug}/roles`.

Update custom roles with `PUT /api/organizations/{org_slug}/roles/{role_id}`.

Delete custom roles with `DELETE /api/organizations/{org_slug}/roles/{role_id}`.

Only users with `org.roles.manage` can manage roles. Organization `owner` and `admin` memberships have this capability by default.

## Permissions

Custom role `permissions` are stored as a JSON array of capability strings, for example:

```json
["services.manage", "webhooks.manage"]
```

When a member has a custom role slug, `PermissionService` resolves that slug inside the member's organization and checks the stored capability list. Custom role permissions do not leak across organizations.

## Built-In Slugs

Custom roles cannot use built-in organization role slugs:

- `owner`
- `admin`
- `member`

Role slugs must also be unique inside an organization.

## Invitations And Memberships

Invitations can target built-in roles or an existing custom role slug in the same organization. When an invitation is accepted, AuthOS creates the membership with that role and grants the matching organization relation tuple.

SCIM group membership currently maps users to the built-in `member` role. Manage owner/admin and custom-role elevation through AuthOS role APIs or invitation workflows.
