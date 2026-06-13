# SCIM Provisioning Setup

AuthOS exposes SCIM 2.0 endpoints for organization-scoped user provisioning and group membership sync.

SCIM tokens are scoped to one AuthOS organization. A token can list, create, update, deactivate, and deprovision users in that organization, and can sync the organization group membership. SCIM group deletion is intentionally rejected because an AuthOS organization should be deleted through the Organizations API, not through an identity provider sync job.

## Endpoints

Use your AuthOS public base URL as the SCIM base URL:

```text
https://auth.example.com/scim/v2
```

Supported resources:

```text
GET    /scim/v2/Users
POST   /scim/v2/Users
GET    /scim/v2/Users/{id}
PUT    /scim/v2/Users/{id}
PATCH  /scim/v2/Users/{id}
DELETE /scim/v2/Users/{id}

GET    /scim/v2/Groups
POST   /scim/v2/Groups
GET    /scim/v2/Groups/{id}
PUT    /scim/v2/Groups/{id}
PATCH  /scim/v2/Groups/{id}
DELETE /scim/v2/Groups/{id}
```

Authentication uses a Bearer token:

```http
Authorization: Bearer scim_xxxxx
Content-Type: application/scim+json
```

Create, list, revoke, and delete SCIM tokens through the organization SCIM-token API:

```text
POST   /api/organizations/{org_slug}/scim-tokens
GET    /api/organizations/{org_slug}/scim-tokens
POST   /api/organizations/{org_slug}/scim-tokens/{token_id}/revoke
DELETE /api/organizations/{org_slug}/scim-tokens/{token_id}
```

The token value is returned only at creation time. Store it in the identity provider immediately.

## Attribute Mapping

AuthOS treats `userName` as the canonical email address. If an `emails` array is present, the first email value is used for create and replace operations.

Recommended mappings:

| SCIM attribute | AuthOS field |
| --- | --- |
| `userName` | User email |
| `emails[type eq "work"].value` | User email |
| `active` | User enabled state |
| `id` | AuthOS user ID |
| `displayName` | Derived from email |

Name fields such as `givenName` and `familyName` may be accepted by providers but are not currently persisted by AuthOS.

## Group And Role Mapping

AuthOS maps the SCIM Group resource to one organization membership set:

| SCIM concept | AuthOS concept |
| --- | --- |
| Group resource | Organization |
| Group `id` | Organization ID |
| Group `displayName` | Organization name |
| Group member | Organization member |
| Added group member | Organization role `member` |

SCIM does not currently create custom AuthOS organization roles. Users added through SCIM group membership receive the built-in `member` role and the corresponding organization permission tuple.

SCIM cannot remove organization owners or admins. Attempts to deactivate, delete, or remove an owner/admin membership return `403 Forbidden`.

## Okta

Create or open the Okta app integration for the customer organization, then enable provisioning.

Use:

```text
SCIM connector base URL: https://auth.example.com/scim/v2
Unique identifier field: userName
Supported provisioning actions: Push New Users, Push Profile Updates, Push Groups
Authentication mode: HTTP Header
Authorization header: Bearer scim_xxxxx
```

Set the primary user-name mapping to email. For group push, push the Okta group that represents the AuthOS organization membership. Keep owner/admin accounts out of automated group-removal rules unless you intentionally manage those roles outside SCIM, because AuthOS will reject owner/admin removal.

## Microsoft Entra ID

Create an Enterprise Application, then open Provisioning and choose automatic provisioning.

Use:

```text
Tenant URL: https://auth.example.com/scim/v2
Secret token: scim_xxxxx
```

Recommended user mappings:

```text
userPrincipalName -> userName
mail or userPrincipalName -> emails[type eq "work"].value
Switch([IsSoftDeleted], , "False", "True", "True", "False") -> active
```

Assign the users or groups that should be organization members. Entra group membership changes map to AuthOS organization membership; added users become `member`.

## JumpCloud

Create or open the AuthOS application in JumpCloud and enable SCIM user provisioning.

Use:

```text
Base URL: https://auth.example.com/scim/v2
Token key: Authorization
Token value: Bearer scim_xxxxx
```

Map JumpCloud username or email to SCIM `userName`, and map work email to `emails.value`. Enable group push only for the group representing the AuthOS organization.

## Generic SCIM Clients

A generic client should:

1. Create users with `POST /scim/v2/Users`.
2. Update emails with `PUT /scim/v2/Users/{id}` or PatchOp `PATCH`.
3. Deactivate users with PatchOp `active=false` when the user should remain auditable.
4. Delete users with `DELETE /scim/v2/Users/{id}` when the membership should be removed.
5. Sync group membership with `PATCH /scim/v2/Groups/{org_id}` or `PUT /scim/v2/Groups/{org_id}`.

Patch requests must include the SCIM PatchOp schema:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "active",
      "value": false
    }
  ]
}
```

PUT requests may include the resource `id`. If a body `id` is present and it does not match the path ID, AuthOS rejects the request with a SCIM `invalidValue` error.
