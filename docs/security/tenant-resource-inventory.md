# AuthOS tenant-resource inventory

Status: source-derived isolation-test scope

Reviewed: 2026-07-14

This inventory identifies data that must be tenant-isolated and the context by
which that isolation is derived. It is not a claim that every handler is already
covered. Its purpose is to make omissions visible and to drive a generated
authorization test matrix.

See the [threat model](./threat-model.md) and
[security architecture](./security-architecture.md) for the surrounding trust
boundaries.

## Scoping model

AuthOS uses four principal scope roots:

- **Organization-scoped:** the record contains `org_id` or is the organization.
- **Service-derived:** the record contains `service_id`; the service contains
  `org_id`.
- **User-derived:** the record contains `user_id`; tenant access must be proven
  through the user's scoped account or membership and, where relevant, a
  service/organization context. A user may participate in multiple
  organizations, so `user_id` alone is not always a tenant predicate.
- **Platform/global:** the record intentionally spans tenants and must be
  limited to platform-owner or internal-job access, or contain no tenant data.

The reviewed database is shared and no database row-level-security policy was
found. Foreign keys and cascading deletes protect referential integrity, but do
not authorize a request. Route path slugs, request headers, JWT organization
claims, and client-supplied IDs are untrusted selectors until resolved and
checked against the authenticated principal.

## Organization-direct resources

| Resource/entity | Tenant key or derivation | Security-sensitive contents | Expected enforcement and required deny tests |
| --- | --- | --- | --- |
| `organizations` | `id`; unique public `slug` | Owner, status, SMTP ciphertext, domain verification, branding, feature overrides | Resolve slug to ID; require membership/capability for reads and mutations; owner-only destructive/transfer actions; deny other-org slug/ID. |
| `memberships` | `org_id` + `user_id` | Role and membership authority | Require actor membership-management capability; prevent last-owner/owner escalation errors; deny cross-org target user and membership ID. |
| `organization_roles` | `org_id` | Custom permission sets | Require role-management capability; bind role ID/slug to org; reject built-in-role mutation and cross-org assignment. |
| `permissions` | Namespace/object relation; organization and service object IDs | Relationship tuples granting capabilities | Prove object belongs to selected org; prevent tuple injection and stale grants; invalidate caches; deny cross-org object IDs. |
| `organization_invitations` | `org_id` | Email, invited role, token/state, inviter | Admin/owner management within org; acceptance bound to invite/token/account; concurrency and cross-org invite-ID tests. |
| `organization_oauth_credentials` | `org_id` | Provider client ID and encrypted secret | Integration-management capability; never return secret; bind provider record to org; deny cross-org provider selection. |
| `organization_billing_credentials` | `org_id` | Encrypted API key and webhook secret | Billing-management capability; never serialize secrets; deny cross-org credential ID/provider. |
| Organization SMTP fields | `organizations.id` | Username and encrypted password | Settings-management capability; mask reads; deny cross-org slug; rotation/redaction tests. |
| `upstream_providers` | `org_id` | Encrypted client secret, endpoints, issuer, metadata | Integration-management capability; provider connection bound to org; SSRF-safe endpoint validation; deny cross-org connection ID/domain routing. |
| `verified_domains` | `org_id` | Domain, verification state/token, provider routing | Integration-management capability; unique ownership and proof; bind provider to same org; deny cross-org domain ID. |
| `scim_tokens` | `org_id` | Hashed provisioning bearer token, status, expiry | Integration manager for lifecycle; SCIM middleware derives org only from token; deny cross-org token ID/header/resource. |
| `webhooks` | `org_id` | Destination URL, plaintext signing secret, event selection | Webhook-management capability; bind webhook ID to org; SSRF-safe delivery; do not expose secret; deny other-org test/update/delete. |
| `webhook_deliveries` | `webhook_id -> webhooks.org_id` | Payload, response, status, attempts, destination context | Authorize through parent webhook and org; never trust delivery ID alone; deny cross-org listing/detail/retry if added. |
| `organization_audit_log` | `org_id` | Actor, event, IP/user agent, details | Membership/audit-view capability; platform access separately explicit; deny cross-org filters and IDs; redaction tests. |
| `risk_rules` | `org_id` | Authentication policy thresholds | Security/settings capability; bind every update/reset/read to org; deny other-org rule ID. |
| `siem_configs` | `org_id` | Endpoint and plaintext API key/auth header | SIEM-management capability; mask/encrypt credentials; SSRF-safe test/delivery; deny cross-org config ID. |
| `mfa_feature_usage` | `org_id`, `user_id` | Factor adoption/security analytics | Authorized tenant analytics only; deny cross-org aggregations and individual IDs. |
| `billing_customers` | `org_id` | External customer identifier and billing state | Billing-view/manage capability; deny other-org customer/subscription references. |

## Service-derived resources

| Resource/entity | Tenant derivation | Security-sensitive contents | Expected enforcement and required deny tests |
| --- | --- | --- | --- |
| `services` | `org_id` | Client secret hash, redirect/resource URIs, SAML config | Resolve by `(org_id, slug)`; require view/manage capability; deny global service ID from another org. |
| `plans` | `service_id -> services.org_id` | Entitlement/pricing configuration | Authorize parent service in selected org; deny cross-service and cross-org plan ID. |
| `api_keys` | `service_id -> services.org_id` | Key hash/prefix, permission list, expiry | Service-management capability for lifecycle; service API bound to stored service; deny other-service key ID. |
| `saml_signing_keys` | `service_id -> services.org_id` | Encrypted private key, certificate, validity/status | Service-management capability; never expose private key; deny other-service certificate mutation/retrieval. |
| `saml_states` | `service_id -> services.org_id` | Request, ACS, issuer, relay state, user, expiry | Created only for configured service; callback must bind expected service and consume once; deny state substitution/replay. |
| `oauth_authorization_grants` | `service_id -> services.org_id` plus `user_id` | Hashed short-lived grant, resource, client, scope | Bind client/service/user/resource; atomic one-time exchange; deny client or tenant substitution. |
| `provider_token_requests` | `service_id -> services.org_id` plus `user_id` | Redirect, scopes, connection/account state | User ownership plus service authorization and registered redirect; consume once; deny state/account/service substitution. |
| `service_provider_grants` | `service_id -> services.org_id` plus `user_id`/account | User consent to external tokens | Require user ownership and service match; deny connected-account or service substitution. |
| `subscriptions` | `service_id -> services.org_id` plus `user_id` | Plan and billing/entitlement state | Service principal or authorized user/admin scoped to service; deny cross-service user/subscription IDs. |
| Service-scoped `sessions` | `service_id -> services.org_id`, optional `org_slug` | Token hash, plaintext refresh token, resource, device metadata | User ownership/admin revocation through proven service/org; deny arbitrary session ID and other-service revocation. |
| `login_events` | `service_id -> services.org_id` and/or `org_id` | Identity, provider, IP, user agent, outcome | Tenant analytics/audit scope; platform aggregation explicit; deny cross-org filters and raw event IDs. |
| Service API user operations | Authenticated `ServicePrincipal.service_id` | User accounts and subscriptions managed by service | Ignore client tenant selectors; filter every lookup/mutation by principal service; enforce each API-key permission independently. |

## User-owned and context-dependent resources

| Resource/entity | Scope derivation | Security-sensitive contents | Expected enforcement and required deny tests |
| --- | --- | --- | --- |
| `users` | `id`; optional `org_id`; memberships; platform flag | Email, password hash, verification, deletion, platform authority | Self or explicit tenant/platform administration; scoped email lookup; prevent platform-flag mutation; deny other user and same-email cross-context confusion. |
| `identities` | `user_id` plus optional issuing org/service fields | External provider subject and provider tokens/metadata | Self ownership and issuing context; enforce `(org, service)` pairing; deny cross-user identity link/unlink and provider-subject collision. |
| `connected_accounts` | `user_id` | Provider tokens, scopes, account identity | Self ownership; encrypted token path; grants separately service-bound; deny other account ID and plaintext disclosure. |
| `sessions` | `user_id`, optional org/service/resource | Token/refresh material and client metadata | Self/device management or scoped admin revocation; bind admin operations through org's services; deny other-user session ID. |
| `user_devices` | `user_id` | Hashed device token, trust/revocation, IP/user agent | Self only except documented admin action; deny other device ID; atomic trust/revoke and token replay tests. |
| `user_passkeys` | `user_id` | Credential public data, counter, metadata | Self management; authentication challenge supplies user; deny rename/delete by other user and credential-ID collision. |
| `webauthn_challenges` | `user_id` | Serialized ceremony state and expiry | Bind challenge to expected user/type, consume once, expire; deny user/type substitution and concurrent reuse. |
| `user_totp_secrets` | `user_id` | Encrypted TOTP secret and enabled state | Self enrollment/disable or explicit platform action; never expose secret after setup; deny other-user ID. |
| `totp_backup_codes` | `user_id` | Argon2 backup-code hashes and used state | Self/recovery flow; atomic one-time consume; deny other-user reset/regeneration. |
| `password_reset_tokens` | `user_id` | Hashed reset token, expiry, used state | Possession plus one-time conditional consume; delete sessions after reset; prevent scoped-email collision and replay. |
| `email_verification_tokens` | `user_id` | Hashed verification token, expiry/used | Possession plus one-time consume; deny token-to-user/context swapping. |
| `magic_link_tokens` | optional `user_id`, email, issuing org/service/context | Hashed login bearer and redirect context | Resolve scoped user, bind issued context, consume once; prevent enumeration, redirect changes, replay, and cross-tenant same-email login. |
| `device_codes` | optional `user_id`, service/client/resource context | Device/user codes, status, expiry, polling state | Bind client/resource, authenticated authorizer, MFA result, and one-time exchange; deny code substitution and concurrent polling/exchange. |
| `oauth_states` | optional service/org/user/link/device/SAML context | CSRF state, PKCE verifier, redirect and requested scopes | Bind callback to stored context, expiry, provider and flow type; delete atomically; deny cross-flow/state replay. |
| `provider_token_requests` | `user_id` + service | Requested scopes and redirect | Self ownership plus service grant; deny other user's state/account. |
| `token_refresh_locks` | `user_id` | Refresh coordination | Internal only; key sufficiently contextual for intended isolation; test multi-service/user concurrency. |
| `mfa_audit_log` | `user_id`, optional `org_id` | Authentication outcomes, IP/user agent, details | Self/platform or authorized tenant security view; ensure optional org cannot leak into tenant queries. |
| `mfa_failure_patterns` | optional `user_id`/`org_id` | Detection aggregates | Authorized security/platform use; partition tenant queries and test null/global rows. |

## Platform and internal resources

| Resource/entity | Intended scope | Required controls and tests |
| --- | --- | --- |
| Platform-owner user flag and platform routes | Platform | Check current database user, not client claims alone; test demotion/cache staleness, MFA policy, bootstrap closure, and tenant-admin denial. |
| `platform_audit_log` | Platform | Platform-owner read access only; redact secrets/PII; test actor/impersonation attribution and cross-role denial. |
| `organization_tiers` and `plans`/feature governance | Platform definitions with tenant assignments | Platform-owner mutations; tenant reads only where intended; deny tenant write and arbitrary tier escalation. |
| `mfa_daily_metrics` | Optional organization or platform aggregate | Explicit org filter for tenant views; platform-only global rows; test null-org handling. |
| `system_jobs` | Internal job queue | No tenant-controlled arbitrary job type/payload; job payload authorization and redaction; idempotency and operator access tests. |
| `distributed_locks`, `token_refresh_locks` | Internal coordination | Namespaced keys, bounded expiry, multi-replica atomicity, no public CRUD route. |
| `webhook_deliveries` and job payloads | Derived tenant/internal | Carry immutable parent IDs and reauthorize on administrative reads/retries. |
| OIDC discovery/JWKS and health/readiness | Public/operational | Publish only intended metadata and restrict operational details at the proxy where required. |
| Metrics | Operational, disabled by default | Require the configured application bearer token plus network/proxy restriction; test no secrets/tenant labels. |
| Managed bootstrap config/state files | Host/platform | Platform-owner plus filesystem/process controls; validate paths/content; audit changes; test bootstrap cannot re-open privilege. |

## Cross-resource invariants

Every handler and store operation must preserve these invariants:

1. A service, plan, API key, subscription, SAML key/state, authorization grant,
   provider-token request, or service-provider grant belongs to the same
   organization/service context used to authorize the actor.
2. A resource ID is never authorized merely because the actor can access an
   organization named elsewhere in the request.
3. A user's organization membership does not grant access to all of that
   user's records from other organizations or platform context.
4. A platform owner uses an explicit platform path/check; tenant checks do not
   accidentally treat platform ownership as implicit membership unless the
   operation's policy says so.
5. API-key and SCIM-token authority comes from the stored principal binding,
   not from `X-Organization-ID`, path slugs, body fields, or JWT claims supplied
   alongside it.
6. Delete, update, rotate, revoke, accept, retry, and test endpoints enforce the
   same parent scope as list/get endpoints.
7. Background jobs re-derive tenant ownership from stored parent IDs instead of
   trusting serialized tenant fields.
8. Cache keys include every scope dimension that affects authorization, and
   privilege changes invalidate or safely age out cached results.
9. Tenant deletion cascades or explicitly handles every derived resource and
   does not delete a shared user's unrelated identity data.
10. Platform analytics may aggregate tenants only for platform-authorized
    callers; tenant analytics always apply an organization predicate before
    pagination/aggregation.

## Required authorization matrix

For each inventory row and each CRUD/action endpoint, automated tests must
cover at least:

| Dimension | Required cases |
| --- | --- |
| Actor | Unauthenticated, end user/self, other user, member, custom role, admin, owner, platform owner, service key with/without permission, SCIM token. |
| Tenant | Same organization, different organization, no membership, suspended/pending organization, deleted parent. |
| Identifier | Correct ID, another tenant's valid ID, nonexistent ID, parent/child mismatch, duplicate slug/email/provider subject. |
| Operation | List, get, create, update/patch, delete, rotate/revoke, accept/complete, test/retry, export/analytics. |
| Timing | Concurrent mutation/consume, privilege revoked during cached window, expired credential/state, parent deleted during action. |
| Database | SQLite, PostgreSQL, and MySQL using the shipped feature combinations. |

Tests should prefer indistinguishable not-found/forbidden behavior where
resource-existence disclosure matters, and should assert both response and
database state. A passing happy-path test is not isolation evidence.

## Recorded isolation evidence

The following focused regressions exist on the current development baseline.
They are evidence for only the cases named here, not completion of the matrix:

| Resource | Database | Test identifier | Covered cases | Remaining gaps |
| --- | --- | --- | --- | --- |
| `webhooks` | SQLite | `store::webhooks::tests::webhook_lists_and_event_selection_are_organization_scoped` | Two organizations with valid webhook IDs; organization-scoped list/count and active event selection return only the selected organization's row; a nonexistent organization returns an empty list. | HTTP handler authentication/role cases, delivery-history endpoints, concurrent changes, PostgreSQL, and MySQL. |
| `webhooks` | SQLite | `store::webhooks::tests::webhook_mutations_deny_other_organization_and_missing_ids` | Same-organization update/delete succeeds; another organization's valid ID and nonexistent IDs produce `NotFound`; denied URL/event/status updates and delete leave the row unchanged. | HTTP response equivalence, test-delivery authorization, secret redaction/rotation, concurrent changes, PostgreSQL, and MySQL. |

## Inventory maintenance

CI should compare SeaORM entities/migrations and router additions against this
inventory. A pull request that adds a tenant-related table, foreign key, route,
background job, cache, or external export must update this file and add matrix
tests before merge. The eventual evidence report should record the exact commit,
database, actor/resource cases, and test identifiers for every row.
