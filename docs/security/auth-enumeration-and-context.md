# Authentication enumeration and context matrix

Status: implementation and deterministic test baseline, 2026-07-14.

This document records the public response policy and security-context binding
for AuthOS authentication handlers. It is not a claim that network requests are
constant time. Database access, email queue writes, cryptographic work, cache
state, scheduling, and upstream providers all create observable variance.

## Enumeration and expensive-work matrix

| Flow | Public response policy | Expensive-work comparison | Deterministic evidence and residual risk |
| --- | --- | --- | --- |
| Password registration | A new account and an existing account return the same success status and generic message after input/context validation. | Both paths perform bounded Argon2 hashing before the account lookup. A new account still performs transactional writes and queues email. | `registration_normalizes_existing_and_new_accounts`; write/email timing remains distinguishable in sufficiently controlled measurements. Hash-before-lookup also lets randomized addresses consume the bounded Argon2 queue, so the route needs both per-IP and normalized-email limits, distributed edge controls, queue-saturation alerts, and measured overload qualification. |
| Password login | Missing, wrong-password, and passwordless/OAuth-only accounts return `401` with `Invalid email or password`. | Missing and passwordless accounts verify against a dummy Argon2 hash through the same bounded worker pool. | `password_login_normalizes_absent_and_passwordless_accounts`; this reduces, but does not prove elimination of, timing disclosure. Verified/unverified and managed-domain policy errors occur only after valid credentials or intentional domain routing. |
| Forgot password | Missing and passwordless accounts return the same generic success response as eligible accounts. | Only eligible accounts create a reset record and queue mail. | `password_recovery_requests_normalize_account_states`; email/DB work remains a timing asymmetry. Never use local timing samples as a release pass/fail oracle. |
| Resend verification | Missing, verified, and unverified accounts return the same generic success response. | Only unverified accounts create a token and queue mail. | `password_recovery_requests_normalize_account_states`; email/DB work remains a timing asymmetry. |
| Magic-link request | Returns generic success and creates a bounded, context-bound request even if no user is resolved. | The request and email queue path is intentionally similar for missing and existing addresses. | Magic-link tenant/service tests cover same-email and cross-service selection. Mail transport behavior can still vary outside AuthOS. |
| Reset/verification token consume | Invalid, expired, and already-used capability tokens may return distinct errors. | Work varies by token state. | These are high-entropy, short-lived, one-time capabilities rather than email lookup endpoints. Atomic claim tests are the primary security evidence. |
| Invitation accept | Token acceptance may distinguish invalid, expired, already accepted, and already-member outcomes. | Work varies by capability state. | Invitation tokens are high entropy and single use. Exact-email tenant selection and one-winner tests prevent a token from selecting a sibling or platform account. |
| Passkey authentication start | Missing and existing-but-unenrolled accounts return the same `400` response. | Both paths perform the passkey-table lookup; the missing path uses the impossible typed predicate `user_id IS NULL` against the non-null foreign-key column, so it cannot collide with an imported sentinel user. An enrolled account additionally parses credentials and asks WebAuthn to create a challenge. | `passkey_auth_start_normalizes_absent_and_unenrolled_accounts`, `absent_public_lookup_cannot_collide_with_an_imported_sentinel_user`; residual timing variance is documented, not represented as constant-time behavior. |
| Passkey finish/WebAuthn | Challenge errors may distinguish invalid, expired, consumed, or invalid authenticator data. | Work varies with authenticator input and challenge state. | Challenge IDs are high entropy, short lived, server stored, and one time. The authentication context is loaded from the claimed challenge rather than accepted again from the browser. |
| Browser device-code verify | Malformed, absent, expired, denied, consumed, already-authorized, and already-user-bound codes return the same `400` response. | Every valid-format code performs three lookups and two 10 ms delays, retaining a bounded eventual-consistency window without a missing-code-only delay. Malformed codes fail before database work. | `browser_device_verify_normalizes_absent_and_expired_codes`; short user codes remain rate-limit sensitive. |
| Device token polling | OAuth device-flow errors intentionally distinguish pending, expired, invalid, and successful states required by the protocol. | Work varies by state. | The device code is a long random capability and is bound to client, organization, service, user, and optional resource before token issue. |
| MFA/recovery-code verify | Invalid MFA codes return a generic authentication error; a preauthentication token is mandatory and one time. | TOTP and backup-code paths differ internally. | Signed token-use checks plus exact device/SAML context tests apply. Ordinary completion re-reads the active user, organization, service identity or membership, and registered resource immediately before one transaction claims the pre-auth/backup code, authorizes an exact bound device code, creates the session, and enqueues the success audit. SAML completion preflights and then rechecks its live continuation context. PostgreSQL/MySQL runtime race evidence remains outstanding. |
| Refresh-token rotation | An unrecognized, replayed, or context-revoked refresh token returns a generic authentication failure. | A recognized current token performs live user/tenant/service/resource reads before its conditional rotation; replay additionally revokes the current family. | Rotation re-reads the session by ID, rejects a soft-deleted user, inactive organization, removed membership or exact service identity, service reparenting, and resource deregistration, then issues and conditionally rotates in the same database transaction. A context denial rolls back without changing the current token or family; `refresh_revalidates_every_live_tenant_resource_binding` covers removal, suspension, reparenting, deregistration, same-email siblings, and unchanged denied state on SQLite. Live PostgreSQL/MySQL isolation/race behavior and multi-replica replay remain required. |
| OAuth/social callback | Missing or empty state is rejected; consumed/invalid state and provider errors may differ. | Upstream and account-linking work is inherently provider dependent. | State is high entropy, server stored, one time, and contains the authoritative org/service/redirect/resource/client-state binding. Do not treat callback latency as an account-enumeration control. |
| SAML SSO | Protocol, tenant, service, request, assertion, and continuation failures may differ. | XML/signature/IdP work varies by request. | SAML request/continuation values are capabilities or public protocol metadata. Parser work is bounded separately; live tenant/service checks and one-winner continuation tests prevent context confusion. |
| Home-realm discovery | Domain routing and configured provider metadata are intentionally discoverable. It must not report whether an individual user exists. | Domain lookup varies by route configuration. | Treat verified-domain policy as public organization login metadata and keep user-specific fields out of the response. |

Generic responses do not replace throttling. Deployments must rate-limit public
email, passkey, device, MFA, OAuth-state, and capability-consume routes and alert
on distributed enumeration patterns.

The deterministic handler tests compare status, response headers, and the
complete JSON error envelope after removing only its per-response `timestamp`;
`error` and `error_code` must match exactly.

## Authentication context-confusion matrix

| Context | Authoritative binding | Qualification |
| --- | --- | --- |
| Password org/service/redirect | The handler resolves the organization, resolves the service beneath that organization, validates the exact registered redirect, verifies membership/identity, and then writes the same scope into token and session. | `org_scoped_password_login_issues_org_claims_and_session_scope`, `service_scoped_password_login_issues_service_claims_and_session_scope`, inactive-organization deny test. |
| Magic org/service/redirect/state | A canonical serialized context is hashed into the stored magic-link row. Consume reloads the exact tenant/service identity and revalidates the callback before atomic claim. | `malformed_callback_and_suspension_after_issuance_preserve_magic_link`, `same_email_and_cross_service_context_cannot_select_or_consume_wrong_identity`. |
| OAuth org/service/redirect/state/resource | Server-side OAuth state is the authority. Redirect and resource are validated before persistence; callback consumes that state and does not accept replacement context. | `callback_requires_nonempty_state`, `service_authorize_persists_resource_indicator_in_oauth_state`, provider-token client-state test, registered-resource tests. |
| Passkey org/service/redirect/state | Start validates tenant/service/redirect and stores the entire context inside the one-time challenge. Finish accepts only challenge ID and credential, then uses stored context. | Inactive-organization start deny test plus WebAuthn challenge ownership/claim behavior. |
| Device org/service/client/resource | Device code is created for one org/service/client. Browser completion can authorize only the signed `device_code_id`; token exchange revalidates the active organization, exact service identity, registered resource, and current platform-owner authority where applicable. Its atomic consume predicate binds the code to the exact client, user, organization, and service. The virtual `platform/admin-cli` device binding is retained for authorization checks but normalized to an unscoped platform-owner session rather than persisted as a tenant organization. | `device_mfa_preauth_token_binds_exact_device_context`, `device_context_requires_exact_signed_match`, `platform_device_binding_is_not_persisted_as_a_tenant_org`, `platform_device_exchange_rechecks_current_owner_authority`, `concurrent_token_exchange_has_exactly_one_winner`, `token_exchange_accepts_only_registered_resource`. |
| MFA token use/device/SAML | JWT `typ`/token-use, issuer, audience, expiry, one-time `jti`, and exact optional `device_code_id` are validated. SAML MFA additionally requires signed org/service/SAML state and forbids device context. Internal `platform`, `org:`, and `service:` audiences are reserved management identifiers and cannot be supplied as external resource indicators; external resources must be valid absolute URIs registered on the exact service. | `management_token_confusion_matrix_rejects_mismatched_security_context`, `internal_management_audiences_are_not_resource_indicators`, `device_context_requires_exact_signed_match`, `live_mfa_context_rejects_revoked_service_and_expired_device_authority`, `saml_mfa_context_requires_signed_state_and_exact_non_device_service_context`. |
| Invitation org/user | Token lookup determines the invitation organization and normalized email; acceptance searches only that organization and ignores same-email platform/sibling users. | Single-use, concurrent one-winner, already-member, and sibling same-email tests in `handlers/invitations.rs`. |
| SAML org/service/request/continuation | Request state records exact tenant/service/SP inputs. Completion reloads live tenant/service access and atomically claims continuation state. | `assertion_access_and_completion_context_are_bound_to_live_tenant_state`, `post_mfa_saml_continuation_state_has_exactly_one_winner`. |

## Bounded timing observations

`scripts/auth-timing-harness.py` accepts at most 20 scenarios, 200 samples per
scenario, 20 warmups, a 30-second request timeout, and a 64 KiB response read.
It does not follow redirects, interleaves scenarios in seeded order, and reports
median, nearest-rank p95,
median absolute deviation, range, and status counts. It deliberately has no
timing threshold and emits this notice in every report:

> Observational timing sample only. Results do not establish constant-time behavior.

The base URL must not contain user-info credentials, a query string, or a
fragment, and reports contain scenario names/status/timing only—not scenario
paths, JSON bodies, passwords, tokens, or seeded email addresses. Keep secrets
out of scenario names and use synthetic credentials even on an isolated target.

Use an isolated deployment with seeded synthetic accounts. Edit
`auth-timing-scenarios.example.json`, then run:

```bash
python3 scripts/auth-timing-harness.py \
  http://127.0.0.1:3001 \
  docs/security/auth-timing-scenarios.example.json \
  --samples 30 --warmups 3 --output /tmp/authos-auth-timing.json
```

Preserve the JSON as review evidence, compare distributions rather than one
request, and investigate large stable differences. A noisy local result neither
proves nor disproves a remotely exploitable timing channel.

See also the [threat model](./threat-model.md),
[security architecture](./security-architecture.md), and
[input/work bounds](./input-work-bounds.md).
