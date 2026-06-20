# Enterprise-Managed Authorization

AuthOS supports a first-party Enterprise-Managed Authorization path for MCP and
Cross-App Access style integrations.

The initial implementation is intentionally scoped:

- AuthOS issues short-lived ID-JAGs from existing AuthOS service-scoped JWT
  sessions.
- AuthOS redeems those ID-JAGs for normal AuthOS bearer tokens scoped to a
  registered service resource URI.
- ID-JAGs are recorded in a dedicated one-time authorization grant table and
  are consumed during JWT bearer exchange.
- The redeemed bearer token is backed by the existing `sessions` table, so
  standard session revocation still applies.
- External IdP-issued ID-JAG trust is not implicit. Accepting third-party
  issuers should be added through an explicit trusted-issuer/JWKS registry.

## Endpoints

Use form-encoded OAuth token requests:

- `POST /oauth/token`
- `POST /oauth2/token`

Existing device flow clients should continue using `POST /auth/token`.
OIDC discovery keeps `token_endpoint` on `/auth/token` for compatibility and
publishes `enterprise_token_endpoint` for this flow.

## Request an ID-JAG

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:id-jag
&audience=https://auth.example.com
&resource=https://api.example.com/mcp
&subject_token=AUTHOS_SERVICE_JWT
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&client_id=SERVICE_CLIENT_ID
```

AuthOS validates that:

- the audience matches the AuthOS issuer,
- the subject token is valid and session-backed,
- the subject token is scoped to the same organization and service as the
  `client_id`,
- the requested resource URI is registered on that service.
- any requested `scope` is already present on the subject token, preventing
  token exchange from escalating access.

## Exchange an ID-JAG for a Bearer Token

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=ID_JAG
&client_id=SERVICE_CLIENT_ID
&client_secret=SERVICE_CLIENT_SECRET
```

AuthOS validates the ID-JAG signature, `typ=oauth-id-jag+jwt`, issuer,
audience, client binding, resource registration, organization status, client
secret, and single-use grant record before issuing a resource-audience bearer
token.

The JWT bearer exchange does not return a refresh token. Re-request an ID-JAG
from a valid AuthOS session when a new resource token is needed.
