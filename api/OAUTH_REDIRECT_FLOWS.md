# OAuth Redirect Flows Documentation

## Overview

The SSO service uses a unified redirect architecture for both initial sign-in and identity linking flows. This document explains how redirects work and what query parameters are used.

## Redirect URI Configuration

Services must configure their `redirect_uris` in the database:

```json
{
  "redirect_uris": ["http://localhost:5173/auth/callback"]
}
```

The **first** URI in the array is used for identity linking callbacks.

## Flow Types

### 1. Initial Sign-In Flow

**User Journey:**
1. User clicks "Sign in with Microsoft"
2. Frontend makes request to `/api/auth/device` or navigates to `/api/auth/microsoft`
3. SSO redirects to Microsoft OAuth
4. Microsoft returns to SSO callback: `http://localhost:3000/auth/microsoft/callback`
5. SSO processes OAuth code, generates JWT tokens
6. SSO redirects to service: `http://localhost:5173/auth/callback?access_token=xxx&refresh_token=xxx`
7. Frontend stores tokens and redirects to dashboard

**Query Parameters:**
- `access_token` (string): JWT access token
- `refresh_token` (string): JWT refresh token
- `error` (string, optional): Error message if authentication failed

**Frontend Handling:**
```javascript
if (route.query.access_token && route.query.refresh_token) {
  // Sign-in flow
  await authStore.setToken(accessToken, refreshToken)
  router.push('/dashboard')
}
```

---

### 2. Identity Linking Flow

**User Journey:**
1. Authenticated user clicks "Link Microsoft Account"
2. Frontend makes request to `/api/user/identities/microsoft/link`
3. SSO redirects to Microsoft OAuth
4. Microsoft returns to SSO callback: `http://localhost:3000/auth/microsoft/callback`
5. SSO saves identity to database
6. SSO redirects to service: `http://localhost:5173/auth/callback?status=success&provider=microsoft&action=link`
7. Frontend shows success message and refreshes UI

**Query Parameters:**
- `status` (string): `"success"` or `"error"`
- `provider` (string): Provider name (`"microsoft"`, `"github"`, `"google"`)
- `action` (string): `"link"` (to differentiate from sign-in)
- `error` (string, optional): Error message if linking failed

**Frontend Handling:**
```javascript
if (route.query.action === 'link' && route.query.status === 'success') {
  // Linking flow
  console.log(`Successfully linked ${provider} account`)
  // Show toast/notification
  router.push('/dashboard')
}
```

---

## Multi-Level Identity Linking

The SSO service supports two levels of identity linking:

### Service-Level Linking

When user is logged into a specific service (e.g., "sdd"):
- Uses service's configured `redirect_uris`
- Uses service's configured scopes
- Supports BYOO (Bring Your Own OAuth) credentials
- Redirect: `http://localhost:5173/auth/callback?status=success&provider=microsoft&action=link`

**Backend Logic:**
```rust
// Extract from service config
let redirect_uris: Vec<String> = serde_json::from_str(&service.redirect_uris)?;
let base_redirect = redirect_uris.first().ok_or(...)?;

// Build callback URL
let redirect_uri = format!(
    "{}?status=success&provider={}&action=link",
    base_redirect,
    provider.as_str()
);
```

### Platform-Level Linking

When user is in admin console or platform owner:
- Uses platform's base_url
- Uses default provider scopes
- Uses platform OAuth credentials
- Redirect: `http://localhost:3000/settings/connections?status=success&provider=microsoft&action=link`

---

## Error Handling

All flows support error query parameters:

**Error Redirect Examples:**
```
# Sign-in error
/auth/callback?error=Authentication+failed

# Linking error
/auth/callback?status=error&error=Account+already+linked&action=link
```

**Frontend Handling:**
```javascript
if (route.query.error) {
  error.value = route.query.error
  // Show error message
}
```

---

## Security Considerations

1. **CSRF Protection**: `state` parameter is validated in OAuth callback
2. **PKCE**: Microsoft OAuth uses PKCE for additional security
3. **Short-lived States**: OAuth states expire after 10 minutes
4. **Redirect URI Validation**: Only configured redirect_uris are accepted
5. **Identity Uniqueness**: Provider accounts cannot be linked to multiple users

---

## Implementation Checklist

### Backend (SSO Service)

- [x] Store `redirect_uri` with query params in `oauth_states`
- [x] Use service's first `redirect_uris` entry for linking
- [x] Include `?status=success&provider=X&action=link` in redirect
- [x] Support both service-level and platform-level linking

### Frontend (Service Application)

- [x] Handle `/auth/callback` route
- [x] Detect `action=link` query parameter
- [x] Show appropriate success/error messages
- [x] Refresh UI or fetch updated identity list

### Configuration

- [x] Add `redirect_uris` to service configuration
- [x] Register redirect URI in provider OAuth app (Azure, GitHub, etc.)
- [x] Configure provider scopes for each service

---

## Debugging

### Check OAuth State

```sql
SELECT state, redirect_uri, user_id_for_linking, is_admin_flow
FROM oauth_states
WHERE user_id_for_linking IS NOT NULL
ORDER BY created_at DESC
LIMIT 1;
```

### Check Identity Created

```sql
SELECT provider, scopes, issuing_org_id
FROM identities
WHERE user_id = 'user-id-here'
AND provider = 'microsoft';
```

### Test Redirect

```bash
# Check if service has redirect_uris
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/user/identities/microsoft/link

# Should return authorization_url with correct redirect_uri in state
```

---

## Examples

### Complete Linking Flow (Service-Level)

1. **Start linking:**
   ```javascript
   const response = await fetch(
     'http://localhost:3000/api/user/identities/microsoft/link',
     { headers: { 'Authorization': `Bearer ${token}` } }
   );
   const { authorization_url } = await response.json();
   window.location.href = authorization_url;
   ```

2. **SSO processes OAuth:**
   - User authorizes in Microsoft
   - Microsoft returns to: `http://localhost:3000/auth/microsoft/callback?code=xxx&state=yyy`
   - SSO validates, saves identity
   - SSO redirects to: `http://localhost:5173/auth/callback?status=success&provider=microsoft&action=link`

3. **Frontend handles callback:**
   ```javascript
   // AuthCallback.vue
   if (action === 'link' && status === 'success') {
     showToast(`${provider} account linked successfully`)
     router.push('/dashboard')
   }
   ```

---

## Migration Notes

### Previous Behavior (Before Unification)

- Identity linking used custom `redirect_uri` parameter
- Different redirect URLs for sign-in vs linking
- Required multiple redirect URI registrations

### Current Behavior (After Unification)

- Identity linking uses service's configured `redirect_uris`
- Same redirect URL for both flows
- Differentiation via query parameters
- Single source of truth for redirect configuration

---

## API Reference

### POST /api/user/identities/:provider/link

**Description:** Start identity linking flow

**Authentication:** Required (Bearer token)

**Path Parameters:**
- `provider`: Provider name (`microsoft`, `github`, `google`)

**Response:**
```json
{
  "authorization_url": "https://login.microsoftonline.com/..."
}
```

**Callback URL:**
```
{service.redirect_uris[0]}?status=success&provider=microsoft&action=link
```

---

## See Also

- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE RFC](https://datatracker.ietf.org/doc/html/rfc7636)
- [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
