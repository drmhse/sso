use crate::auth::jwt::{Claims, JwtService};
use crate::db::models::{Membership, Organization, User};
use crate::error::{AppError, Result};
use axum::{
    extract::{FromRequestParts, Path, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;

/// Extension type for storing authenticated user claims
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub claims: Claims,
    pub user: User,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))
    }
}

/// Extract and validate JWT from Authorization header
pub async fn extract_user_from_jwt(
    State((pool, jwt_service)): State<(SqlitePool, Arc<JwtService>)>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    // Extract token from Authorization header
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or_else(|| {
            AppError::Unauthorized("Missing or invalid Authorization header".to_string())
        })?;

    // Validate token
    let claims = jwt_service.validate_token(token)?;

    // Check if session is still valid (not revoked)
    let token_hash = JwtService::hash_token(token);
    let session = sqlx::query!(
        "SELECT id FROM sessions WHERE token_hash = ? AND expires_at > datetime('now')",
        token_hash
    )
    .fetch_optional(&pool)
    .await
    .map_err(AppError::Database)?;

    if session.is_none() {
        return Err(AppError::Unauthorized(
            "Session revoked or expired".to_string(),
        ));
    }

    // Load user from database
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, is_platform_owner, created_at FROM users WHERE id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(&pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    // Store user in request extensions
    req.extensions_mut().insert(AuthUser {
        claims: claims.clone(),
        user,
    });

    Ok(next.run(req).await)
}

/// Middleware to require platform owner role
pub async fn require_platform_owner(
    req: Request,
    next: Next,
) -> std::result::Result<Response, (StatusCode, String)> {
    let auth_user = req
        .extensions()
        .get::<AuthUser>()
        .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

    if !auth_user.user.is_platform_owner {
        return Err((
            StatusCode::FORBIDDEN,
            "Platform owner access required".to_string(),
        ));
    }

    Ok(next.run(req).await)
}

/// Middleware to require organization membership with specific roles
#[allow(dead_code)] // Currently unused, kept for future middleware implementation
pub async fn require_org_member(
    _org_id: String,
    _required_roles: Vec<String>,
) -> impl Fn(
    Request,
    Next,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = std::result::Result<Response, (StatusCode, String)>>
            + Send,
    >,
> {
    move |req: Request, next: Next| {
        Box::pin(async move {
            let _auth_user = req
                .extensions()
                .get::<AuthUser>()
                .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

            // Get pool from request state/extensions - this would need to be set up properly
            // For now, this is a placeholder. In practice, you'd extract the pool from State
            // when calling this middleware in route definitions

            // This middleware builder pattern isn't ideal for runtime org_id validation
            // Better to do this check inside the handler itself
            // Keeping this as a reference implementation

            Ok(next.run(req).await)
        })
    }
}

/// Helper function to check if user has required role in organization
pub async fn check_org_membership(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
    required_roles: &[&str],
) -> Result<Membership> {
    let membership = sqlx::query_as::<_, Membership>(
        "SELECT id, org_id, user_id, role, created_at
         FROM memberships
         WHERE org_id = ? AND user_id = ?",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    if !required_roles.is_empty() && !required_roles.contains(&membership.role.as_str()) {
        return Err(AppError::Forbidden(format!(
            "Requires one of roles: {}",
            required_roles.join(", ")
        )));
    }

    Ok(membership)
}

/// Helper function to check if user is organization owner
pub async fn check_org_owner(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<()> {
    check_org_membership(pool, user_id, org_id, &["owner"]).await?;
    Ok(())
}

/// Helper function to check if user is organization admin or owner
pub async fn check_org_admin(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<Membership> {
    check_org_membership(pool, user_id, org_id, &["owner", "admin"]).await
}

/// Context for organization member operations
#[derive(Clone, Debug)]
#[allow(dead_code)] // Currently unused, kept for future middleware implementation
pub struct OrgMemberContext {
    pub org: Organization,
    pub user: User,
    pub membership: Membership,
}

/// Extractor for organization member context
#[allow(dead_code)] // Currently unused, kept for future middleware implementation
pub async fn extract_org_member_context(
    State(state): State<crate::handlers::auth::AppState>,
    Path(org_slug): Path<String>,
    mut request: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    // Get authenticated user
    let auth_user = request
        .extensions()
        .get::<AuthUser>()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?;

    // Get organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Get membership
    let membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&org.id)
    .bind(&auth_user.user.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    // Store context in request extensions
    request.extensions_mut().insert(OrgMemberContext {
        org,
        user: auth_user.user,
        membership,
    });

    Ok(next.run(request).await)
}

/// Middleware to require organization admin or owner role
#[allow(dead_code)] // Currently unused, kept for future middleware implementation
pub async fn require_org_admin_or_owner(
    State(state): State<crate::handlers::auth::AppState>,
    Path(org_slug): Path<String>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    // Get authenticated user
    let auth_user = req
        .extensions()
        .get::<AuthUser>()
        .cloned()
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?;

    // Get organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is admin or owner
    check_org_admin(&state.pool, &auth_user.user.id, &org.id).await?;

    // Store context in request extensions
    req.extensions_mut().insert(OrgMemberContext {
        org: org.clone(),
        user: auth_user.user.clone(),
        membership: check_org_admin(&state.pool, &auth_user.user.id, &org.id).await?,
    });

    Ok(next.run(req).await)
}

/// Extractor struct for organization slug path parameter
#[derive(Deserialize)]
pub struct OrgSlugParam {
    org_slug: String,
}

/// Middleware to require organization to be in active status
/// This prevents access to certain features (services, BYOO credentials, etc.)
/// while organization is pending approval
pub async fn require_active_organization(
    State(state): State<crate::handlers::auth::AppState>,
    Path(path): Path<OrgSlugParam>,
    req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    // Get organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&path.org_slug)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if organization is active
    if org.status != "active" {
        return Err(AppError::Forbidden(format!(
            "Organization is not active. Current status: {}. This feature is only available for active organizations.",
            org.status
        )));
    }

    Ok(next.run(req).await)
}
