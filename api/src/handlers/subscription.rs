use crate::auth::jwt::Claims;
use crate::constants::DEFAULT_TIER_NAME;
use crate::db::models::User;
use crate::error::{AppError, Result};
use crate::handlers::auth::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub org: String,
    pub service: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub service: String,
    pub plan: String,
    pub features: Vec<String>,
    pub status: String,
    pub current_period_end: String,
}

/// Get current user info
pub async fn get_user(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<UserResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Verify user is member of org if org claim exists
    if let Some(ref org_slug) = auth_user.claims.org {
        let is_member = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM memberships m
            JOIN organizations o ON m.org_id = o.id
            WHERE m.user_id = ? AND o.slug = ?
            "#,
        )
        .bind(&auth_user.claims.sub)
        .bind(org_slug)
        .fetch_one(&state.pool)
        .await?;

        if is_member == 0 {
            return Err(AppError::Forbidden(
                "User is not a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(UserResponse {
        id: auth_user.user.id.clone(),
        email: auth_user.user.email.clone(),
        org: auth_user.claims.org.unwrap_or_default(),
        service: auth_user.claims.service.unwrap_or_default(),
    }))
}

/// Get current subscription
pub async fn get_subscription(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<SubscriptionResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Extract org and service from claims
    let org_slug = auth_user
        .claims
        .org
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Missing org in token".to_string()))?;
    let service_slug = auth_user
        .claims
        .service
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Missing service in token".to_string()))?;

    // Get subscription info
    let result = sqlx::query!(
        r#"
        SELECT
            s.slug as service_slug,
            p.name as plan_name,
            p.features as features,
            sub.status as status,
            sub.current_period_end as current_period_end
        FROM subscriptions sub
        JOIN services s ON sub.service_id = s.id
        JOIN plans p ON sub.plan_id = p.id
        JOIN organizations o ON s.org_id = o.id
        WHERE sub.user_id = ? AND o.slug = ? AND s.slug = ?
        "#,
        auth_user.claims.sub,
        org_slug,
        service_slug
    )
    .fetch_optional(&state.pool)
    .await?;

    if let Some(result) = result {
        let features: Vec<String> = result
            .features
            .as_ref()
            .and_then(|f| serde_json::from_str(f).ok())
            .unwrap_or_default();

        Ok(Json(SubscriptionResponse {
            service: result.service_slug,
            plan: result.plan_name,
            features,
            status: result.status,
            current_period_end: result.current_period_end.to_string(),
        }))
    } else {
        // No active subscription, return free plan
        Ok(Json(SubscriptionResponse {
            service: service_slug.to_string(),
            plan: DEFAULT_TIER_NAME.to_string(),
            features: vec![],
            status: "active".to_string(),
            current_period_end: "N/A".to_string(),
        }))
    }
}

#[allow(dead_code)]
pub fn validate_claims_match_path(
    claims: &Claims,
    org_slug: &str,
    service_slug: &str,
) -> Result<()> {
    if claims.org.as_deref() != Some(org_slug) || claims.service.as_deref() != Some(service_slug) {
        return Err(AppError::Forbidden(
            "Token does not match requested resource".to_string(),
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn has_feature(claims: &Claims, feature: &str) -> bool {
    claims
        .features
        .as_ref()
        .map(|features| features.iter().any(|f| f == feature))
        .unwrap_or(false)
}

/// Update user profile
pub async fn update_user(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Get current user
    let mut user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&auth_user.claims.sub)
        .fetch_one(&state.pool)
        .await?;

    // Update email if provided
    if let Some(new_email) = req.email {
        // Validate email format
        if !new_email.contains('@') || new_email.len() < 5 {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }

        // Check if email is already taken
        let existing =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?")
                .bind(&new_email)
                .bind(&user.id)
                .fetch_one(&state.pool)
                .await?;

        if existing > 0 {
            return Err(AppError::BadRequest("Email already in use".to_string()));
        }

        // Update email
        sqlx::query!(
            "UPDATE users SET email = ? WHERE id = ?",
            new_email,
            user.id
        )
        .execute(&state.pool)
        .await?;

        user.email = new_email;
    }

    // Verify user is still member of org if org claim exists
    if let Some(ref org_slug) = auth_user.claims.org {
        let is_member = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM memberships m
            JOIN organizations o ON m.org_id = o.id
            WHERE m.user_id = ? AND o.slug = ?
            "#,
        )
        .bind(&auth_user.claims.sub)
        .bind(org_slug)
        .fetch_one(&state.pool)
        .await?;

        if is_member == 0 {
            return Err(AppError::Forbidden(
                "User is not a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
        org: auth_user.claims.org.unwrap_or_default(),
        service: auth_user.claims.service.unwrap_or_default(),
    }))
}
