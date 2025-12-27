use crate::error::{AppError, Result};
use crate::middleware::{AuthUser, RequestInfo};
use crate::services::webauthn::WebAuthnService;
use crate::state::AppState;
use crate::store::users::UserStore;
use crate::store::webauthn_challenges::WebAuthnChallengeStore;
use crate::store::DB;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json},
    Extension,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterStartRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterStartResponse {
    pub challenge_id: String,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterFinishResponse {
    pub success: bool,
    pub passkey_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyAuthStartRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PasskeyAuthStartResponse {
    pub challenge_id: String,
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyAuthFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct PasskeyAuthFinishResponse {
    pub token: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_trust_token: Option<String>,
}

/// POST /auth/passkeys/register/start
/// Start passkey registration ceremony (requires authenticated user)
pub async fn register_start(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<impl IntoResponse> {
    let db = DB::Conn(&state.db);

    let user = UserStore::find_by_id(db.clone(), &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let existing_passkeys = WebAuthnService::load_user_passkeys(db.clone(), &user.id).await?;

    let exclude_credentials: Vec<CredentialID> = existing_passkeys
        .iter()
        .map(|p| p.cred_id().clone())
        .collect();

    let (challenge_response, passkey_reg) =
        webauthn.start_registration(&user.id, &user.email, &user.email, exclude_credentials)?;

    let challenge_state = serde_json::to_string(&passkey_reg).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize challenge: {}", e))
    })?;

    let challenge_record =
        WebAuthnChallengeStore::create(db, &user.id, "registration", &challenge_state, 300).await?;

    Ok((
        StatusCode::OK,
        Json(PasskeyRegisterStartResponse {
            challenge_id: challenge_record.id,
            options: challenge_response,
        }),
    ))
}

/// POST /auth/passkeys/register/finish
/// Complete passkey registration ceremony (requires authenticated user)
pub async fn register_finish(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<PasskeyRegisterFinishRequest>,
) -> Result<impl IntoResponse> {
    let db = DB::Conn(&state.db);

    let user = UserStore::find_by_id(db.clone(), &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let challenge_record = WebAuthnChallengeStore::find_by_id(db.clone(), &req.challenge_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired challenge".to_string()))?;

    if challenge_record.user_id != user.id {
        return Err(AppError::Unauthorized(
            "Challenge does not belong to user".to_string(),
        ));
    }

    if challenge_record.challenge_type != "registration" {
        return Err(AppError::BadRequest("Invalid challenge type".to_string()));
    }

    let passkey_reg: PasskeyRegistration = serde_json::from_str(&challenge_record.challenge_state)
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to deserialize challenge: {}", e))
        })?;

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let passkey = webauthn.finish_registration(&req.credential, &passkey_reg)?;

    let passkey_name = "My Passkey";

    let passkey_id =
        WebAuthnService::store_passkey(db.clone(), &user.id, &passkey, passkey_name).await?;

    WebAuthnChallengeStore::delete(db, &req.challenge_id).await?;

    tracing::info!(
        user_id = %user.id,
        passkey_id = %passkey_id,
        "Passkey registered successfully"
    );

    Ok((
        StatusCode::OK,
        Json(PasskeyRegisterFinishResponse {
            success: true,
            passkey_id,
        }),
    ))
}

/// POST /auth/passkeys/authenticate/start
/// Start passkey authentication ceremony (public endpoint)
pub async fn authenticate_start(
    State(state): State<AppState>,
    Json(req): Json<PasskeyAuthStartRequest>,
) -> Result<impl IntoResponse> {
    let db = DB::Conn(&state.db);

    let user = UserStore::find_by_email(db.clone(), &req.email)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let passkeys = WebAuthnService::load_user_passkeys(db.clone(), &user.id).await?;

    if passkeys.is_empty() {
        return Err(AppError::BadRequest(
            "No passkeys registered for this user".to_string(),
        ));
    }

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let (challenge_response, passkey_auth) = webauthn.start_authentication(passkeys)?;

    let challenge_state = serde_json::to_string(&passkey_auth).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize challenge: {}", e))
    })?;

    let challenge_record =
        WebAuthnChallengeStore::create(db, &user.id, "authentication", &challenge_state, 300)
            .await?;

    Ok((
        StatusCode::OK,
        Json(PasskeyAuthStartResponse {
            challenge_id: challenge_record.id,
            options: challenge_response,
        }),
    ))
}

/// POST /auth/passkeys/authenticate/finish
/// Complete passkey authentication ceremony and issue JWT (public endpoint)
pub async fn authenticate_finish(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Json(req): Json<PasskeyAuthFinishRequest>,
) -> Result<impl IntoResponse> {
    let db = DB::Conn(&state.db);

    let challenge_record = WebAuthnChallengeStore::find_by_id(db.clone(), &req.challenge_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired challenge".to_string()))?;

    if challenge_record.challenge_type != "authentication" {
        return Err(AppError::BadRequest("Invalid challenge type".to_string()));
    }

    let passkey_auth: PasskeyAuthentication =
        serde_json::from_str(&challenge_record.challenge_state).map_err(|e| {
            AppError::InternalServerError(format!("Failed to deserialize challenge: {}", e))
        })?;

    let webauthn = state
        .webauthn_service
        .as_ref()
        .ok_or_else(|| {
            AppError::InternalServerError("WebAuthn service not configured".to_string())
        })?
        .as_ref();

    let auth_result = webauthn.finish_authentication(&req.credential, &passkey_auth)?;

    let credential_id_value = serde_json::to_value(auth_result.cred_id()).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize credential ID: {}", e))
    })?;

    let credential_id_str = credential_id_value
        .as_str()
        .ok_or_else(|| AppError::InternalServerError("Invalid credential ID format".to_string()))?;

    let new_counter = auth_result.counter();

    WebAuthnService::update_passkey_counter(db.clone(), credential_id_str, new_counter).await?;

    WebAuthnChallengeStore::delete(db.clone(), &req.challenge_id).await?;

    let user = UserStore::find_by_id(db.clone(), &challenge_record.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Determine organization context for risk evaluation
    // Use the user's first (oldest) organization membership if available
    use crate::entities::{memberships, prelude::Memberships};
    use sea_orm::{ColumnTrait, EntityTrait, Order, QueryFilter, QueryOrder};

    let user_membership = Memberships::find()
        .filter(memberships::Column::UserId.eq(&user.id))
        .order_by(memberships::Column::CreatedAt, Order::Asc)
        .one(&db)
        .await?;

    let org_id_opt = user_membership.as_ref().map(|m| m.org_id.as_str());

    // Run risk engine evaluation
    use crate::services::risk_engine::RiskContext;
    let risk_ctx = RiskContext {
        user_id: &user.id,
        org_id: org_id_opt, // Use first organization membership if available
        ip_address: &request_info.ip_address,
        user_agent: &request_info.user_agent,
        device_cookie: None, // No device cookie available during passkey auth
    };

    let risk_assessment = state.risk_engine.evaluate(db.clone(), risk_ctx).await?;

    // Log risk assessment
    tracing::info!(
        user_id = %user.id,
        email = %user.email,
        risk_score = risk_assessment.score,
        risk_action = ?risk_assessment.action,
        risk_factors = ?risk_assessment.factors,
        "Passkey authentication risk assessment"
    );

    // Persist risk assessment to login_events via buffered audit actor (non-blocking)
    {
        use crate::entities::login_events;
        use sea_orm::Set;
        use uuid::Uuid;

        let risk_factors_json = serde_json::to_string(&risk_assessment.factors).ok();

        let event_model = login_events::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user.id.clone()),
            service_id: Set(None), // No service_id for passkey authentication
            provider: Set("passkey".to_string()),
            ip_address: Set(Some(request_info.ip_address.clone())),
            user_agent: Set(Some(request_info.user_agent.clone())),
            risk_score: Set(Some(risk_assessment.score)),
            risk_factors: Set(risk_factors_json),
            geo_country: Set(None),
            geo_city: Set(None),
            geo_lat: Set(None),
            geo_long: Set(None),
            ..Default::default()
        };

        state.audit_actor.log_login(event_model).await;
    }

    // Handle risk engine actions
    use crate::services::risk_engine::RiskAction;
    match risk_assessment.action {
        RiskAction::Allow | RiskAction::LogOnly => {
            // Continue with normal flow
        }
        RiskAction::ChallengeMFA => {
            // Passkey auth should be strong enough, but risk engine demands additional verification
            return Err(AppError::Forbidden(
                "Additional verification required. Please use another login method.".to_string(),
            ));
        }
        RiskAction::Block => {
            tracing::warn!(
                user_id = %user.id,
                email = %user.email,
                risk_score = risk_assessment.score,
                factors = ?risk_assessment.factors,
                "Passkey authentication blocked by risk engine"
            );

            return Err(AppError::Forbidden(
                "Suspicious login detected. Please contact support.".to_string(),
            ));
        }
    }

    let token = state.jwt_service.create_token(
        &user.id,
        &user.email,
        user.is_platform_owner,
        None,
        None,
    )?;

    // Generate device trust cookie if risk assessment allows
    let device_cookie_value = if matches!(risk_assessment.action, RiskAction::Allow) {
        let device_token = state.risk_engine.generate_device_token(&user.id);

        // Store device in database
        use crate::store::user_devices::UserDevicesStore;
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(device_token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let expires_at = (Utc::now() + chrono::Duration::days(90)).naive_utc();

        UserDevicesStore::create(
            db.clone(),
            &user.id,
            &token_hash,
            "Passkey Authentication Device",
            Some(request_info.ip_address.clone()),
            expires_at,
        )
        .await?;

        Some(device_token)
    } else {
        None
    };

    tracing::info!(
        user_id = %user.id,
        email = %user.email,
        "Passkey authentication successful"
    );

    // Add device trust token to response for native clients
    let device_trust_token = device_cookie_value.clone();

    // Prepare response
    let response = PasskeyAuthFinishResponse {
        token,
        user_id: user.id,
        device_trust_token,
    };

    // For web clients, set the cookie if device trust was established
    if let Some(device_token) = device_cookie_value {
        let cookie_value = format!(
            "device_token={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
            device_token,
            90 * 24 * 3600 // 90 days in seconds
        );

        let response = Json(response);
        Ok((
            StatusCode::OK,
            [(header::SET_COOKIE, cookie_value)],
            response,
        )
            .into_response())
    } else {
        Ok((StatusCode::OK, Json(response)).into_response())
    }
}
