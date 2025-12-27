use crate::error::{AppError, Result};
use crate::store::user_passkeys::UserPasskeysStore;
use crate::store::DB;
use webauthn_rs::prelude::*;

/// WebAuthn service for FIDO2 passkey registration and authentication
pub struct WebAuthnService {
    webauthn: Webauthn,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    ///
    /// # Arguments
    /// * `rp_id` - Relying Party ID (domain name, e.g., "example.com")
    /// * `rp_origin` - Relying Party Origin (full URL, e.g., "https://example.com")
    /// * `rp_name` - Relying Party display name (e.g., "Example Corp SSO")
    pub fn new(rp_id: &str, rp_origin: &str, rp_name: Option<&str>) -> Result<Self> {
        let rp_origin_url = Url::parse(rp_origin)
            .map_err(|e| AppError::InternalServerError(format!("Invalid RP origin URL: {}", e)))?;

        let builder = WebauthnBuilder::new(rp_id, &rp_origin_url).map_err(|e| {
            AppError::InternalServerError(format!("Failed to create WebAuthn builder: {:?}", e))
        })?;

        let builder = if let Some(name) = rp_name {
            builder.rp_name(name)
        } else {
            builder
        };

        let webauthn = builder.build().map_err(|e| {
            AppError::InternalServerError(format!("Failed to build WebAuthn: {:?}", e))
        })?;

        Ok(Self { webauthn })
    }

    /// Start passkey registration ceremony
    ///
    /// Returns (CreationChallengeResponse, PasskeyRegistration state)
    /// The state must be stored temporarily (e.g., in session) and passed to finish_registration
    pub fn start_registration(
        &self,
        user_id: &str,
        user_email: &str,
        user_display_name: &str,
        exclude_credentials: Vec<CredentialID>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let user_unique_id = Uuid::parse_str(user_id).unwrap_or_else(|_| Uuid::new_v4());

        let (creation_challenge, passkey_reg) = self
            .webauthn
            .start_passkey_registration(
                user_unique_id,
                user_email,
                user_display_name,
                Some(exclude_credentials),
            )
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to start passkey registration");
                AppError::InternalServerError(format!(
                    "Failed to start passkey registration: {:?}",
                    e
                ))
            })?;

        Ok((creation_challenge, passkey_reg))
    }

    /// Finish passkey registration ceremony
    ///
    /// Verifies the credential and returns the Passkey for storage
    pub fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey> {
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, state)
            .map_err(|e| {
                tracing::warn!(error = ?e, "Passkey registration verification failed");
                AppError::BadRequest(format!("Invalid passkey registration: {:?}", e))
            })?;

        Ok(passkey)
    }

    /// Start passkey authentication ceremony
    ///
    /// Returns (RequestChallengeResponse, PasskeyAuthentication state)
    /// The state must be stored temporarily (e.g., in session) and passed to finish_authentication
    pub fn start_authentication(
        &self,
        allow_credentials: Vec<Passkey>,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        let (auth_challenge, passkey_auth) = self
            .webauthn
            .start_passkey_authentication(&allow_credentials)
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to start passkey authentication");
                AppError::InternalServerError(format!(
                    "Failed to start passkey authentication: {:?}",
                    e
                ))
            })?;

        Ok((auth_challenge, passkey_auth))
    }

    /// Finish passkey authentication ceremony
    ///
    /// Verifies the assertion and updates the passkey credential (counter)
    /// Returns the updated Passkey
    pub fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult> {
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(credential, state)
            .map_err(|e| {
                tracing::warn!(error = ?e, "Passkey authentication verification failed");
                AppError::Unauthorized("Invalid passkey authentication".to_string())
            })?;

        Ok(auth_result)
    }

    /// Store a new passkey in the database after successful registration
    pub async fn store_passkey(
        db: DB<'_>,
        user_id: &str,
        passkey: &Passkey,
        name: &str,
    ) -> Result<String> {
        // Serialize the entire passkey as JSON for easier storage/retrieval
        let passkey_json = serde_json::to_string(passkey).map_err(|e| {
            AppError::InternalServerError(format!("Failed to serialize passkey: {}", e))
        })?;

        // Serialize to JSON Value to extract fields we need for indexing/display
        let passkey_value: serde_json::Value = serde_json::to_value(passkey).map_err(|e| {
            AppError::InternalServerError(format!("Failed to serialize passkey to value: {}", e))
        })?;

        // Extract credential ID for indexing (it's stored as base64 in the JSON)
        let credential_id = passkey_value
            .get("cred_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AppError::InternalServerError("Missing credential ID in passkey".to_string())
            })?
            .to_string();

        // Store serialized passkey in public_key field (we'll use JSON serialization)
        let public_key = passkey_json;

        // Extract authenticator metadata for filtering/display
        let cred = passkey_value.get("cred");

        let aaguid = cred
            .and_then(|c| c.get("aaguid"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let backup_eligible = cred
            .and_then(|c| c.get("backup_eligible"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let backup_state = cred
            .and_then(|c| c.get("backup_state"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Extract transports if available
        let transports = cred
            .and_then(|c| c.get("transports"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            });

        let passkey_model = UserPasskeysStore::create(
            db,
            user_id,
            &credential_id,
            &public_key,
            aaguid,
            name,
            backup_eligible,
            backup_state,
            transports,
        )
        .await?;

        Ok(passkey_model.id)
    }

    /// Load passkeys from database and convert to webauthn-rs Passkey format
    pub async fn load_user_passkeys(db: DB<'_>, user_id: &str) -> Result<Vec<Passkey>> {
        let passkey_models = UserPasskeysStore::list_by_user(db, user_id).await?;

        let mut passkeys = Vec::new();
        for model in passkey_models {
            match Self::model_to_passkey(&model) {
                Ok(passkey) => passkeys.push(passkey),
                Err(e) => {
                    tracing::warn!(
                        passkey_id = %model.id,
                        error = ?e,
                        "Failed to deserialize passkey, skipping"
                    );
                    continue;
                }
            }
        }

        Ok(passkeys)
    }

    /// Convert database model to webauthn-rs Passkey
    /// The passkey is stored as serialized JSON in the public_key field
    fn model_to_passkey(model: &crate::entities::user_passkeys::Model) -> Result<Passkey> {
        let passkey: Passkey = serde_json::from_str(&model.public_key).map_err(|e| {
            AppError::InternalServerError(format!("Failed to deserialize passkey: {}", e))
        })?;

        Ok(passkey)
    }

    /// Update passkey counter after successful authentication
    pub async fn update_passkey_counter(
        db: DB<'_>,
        credential_id: &str,
        new_counter: u32,
    ) -> Result<()> {
        let passkey = UserPasskeysStore::find_by_credential_id(db.clone(), credential_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Passkey not found".to_string()))?;

        UserPasskeysStore::update_after_use(db, &passkey.id, new_counter as i64).await?;

        Ok(())
    }
}
