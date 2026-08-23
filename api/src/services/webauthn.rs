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

        Self::deserialize_passkeys(passkey_models)
    }

    pub async fn load_user_passkeys_for_public_auth(
        db: DB<'_>,
        user_id: Option<&str>,
    ) -> Result<Vec<Passkey>> {
        let passkey_models = UserPasskeysStore::list_for_public_auth_lookup(db, user_id).await?;
        Self::deserialize_passkeys(passkey_models)
    }

    fn deserialize_passkeys(
        passkey_models: Vec<crate::entities::user_passkeys::Model>,
    ) -> Result<Vec<Passkey>> {
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

    /// Apply the library-validated authentication result to the complete
    /// serialized credential with optimistic concurrency. The denormalized
    /// counter and backup flags are updated in the same statement.
    pub async fn update_passkey_after_authentication(
        db: DB<'_>,
        authentication_result: &AuthenticationResult,
    ) -> Result<()> {
        let credential_id_value =
            serde_json::to_value(authentication_result.cred_id()).map_err(|error| {
                AppError::InternalServerError(format!("Failed to serialize credential ID: {error}"))
            })?;
        let credential_id = credential_id_value.as_str().ok_or_else(|| {
            AppError::InternalServerError("Invalid credential ID format".to_string())
        })?;

        for _ in 0..3 {
            let model = UserPasskeysStore::find_by_credential_id(db.clone(), credential_id)
                .await?
                .ok_or_else(|| AppError::NotFound("Passkey not found".to_string()))?;
            let result_counter = authentication_result.counter() as i64;
            if model.counter > 0 && result_counter <= model.counter {
                return Err(AppError::Unauthorized(
                    "Authenticator counter did not advance".to_string(),
                ));
            }
            let mut passkey = Self::model_to_passkey(&model)?;
            passkey
                .update_credential(authentication_result)
                .ok_or_else(|| {
                    AppError::Unauthorized(
                        "Authenticator result does not match the stored passkey".to_string(),
                    )
                })?;
            let updated_public_key = serde_json::to_string(&passkey).map_err(|error| {
                AppError::InternalServerError(format!(
                    "Failed to serialize updated passkey: {error}"
                ))
            })?;

            if UserPasskeysStore::compare_and_update_after_use(
                db.clone(),
                &model.id,
                &model.public_key,
                &updated_public_key,
                result_counter,
                authentication_result.backup_eligible(),
                authentication_result.backup_state(),
            )
            .await?
            {
                return Ok(());
            }
        }

        Err(AppError::Unauthorized(
            "Passkey state changed concurrently; start authentication again".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_accepts_valid_relying_party_configuration() {
        let service =
            WebAuthnService::new("example.com", "https://example.com", Some("Example SSO"));
        // The builder validates the rp id/origin pairing; a valid pair builds.
        assert!(service.is_ok());

        let service = WebAuthnService::new("example.com", "https://example.com", None);
        assert!(service.is_ok(), "a missing display name is optional");
    }

    #[test]
    fn an_origin_that_is_not_a_url_is_refused_at_construction() {
        let error = WebAuthnService::new("example.com", "not-a-url", None);
        match error {
            Err(AppError::InternalServerError(message)) => {
                assert!(message.contains("Invalid RP origin URL"))
            }
            Err(other_error) => panic!("expected internal error, got {other_error:?}"),
            Ok(_) => panic!("expected construction to fail"),
        }
    }

    #[test]
    fn an_origin_mismatching_the_rp_id_is_refused() {
        // The origin's host must be derivable from the relying party id.
        let error = WebAuthnService::new("example.com", "https://other.example.org", None);
        assert!(error.is_err(), "mismatched rp id/origin must be refused");
    }
}
