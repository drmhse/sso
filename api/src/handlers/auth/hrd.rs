use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{verified_domains::VerifiedDomainStore, DB};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct LookupEmailRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LookupEmailResponse {
    /// The connection ID to use for authentication, if any
    pub connection_id: Option<String>,
    /// The name of the upstream provider, for display purposes
    pub provider_name: Option<String>,
    /// Whether the domain is verified
    pub domain_verified: bool,
    /// The authentication method to use: "upstream", "password", or "oauth"
    pub auth_method: String,
}

/// Home Realm Discovery: Lookup an email address to determine which IdP to use
///
/// This endpoint implements HRD (Home Realm Discovery) which allows users to
/// simply enter their email address, and the system automatically determines
/// which identity provider they should authenticate with.
///
/// # Flow
/// 1. User enters email (e.g., "john@acme.com")
/// 2. System extracts domain ("acme.com")
/// 3. System checks if domain is verified and mapped to an upstream provider
/// 4. Returns the connection ID if found, or indicates fallback auth method
pub async fn lookup_email(
    State(state): State<AppState>,
    Json(payload): Json<LookupEmailRequest>,
) -> Result<Json<LookupEmailResponse>> {
    // Extract domain from email
    let email = payload.email.to_lowercase();
    let domain = email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::BadRequest("Invalid email address".to_string()))?;

    // Look up the domain in verified_domains table
    match VerifiedDomainStore::find_by_domain(DB::Conn(&state.db), domain).await? {
        Some(verified_domain) if verified_domain.verified => {
            // Domain is verified and mapped to an upstream provider
            if let Some(provider_id) = verified_domain.upstream_provider_id {
                // Fetch the upstream provider to get connection_id and name
                use crate::store::upstream_providers::UpstreamProviderStore;
                match UpstreamProviderStore::find_by_id(DB::Conn(&state.db), &provider_id).await? {
                    Some(provider) if provider.enabled => Ok(Json(LookupEmailResponse {
                        connection_id: Some(provider.connection_id),
                        provider_name: Some(provider.name),
                        domain_verified: true,
                        auth_method: "upstream".to_string(),
                    })),
                    _ => {
                        // Provider not found or disabled, fall back to password
                        Ok(Json(LookupEmailResponse {
                            connection_id: None,
                            provider_name: None,
                            domain_verified: true,
                            auth_method: "password".to_string(),
                        }))
                    }
                }
            } else {
                // Domain verified but no upstream provider mapped
                Ok(Json(LookupEmailResponse {
                    connection_id: None,
                    provider_name: None,
                    domain_verified: true,
                    auth_method: "password".to_string(),
                }))
            }
        }
        _ => {
            // Domain not verified or not found, fall back to default OAuth or password
            Ok(Json(LookupEmailResponse {
                connection_id: None,
                provider_name: None,
                domain_verified: false,
                auth_method: "oauth".to_string(),
            }))
        }
    }
}
