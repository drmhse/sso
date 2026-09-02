use axum::{extract::Extension, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const ID_JAG_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
const ID_JAG_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";

#[derive(Clone)]
struct RuntimeMetadata {
    base_url: String,
}

#[derive(Serialize)]
struct AuthosConfiguration {
    service: &'static str,
    metadata_version: u8,
    issuer: String,
    jwks_uri: String,
    openid_connect: OpenIdConnectSupport,
    oauth_device_authorization: DeviceAuthorizationMetadata,
    enterprise_managed_authorization: EnterpriseAuthorizationMetadata,
}

#[derive(Serialize)]
struct OpenIdConnectSupport {
    status: &'static str,
    authorization_code_provider: bool,
    id_token_issuance: bool,
}

#[derive(Serialize)]
struct DeviceAuthorizationMetadata {
    status: &'static str,
    device_authorization_endpoint: String,
    token_endpoint: String,
    grant_types_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 1],
}

#[derive(Serialize)]
struct EnterpriseAuthorizationMetadata {
    status: &'static str,
    token_endpoint: String,
    token_endpoint_aliases: [String; 1],
    grant_types_supported: [&'static str; 2],
    authorization_grant_profiles_supported: [&'static str; 1],
    requested_token_types_supported: [&'static str; 1],
    client_authentication: &'static str,
}

fn configuration(base_url: &str) -> AuthosConfiguration {
    let base_url = base_url.trim_end_matches('/');

    AuthosConfiguration {
        service: "AuthOS",
        metadata_version: 1,
        issuer: base_url.to_string(),
        jwks_uri: format!("{base_url}/.well-known/jwks.json"),
        openid_connect: OpenIdConnectSupport {
            status: "unsupported",
            authorization_code_provider: false,
            id_token_issuance: false,
        },
        oauth_device_authorization: DeviceAuthorizationMetadata {
            status: "beta",
            device_authorization_endpoint: format!("{base_url}/auth/device/code"),
            token_endpoint: format!("{base_url}/auth/token"),
            grant_types_supported: [DEVICE_CODE_GRANT],
            token_endpoint_auth_methods_supported: ["none"],
        },
        enterprise_managed_authorization: EnterpriseAuthorizationMetadata {
            status: "beta",
            token_endpoint: format!("{base_url}/oauth/token"),
            token_endpoint_aliases: [format!("{base_url}/oauth2/token")],
            grant_types_supported: [TOKEN_EXCHANGE_GRANT, JWT_BEARER_GRANT],
            authorization_grant_profiles_supported: [ID_JAG_PROFILE],
            requested_token_types_supported: [ID_JAG_TOKEN_TYPE],
            client_authentication:
                "grant-specific: token exchange accepts an authenticated subject token; JWT bearer exchange also requires the service client secret",
        },
    }
}

async fn authos_configuration(
    Extension(metadata): Extension<RuntimeMetadata>,
) -> Json<AuthosConfiguration> {
    Json(configuration(&metadata.base_url))
}

async fn unsupported_standard_discovery() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Runtime capability metadata for the flows AuthOS actually implements.
///
/// AuthOS does not expose OpenID Connect or RFC 8414 authorization-server
/// metadata until it implements a standards authorization endpoint and ID-token
/// issuance. Explicit 404 routes prevent the web-client fallback from turning
/// those discovery probes into a misleading HTML success response.
pub fn routes<S>(base_url: &str) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/.well-known/authos-configuration",
            get(authos_configuration),
        )
        .route(
            "/.well-known/openid-configuration",
            get(unsupported_standard_discovery),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(unsupported_standard_discovery),
        )
        .layer(Extension(RuntimeMetadata {
            base_url: base_url.to_string(),
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    async fn get_json(path: &str) -> (StatusCode, Value) {
        let response = routes::<()>("https://auth.example.test/")
            .oneshot(Request::get(path).body(Body::empty()).expect("request"))
            .await
            .expect("metadata response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("metadata body");
        let json = serde_json::from_slice(&body).expect("JSON metadata");
        (status, json)
    }

    #[tokio::test]
    async fn authos_metadata_advertises_only_implemented_grants_and_endpoints() {
        let (status, metadata) = get_json("/.well-known/authos-configuration").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(metadata["issuer"], "https://auth.example.test");
        assert_eq!(
            metadata["oauth_device_authorization"]["device_authorization_endpoint"],
            "https://auth.example.test/auth/device/code"
        );
        assert_eq!(
            metadata["oauth_device_authorization"]["token_endpoint"],
            "https://auth.example.test/auth/token"
        );
        assert_eq!(
            metadata["oauth_device_authorization"]["grant_types_supported"],
            serde_json::json!([DEVICE_CODE_GRANT])
        );
        assert_eq!(
            metadata["enterprise_managed_authorization"]["token_endpoint"],
            "https://auth.example.test/oauth/token"
        );
        assert_eq!(
            metadata["enterprise_managed_authorization"]["token_endpoint_aliases"],
            serde_json::json!(["https://auth.example.test/oauth2/token"])
        );
        assert_eq!(
            metadata["enterprise_managed_authorization"]["grant_types_supported"],
            serde_json::json!([TOKEN_EXCHANGE_GRANT, JWT_BEARER_GRANT])
        );

        let serialized = metadata.to_string();
        assert!(!serialized.contains("\"authorization_code\""));
        assert!(!serialized.contains("id_token_signing_alg_values_supported"));
        assert!(!serialized.contains("scopes_supported"));
    }

    #[tokio::test]
    async fn metadata_explicitly_marks_oidc_provider_behavior_unsupported() {
        let (_, metadata) = get_json("/.well-known/authos-configuration").await;

        assert_eq!(metadata["openid_connect"]["status"], "unsupported");
        assert_eq!(
            metadata["openid_connect"]["authorization_code_provider"],
            false
        );
        assert_eq!(metadata["openid_connect"]["id_token_issuance"], false);
    }

    #[tokio::test]
    async fn unsupported_standard_discovery_documents_return_not_found() {
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ] {
            let response = routes::<()>("https://auth.example.test")
                .oneshot(Request::get(path).body(Body::empty()).expect("request"))
                .await
                .expect("discovery response");

            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}
