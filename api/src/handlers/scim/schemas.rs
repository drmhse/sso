#![allow(dead_code)]

use axum::{
    async_trait,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// SCIM Resource Type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMeta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    pub created: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    pub location: Option<String>,
}

/// SCIM User Name structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

/// SCIM Email structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM User (RFC 7643 Section 4.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub meta: ScimMeta,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<ScimEmail>>,
    pub active: bool,
}

/// SCIM Group Member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupMember {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub member_type: Option<String>,
}

/// SCIM Group (RFC 7643 Section 4.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub meta: ScimMeta,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<ScimGroupMember>>,
}

/// SCIM List Response (RFC 7644 Section 3.4.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: u64,
    pub start_index: u64,
    pub items_per_page: u64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ScimListResponse<T> {
    pub fn new(resources: Vec<T>, total_results: u64, start_index: u64) -> Self {
        let items_per_page = resources.len() as u64;
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
            total_results,
            start_index,
            items_per_page,
            resources,
        }
    }
}

/// SCIM Error Response (RFC 7644 Section 3.12)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    pub detail: String,
}

impl ScimError {
    pub fn new(status: u16, detail: String, scim_type: Option<String>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
            status,
            scim_type,
            detail,
        }
    }

    pub fn not_found(detail: String) -> Self {
        Self::new(404, detail, None)
    }

    pub fn invalid_value(detail: String) -> Self {
        Self::new(400, detail, Some("invalidValue".to_string()))
    }

    pub fn uniqueness(detail: String) -> Self {
        Self::new(409, detail, Some("uniqueness".to_string()))
    }

    pub fn invalid_filter(detail: String) -> Self {
        Self::new(400, detail, Some("invalidFilter".to_string()))
    }

    pub fn unauthorized(detail: String) -> Self {
        Self::new(401, detail, None)
    }

    pub fn invalid_syntax(detail: String) -> Self {
        Self::new(422, detail, Some("invalidSyntax".to_string()))
    }
}

pub fn scim_id_mismatch_error(
    path_id: &str,
    body_id: Option<&str>,
    resource_type: &str,
) -> Option<ScimError> {
    body_id.filter(|id| *id != path_id).map(|id| {
        ScimError::invalid_value(format!(
            "{} id '{}' does not match request path id '{}'",
            resource_type, id, path_id
        ))
    })
}

pub fn scim_patch_schema_error(schemas: &[String]) -> Option<ScimError> {
    if schemas.iter().any(|schema| schema == SCIM_PATCH_SCHEMA) {
        return None;
    }

    Some(ScimError::invalid_value(format!(
        "PATCH request schemas must include {}",
        SCIM_PATCH_SCHEMA
    )))
}

/// Custom SCIM JSON extractor that returns SCIM-formatted errors
/// This wraps Axum's Json extractor and converts rejection errors to SCIM errors
pub struct ScimJson<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for ScimJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ScimJson(value)),
            Err(rejection) => {
                // Convert the rejection to a SCIM error
                let error_detail = format!("Failed to parse request body: {}", rejection);
                let scim_error = ScimError::invalid_syntax(error_detail);
                Err((StatusCode::UNPROCESSABLE_ENTITY, Json(scim_error)).into_response())
            }
        }
    }
}

/// SCIM User creation/update request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<ScimEmail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

/// SCIM Group creation/update request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<ScimGroupMember>>,
}

/// SCIM Patch Operation (RFC 7644 Section 3.5.2)
#[derive(Debug, Clone, Deserialize)]
pub struct ScimPatchOp {
    pub op: String, // "add", "remove", "replace"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// SCIM Patch Request
#[derive(Debug, Clone, Deserialize)]
pub struct ScimPatchRequest {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOp>,
}

// SCIM Schema URNs
pub const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCIM_LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const SCIM_PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scim_user_request_accepts_optional_id_for_put_validation() {
        let request: ScimUserRequest = serde_json::from_value(serde_json::json!({
            "schemas": [SCIM_USER_SCHEMA],
            "id": "user-123",
            "userName": "person@example.com"
        }))
        .expect("deserialize scim user request with id");

        assert_eq!(request.id.as_deref(), Some("user-123"));
        assert_eq!(request.user_name, "person@example.com");
    }

    #[test]
    fn scim_group_request_accepts_optional_id_for_put_validation() {
        let request: ScimGroupRequest = serde_json::from_value(serde_json::json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": "group-123",
            "displayName": "Acme"
        }))
        .expect("deserialize scim group request with id");

        assert_eq!(request.id.as_deref(), Some("group-123"));
        assert_eq!(request.display_name, "Acme");
    }

    #[test]
    fn scim_id_mismatch_error_rejects_conflicting_body_id() {
        let error = scim_id_mismatch_error("path-id", Some("body-id"), "User")
            .expect("mismatched ids should return scim error");

        assert_eq!(error.status, 400);
        assert_eq!(error.scim_type.as_deref(), Some("invalidValue"));
        assert!(error.detail.contains("body-id"));
        assert!(error.detail.contains("path-id"));
    }

    #[test]
    fn scim_id_mismatch_error_allows_missing_or_matching_body_id() {
        assert!(scim_id_mismatch_error("path-id", None, "User").is_none());
        assert!(scim_id_mismatch_error("path-id", Some("path-id"), "User").is_none());
    }

    #[test]
    fn scim_patch_schema_error_requires_patchop_schema() {
        let error = scim_patch_schema_error(&[SCIM_USER_SCHEMA.to_string()])
            .expect("missing PatchOp schema should return scim error");

        assert_eq!(error.status, 400);
        assert_eq!(error.scim_type.as_deref(), Some("invalidValue"));
        assert!(error.detail.contains(SCIM_PATCH_SCHEMA));
    }

    #[test]
    fn scim_patch_schema_error_allows_patchop_schema() {
        assert!(scim_patch_schema_error(&[SCIM_PATCH_SCHEMA.to_string()]).is_none());
    }

    #[test]
    fn scim_patch_request_accepts_standard_field_casing() {
        let request: ScimPatchRequest = serde_json::from_value(serde_json::json!({
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [{
                "op": "replace",
                "path": "userName",
                "value": "person@example.com"
            }]
        }))
        .expect("deserialize standard scim patch request");

        assert_eq!(request.schemas, vec![SCIM_PATCH_SCHEMA.to_string()]);
        assert_eq!(request.operations.len(), 1);
        assert_eq!(request.operations[0].op, "replace");
    }
}
