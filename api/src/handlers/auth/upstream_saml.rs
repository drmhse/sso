use crate::db::models::UpstreamProvider;
use crate::error::{AppError, Result};
use crate::state::AppState;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;
use uuid::Uuid;

/// SAML SP: Generate AuthnRequest
pub fn generate_authn_request(
    sp_entity_id: &str,
    idp_sso_url: &str,
    acs_url: &str,
) -> Result<(String, String)> {
    let request_id = format!("_{}", Uuid::new_v4());
    let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let authn_request = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{}"
                    Version="2.0"
                    IssueInstant="{}"
                    Destination="{}"
                    AssertionConsumerServiceURL="{}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"#,
        request_id, issue_instant, idp_sso_url, acs_url, sp_entity_id
    );

    // Deflate and Base64 encode for HTTP-Redirect binding
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(authn_request.as_bytes())?;
    let compressed = encoder.finish()?;
    let encoded = BASE64.encode(compressed);

    Ok((encoded, request_id))
}

/// SAML SP: Parse and verify SAMLResponse
/// This is a simplified implementation for the testbed proof
pub async fn process_saml_response(
    _state: &AppState,
    saml_response_b64: &str,
    _provider: &UpstreamProvider,
) -> Result<SamlUserInfo> {
    let saml_response_xml = String::from_utf8(
        BASE64
            .decode(saml_response_b64)
            .map_err(|_| AppError::BadRequest("Invalid base64 in SAMLResponse".to_string()))?,
    )
    .map_err(|_| AppError::BadRequest("Invalid UTF-8 in SAMLResponse".to_string()))?;

    // Security check: No XXE
    validate_xml_no_xxe(&saml_response_xml)?;

    // Extract email from NameID or Attributes
    // In a real implementation, we would also verify the signature here using the provider's certificate
    let email = extract_email_from_saml(&saml_response_xml)?;

    Ok(SamlUserInfo {
        email,
        provider_user_id: None, // Can be extracted from NameID
    })
}

pub struct SamlUserInfo {
    pub email: String,
    pub provider_user_id: Option<String>,
}

fn validate_xml_no_xxe(xml: &str) -> Result<()> {
    let xml_upper = xml.to_uppercase();
    if xml_upper.contains("<!DOCTYPE")
        || xml_upper.contains("<!ENTITY")
        || xml_upper.contains("SYSTEM ")
        || xml_upper.contains("PUBLIC ")
    {
        return Err(AppError::BadRequest("XXE detected in SAML XML".to_string()));
    }
    Ok(())
}

fn extract_email_from_saml(xml: &str) -> Result<String> {
    // Simple regex-based extraction for the proof
    // A real implementation would use a proper XML parser and handle namespaces correctly
    let re = regex::Regex::new(r#"(?i)<saml:NameID[^>]*>([^<]+)</saml:NameID>"#).unwrap();
    if let Some(caps) = re.captures(xml) {
        return Ok(caps.get(1).unwrap().as_str().to_string());
    }

    // Fallback to searching for an email attribute
    let re_attr = regex::Regex::new(r#"(?i)AttributeName="[^"]*email"[^>]*>\s*<saml:AttributeValue[^>]*>([^<]+)</saml:AttributeValue>"#).unwrap();
    if let Some(caps) = re_attr.captures(xml) {
        return Ok(caps.get(1).unwrap().as_str().to_string());
    }

    Err(AppError::BadRequest(
        "Could not find email in SAMLResponse".to_string(),
    ))
}
