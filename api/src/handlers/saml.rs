use crate::db::models::{SamlCertificateInfo, User};
use crate::error::{with_retrying_transaction, AppError, Json400, Result};
use crate::middleware::{AuthUser, RequestInfo};
use crate::services::permission_service::{PermissionService, CAP_SERVICES_MANAGE};
use crate::services::tier_enforcement::TierService;
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organizations::OrganizationStore, permissions::PermissionsStore,
    saml_signing_keys::SamlSigningKeysStore, saml_states::SamlStateStore, services::ServiceStore,
    DB,
};
use axum::{
    extract::{Extension, Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SerialNumber};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use uuid::Uuid;

/// Maximum decoded XML accepted from a SAML request. This bound is applied
/// after HTTP-Redirect DEFLATE expansion so a small compressed query cannot
/// cause unbounded allocation.
const MAX_SAML_REQUEST_XML_BYTES: usize = 1_048_576;
const MAX_SAML_REQUEST_ENCODED_BYTES: usize = 262_144;

// Security Audit Item 7: XXE (XML External Entity) Prevention
// This function validates XML input to prevent XXE attacks which could lead to:
// - File disclosure (reading local files)
// - SSRF (Server-Side Request Forgery)
// - Denial of Service (billion laughs attack)
fn validate_xml_no_xxe(xml: &str) -> Result<()> {
    // Check for dangerous patterns in a case-insensitive manner
    let xml_upper = xml.to_uppercase();

    // Reject DOCTYPE declarations (could reference external entities)
    if xml_upper.contains("<!DOCTYPE") {
        return Err(AppError::BadRequest(
            "XML external entities (DOCTYPE) are forbidden in SAML requests".to_string(),
        ));
    }

    // Reject ENTITY declarations (could define external entities)
    if xml_upper.contains("<!ENTITY") {
        return Err(AppError::BadRequest(
            "XML external entities (ENTITY) are forbidden in SAML requests".to_string(),
        ));
    }

    // Reject SYSTEM references (external file/URL references)
    if xml_upper.contains("SYSTEM ")
        || xml_upper.contains("SYSTEM\"")
        || xml_upper.contains("SYSTEM'")
    {
        return Err(AppError::BadRequest(
            "XML external entities (SYSTEM) are forbidden in SAML requests".to_string(),
        ));
    }

    // Reject PUBLIC references (external DTD references)
    if xml_upper.contains("PUBLIC ")
        || xml_upper.contains("PUBLIC\"")
        || xml_upper.contains("PUBLIC'")
    {
        return Err(AppError::BadRequest(
            "XML external entities (PUBLIC) are forbidden in SAML requests".to_string(),
        ));
    }

    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedAuthnRequest {
    request_id: Option<String>,
    issuer: Option<String>,
    acs_url: Option<String>,
    destination: Option<String>,
}

fn decode_xml_reference(reference: &quick_xml::events::BytesRef<'_>) -> Result<String> {
    let name = reference.decode().map_err(|error| {
        AppError::BadRequest(format!("Invalid SAMLRequest entity encoding: {}", error))
    })?;
    let encoded = format!("&{};", name);

    quick_xml::escape::unescape(&encoded)
        .map(|value| value.into_owned())
        .map_err(|error| {
            AppError::BadRequest(format!(
                "Invalid or unknown SAMLRequest entity reference: {}",
                error
            ))
        })
}

fn is_authn_request_element(name: &[u8]) -> bool {
    matches!(name, b"samlp:AuthnRequest" | b"AuthnRequest")
}

fn read_saml_xml_bounded(reader: impl Read, operation: &str) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_SAML_REQUEST_XML_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| AppError::BadRequest(format!("Failed to {operation}: {error}")))?;

    if bytes.len() > MAX_SAML_REQUEST_XML_BYTES {
        return Err(AppError::BadRequest(format!(
            "Decoded SAMLRequest exceeds the {MAX_SAML_REQUEST_XML_BYTES}-byte limit"
        )));
    }

    String::from_utf8(bytes)
        .map_err(|error| AppError::BadRequest(format!("Invalid UTF-8 in SAMLRequest: {error}")))
}

/// Decode a SAML request for either HTTP-Redirect (raw RFC 1951 DEFLATE) or
/// HTTP-POST (plain XML) binding while bounding the decoded representation.
fn decode_saml_request_xml(encoded: &str, redirect_binding: bool) -> Result<String> {
    if encoded.len() > MAX_SAML_REQUEST_ENCODED_BYTES {
        return Err(AppError::BadRequest(format!(
            "Encoded SAMLRequest exceeds the {MAX_SAML_REQUEST_ENCODED_BYTES}-byte limit"
        )));
    }

    let payload = BASE64
        .decode(encoded)
        .map_err(|error| AppError::BadRequest(format!("Invalid base64 SAMLRequest: {error}")))?;

    if redirect_binding {
        let decoder = flate2::read::DeflateDecoder::new(payload.as_slice());
        read_saml_xml_bounded(decoder, "inflate SAMLRequest")
    } else {
        read_saml_xml_bounded(payload.as_slice(), "read SAMLRequest")
    }
}

/// Parse the fields AuthOS consumes from an SP-initiated AuthnRequest.
///
/// This stays intentionally separate from XML signature validation. It rejects
/// DTD/entity declarations, malformed XML, malformed attributes, and unknown
/// entity references before returning any request data.
fn parse_authn_request(xml: &str) -> Result<ParsedAuthnRequest> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    validate_xml_no_xxe(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut parsed = ParsedAuthnRequest::default();
    let mut in_issuer = false;
    let mut open_elements = 0_usize;
    let mut seen_authn_request = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(element)) => {
                if open_elements == 0 {
                    if seen_authn_request || !is_authn_request_element(element.name().as_ref()) {
                        return Err(AppError::BadRequest(
                            "SAMLRequest root element must be AuthnRequest".into(),
                        ));
                    }
                    seen_authn_request = true;
                } else if is_authn_request_element(element.name().as_ref()) {
                    return Err(AppError::BadRequest(
                        "SAMLRequest must contain exactly one AuthnRequest element".into(),
                    ));
                }
                open_elements += 1;
                match element.name().as_ref() {
                    b"samlp:AuthnRequest" | b"AuthnRequest" => {
                        for attribute in element.attributes() {
                            let attribute = attribute.map_err(|error| {
                                AppError::BadRequest(format!(
                                    "Invalid SAMLRequest attribute: {}",
                                    error
                                ))
                            })?;
                            let value = attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )
                                .map_err(|error| {
                                    AppError::BadRequest(format!(
                                        "Invalid SAMLRequest attribute value: {}",
                                        error
                                    ))
                                })?
                                .into_owned();

                            match attribute.key.as_ref() {
                                b"ID" => parsed.request_id = Some(value),
                                b"AssertionConsumerServiceURL" => parsed.acs_url = Some(value),
                                b"Destination" => parsed.destination = Some(value),
                                _ => {}
                            }
                        }
                    }
                    b"saml:Issuer" | b"Issuer" => {
                        in_issuer = true;
                        parsed.issuer = Some(String::new());
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(element)) => {
                if open_elements == 0 {
                    if seen_authn_request || !is_authn_request_element(element.name().as_ref()) {
                        return Err(AppError::BadRequest(
                            "SAMLRequest root element must be AuthnRequest".into(),
                        ));
                    }
                    seen_authn_request = true;
                } else if is_authn_request_element(element.name().as_ref()) {
                    return Err(AppError::BadRequest(
                        "SAMLRequest must contain exactly one AuthnRequest element".into(),
                    ));
                }

                if is_authn_request_element(element.name().as_ref()) {
                    for attribute in element.attributes() {
                        let attribute = attribute.map_err(|error| {
                            AppError::BadRequest(format!(
                                "Invalid SAMLRequest attribute: {}",
                                error
                            ))
                        })?;
                        let value = attribute
                            .decoded_and_normalized_value(
                                quick_xml::XmlVersion::Implicit1_0,
                                reader.decoder(),
                            )
                            .map_err(|error| {
                                AppError::BadRequest(format!(
                                    "Invalid SAMLRequest attribute value: {}",
                                    error
                                ))
                            })?
                            .into_owned();

                        match attribute.key.as_ref() {
                            b"ID" => parsed.request_id = Some(value),
                            b"AssertionConsumerServiceURL" => parsed.acs_url = Some(value),
                            b"Destination" => parsed.destination = Some(value),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::End(element)) => {
                if matches!(element.name().as_ref(), b"saml:Issuer" | b"Issuer") {
                    in_issuer = false;
                }
                open_elements = open_elements.checked_sub(1).ok_or_else(|| {
                    AppError::BadRequest(
                        "Error parsing SAMLRequest XML: unexpected closing element".into(),
                    )
                })?;
            }
            Ok(Event::Text(text)) if in_issuer => {
                let decoded = text.decode().map_err(|error| {
                    AppError::BadRequest(format!("Invalid SAMLRequest text encoding: {}", error))
                })?;
                parsed.issuer.get_or_insert_default().push_str(
                    &quick_xml::escape::unescape(&decoded).map_err(|error| {
                        AppError::BadRequest(format!(
                            "Invalid SAMLRequest text escaping: {}",
                            error
                        ))
                    })?,
                );
            }
            Ok(Event::GeneralRef(reference)) if in_issuer => {
                parsed
                    .issuer
                    .get_or_insert_default()
                    .push_str(&decode_xml_reference(&reference)?);
            }
            Ok(Event::DocType(_)) | Ok(Event::GeneralRef(_)) => {
                return Err(AppError::BadRequest(
                    "XML entity declarations and references are forbidden in SAML requests".into(),
                ));
            }
            Ok(Event::Eof) => {
                if open_elements != 0 {
                    return Err(AppError::BadRequest(
                        "Error parsing SAMLRequest XML: unclosed element".into(),
                    ));
                }
                if !seen_authn_request {
                    return Err(AppError::BadRequest(
                        "SAMLRequest root element must be AuthnRequest".into(),
                    ));
                }
                break;
            }
            Err(error) => {
                return Err(AppError::BadRequest(format!(
                    "Error parsing SAMLRequest XML: {}",
                    error
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(parsed)
}

fn escape_html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// SAML Response Builder for deduplicating XML generation
struct SamlResponseBuilder {
    assertion_id: String,
    response_id: String,
    issue_instant: chrono::DateTime<Utc>,
    not_on_or_after: chrono::DateTime<Utc>,
    entity_id: String,
    acs_url: String,
    name_id_format: String,
    email: String,
    sp_entity_id: String,
    attributes: Vec<(String, String)>,
    in_response_to: Option<String>,
}

impl SamlResponseBuilder {
    fn new(
        user_email: &str,
        entity_id: &str,
        acs_url: &str,
        sp_entity_id: &str,
        name_id_format: &str,
        attributes: Vec<(String, String)>,
        in_response_to: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let later = now + Duration::minutes(5); // 5 minutes validity

        Self {
            assertion_id: format!("_{}", Uuid::new_v4()),
            response_id: format!("_{}", Uuid::new_v4()),
            issue_instant: now,
            not_on_or_after: later,
            entity_id: entity_id.to_string(),
            acs_url: acs_url.to_string(),
            name_id_format: name_id_format.to_string(),
            email: user_email.to_string(),
            sp_entity_id: sp_entity_id.to_string(),
            attributes,
            in_response_to,
        }
    }

    fn build_assertion(&self) -> Result<String> {
        use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
        use quick_xml::Writer;
        use std::io::Cursor;

        let mut writer = Writer::new(Cursor::new(Vec::new()));
        let write_error = |error| {
            AppError::InternalServerError(format!("Failed to build SAML assertion XML: {error}"))
        };

        // Start saml:Assertion
        let mut assertion = BytesStart::new("saml:Assertion");
        assertion.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
        assertion.push_attribute(("ID", self.assertion_id.as_str()));
        assertion.push_attribute(("Version", "2.0"));
        assertion.push_attribute(("IssueInstant", self.issue_instant.to_rfc3339().as_str()));
        writer
            .write_event(Event::Start(assertion))
            .map_err(write_error)?;

        // Issuer - properly escaped
        writer
            .write_event(Event::Start(BytesStart::new("saml:Issuer")))
            .map_err(write_error)?;
        writer
            .write_event(Event::Text(BytesText::new(&self.entity_id)))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:Issuer")))
            .map_err(write_error)?;

        // Subject
        writer
            .write_event(Event::Start(BytesStart::new("saml:Subject")))
            .map_err(write_error)?;

        // NameID - user email is properly escaped to prevent injection
        let mut name_id = BytesStart::new("saml:NameID");
        name_id.push_attribute(("Format", self.name_id_format.as_str()));
        writer
            .write_event(Event::Start(name_id))
            .map_err(write_error)?;
        writer
            .write_event(Event::Text(BytesText::new(&self.email)))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:NameID")))
            .map_err(write_error)?;

        // SubjectConfirmation
        let mut subj_conf = BytesStart::new("saml:SubjectConfirmation");
        subj_conf.push_attribute(("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer"));
        writer
            .write_event(Event::Start(subj_conf))
            .map_err(write_error)?;

        // SubjectConfirmationData
        let mut subj_conf_data = BytesStart::new("saml:SubjectConfirmationData");
        if let Some(ref in_response_to) = self.in_response_to {
            subj_conf_data.push_attribute(("InResponseTo", in_response_to.as_str()));
        }
        subj_conf_data.push_attribute(("NotOnOrAfter", self.not_on_or_after.to_rfc3339().as_str()));
        subj_conf_data.push_attribute(("Recipient", self.acs_url.as_str()));
        writer
            .write_event(Event::Empty(subj_conf_data))
            .map_err(write_error)?;

        writer
            .write_event(Event::End(BytesEnd::new("saml:SubjectConfirmation")))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:Subject")))
            .map_err(write_error)?;

        // Conditions
        let mut conditions = BytesStart::new("saml:Conditions");
        conditions.push_attribute(("NotBefore", self.issue_instant.to_rfc3339().as_str()));
        conditions.push_attribute(("NotOnOrAfter", self.not_on_or_after.to_rfc3339().as_str()));
        writer
            .write_event(Event::Start(conditions))
            .map_err(write_error)?;

        writer
            .write_event(Event::Start(BytesStart::new("saml:AudienceRestriction")))
            .map_err(write_error)?;
        writer
            .write_event(Event::Start(BytesStart::new("saml:Audience")))
            .map_err(write_error)?;
        writer
            .write_event(Event::Text(BytesText::new(&self.sp_entity_id)))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:Audience")))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:AudienceRestriction")))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:Conditions")))
            .map_err(write_error)?;

        // AuthnStatement
        let mut authn_stmt = BytesStart::new("saml:AuthnStatement");
        authn_stmt.push_attribute(("AuthnInstant", self.issue_instant.to_rfc3339().as_str()));
        writer
            .write_event(Event::Start(authn_stmt))
            .map_err(write_error)?;

        writer
            .write_event(Event::Start(BytesStart::new("saml:AuthnContext")))
            .map_err(write_error)?;
        writer
            .write_event(Event::Start(BytesStart::new("saml:AuthnContextClassRef")))
            .map_err(write_error)?;
        writer
            .write_event(Event::Text(BytesText::new(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
            )))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:AuthnContextClassRef")))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:AuthnContext")))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:AuthnStatement")))
            .map_err(write_error)?;

        writer
            .write_event(Event::Start(BytesStart::new("saml:AttributeStatement")))
            .map_err(write_error)?;
        for (name, value) in &self.attributes {
            let mut attribute = BytesStart::new("saml:Attribute");
            attribute.push_attribute(("Name", name.as_str()));
            writer
                .write_event(Event::Start(attribute))
                .map_err(write_error)?;
            writer
                .write_event(Event::Start(BytesStart::new("saml:AttributeValue")))
                .map_err(write_error)?;
            writer
                .write_event(Event::Text(BytesText::new(value)))
                .map_err(write_error)?;
            writer
                .write_event(Event::End(BytesEnd::new("saml:AttributeValue")))
                .map_err(write_error)?;
            writer
                .write_event(Event::End(BytesEnd::new("saml:Attribute")))
                .map_err(write_error)?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("saml:AttributeStatement")))
            .map_err(write_error)?;

        // End Assertion
        writer
            .write_event(Event::End(BytesEnd::new("saml:Assertion")))
            .map_err(write_error)?;

        String::from_utf8(writer.into_inner().into_inner()).map_err(|error| {
            AppError::InternalServerError(format!("SAML assertion was not valid UTF-8: {error}"))
        })
    }

    fn build_response(&self, assertion_with_signature: &str) -> Result<String> {
        use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
        use quick_xml::Writer;
        use std::io::Cursor;

        let mut writer = Writer::new(Cursor::new(Vec::new()));
        let write_error = |error| {
            AppError::InternalServerError(format!("Failed to build SAML response XML: {error}"))
        };

        // Start samlp:Response
        let mut response = BytesStart::new("samlp:Response");
        response.push_attribute(("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol"));
        response.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
        response.push_attribute(("ID", self.response_id.as_str()));
        response.push_attribute(("Version", "2.0"));

        if let Some(ref in_response_to) = self.in_response_to {
            response.push_attribute(("InResponseTo", in_response_to.as_str()));
        }

        response.push_attribute(("IssueInstant", self.issue_instant.to_rfc3339().as_str()));
        response.push_attribute(("Destination", self.acs_url.as_str()));
        writer
            .write_event(Event::Start(response))
            .map_err(write_error)?;

        // Issuer
        writer
            .write_event(Event::Start(BytesStart::new("saml:Issuer")))
            .map_err(write_error)?;
        writer
            .write_event(Event::Text(BytesText::new(&self.entity_id)))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("saml:Issuer")))
            .map_err(write_error)?;

        // Status
        writer
            .write_event(Event::Start(BytesStart::new("samlp:Status")))
            .map_err(write_error)?;
        let mut status_code = BytesStart::new("samlp:StatusCode");
        status_code.push_attribute(("Value", "urn:oasis:names:tc:SAML:2.0:status:Success"));
        writer
            .write_event(Event::Empty(status_code))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new("samlp:Status")))
            .map_err(write_error)?;

        // Write the signed assertion raw (since it's already built and signed)
        // Use from_escaped to treat the input as raw XML (not escaping it)
        writer
            .write_event(Event::Text(BytesText::from_escaped(
                assertion_with_signature,
            )))
            .map_err(write_error)?;

        // End samlp:Response
        writer
            .write_event(Event::End(BytesEnd::new("samlp:Response")))
            .map_err(write_error)?;

        String::from_utf8(writer.into_inner().into_inner()).map_err(|error| {
            AppError::InternalServerError(format!("SAML response was not valid UTF-8: {error}"))
        })
    }

    fn get_assertion_id(&self) -> &str {
        &self.assertion_id
    }

    fn get_response_id(&self) -> &str {
        &self.response_id
    }
}

fn insert_signature_after_issuer(xml: &str, signature: &str) -> Result<String> {
    const ISSUER_END: &str = "</saml:Issuer>";
    let insertion_point = xml.find(ISSUER_END).ok_or_else(|| {
        AppError::InternalServerError(
            "Generated SAML XML did not contain the expected Issuer element".into(),
        )
    })? + ISSUER_END.len();

    let mut signed = String::with_capacity(xml.len() + signature.len());
    signed.push_str(&xml[..insertion_point]);
    signed.push_str(signature);
    signed.push_str(&xml[insertion_point..]);
    Ok(signed)
}

fn build_logout_response_xml(
    response_id: &str,
    issue_instant: &chrono::DateTime<Utc>,
    destination: &str,
    in_response_to: &str,
    entity_id: &str,
) -> Result<String> {
    use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
    use quick_xml::Writer;
    use std::io::Cursor;

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let write_error = |error| {
        AppError::InternalServerError(format!("Failed to build SAML logout response: {error}"))
    };

    let mut response = BytesStart::new("samlp:LogoutResponse");
    response.push_attribute(("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol"));
    response.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
    response.push_attribute(("ID", response_id));
    response.push_attribute(("Version", "2.0"));
    response.push_attribute(("IssueInstant", issue_instant.to_rfc3339().as_str()));
    response.push_attribute(("Destination", destination));
    response.push_attribute(("InResponseTo", in_response_to));
    writer
        .write_event(Event::Start(response))
        .map_err(write_error)?;

    writer
        .write_event(Event::Start(BytesStart::new("saml:Issuer")))
        .map_err(write_error)?;
    writer
        .write_event(Event::Text(BytesText::new(entity_id)))
        .map_err(write_error)?;
    writer
        .write_event(Event::End(BytesEnd::new("saml:Issuer")))
        .map_err(write_error)?;

    writer
        .write_event(Event::Start(BytesStart::new("samlp:Status")))
        .map_err(write_error)?;
    let mut status = BytesStart::new("samlp:StatusCode");
    status.push_attribute(("Value", "urn:oasis:names:tc:SAML:2.0:status:Success"));
    writer
        .write_event(Event::Empty(status))
        .map_err(write_error)?;
    writer
        .write_event(Event::End(BytesEnd::new("samlp:Status")))
        .map_err(write_error)?;
    writer
        .write_event(Event::End(BytesEnd::new("samlp:LogoutResponse")))
        .map_err(write_error)?;

    String::from_utf8(writer.into_inner().into_inner()).map_err(|error| {
        AppError::InternalServerError(format!("SAML logout response was not valid UTF-8: {error}"))
    })
}

#[allow(clippy::too_many_arguments)]
fn build_saml_metadata_xml(
    entity_id: &str,
    certificate: &str,
    name_id_format: &str,
    sso_url: &str,
    slo_url: &str,
    organization_name: &str,
    organization_url: &str,
) -> Result<String> {
    use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
    use quick_xml::Writer;
    use std::io::Cursor;

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let write_error = |error| {
        AppError::InternalServerError(format!("Failed to build SAML metadata XML: {error}"))
    };
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .map_err(write_error)?;

    let mut entity = BytesStart::new("EntityDescriptor");
    entity.push_attribute(("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata"));
    entity.push_attribute(("entityID", entity_id));
    writer
        .write_event(Event::Start(entity))
        .map_err(write_error)?;

    let mut idp = BytesStart::new("IDPSSODescriptor");
    idp.push_attribute(("WantAuthnRequestsSigned", "false"));
    idp.push_attribute((
        "protocolSupportEnumeration",
        "urn:oasis:names:tc:SAML:2.0:protocol",
    ));
    writer.write_event(Event::Start(idp)).map_err(write_error)?;

    let mut key_descriptor = BytesStart::new("KeyDescriptor");
    key_descriptor.push_attribute(("use", "signing"));
    writer
        .write_event(Event::Start(key_descriptor))
        .map_err(write_error)?;
    let mut key_info = BytesStart::new("KeyInfo");
    key_info.push_attribute(("xmlns", "http://www.w3.org/2000/09/xmldsig#"));
    writer
        .write_event(Event::Start(key_info))
        .map_err(write_error)?;
    writer
        .write_event(Event::Start(BytesStart::new("X509Data")))
        .map_err(write_error)?;
    writer
        .write_event(Event::Start(BytesStart::new("X509Certificate")))
        .map_err(write_error)?;
    writer
        .write_event(Event::Text(BytesText::new(certificate)))
        .map_err(write_error)?;
    for name in ["X509Certificate", "X509Data", "KeyInfo", "KeyDescriptor"] {
        writer
            .write_event(Event::End(BytesEnd::new(name)))
            .map_err(write_error)?;
    }

    writer
        .write_event(Event::Start(BytesStart::new("NameIDFormat")))
        .map_err(write_error)?;
    writer
        .write_event(Event::Text(BytesText::new(name_id_format)))
        .map_err(write_error)?;
    writer
        .write_event(Event::End(BytesEnd::new("NameIDFormat")))
        .map_err(write_error)?;

    for binding in [
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    ] {
        let mut service = BytesStart::new("SingleSignOnService");
        service.push_attribute(("Binding", binding));
        service.push_attribute(("Location", sso_url));
        writer
            .write_event(Event::Empty(service))
            .map_err(write_error)?;
    }
    for binding in [
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    ] {
        let mut service = BytesStart::new("SingleLogoutService");
        service.push_attribute(("Binding", binding));
        service.push_attribute(("Location", slo_url));
        writer
            .write_event(Event::Empty(service))
            .map_err(write_error)?;
    }
    writer
        .write_event(Event::End(BytesEnd::new("IDPSSODescriptor")))
        .map_err(write_error)?;

    writer
        .write_event(Event::Start(BytesStart::new("Organization")))
        .map_err(write_error)?;
    for (element_name, value) in [
        ("OrganizationName", organization_name),
        ("OrganizationDisplayName", organization_name),
        ("OrganizationURL", organization_url),
    ] {
        let mut element = BytesStart::new(element_name);
        element.push_attribute(("xml:lang", "en"));
        writer
            .write_event(Event::Start(element))
            .map_err(write_error)?;
        writer
            .write_event(Event::Text(BytesText::new(value)))
            .map_err(write_error)?;
        writer
            .write_event(Event::End(BytesEnd::new(element_name)))
            .map_err(write_error)?;
    }
    writer
        .write_event(Event::End(BytesEnd::new("Organization")))
        .map_err(write_error)?;
    writer
        .write_event(Event::End(BytesEnd::new("EntityDescriptor")))
        .map_err(write_error)?;

    String::from_utf8(writer.into_inner().into_inner()).map_err(|error| {
        AppError::InternalServerError(format!("SAML metadata was not valid UTF-8: {error}"))
    })
}

// XML Signing Helper Functions

/// Sign an XML element using XML-DSIG with RSA-SHA256
fn sign_xml_element(
    xml_element: &str,
    element_id: &str,
    private_key_pem: &str,
    public_cert_pem: &str,
) -> Result<String> {
    let private_key = PKey::private_key_from_pem(private_key_pem.as_bytes()).map_err(|e| {
        tracing::error!(
            "Failed to parse private key. PEM preview: {}",
            &private_key_pem.chars().take(100).collect::<String>()
        );
        AppError::InternalServerError(format!("Failed to parse private key: {}", e))
    })?;

    // Canonicalize the XML element (basic C14N - remove extra whitespace, normalize)
    let canonical_xml = canonicalize_xml(xml_element)?;

    // Compute SHA-256 digest
    let mut hasher = Sha256::new();
    hasher.update(canonical_xml.as_bytes());
    let digest = hasher.finalize();
    let digest_b64 = BASE64.encode(digest);

    // Create SignedInfo element with namespace for canonicalization
    let signed_info_for_signing = format!(
        r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <ds:Reference URI="#{element_id}">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digest_b64}</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>"##,
        element_id = element_id,
        digest_b64 = digest_b64
    );

    // Create SignedInfo element without redundant namespace for final output
    let signed_info = format!(
        r##"<ds:SignedInfo>
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <ds:Reference URI="#{element_id}">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digest_b64}</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>"##,
        element_id = element_id,
        digest_b64 = digest_b64
    );

    // Canonicalize SignedInfo (use version with namespace)
    let canonical_signed_info = canonicalize_xml(&signed_info_for_signing)?;

    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
        .map_err(|e| AppError::InternalServerError(format!("Failed to create signer: {}", e)))?;
    signer
        .update(canonical_signed_info.as_bytes())
        .map_err(|e| AppError::InternalServerError(format!("Failed to update signer: {}", e)))?;
    let signature = signer
        .sign_to_vec()
        .map_err(|e| AppError::InternalServerError(format!("Failed to sign XML: {}", e)))?;

    let signature_b64 = BASE64.encode(signature);

    // Extract certificate content (remove PEM headers/footers)
    let cert_content = public_cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    // Build the Signature element with ds: prefix
    let signature_element = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
{signed_info}
  <ds:SignatureValue>{signature_b64}</ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>{cert_content}</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>"##,
        signed_info = signed_info,
        signature_b64 = signature_b64,
        cert_content = cert_content
    );

    Ok(signature_element)
}

/// Exclusive XML Canonicalization (exc-c14n) implementation
/// Implements http://www.w3.org/2001/10/xml-exc-c14n# algorithm
fn canonicalize_xml(xml: &str) -> Result<String> {
    use quick_xml::events::{BytesEnd, BytesText, Event};
    use quick_xml::{Reader, Writer};
    use std::borrow::Cow;
    use std::io::Cursor;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false); // Don't auto-trim - we handle whitespace
    reader.config_mut().expand_empty_elements = true; // Convert empty elements to start/end pairs

    let mut output = Vec::new();
    let mut writer = Writer::new(Cursor::new(&mut output));

    // Track namespace stack for exclusive rendering
    let mut ns_stack: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];

    let mut buf = Vec::new();
    let mut open_elements = 0_usize;
    let mut root_elements = 0_usize;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(_)) => {
                // XML declaration is omitted in canonical form
            }
            Ok(Event::Start(e)) => {
                if open_elements == 0 {
                    root_elements += 1;
                }
                open_elements += 1;
                let sorted_element = canonicalize_start_element(&e, &mut ns_stack)?;
                writer
                    .write_event(Event::Start(sorted_element))
                    .map_err(|error| {
                        AppError::InternalServerError(format!(
                            "Failed to canonicalize XML start element: {error}"
                        ))
                    })?;
            }
            Ok(Event::End(e)) => {
                open_elements = open_elements.checked_sub(1).ok_or_else(|| {
                    AppError::InternalServerError(
                        "Cannot canonicalize XML with an unexpected closing element".into(),
                    )
                })?;
                // Pop namespace scope
                if ns_stack.len() > 1 {
                    ns_stack.pop();
                }
                writer
                    .write_event(Event::End(e.to_owned()))
                    .map_err(|error| {
                        AppError::InternalServerError(format!(
                            "Failed to canonicalize XML end element: {error}"
                        ))
                    })?;
            }
            Ok(Event::Empty(e)) => {
                // Empty elements are expanded to start/end pairs by reader config
                // But handle if we still get one
                if open_elements == 0 {
                    root_elements += 1;
                }
                let sorted_element = canonicalize_start_element(&e, &mut ns_stack)?;
                let end_name: Cow<'static, str> =
                    Cow::Owned(String::from_utf8_lossy(e.name().as_ref()).into_owned());
                writer
                    .write_event(Event::Start(sorted_element))
                    .and_then(|_| writer.write_event(Event::End(BytesEnd::new(end_name))))
                    .map_err(|error| {
                        AppError::InternalServerError(format!(
                            "Failed to canonicalize empty XML element: {error}"
                        ))
                    })?;
                if ns_stack.len() > 1 {
                    ns_stack.pop();
                }
            }
            Ok(Event::Text(e)) => {
                // Normalize text content - preserve significant whitespace
                let decoded = e.decode().map_err(|error| {
                    AppError::InternalServerError(format!(
                        "Cannot canonicalize invalid XML text encoding: {error}"
                    ))
                })?;
                let text = quick_xml::escape::unescape(&decoded).map_err(|error| {
                    AppError::InternalServerError(format!(
                        "Cannot canonicalize invalid XML text escaping: {error}"
                    ))
                })?;
                let normalized = normalize_text(&text);
                writer
                    .write_event(Event::Text(BytesText::new(&normalized)))
                    .map_err(|error| {
                        AppError::InternalServerError(format!(
                            "Failed to canonicalize XML text: {error}"
                        ))
                    })?;
            }
            Ok(Event::Comment(_)) => {
                // Comments are omitted in canonical form (without comments variant)
            }
            Ok(Event::PI(_)) => {
                // Processing instructions are preserved but we omit for SAML
            }
            Ok(Event::CData(e)) => {
                // CDATA sections are replaced with their character content
                let text = e.decode().map_err(|error| {
                    AppError::InternalServerError(format!(
                        "Cannot canonicalize invalid XML CDATA encoding: {error}"
                    ))
                })?;
                let normalized = normalize_text(&text);
                writer
                    .write_event(Event::Text(BytesText::new(&normalized)))
                    .map_err(|error| {
                        AppError::InternalServerError(format!(
                            "Failed to canonicalize XML CDATA: {error}"
                        ))
                    })?;
            }
            Ok(Event::GeneralRef(reference)) => {
                let decoded = decode_xml_reference(&reference)?;
                writer
                    .write_event(Event::Text(BytesText::new(&decoded)))
                    .map_err(|error| {
                        AppError::InternalServerError(format!(
                            "Failed to canonicalize XML entity reference: {error}"
                        ))
                    })?;
            }
            Ok(Event::Eof) => {
                if open_elements != 0 || root_elements != 1 {
                    return Err(AppError::InternalServerError(
                        "Cannot canonicalize malformed XML: expected exactly one closed root element"
                            .into(),
                    ));
                }
                break;
            }
            Err(error) => {
                return Err(AppError::InternalServerError(format!(
                    "Cannot canonicalize malformed XML: {error}"
                )))
            }
            _ => {}
        }
        buf.clear();
    }

    String::from_utf8(output).map_err(|error| {
        AppError::InternalServerError(format!("Canonical XML was not valid UTF-8: {error}"))
    })
}

/// Canonicalize a start element by sorting namespaces and attributes
fn canonicalize_start_element(
    element: &quick_xml::events::BytesStart,
    ns_stack: &mut Vec<BTreeMap<String, String>>,
) -> Result<quick_xml::events::BytesStart<'static>> {
    use quick_xml::events::BytesStart;

    // Collect namespaces and attributes from the element
    let mut namespaces: BTreeMap<String, String> = BTreeMap::new(); // prefix -> uri
    let mut attributes: BTreeMap<(String, String), String> = BTreeMap::new(); // (ns_uri, local) -> value

    // Get parent namespace scope
    let parent_ns = ns_stack.last().cloned().unwrap_or_default();
    let mut current_ns = parent_ns.clone();

    // Parse all attributes
    for attr in element.attributes() {
        let attr = attr.map_err(|error| {
            AppError::InternalServerError(format!(
                "Cannot canonicalize malformed XML attribute: {error}"
            ))
        })?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|error| {
                AppError::InternalServerError(format!(
                    "Cannot canonicalize invalid XML attribute value: {error}"
                ))
            })?
            .into_owned();

        if key == "xmlns" {
            // Default namespace declaration
            namespaces.insert(String::new(), value.clone());
            current_ns.insert(String::new(), value);
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            // Prefixed namespace declaration
            namespaces.insert(prefix.to_string(), value.clone());
            current_ns.insert(prefix.to_string(), value);
        } else {
            // Regular attribute - store with empty namespace for now
            let (ns_uri, local_name) = if key.contains(':') {
                let parts: Vec<&str> = key.splitn(2, ':').collect();
                let prefix = parts[0];
                let local = parts[1];
                // Look up namespace URI from current scope
                let uri = current_ns.get(prefix).cloned().unwrap_or_default();
                (uri, local.to_string())
            } else {
                (String::new(), key)
            };
            attributes.insert((ns_uri, local_name), value);
        }
    }

    // Push new namespace scope
    ns_stack.push(current_ns.clone());

    // Build the canonicalized element
    let element_name = String::from_utf8_lossy(element.name().as_ref()).into_owned();
    let mut new_element = BytesStart::new(element_name);

    // Add namespace declarations in sorted order (by prefix)
    // Only include namespaces that are:
    // 1. Newly declared in this element (not inherited)
    // 2. Actually used (visibly utilized) - for exc-c14n
    let mut used_prefixes: BTreeSet<String> = BTreeSet::new();

    // Check element name for prefix
    if let Some(colon_pos) = new_element.name().as_ref().iter().position(|&b| b == b':') {
        let prefix =
            String::from_utf8_lossy(&new_element.name().as_ref()[..colon_pos]).into_owned();
        used_prefixes.insert(prefix);
    }

    // Check attributes for prefixes
    for (ns_uri, _) in attributes.keys() {
        if !ns_uri.is_empty() {
            // Find the prefix for this namespace URI
            for (prefix, uri) in &current_ns {
                if uri == ns_uri && !prefix.is_empty() {
                    used_prefixes.insert(prefix.clone());
                }
            }
        }
    }

    // Render namespace declarations that are new in this scope
    for (prefix, uri) in &namespaces {
        // In exc-c14n, only render if visibly utilized OR if it's a new declaration
        let is_new = parent_ns.get(prefix) != Some(uri);
        let is_used = if prefix.is_empty() {
            // Default namespace is always relevant if changed
            true
        } else {
            used_prefixes.contains(prefix)
        };

        if is_new && (is_used || prefix.is_empty()) {
            if prefix.is_empty() {
                new_element.push_attribute(("xmlns", uri.as_str()));
            } else {
                let attr_name = format!("xmlns:{}", prefix);
                new_element.push_attribute((attr_name.as_str(), uri.as_str()));
            }
        }
    }

    // Add attributes sorted by namespace URI, then by local name
    for ((ns_uri, local_name), value) in &attributes {
        // Normalize attribute value according to c14n spec
        let normalized_value = normalize_attribute_value(value);

        if !ns_uri.is_empty() {
            // Find prefix for this namespace
            if let Some(prefix) = current_ns
                .iter()
                .find(|(_, u)| *u == ns_uri)
                .map(|(p, _)| p)
            {
                if !prefix.is_empty() {
                    let attr_name = format!("{}:{}", prefix, local_name);
                    new_element.push_attribute((attr_name.as_str(), normalized_value.as_str()));
                } else {
                    new_element.push_attribute((local_name.as_str(), normalized_value.as_str()));
                }
            } else {
                new_element.push_attribute((local_name.as_str(), normalized_value.as_str()));
            }
        } else {
            new_element.push_attribute((local_name.as_str(), normalized_value.as_str()));
        }
    }

    Ok(new_element)
}

/// Normalize attribute values according to XML C14N spec
/// Note: quick-xml writer handles basic escaping, but we need to ensure
/// specific C14N character replacements for tabs, newlines, carriage returns
fn normalize_attribute_value(value: &str) -> String {
    // According to C14N spec, attribute values should have:
    // - & -> &amp; (handled by quick-xml)
    // - < -> &lt; (handled by quick-xml)
    // - " -> &quot; (handled by quick-xml)
    // - \t (0x9) -> &#x9;
    // - \n (0xA) -> &#xA;
    // - \r (0xD) -> &#xD;
    // We only handle the special whitespace characters here since quick-xml
    // will handle the basic XML escaping when writing
    value
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

/// Normalize text content according to XML C14N spec
/// Note: quick-xml writer handles basic escaping, we just need to handle
/// carriage returns specifically as per C14N
fn normalize_text(text: &str) -> String {
    // According to C14N spec, text content should have:
    // - & -> &amp; (handled by quick-xml)
    // - < -> &lt; (handled by quick-xml)
    // - > -> &gt; (handled by quick-xml when necessary)
    // - \r (0xD) -> &#xD;
    // We only handle carriage returns here
    text.replace('\r', "&#xD;")
}

// Request/Response types

#[derive(Debug, Deserialize, Clone)]
pub struct ConfigureSamlRequest {
    pub enabled: bool,
    pub entity_id: Option<String>,
    pub acs_url: Option<String>,
    pub slo_url: Option<String>,
    pub name_id_format: Option<String>,
    pub attribute_mapping: Option<HashMap<String, String>>,
    pub sign_assertions: Option<bool>,
    pub sign_response: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConfigureSamlResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct SamlConfigResponse {
    pub enabled: bool,
    pub entity_id: Option<String>,
    pub acs_url: Option<String>,
    pub slo_url: Option<String>,
    pub name_id_format: Option<String>,
    pub attribute_mapping: Option<HashMap<String, String>>,
    pub sign_assertions: bool,
    pub sign_response: bool,
    pub has_certificate: bool,
}

#[derive(Debug, Deserialize)]
pub struct SamlSsoQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

// Helper function to check if user can manage service
async fn can_manage_service(
    pool: &sea_orm::DatabaseConnection,
    user_id: &str,
    org_id: &str,
) -> Result<bool> {
    PermissionService::check(DB::Conn(pool), org_id, user_id, CAP_SERVICES_MANAGE).await
}

async fn can_manage_specific_service(
    pool: &sea_orm::DatabaseConnection,
    user_id: &str,
    org_id: &str,
    service_id: &str,
) -> Result<bool> {
    if can_manage_service(pool, user_id, org_id).await? {
        return Ok(true);
    }

    if MembershipStore::find_by_org_and_user(DB::Conn(pool), org_id, user_id)
        .await?
        .is_none()
    {
        return Ok(false);
    }

    PermissionsStore::check(DB::Conn(pool), "service", service_id, "manager", user_id).await
}

// Handler: Configure SAML for a service
pub async fn configure_saml(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, service_slug)): Path<(String, String)>,
    Extension(req_info): Extension<RequestInfo>,
    Json400(req): Json400<ConfigureSamlRequest>,
) -> Result<Json<ConfigureSamlResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Check if org is active
    if org.status != "active" {
        return Err(AppError::Forbidden(
            "Organization must be active to configure SAML".into(),
        ));
    }

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_saml_idp,
        "Enterprise SSO (SAML)",
    )
    .await?;

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    if !can_manage_specific_service(&state.db, &user.user.id, &org.id, &service.id).await? {
        return Err(AppError::Forbidden(
            "You don't have permission to manage this service".into(),
        ));
    }

    // Validate entity_id and acs_url
    if req.enabled {
        let entity_id = req.entity_id.as_ref().ok_or_else(|| {
            AppError::BadRequest("Entity ID is required when SAML is enabled".into())
        })?;

        let acs_url = req.acs_url.as_ref().ok_or_else(|| {
            AppError::BadRequest("ACS URL is required when SAML is enabled".into())
        })?;

        if entity_id.is_empty() {
            return Err(AppError::BadRequest(
                "Entity ID cannot be empty when SAML is enabled".into(),
            ));
        }
        if acs_url.is_empty() {
            return Err(AppError::BadRequest(
                "ACS URL cannot be empty when SAML is enabled".into(),
            ));
        }

        // Validate URLs - must be valid HTTP/HTTPS URLs
        let acs_parsed =
            Url::parse(acs_url).map_err(|_| AppError::BadRequest("Invalid ACS URL".into()))?;
        let acs_scheme = acs_parsed.scheme();
        if acs_scheme != "http" && acs_scheme != "https" {
            return Err(AppError::BadRequest(
                "ACS URL must use HTTP or HTTPS scheme".into(),
            ));
        }
        // Ensure URL has a valid host
        if acs_parsed.host_str().is_none() || acs_parsed.host_str() == Some("") {
            return Err(AppError::BadRequest(
                "ACS URL must have a valid host".into(),
            ));
        }

        if let Some(ref slo_url) = req.slo_url {
            if !slo_url.is_empty() && !slo_url.trim().is_empty() {
                let slo_parsed = Url::parse(slo_url)
                    .map_err(|_| AppError::BadRequest("Invalid SLO URL".into()))?;
                let slo_scheme = slo_parsed.scheme();
                if slo_scheme != "http" && slo_scheme != "https" {
                    return Err(AppError::BadRequest(
                        "SLO URL must use HTTP or HTTPS scheme".into(),
                    ));
                }
                // Ensure URL has a valid host
                if slo_parsed.host_str().is_none() || slo_parsed.host_str() == Some("") {
                    return Err(AppError::BadRequest(
                        "SLO URL must have a valid host".into(),
                    ));
                }
            }
        }
    }

    // Serialize attribute mapping if provided
    let _attribute_mapping_json = req
        .attribute_mapping
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to serialize attribute mapping: {}", e))
        })?;

    // Update service SAML configuration
    // Update service configuration with retry
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "configure_saml",
        |db| {
            let service_id = service.id.clone();
            let req = req.clone();
            Box::pin(async move {
                let name_id_format = req.name_id_format.clone().unwrap_or_else(|| {
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
                });

                ServiceStore::update_saml_config(
                    db.clone(),
                    &service_id,
                    req.enabled,
                    req.entity_id.as_deref(),
                    req.acs_url.as_deref(),
                    req.slo_url.as_deref(),
                    Some(&name_id_format),
                    req.attribute_mapping
                        .as_ref()
                        .map(|m| serde_json::to_string(m).unwrap_or_default())
                        .as_deref(),
                    req.sign_assertions.unwrap_or(true),
                    req.sign_response.unwrap_or(true),
                )
                .await
            })
        },
    )
    .await?;

    // Non-blocking audit via actor
    use crate::services::audit_builder::OrgAuditBuilder;
    let event = OrgAuditBuilder::new(&org.id, Some(&user.user.id), "saml.configured")
        .target("service", &service.id)
        .ip_address(Some(&req_info.ip_address))
        .user_agent(Some(req_info.user_agent.clone()))
        .success(true)
        .details_json(Some(serde_json::json!({
            "action": if req.enabled { "saml_configured" } else { "saml_disabled" },
            "entity_id": req.entity_id,
            "acs_url": req.acs_url
        })))
        .build();
    state.audit_actor.log_org(event).await;

    Ok(Json(ConfigureSamlResponse {
        success: true,
        message: if req.enabled {
            "SAML configuration updated successfully"
        } else {
            "SAML disabled successfully"
        }
        .to_string(),
    }))
}

// Handler: Get SAML configuration
pub async fn get_saml_config(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, service_slug)): Path<(String, String)>,
) -> Result<Json<SamlConfigResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    if !can_manage_specific_service(&state.db, &user.user.id, &org.id, &service.id).await? {
        return Err(AppError::Forbidden(
            "You don't have permission to view this service".into(),
        ));
    }

    // Check if certificate exists
    let count =
        SamlSigningKeysStore::count_active_by_service(DB::Conn(&state.db), &service.id).await?;
    let has_certificate = count > 0;

    // Parse attribute mapping
    let attribute_mapping = service
        .saml_attribute_mapping
        .and_then(|s| serde_json::from_str(&s).ok());

    Ok(Json(SamlConfigResponse {
        enabled: service.saml_enabled,
        entity_id: service.saml_entity_id,
        acs_url: service.saml_acs_url,
        slo_url: service.saml_slo_url,
        name_id_format: service.saml_name_id_format,
        attribute_mapping,
        sign_assertions: service.saml_sign_assertions,
        sign_response: service.saml_sign_response,
        has_certificate,
    }))
}

// Handler: Generate SAML signing certificate
pub async fn generate_saml_certificate(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, service_slug)): Path<(String, String)>,
    Extension(req_info): Extension<RequestInfo>,
) -> Result<Json<SamlCertificateInfo>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Check if org is active
    if org.status != "active" {
        return Err(AppError::Forbidden(
            "Organization must be active to generate SAML certificate".into(),
        ));
    }

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    if !can_manage_specific_service(&state.db, &user.user.id, &org.id, &service.id).await? {
        return Err(AppError::Forbidden(
            "You don't have permission to manage this service".into(),
        ));
    }

    // Check if SAML is enabled
    if !service.saml_enabled {
        return Err(AppError::BadRequest(
            "SAML must be enabled before generating certificate".into(),
        ));
    }

    // Get encryption service
    let encryption = state
        .encryption
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("Encryption service not available".into()))?;

    let rsa_key = Rsa::generate(2048)
        .map_err(|e| AppError::InternalServerError(format!("Failed to generate RSA key: {}", e)))?;
    let key_pair_pem = PKey::from_rsa(rsa_key)
        .and_then(|key| key.private_key_to_pem_pkcs8())
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to encode RSA key to PKCS#8 PEM: {}", e))
        })?;

    let private_key_pem = String::from_utf8(key_pair_pem).map_err(|e| {
        AppError::InternalServerError(format!("Failed to encode private key PEM as UTF-8: {}", e))
    })?;

    // Create rcgen KeyPair from the PEM-encoded private key
    let key_pair = KeyPair::from_pem(&private_key_pem).map_err(|e| {
        AppError::InternalServerError(format!("Failed to create KeyPair from PEM: {}", e))
    })?;

    // Create certificate parameters
    // rcgen 0.13 requires SANs in new()
    let mut params = CertificateParams::new(vec![org.name.clone()]).map_err(|e| {
        AppError::InternalServerError(format!("Failed to create certificate params: {}", e))
    })?;

    // Set validity period using time crate
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365 * 10); // 10 years
    params.serial_number = Some(SerialNumber::from(42));

    // Set Distinguished Name (Subject)
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, format!("{} SAML IdP", org.name));
    distinguished_name.push(DnType::OrganizationName, &org.name);
    params.distinguished_name = distinguished_name;

    // Create certificate using the specific key pair (RSA)
    let cert = params.self_signed(&key_pair).map_err(|e| {
        AppError::InternalServerError(format!("Failed to generate certificate: {}", e))
    })?;

    // Get the certificate PEM (public part)
    let public_cert_pem = cert.pem();

    // Encrypt the PKCS#8 private key
    let private_key_encrypted = encryption.encrypt(&private_key_pem).map_err(|e| {
        AppError::InternalServerError(format!("Failed to encrypt private key: {}", e))
    })?;

    let _key_id = Uuid::new_v4().to_string();
    let valid_from = Utc::now();
    let valid_until = Utc::now() + Duration::days(365 * 3);
    let encryption_key_id = encryption.key_id().to_string();

    // Use standard retry wrapper
    let helper_service_id = service.id.clone();
    let helper_private_key = private_key_encrypted.clone();
    let helper_public_cert = public_cert_pem.clone();
    let helper_key_id = encryption_key_id.clone();

    let cert_info = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "generate_saml_cert",
        |db| {
            let service_id = helper_service_id.clone();
            let private_key_encrypted = helper_private_key.clone();
            let public_cert_pem = helper_public_cert.clone();
            let encryption_key_id = helper_key_id.clone();
            Box::pin(async move {
                use sea_orm::{EntityTrait, QuerySelect};
                // 1. LOCKING: Select the Service row "FOR UPDATE" to serialize concurrent requests
                let _service_lock = crate::entities::services::Entity::find_by_id(&service_id)
                    .lock_exclusive()
                    .one(&db)
                    .await
                    .map_err(|e| {
                        AppError::InternalServerError(format!("Failed to lock service: {}", e))
                    })?
                    .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

                // 2. Check if a recent active certificate already exists
                if let Some(existing_cert) =
                    SamlSigningKeysStore::find_active_by_service(db.clone(), &service_id).await?
                {
                    let created_at =
                        chrono::DateTime::from_naive_utc_and_offset(existing_cert.created_at, Utc);
                    let age = Utc::now().signed_duration_since(created_at);
                    if age.num_seconds() < 1 {
                        return Ok(SamlCertificateInfo {
                            public_key: existing_cert.public_key,
                            valid_from: chrono::DateTime::from_naive_utc_and_offset(
                                existing_cert.valid_from,
                                Utc,
                            ),
                            valid_until: chrono::DateTime::from_naive_utc_and_offset(
                                existing_cert.valid_until,
                                Utc,
                            ),
                            is_active: existing_cert.is_active,
                            created_at,
                        });
                    }
                }

                // 3. Deactivate any existing active keys
                SamlSigningKeysStore::deactivate_all_for_service(db.clone(), &service_id).await?;

                // 4. Insert new certificate
                SamlSigningKeysStore::create(
                    db.clone(),
                    &service_id,
                    private_key_encrypted,
                    &public_cert_pem,
                    &encryption_key_id,
                    valid_from,
                    valid_until,
                    true, // is_active
                )
                .await?;

                Ok(SamlCertificateInfo {
                    public_key: public_cert_pem,
                    valid_from,
                    valid_until,
                    is_active: true,
                    created_at: Utc::now(),
                })
            })
        },
    )
    .await?;

    // Non-blocking audit via actor
    use crate::services::audit_builder::OrgAuditBuilder;
    let event = OrgAuditBuilder::new(&org.id, Some(&user.user.id), "saml.certificate_generated")
        .target("service", &service.id)
        .ip_address(Some(&req_info.ip_address))
        .user_agent(Some(req_info.user_agent.clone()))
        .success(true)
        .details_json(Some(serde_json::json!({
            "action": "saml_certificate_generated",
            "valid_until": valid_until.naive_utc()
        })))
        .build();
    state.audit_actor.log_org(event).await;

    Ok(Json(cert_info))
}

// Handler: Get SAML certificate info
pub async fn get_saml_certificate(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, service_slug)): Path<(String, String)>,
) -> Result<Json<SamlCertificateInfo>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    if !can_manage_specific_service(&state.db, &user.user.id, &org.id, &service.id).await? {
        return Err(AppError::Forbidden(
            "You don't have permission to view this service".into(),
        ));
    }

    // Get active certificate
    let cert = SamlSigningKeysStore::find_active_by_service(DB::Conn(&state.db), &service.id)
        .await?
        .ok_or_else(|| AppError::NotFound("No active SAML certificate found".into()))?;

    Ok(Json(SamlCertificateInfo {
        public_key: cert.public_key,
        valid_from: chrono::DateTime::from_naive_utc_and_offset(cert.valid_from, Utc),
        valid_until: chrono::DateTime::from_naive_utc_and_offset(cert.valid_until, Utc),
        is_active: cert.is_active,
        created_at: chrono::DateTime::from_naive_utc_and_offset(cert.created_at, Utc),
    }))
}

// Handler: Delete SAML configuration
pub async fn delete_saml_config(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, service_slug)): Path<(String, String)>,
    Extension(req_info): Extension<RequestInfo>,
) -> Result<Json<ConfigureSamlResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    if !can_manage_specific_service(&state.db, &user.user.id, &org.id, &service.id).await? {
        return Err(AppError::Forbidden(
            "You don't have permission to manage this service".into(),
        ));
    }

    // Delete SAML configuration
    // Delete SAML configuration with retry
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_saml_config",
        |db| {
            let service_id = service.id.clone();
            Box::pin(async move {
                ServiceStore::update_saml_config(
                    db.clone(),
                    &service_id,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    false,
                    false,
                )
                .await?;

                // Deactivate certificates
                SamlSigningKeysStore::deactivate_all_for_service(db.clone(), &service_id).await
            })
        },
    )
    .await?;

    // Non-blocking audit via actor
    use crate::services::audit_builder::OrgAuditBuilder;
    let event = OrgAuditBuilder::new(&org.id, Some(&user.user.id), "saml.deleted")
        .target("service", &service.id)
        .ip_address(Some(&req_info.ip_address))
        .user_agent(Some(req_info.user_agent.clone()))
        .success(true)
        .details_json(Some(serde_json::json!({"action": "saml_config_deleted"})))
        .build();
    state.audit_actor.log_org(event).await;

    Ok(Json(ConfigureSamlResponse {
        success: true,
        message: "SAML configuration deleted successfully".to_string(),
    }))
}

// Handler: Generate IdP metadata XML
pub async fn saml_metadata(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
) -> Result<Response> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Check if org is active
    if org.status != "active" {
        return Err(AppError::Forbidden("Organization is not active".into()));
    }

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    // Check if SAML is enabled
    if !service.saml_enabled {
        return Err(AppError::NotFound(
            "SAML is not enabled for this service".into(),
        ));
    }

    // Get active certificate
    let cert = SamlSigningKeysStore::find_active_by_service(DB::Conn(&state.db), &service.id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(
                "No active SAML certificate found. Please generate a certificate first.".into(),
            )
        })?;

    // Generate metadata XML
    // Use the configured entity_id from service, fallback to default if not configured
    let entity_id = service
        .saml_entity_id
        .as_ref()
        .cloned()
        .unwrap_or_else(|| format!("{}/saml/{}/{}", state.base_url, org_slug, service_slug));
    let sso_url = format!("{}/saml/{}/{}/sso", state.base_url, org_slug, service_slug);
    let slo_url = format!("{}/saml/{}/{}/slo", state.base_url, org_slug, service_slug);

    // Extract certificate without PEM headers
    let cert_content = cert
        .public_key
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let metadata = build_saml_metadata_xml(
        &entity_id,
        &cert_content,
        service
            .saml_name_id_format
            .as_deref()
            .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        &sso_url,
        &slo_url,
        &org.name,
        &state.base_url,
    )?;

    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/samlmetadata+xml",
        )],
        metadata,
    )
        .into_response())
}

// Handler: SAML SSO initiation (receives SAMLRequest from SP)
pub async fn saml_sso(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    Query(query): Query<SamlSsoQuery>,
) -> Result<Response> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Check if org is active
    if org.status != "active" {
        return Err(AppError::Forbidden("Organization is not active".into()));
    }

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    // Check if SAML is enabled
    if !service.saml_enabled {
        return Err(AppError::BadRequest(
            "SAML is not enabled for this service".into(),
        ));
    }

    // Extract and decode SAMLRequest
    let saml_request_b64 = query
        .saml_request
        .ok_or_else(|| AppError::BadRequest("SAMLRequest parameter is required".into()))?;

    let saml_request_xml = decode_saml_request_xml(&saml_request_b64, true)?;

    let parsed_request = parse_authn_request(&saml_request_xml)?;
    let request_id = parsed_request.request_id;
    let issuer = parsed_request.issuer;
    let acs_url_from_request = parsed_request.acs_url;
    let destination = parsed_request.destination;

    let configured_acs_url = service
        .saml_acs_url
        .clone()
        .ok_or_else(|| AppError::BadRequest("No ACS URL configured for this service".into()))?;

    if let Some(ref requested_acs_url) = acs_url_from_request {
        if requested_acs_url != &configured_acs_url {
            return Err(AppError::BadRequest(
                "SAMLRequest ACS URL does not match service configuration".into(),
            ));
        }
    }

    // Validate destination if present
    if let Some(ref dest) = destination {
        let expected_sso_url = format!("{}/saml/{}/{}/sso", state.base_url, org_slug, service_slug);
        if dest != &expected_sso_url {
            return Err(AppError::BadRequest(
                "SAMLRequest destination does not match this SSO endpoint".into(),
            ));
        }
    }

    let configured_issuer = service.saml_entity_id.clone().ok_or_else(|| {
        AppError::BadRequest("No SAML entity ID configured for this service".into())
    })?;

    match issuer.as_deref() {
        Some(req_issuer) if req_issuer == configured_issuer => {}
        Some(_) => {
            return Err(AppError::BadRequest(
                "SAMLRequest issuer does not match service configuration".into(),
            ));
        }
        None => {
            return Err(AppError::BadRequest(
                "SAMLRequest Issuer is required".into(),
            ));
        }
    }

    // Store SAML state with parsed information
    let state_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(15);
    let binding = Some("HTTP-POST"); // Assume HTTP-POST for response

    SamlStateStore::create(
        DB::Conn(&state.db),
        &state_id,
        &service.id,
        &saml_request_b64,
        query.relay_state.as_deref(),
        &configured_acs_url,
        request_id.as_deref(),
        Some(&configured_issuer),
        binding,
        &expires_at.naive_utc(),
    )
    .await?;

    // Redirect to authentication page
    // The authentication page will need to handle the saml_state parameter
    let auth_url = format!(
        "{}/saml/{}/{}/authenticate?state={}",
        state.base_url, org_slug, service_slug, state_id
    );

    Ok(Redirect::to(&auth_url).into_response())
}

// Handler: SAML authentication page (shows login options)
#[derive(Debug, Deserialize)]
pub struct SamlAuthQuery {
    pub state: String,
}

pub async fn saml_authenticate(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    Query(query): Query<SamlAuthQuery>,
) -> Result<Response> {
    // Verify SAML state exists and is valid
    let is_valid = SamlStateStore::validate_state(DB::Conn(&state.db), &query.state).await?;
    if !is_valid {
        return Err(AppError::BadRequest("Invalid or expired SAML state".into()));
    }

    // Generate HTML page with authentication options
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Sign In</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, system-ui, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ margin: 0 0 30px 0; font-size: 24px; text-align: center; }}
        .btn {{ display: block; width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; text-decoration: none; text-align: center; color: #333; }}
        .btn:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Sign In to Continue</h1>
        <p style="text-align: center; color: #666; margin-bottom: 30px;">Choose a sign-in method</p>
        <a href="/auth/github?org={}&service={}&saml_state={}" class="btn">Continue with GitHub</a>
        <a href="/auth/google?org={}&service={}&saml_state={}" class="btn">Continue with Google</a>
        <a href="/auth/microsoft?org={}&service={}&saml_state={}" class="btn">Continue with Microsoft</a>
    </div>
</body>
</html>"#,
        org_slug,
        service_slug,
        query.state,
        org_slug,
        service_slug,
        query.state,
        org_slug,
        service_slug,
        query.state
    );

    Ok(Html(html).into_response())
}

// Handler: IdP-Initiated SAML Login
// This allows an authenticated user to initiate SSO to a Service Provider
// without requiring a SAMLRequest from the SP (unsolicited SAML response)
pub async fn saml_idp_login(
    State(state): State<AppState>,
    user: AuthUser,
    Path((org_slug, service_slug)): Path<(String, String)>,
) -> Result<Response> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Check if org is active
    if org.status != "active" {
        return Err(AppError::Forbidden("Organization is not active".into()));
    }

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    // Check if SAML is enabled
    if !service.saml_enabled {
        return Err(AppError::BadRequest(
            "SAML is not enabled for this service".into(),
        ));
    }

    // Get ACS URL from service configuration
    let acs_url = service
        .saml_acs_url
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("No ACS URL configured for this service".into()))?;

    // Get signing key
    let signing_key =
        SamlSigningKeysStore::find_active_by_service(DB::Conn(&state.db), &service.id)
            .await?
            .ok_or_else(|| {
                AppError::InternalServerError("No active SAML signing key found".into())
            })?;

    // Decrypt private key
    let encryption = state
        .encryption
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("Encryption service not available".into()))?;

    let private_key_pem = encryption
        .decrypt(&signing_key.private_key_encrypted)
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to decrypt private key: {}", e))
        })?;

    // Build SAML response using SamlResponseBuilder
    let entity_id = format!("{}/saml/{}/{}", state.base_url, org.slug, service.slug);

    // Build SAML response XML
    let name_id_format = service
        .saml_name_id_format
        .as_deref()
        .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

    // Parse attribute mapping if available
    let mut attributes: Vec<(String, String)> = Vec::new();
    attributes.push(("email".to_string(), user.user.email.clone()));

    if let Some(ref attr_mapping_json) = service.saml_attribute_mapping {
        if let Ok(mapping) = serde_json::from_str::<HashMap<String, String>>(attr_mapping_json) {
            // Apply custom attribute mappings
            for (source, saml_attr_name) in mapping.iter() {
                match source.as_str() {
                    "email" => {
                        if saml_attr_name != "email" {
                            attributes.push((saml_attr_name.clone(), user.user.email.clone()));
                        }
                    }
                    "id" => {
                        attributes.push((saml_attr_name.clone(), user.user.id.clone()));
                    }
                    _ => {
                        tracing::warn!("Unknown attribute mapping source: {}", source);
                    }
                }
            }
        }
    }

    // Create SAML Response Builder (IdP-initiated, no InResponseTo)
    let saml_builder = SamlResponseBuilder::new(
        &user.user.email,
        &entity_id,
        acs_url,
        service
            .saml_entity_id
            .as_deref()
            .unwrap_or(&service.client_id),
        name_id_format,
        attributes,
        None, // No InResponseTo for IdP-initiated flow
    );

    // Build the Assertion element using the builder
    let assertion_xml = saml_builder.build_assertion()?;

    // Check if we should sign the assertion
    let sign_assertions = service.saml_sign_assertions;
    let assertion_with_signature = if sign_assertions {
        // Sign the assertion
        let signature = sign_xml_element(
            &assertion_xml,
            saml_builder.get_assertion_id(),
            &private_key_pem,
            &signing_key.public_key,
        )?;

        insert_signature_after_issuer(&assertion_xml, &signature)?
    } else {
        assertion_xml
    };

    // Build the complete SAML Response using the builder
    let response_xml = saml_builder.build_response(&assertion_with_signature)?;

    // Check if we should sign the response
    let sign_response = service.saml_sign_response;
    let saml_response_xml = if sign_response {
        // Sign the response
        let signature = sign_xml_element(
            &response_xml,
            saml_builder.get_response_id(),
            &private_key_pem,
            &signing_key.public_key,
        )?;

        insert_signature_after_issuer(&response_xml, &signature)?
    } else {
        response_xml
    };

    // Base64 encode the response
    let saml_response_b64 = BASE64.encode(saml_response_xml.as_bytes());

    // Generate HTML auto-post form
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Signing you in...</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, system-ui, sans-serif; background: #f5f5f5; padding: 20px; text-align: center; }}
        .container {{ max-width: 400px; margin: 50px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .spinner {{ border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body onload="document.forms[0].submit()">
    <div class="container">
        <div class="spinner"></div>
        <h2>Signing you in...</h2>
        <p style="color: #666;">Please wait while we redirect you to the service.</p>
    </div>
    <form method="post" action="{}" style="display: none;">
        <input type="hidden" name="SAMLResponse" value="{}" />
        <noscript>
            <p>JavaScript is disabled. Please click the button below to continue.</p>
            <input type="submit" value="Continue" />
        </noscript>
    </form>
</body>
</html>"#,
        acs_url, saml_response_b64
    );

    Ok(Html(html).into_response())
}

// Handler: SAML Assertion Consumer Service (generates SAML Response after authentication)
// This will be called from the OAuth callback after successful authentication
pub async fn complete_saml_authentication(
    state: &AppState,
    saml_state_id: &str,
    expected_service_id: Option<&str>,
    user: &User,
) -> Result<Response> {
    // Get SAML state
    let saml_state = SamlStateStore::find_by_state_id(DB::Conn(&state.db), saml_state_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired SAML state".into()))?;

    if expected_service_id != Some(saml_state.service_id.as_str()) {
        return Err(AppError::BadRequest(
            "SAML state does not belong to the OAuth service context".into(),
        ));
    }

    if !SamlStateStore::update_user_id(DB::Conn(&state.db), saml_state_id, &user.id).await? {
        return Err(AppError::BadRequest(
            "Invalid, expired, or already used SAML state".into(),
        ));
    }

    // Get service
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &saml_state.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    // Get organization
    let org = OrganizationStore::find_by_id(DB::Conn(&state.db), &service.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Get signing key
    let signing_key =
        SamlSigningKeysStore::find_active_by_service(DB::Conn(&state.db), &service.id)
            .await?
            .ok_or_else(|| {
                AppError::InternalServerError("No active SAML signing key found".into())
            })?;

    // Decrypt private key
    let encryption = state
        .encryption
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("Encryption service not available".into()))?;

    let private_key_pem = encryption
        .decrypt(&signing_key.private_key_encrypted)
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to decrypt private key: {}", e))
        })?;

    let entity_id = format!("{}/saml/{}/{}", state.base_url, org.slug, service.slug);

    // Build SAML response XML
    let name_id_format = service
        .saml_name_id_format
        .as_deref()
        .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

    // Parse attribute mapping if available
    let mut attributes: Vec<(String, String)> = Vec::new();
    attributes.push(("email".to_string(), user.email.clone()));

    if let Some(ref attr_mapping_json) = service.saml_attribute_mapping {
        if let Ok(mapping) = serde_json::from_str::<HashMap<String, String>>(attr_mapping_json) {
            // Apply custom attribute mappings
            // Format: {"source_field": "saml_attribute_name"}
            // e.g., {"email": "urn:oid:0.9.2342.19200300.100.1.3", "id": "uid"}
            for (source, saml_attr_name) in mapping.iter() {
                match source.as_str() {
                    "email" => {
                        // If email is explicitly mapped, use the custom name
                        if saml_attr_name != "email" {
                            attributes.push((saml_attr_name.clone(), user.email.clone()));
                        }
                    }
                    "id" => {
                        attributes.push((saml_attr_name.clone(), user.id.clone()));
                    }
                    _ => {
                        // Ignore unknown fields for now
                        tracing::warn!("Unknown attribute mapping source: {}", source);
                    }
                }
            }
        }
    }

    let saml_builder = SamlResponseBuilder::new(
        &user.email,
        &entity_id,
        &saml_state.acs_url,
        saml_state
            .issuer
            .as_deref()
            .or(service.saml_entity_id.as_deref())
            .unwrap_or(&service.client_id),
        name_id_format,
        attributes,
        saml_state.request_id.clone(),
    );

    let assertion_xml = saml_builder.build_assertion()?;

    // Check if we should sign the assertion
    let sign_assertions = service.saml_sign_assertions;
    let assertion_with_signature = if sign_assertions {
        // Sign the assertion
        let signature = sign_xml_element(
            &assertion_xml,
            saml_builder.get_assertion_id(),
            &private_key_pem,
            &signing_key.public_key,
        )?;

        insert_signature_after_issuer(&assertion_xml, &signature)?
    } else {
        assertion_xml
    };

    let response_xml = saml_builder.build_response(&assertion_with_signature)?;

    // Check if we should sign the response
    let sign_response = service.saml_sign_response;
    let saml_response_xml = if sign_response {
        // Sign the response
        let signature = sign_xml_element(
            &response_xml,
            saml_builder.get_response_id(),
            &private_key_pem,
            &signing_key.public_key,
        )?;

        insert_signature_after_issuer(&response_xml, &signature)?
    } else {
        response_xml
    };

    // Base64 encode the response
    let saml_response_b64 = BASE64.encode(saml_response_xml.as_bytes());

    // Generate HTML auto-post form
    let relay_state_input = if let Some(ref relay_state) = saml_state.relay_state {
        format!(
            r#"<input type="hidden" name="RelayState" value="{}" />"#,
            escape_html_attr(relay_state)
        )
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML Response</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="post" action="{}">
        <input type="hidden" name="SAMLResponse" value="{}" />
        {}
        <noscript>
            <p>JavaScript is disabled. Please click the button below to continue.</p>
            <input type="submit" value="Continue" />
        </noscript>
    </form>
</body>
</html>"#,
        escape_html_attr(&saml_state.acs_url),
        escape_html_attr(&saml_response_b64),
        relay_state_input
    );

    // Clean up the SAML state
    let _ = SamlStateStore::delete(DB::Conn(&state.db), saml_state_id).await;

    Ok(Html(html).into_response())
}

// Request/Response types for SLO

#[derive(Debug, Deserialize)]
pub struct SamlSloQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SamlSloPostRequest {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

// Handler: SAML Single Logout (SLO)
// Receives LogoutRequest from Service Provider, invalidates sessions, returns LogoutResponse
pub async fn saml_slo(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    Query(query): Query<SamlSloQuery>,
) -> Result<Response> {
    // Extract SAMLRequest from query parameters (HTTP-Redirect binding)
    let saml_request_b64 = query
        .saml_request
        .ok_or_else(|| AppError::BadRequest("SAMLRequest parameter is required".into()))?;

    process_saml_logout_request(
        &state,
        &org_slug,
        &service_slug,
        &saml_request_b64,
        query.relay_state.as_deref(),
        true, // deflated (HTTP-Redirect binding)
    )
    .await
}

// Handler: SAML Single Logout via POST binding
pub async fn saml_slo_post(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    axum::Form(form): axum::Form<SamlSloPostRequest>,
) -> Result<Response> {
    process_saml_logout_request(
        &state,
        &org_slug,
        &service_slug,
        &form.saml_request,
        form.relay_state.as_deref(),
        false, // not deflated (HTTP-POST binding)
    )
    .await
}

// Common function to process SAML LogoutRequest
async fn process_saml_logout_request(
    state: &AppState,
    org_slug: &str,
    service_slug: &str,
    saml_request_b64: &str,
    relay_state: Option<&str>,
    is_deflated: bool,
) -> Result<Response> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Check if org is active
    if org.status != "active" {
        return Err(AppError::Forbidden("Organization is not active".into()));
    }

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".into()))?;

    // Check if SAML is enabled
    if !service.saml_enabled {
        return Err(AppError::BadRequest(
            "SAML is not enabled for this service".into(),
        ));
    }

    let saml_request_xml = decode_saml_request_xml(saml_request_b64, is_deflated)?;

    // Parse XML to extract important fields
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // Security Audit Item 7: Validate XML for XXE attacks before parsing
    validate_xml_no_xxe(&saml_request_xml)?;

    let mut reader = Reader::from_str(&saml_request_xml);
    reader.config_mut().trim_text(true);

    let mut request_id: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut name_id: Option<String> = None;
    let mut name_id_format: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut in_issuer = false;
    let mut in_name_id = false;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                match e.name().as_ref() {
                    b"samlp:LogoutRequest" | b"LogoutRequest" => {
                        // Extract attributes from LogoutRequest element
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"ID" => {
                                    request_id =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                                b"Destination" => {
                                    destination =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                    b"saml:Issuer" | b"Issuer" => {
                        in_issuer = true;
                    }
                    b"saml:NameID" | b"NameID" => {
                        // Extract Format attribute if present
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Format" {
                                name_id_format =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                        in_name_id = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if in_issuer {
                    let decoded = e.decode().map_err(|error| {
                        AppError::BadRequest(format!(
                            "Invalid LogoutRequest issuer encoding: {}",
                            error
                        ))
                    })?;
                    issuer = Some(
                        quick_xml::escape::unescape(&decoded)
                            .map_err(|error| {
                                AppError::BadRequest(format!(
                                    "Invalid LogoutRequest issuer escaping: {}",
                                    error
                                ))
                            })?
                            .into_owned(),
                    );
                    in_issuer = false;
                } else if in_name_id {
                    let decoded = e.decode().map_err(|error| {
                        AppError::BadRequest(format!(
                            "Invalid LogoutRequest NameID encoding: {}",
                            error
                        ))
                    })?;
                    name_id = Some(
                        quick_xml::escape::unescape(&decoded)
                            .map_err(|error| {
                                AppError::BadRequest(format!(
                                    "Invalid LogoutRequest NameID escaping: {}",
                                    error
                                ))
                            })?
                            .into_owned(),
                    );
                    in_name_id = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(AppError::BadRequest(format!(
                    "Error parsing SAMLRequest XML: {}",
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    // Validate required fields
    let request_id =
        request_id.ok_or_else(|| AppError::BadRequest("LogoutRequest ID is required".into()))?;

    let name_id = name_id.ok_or_else(|| AppError::BadRequest("NameID is required".into()))?;

    // Validate destination if present
    if let Some(ref dest) = destination {
        let expected_slo_url = format!("{}/saml/{}/{}/slo", state.base_url, org_slug, service_slug);
        if dest != &expected_slo_url {
            return Err(AppError::BadRequest(
                "SAML LogoutRequest destination does not match this SLO endpoint".into(),
            ));
        }
    }

    let configured_issuer = service.saml_entity_id.as_ref().ok_or_else(|| {
        AppError::BadRequest("No SAML entity ID configured for this service".into())
    })?;

    match issuer.as_deref() {
        Some(req_issuer) if req_issuer == configured_issuer => {}
        Some(_) => {
            return Err(AppError::BadRequest(
                "SAML LogoutRequest issuer does not match service configuration".into(),
            ));
        }
        None => {
            return Err(AppError::BadRequest(
                "SAML LogoutRequest Issuer is required".into(),
            ));
        }
    }

    tracing::warn!(
        name_id = %name_id,
        name_id_format = ?name_id_format,
        service_id = %service.id,
        "Skipping SAML LogoutRequest session invalidation because request signature verification is not implemented"
    );

    // Get signing key for response
    let signing_key =
        SamlSigningKeysStore::find_active_by_service(DB::Conn(&state.db), &service.id)
            .await?
            .ok_or_else(|| {
                AppError::InternalServerError("No active SAML signing key found".into())
            })?;

    // Decrypt private key
    let encryption = state
        .encryption
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("Encryption service not available".into()))?;

    let private_key_pem = encryption
        .decrypt(&signing_key.private_key_encrypted)
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to decrypt private key: {}", e))
        })?;

    // Generate SAML LogoutResponse
    let response_id = format!("_{}", Uuid::new_v4());
    let issue_instant = Utc::now();
    let entity_id = format!("{}/saml/{}/{}", state.base_url, org_slug, service_slug);

    let slo_response_url = service
        .saml_slo_url
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("No SLO URL configured for this service".into()))?;

    let logout_response_xml = build_logout_response_xml(
        &response_id,
        &issue_instant,
        slo_response_url,
        &request_id,
        &entity_id,
    )?;

    // Sign the LogoutResponse if configured
    let sign_response = service.saml_sign_response;
    let saml_response_xml = if sign_response {
        let signature = sign_xml_element(
            &logout_response_xml,
            &response_id,
            &private_key_pem,
            &signing_key.public_key,
        )?;

        insert_signature_after_issuer(&logout_response_xml, &signature)?
    } else {
        logout_response_xml
    };

    // Base64 encode the response
    let saml_response_b64 = BASE64.encode(saml_response_xml.as_bytes());

    // Generate HTML auto-post form to send LogoutResponse back to SP
    let relay_state_input = if let Some(relay) = relay_state {
        format!(
            r#"<input type="hidden" name="RelayState" value="{}" />"#,
            escape_html_attr(relay)
        )
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Logging out...</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, system-ui, sans-serif; background: #f5f5f5; padding: 20px; text-align: center; }}
        .container {{ max-width: 400px; margin: 50px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .spinner {{ border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body onload="document.forms[0].submit()">
    <div class="container">
        <div class="spinner"></div>
        <h2>Logging out...</h2>
        <p style="color: #666;">Please wait while we complete the logout process.</p>
    </div>
    <form method="post" action="{}" style="display: none;">
        <input type="hidden" name="SAMLResponse" value="{}" />
        {}
        <noscript>
            <p>JavaScript is disabled. Please click the button below to continue.</p>
            <input type="submit" value="Continue" />
        </noscript>
    </form>
</body>
</html>"#,
        escape_html_attr(slo_response_url),
        escape_html_attr(&saml_response_b64),
        relay_state_input
    );

    Ok(Html(html).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;

    fn redirect_encode(xml: &str) -> String {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).expect("compress XML");
        BASE64.encode(encoder.finish().expect("finish compression"))
    }

    #[test]
    fn redirect_binding_accepts_deflated_xml_without_declaration() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="request-1"><Issuer>sp.example</Issuer></samlp:AuthnRequest>"#;
        let encoded = redirect_encode(xml);

        assert_eq!(
            decode_saml_request_xml(&encoded, true).expect("decode Redirect request"),
            xml
        );
    }

    #[test]
    fn saml_request_decode_enforces_encoded_and_expanded_limits() {
        let oversized_encoded = "A".repeat(MAX_SAML_REQUEST_ENCODED_BYTES + 1);
        assert!(matches!(
            decode_saml_request_xml(&oversized_encoded, false),
            Err(AppError::BadRequest(message)) if message.contains("Encoded SAMLRequest exceeds")
        ));

        let expanded = "A".repeat(MAX_SAML_REQUEST_XML_BYTES + 1);
        let compressed = redirect_encode(&expanded);
        assert!(compressed.len() < MAX_SAML_REQUEST_ENCODED_BYTES);
        assert!(matches!(
            decode_saml_request_xml(&compressed, true),
            Err(AppError::BadRequest(message)) if message.contains("Decoded SAMLRequest exceeds")
        ));
    }

    #[test]
    fn post_binding_accepts_bounded_plain_xml() {
        let xml = r#"<LogoutRequest ID="logout-1"/>"#;
        assert_eq!(
            decode_saml_request_xml(&BASE64.encode(xml), false).expect("decode POST request"),
            xml
        );
    }

    #[test]
    fn authn_request_parser_decodes_escaped_text_and_attributes() {
        let parsed = parse_authn_request(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="request&amp;42"
                    AssertionConsumerServiceURL="https://sp.example.test/acs?one=1&amp;two=2"
                    Destination="https://idp.example.test/sso?realm=R&amp;mode=login">
                <saml:Issuer>sp&amp;partner&lt;production&gt;</saml:Issuer>
            </samlp:AuthnRequest>"#,
        )
        .expect("valid AuthnRequest should parse");

        assert_eq!(parsed.request_id.as_deref(), Some("request&42"));
        assert_eq!(
            parsed.acs_url.as_deref(),
            Some("https://sp.example.test/acs?one=1&two=2")
        );
        assert_eq!(
            parsed.destination.as_deref(),
            Some("https://idp.example.test/sso?realm=R&mode=login")
        );
        assert_eq!(parsed.issuer.as_deref(), Some("sp&partner<production>"));
    }

    #[test]
    fn authn_request_parser_rejects_mismatched_and_unclosed_xml() {
        let mismatched = r#"<AuthnRequest><Issuer>sp.example</AuthnRequest>"#;
        let unclosed = r#"<AuthnRequest><Issuer>sp.example</Issuer>"#;

        assert!(parse_authn_request(mismatched).is_err());
        assert!(parse_authn_request(unclosed).is_err());
    }

    #[test]
    fn authn_request_parser_requires_one_authn_request_root() {
        let wrong_root = r#"<Issuer>sp.example</Issuer>"#;
        let duplicate_root = r#"<AuthnRequest/><AuthnRequest/>"#;
        let nested_request = r#"<AuthnRequest><AuthnRequest/></AuthnRequest>"#;

        assert!(parse_authn_request(wrong_root).is_err());
        assert!(parse_authn_request(duplicate_root).is_err());
        assert!(parse_authn_request(nested_request).is_err());
    }

    #[test]
    fn authn_request_parser_rejects_malformed_attributes() {
        let duplicate_attribute = r#"<AuthnRequest ID="one" ID="two"/>"#;
        let unterminated_attribute = r#"<AuthnRequest ID="one/>"#;

        assert!(parse_authn_request(duplicate_attribute).is_err());
        assert!(parse_authn_request(unterminated_attribute).is_err());
    }

    #[test]
    fn authn_request_parser_rejects_xxe_doctype() {
        let xxe = r#"<!DOCTYPE AuthnRequest [
            <!ENTITY secret SYSTEM "file:///etc/passwd">
        ]>
        <AuthnRequest ID="request-1">
            <Issuer>&secret;</Issuer>
        </AuthnRequest>"#;

        assert!(parse_authn_request(xxe).is_err());
    }

    #[test]
    fn authn_request_parser_does_not_expand_unknown_entity_references() {
        let entity_reference =
            r#"<AuthnRequest ID="request-1"><Issuer>&external;</Issuer></AuthnRequest>"#;

        assert!(parse_authn_request(entity_reference).is_err());
    }

    #[test]
    fn canonicalization_decodes_then_safely_reescapes_xml_values() {
        let canonical = canonicalize_xml(
            r#"<root z="one&amp;two" a="&quot;quoted&quot;">Tom &amp; Jerry</root>"#,
        )
        .expect("canonicalize valid XML");

        assert_eq!(
            canonical,
            r#"<root a="&quot;quoted&quot;" z="one&amp;two">Tom &amp; Jerry</root>"#
        );
        assert!(!canonical.contains("<Jerry"));
    }

    #[test]
    fn canonicalization_rejects_malformed_xml_instead_of_signing_partial_output() {
        assert!(canonicalize_xml("<root><child></root>").is_err());
        assert!(canonicalize_xml("<one/><two/>").is_err());
        assert!(canonicalize_xml("not XML").is_err());
    }

    #[test]
    fn response_builder_escapes_configurable_and_user_values() {
        let builder = SamlResponseBuilder::new(
            "user<&@example.test",
            "https://idp.example.test/a?x=1&y=2",
            "https://sp.example.test/acs?x=1&y=2",
            "sp<&audience",
            "format\"<&",
            vec![(
                "role\"><evil injected=\"true".to_string(),
                "admin</saml:AttributeValue><evil>".to_string(),
            )],
            Some("request\"<&".to_string()),
        );

        let assertion = builder.build_assertion().expect("build safe assertion");
        let response = builder
            .build_response(&assertion)
            .expect("build safe response");

        assert!(assertion.contains("Name=\"role&quot;&gt;&lt;evil injected=&quot;true\""));
        assert!(assertion.contains("admin&lt;/saml:AttributeValue&gt;&lt;evil&gt;"));
        assert!(!assertion.contains("<evil"));
        assert!(response.contains("Destination=\"https://sp.example.test/acs?x=1&amp;y=2\""));
        assert!(canonicalize_xml(&response).is_ok());
    }

    #[test]
    fn metadata_and_logout_response_escape_configurable_and_request_values() {
        let metadata = build_saml_metadata_xml(
            "entity\"><evil>",
            "certificate<&data",
            "format<&value",
            "https://idp.example.test/sso?x=1&y=2",
            "https://idp.example.test/slo?x=1&y=2",
            "Org </OrganizationName><evil>",
            "https://idp.example.test/?x=1&y=2",
        )
        .expect("build metadata");
        assert!(metadata.contains("entityID=\"entity&quot;&gt;&lt;evil&gt;\""));
        assert!(metadata.contains("Org &lt;/OrganizationName&gt;&lt;evil&gt;"));
        assert!(!metadata.contains("<evil>"));
        assert!(canonicalize_xml(&metadata).is_ok());

        let logout = build_logout_response_xml(
            "response\"><evil>",
            &Utc::now(),
            "https://sp.example.test/slo?x=1&y=2",
            "request\"><evil>",
            "entity<&value",
        )
        .expect("build logout response");
        assert!(logout.contains("InResponseTo=\"request&quot;&gt;&lt;evil&gt;\""));
        assert!(logout.contains("Destination=\"https://sp.example.test/slo?x=1&amp;y=2\""));
        assert!(!logout.contains("<evil>"));
        assert!(canonicalize_xml(&logout).is_ok());
    }

    #[test]
    fn html_attribute_escaping_covers_markup_and_quotes() {
        assert_eq!(escape_html_attr(r#"&<>"'"#), "&amp;&lt;&gt;&quot;&#x27;");
    }
}
