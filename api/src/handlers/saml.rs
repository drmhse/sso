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
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SerialNumber};
use reqwest::Url;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use uuid::Uuid;

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
    attribute_statement: String,
    in_response_to: Option<String>,
}

impl SamlResponseBuilder {
    fn new(
        user_email: &str,
        entity_id: &str,
        acs_url: &str,
        sp_entity_id: &str,
        name_id_format: &str,
        attribute_statement: String,
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
            attribute_statement,
            in_response_to,
        }
    }

    fn build_assertion(&self) -> String {
        use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
        use quick_xml::Writer;
        use std::io::Cursor;

        let mut writer = Writer::new(Cursor::new(Vec::new()));

        // Start saml:Assertion
        let mut assertion = BytesStart::new("saml:Assertion");
        assertion.push_attribute(("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion"));
        assertion.push_attribute(("ID", self.assertion_id.as_str()));
        assertion.push_attribute(("Version", "2.0"));
        assertion.push_attribute(("IssueInstant", self.issue_instant.to_rfc3339().as_str()));
        let _ = writer.write_event(Event::Start(assertion));

        // Issuer - properly escaped
        let _ = writer.write_event(Event::Start(BytesStart::new("saml:Issuer")));
        let _ = writer.write_event(Event::Text(BytesText::new(&self.entity_id)));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:Issuer")));

        // Subject
        let _ = writer.write_event(Event::Start(BytesStart::new("saml:Subject")));

        // NameID - user email is properly escaped to prevent injection
        let mut name_id = BytesStart::new("saml:NameID");
        name_id.push_attribute(("Format", self.name_id_format.as_str()));
        let _ = writer.write_event(Event::Start(name_id));
        let _ = writer.write_event(Event::Text(BytesText::new(&self.email)));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:NameID")));

        // SubjectConfirmation
        let mut subj_conf = BytesStart::new("saml:SubjectConfirmation");
        subj_conf.push_attribute(("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer"));
        let _ = writer.write_event(Event::Start(subj_conf));

        // SubjectConfirmationData
        let mut subj_conf_data = BytesStart::new("saml:SubjectConfirmationData");
        if let Some(ref in_response_to) = self.in_response_to {
            subj_conf_data.push_attribute(("InResponseTo", in_response_to.as_str()));
        }
        subj_conf_data.push_attribute(("NotOnOrAfter", self.not_on_or_after.to_rfc3339().as_str()));
        subj_conf_data.push_attribute(("Recipient", self.acs_url.as_str()));
        let _ = writer.write_event(Event::Empty(subj_conf_data));

        let _ = writer.write_event(Event::End(BytesEnd::new("saml:SubjectConfirmation")));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:Subject")));

        // Conditions
        let mut conditions = BytesStart::new("saml:Conditions");
        conditions.push_attribute(("NotBefore", self.issue_instant.to_rfc3339().as_str()));
        conditions.push_attribute(("NotOnOrAfter", self.not_on_or_after.to_rfc3339().as_str()));
        let _ = writer.write_event(Event::Start(conditions));

        let _ = writer.write_event(Event::Start(BytesStart::new("saml:AudienceRestriction")));
        let _ = writer.write_event(Event::Start(BytesStart::new("saml:Audience")));
        let _ = writer.write_event(Event::Text(BytesText::new(&self.sp_entity_id)));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:Audience")));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:AudienceRestriction")));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:Conditions")));

        // AuthnStatement
        let mut authn_stmt = BytesStart::new("saml:AuthnStatement");
        authn_stmt.push_attribute(("AuthnInstant", self.issue_instant.to_rfc3339().as_str()));
        let _ = writer.write_event(Event::Start(authn_stmt));

        let _ = writer.write_event(Event::Start(BytesStart::new("saml:AuthnContext")));
        let _ = writer.write_event(Event::Start(BytesStart::new("saml:AuthnContextClassRef")));
        let _ = writer.write_event(Event::Text(BytesText::new(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
        )));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:AuthnContextClassRef")));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:AuthnContext")));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:AuthnStatement")));

        // AttributeStatement - already formatted, write as raw XML
        let _ = writer.write_event(Event::Start(BytesStart::new("saml:AttributeStatement")));
        // Note: attribute_statement is pre-built; in a full refactor, this should also use Writer
        let _ = writer
            .get_mut()
            .get_mut()
            .extend_from_slice(self.attribute_statement.as_bytes());
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:AttributeStatement")));

        // End Assertion
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:Assertion")));

        String::from_utf8(writer.into_inner().into_inner()).unwrap_or_default()
    }

    fn build_response(&self, assertion_with_signature: &str) -> String {
        use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
        use quick_xml::Writer;
        use std::io::Cursor;

        let mut writer = Writer::new(Cursor::new(Vec::new()));

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
        let _ = writer.write_event(Event::Start(response));

        // Issuer
        let _ = writer.write_event(Event::Start(BytesStart::new("saml:Issuer")));
        let _ = writer.write_event(Event::Text(BytesText::new(&self.entity_id)));
        let _ = writer.write_event(Event::End(BytesEnd::new("saml:Issuer")));

        // Status
        let _ = writer.write_event(Event::Start(BytesStart::new("samlp:Status")));
        let mut status_code = BytesStart::new("samlp:StatusCode");
        status_code.push_attribute(("Value", "urn:oasis:names:tc:SAML:2.0:status:Success"));
        let _ = writer.write_event(Event::Empty(status_code));
        let _ = writer.write_event(Event::End(BytesEnd::new("samlp:Status")));

        // Write the signed assertion raw (since it's already built and signed)
        // Use from_escaped to treat the input as raw XML (not escaping it)
        let _ = writer.write_event(Event::Text(BytesText::from_escaped(
            assertion_with_signature,
        )));

        // End samlp:Response
        let _ = writer.write_event(Event::End(BytesEnd::new("samlp:Response")));

        String::from_utf8(writer.into_inner().into_inner()).unwrap_or_default()
    }

    fn get_assertion_id(&self) -> &str {
        &self.assertion_id
    }

    fn get_response_id(&self) -> &str {
        &self.response_id
    }
}

// XML Signing Helper Functions

/// Sign an XML element using XML-DSIG with RSA-SHA256
fn sign_xml_element(
    xml_element: &str,
    element_id: &str,
    private_key_pem: &str,
    public_cert_pem: &str,
) -> Result<String> {
    // Parse the private key from PKCS#8 PEM format (rcgen's serialize_private_key_pem() output)
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
        tracing::error!(
            "Failed to parse private key. PEM preview: {}",
            &private_key_pem.chars().take(100).collect::<String>()
        );
        AppError::InternalServerError(format!("Failed to parse PKCS#8 private key: {}", e))
    })?;

    // Canonicalize the XML element (basic C14N - remove extra whitespace, normalize)
    let canonical_xml = canonicalize_xml(xml_element);

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
    let canonical_signed_info = canonicalize_xml(&signed_info_for_signing);

    // Sign the SignedInfo using RSA-PKCS#1 v1.5 with SHA-256
    use rsa::pkcs1v15::SigningKey;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key
        .try_sign(canonical_signed_info.as_bytes())
        .map_err(|e| AppError::InternalServerError(format!("Failed to sign XML: {}", e)))?;

    let signature_b64 = BASE64.encode(signature.to_bytes());

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
fn canonicalize_xml(xml: &str) -> String {
    use quick_xml::events::{BytesEnd, BytesText, Event};
    use quick_xml::{Reader, Writer};
    use std::borrow::Cow;
    use std::io::Cursor;

    let mut reader = Reader::from_str(xml);
    reader.trim_text(false); // Don't auto-trim - we handle whitespace
    reader.expand_empty_elements(true); // Convert empty elements to start/end pairs

    let mut output = Vec::new();
    let mut writer = Writer::new(Cursor::new(&mut output));

    // Track namespace stack for exclusive rendering
    let mut ns_stack: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(_)) => {
                // XML declaration is omitted in canonical form
            }
            Ok(Event::Start(e)) => {
                let sorted_element = canonicalize_start_element(&e, &mut ns_stack);
                writer.write_event(Event::Start(sorted_element)).ok();
            }
            Ok(Event::End(e)) => {
                // Pop namespace scope
                if ns_stack.len() > 1 {
                    ns_stack.pop();
                }
                writer.write_event(Event::End(e.to_owned())).ok();
            }
            Ok(Event::Empty(e)) => {
                // Empty elements are expanded to start/end pairs by reader config
                // But handle if we still get one
                let sorted_element = canonicalize_start_element(&e, &mut ns_stack);
                let end_name: Cow<'static, str> =
                    Cow::Owned(String::from_utf8_lossy(e.name().as_ref()).into_owned());
                writer.write_event(Event::Start(sorted_element)).ok();
                writer.write_event(Event::End(BytesEnd::new(end_name))).ok();
                if ns_stack.len() > 1 {
                    ns_stack.pop();
                }
            }
            Ok(Event::Text(e)) => {
                // Normalize text content - preserve significant whitespace
                let text = e.unescape().unwrap_or_default();
                let normalized = normalize_text(&text);
                writer
                    .write_event(Event::Text(BytesText::new(&normalized)))
                    .ok();
            }
            Ok(Event::Comment(_)) => {
                // Comments are omitted in canonical form (without comments variant)
            }
            Ok(Event::PI(_)) => {
                // Processing instructions are preserved but we omit for SAML
            }
            Ok(Event::CData(e)) => {
                // CDATA sections are replaced with their character content
                let text = String::from_utf8_lossy(&e);
                let normalized = normalize_text(&text);
                writer
                    .write_event(Event::Text(BytesText::new(&normalized)))
                    .ok();
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    String::from_utf8_lossy(&output).into_owned()
}

/// Canonicalize a start element by sorting namespaces and attributes
fn canonicalize_start_element(
    element: &quick_xml::events::BytesStart,
    ns_stack: &mut Vec<BTreeMap<String, String>>,
) -> quick_xml::events::BytesStart<'static> {
    use quick_xml::events::BytesStart;

    // Collect namespaces and attributes from the element
    let mut namespaces: BTreeMap<String, String> = BTreeMap::new(); // prefix -> uri
    let mut attributes: BTreeMap<(String, String), String> = BTreeMap::new(); // (ns_uri, local) -> value

    // Get parent namespace scope
    let parent_ns = ns_stack.last().cloned().unwrap_or_default();
    let mut current_ns = parent_ns.clone();

    // Parse all attributes
    for attr_result in element.attributes() {
        if let Ok(attr) = attr_result {
            let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
            let value = attr.unescape_value().unwrap_or_default().into_owned();

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

    new_element
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

    // Generate certificate parameters with RSA key pair
    // Generate 2048-bit RSA key pair for SAML signing using the rsa crate directly
    // This ensures compatibility with the rsa crate's PKCS#8 parser used in signing
    use rand::rngs::OsRng;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    let mut rng = OsRng;
    let bits = 2048;
    let rsa_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| AppError::InternalServerError(format!("Failed to generate RSA key: {}", e)))?;

    // Convert to PKCS#8 PEM for rcgen (rcgen expects PEM format)
    let private_key_pem_for_rcgen =
        rsa_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to encode RSA key to PKCS#8 PEM: {}",
                    e
                ))
            })?;

    // Create rcgen KeyPair from the PEM-encoded private key
    let key_pair = KeyPair::from_pem(private_key_pem_for_rcgen.as_str()).map_err(|e| {
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

    // Convert the RSA private key to PEM format (this will be compatible with rsa crate's parser)
    let private_key_pem = rsa_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to encode private key to PEM: {}", e))
        })?
        .to_string();

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
            let valid_from = valid_from;
            let valid_until = valid_until;

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

    // Build metadata XML manually (samael crate has limited builder support)
    let metadata = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>{}</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{}"/>
  </IDPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">{}</OrganizationName>
    <OrganizationDisplayName xml:lang="en">{}</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">{}</OrganizationURL>
  </Organization>
</EntityDescriptor>"#,
        entity_id,
        cert_content,
        service
            .saml_name_id_format
            .as_deref()
            .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        sso_url,
        sso_url,
        slo_url,
        slo_url,
        org.name,
        org.name,
        state.base_url
    );

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

    // Decode base64
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let saml_request_bytes = BASE64
        .decode(&saml_request_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid base64 SAMLRequest: {}", e)))?;

    // Try to inflate (SAMLRequest is typically deflated for HTTP-Redirect binding)
    // SAML HTTP-Redirect uses raw DEFLATE (RFC 1951) without zlib/gzip wrappers
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    // Try to inflate as raw deflate first (standard for SAML HTTP-Redirect)
    let mut decoder = DeflateDecoder::new(&saml_request_bytes[..]);
    let mut inflated = String::new();
    let saml_request_xml =
        if decoder.read_to_string(&mut inflated).is_ok() && inflated.starts_with("<?xml") {
            // Successfully inflated and looks like XML
            inflated
        } else {
            // Not deflated or inflation failed, treat as raw XML
            String::from_utf8(saml_request_bytes)
                .map_err(|e| AppError::BadRequest(format!("Invalid UTF-8 in SAMLRequest: {}", e)))?
        };

    // Parse XML to extract important fields
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // Security Audit Item 7: Validate XML for XXE attacks before parsing
    validate_xml_no_xxe(&saml_request_xml)?;

    let mut reader = Reader::from_str(&saml_request_xml);
    reader.trim_text(true);

    let mut request_id: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut acs_url_from_request: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut in_issuer = false;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                match e.name().as_ref() {
                    b"samlp:AuthnRequest" | b"AuthnRequest" => {
                        // Extract attributes from AuthnRequest element
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"ID" => {
                                    request_id =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                                b"AssertionConsumerServiceURL" => {
                                    acs_url_from_request =
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
                    _ => {}
                }
            }
            Ok(Event::Text(e)) if in_issuer => {
                issuer = Some(e.unescape().unwrap_or_default().to_string());
                in_issuer = false;
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

    // Validate extracted data
    let acs_url = acs_url_from_request
        .or(service.saml_acs_url.clone())
        .ok_or_else(|| {
            AppError::BadRequest("No ACS URL found in request or service configuration".into())
        })?;

    // Validate destination if present
    if let Some(ref dest) = destination {
        let expected_sso_url = format!("{}/saml/{}/{}/sso", state.base_url, org_slug, service_slug);
        if dest != &expected_sso_url {
            tracing::warn!(
                "SAMLRequest destination mismatch: expected {}, got {}",
                expected_sso_url,
                dest
            );
            // Continue anyway - some SPs send incorrect destinations
        }
    }

    // Validate issuer matches configured entity ID if both are present
    if let (Some(ref req_issuer), Some(ref configured_issuer)) = (&issuer, &service.saml_entity_id)
    {
        if req_issuer != configured_issuer {
            tracing::warn!(
                "SAMLRequest issuer mismatch: expected {}, got {}",
                configured_issuer,
                req_issuer
            );
            // Continue anyway - use the issuer from request
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
        &acs_url,
        request_id.as_deref(),
        issuer.as_deref(),
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

    // Build AttributeStatement XML
    let attribute_statement = attributes
        .iter()
        .map(|(name, value)| {
            format!(
                r#"      <saml:Attribute Name="{}">
        <saml:AttributeValue>{}</saml:AttributeValue>
      </saml:Attribute>"#,
                name, value
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Create SAML Response Builder (IdP-initiated, no InResponseTo)
    let saml_builder = SamlResponseBuilder::new(
        &user.user.email,
        &entity_id,
        &acs_url,
        service
            .saml_entity_id
            .as_deref()
            .unwrap_or(&service.client_id),
        name_id_format,
        attribute_statement,
        None, // No InResponseTo for IdP-initiated flow
    );

    // Build the Assertion element using the builder
    let assertion_xml = saml_builder.build_assertion();

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

        // Insert signature after the Issuer element (use replacen to only match first occurrence)
        assertion_xml.replacen(
            &format!("<saml:Issuer>{}</saml:Issuer>", entity_id),
            &format!("<saml:Issuer>{}</saml:Issuer>{}", entity_id, signature),
            1,
        )
    } else {
        assertion_xml
    };

    // Build the complete SAML Response using the builder
    let response_xml = saml_builder.build_response(&assertion_with_signature);

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

        // Insert signature after the Issuer element (use replacen to only match first occurrence)
        response_xml.replacen(
            &format!("<saml:Issuer>{}</saml:Issuer>", entity_id),
            &format!("<saml:Issuer>{}</saml:Issuer>{}", entity_id, signature),
            1,
        )
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
    user: &User,
) -> Result<Response> {
    // Get SAML state
    let saml_state = SamlStateStore::find_by_state_id(DB::Conn(&state.db), saml_state_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired SAML state".into()))?;

    // Update state with user_id
    SamlStateStore::update_user_id(DB::Conn(&state.db), saml_state_id, &user.id).await?;

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

    // Generate SAML Response
    let response_id = format!("_{}", Uuid::new_v4());
    let assertion_id = format!("_{}", Uuid::new_v4());
    let issue_instant = Utc::now();
    let not_on_or_after = issue_instant + Duration::minutes(5);

    let entity_id = format!("{}/saml/{}/{}", state.base_url, org.slug, service.slug);

    // Build SAML response XML
    let name_id_format = service
        .saml_name_id_format
        .as_deref()
        .unwrap_or("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

    // Build InResponseTo attribute if we have a request ID
    let in_response_to_attr = if let Some(ref req_id) = saml_state.request_id {
        format!(r#" InResponseTo="{}"#, req_id)
    } else {
        String::new()
    };

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

    // Build AttributeStatement XML
    let attribute_statement = attributes
        .iter()
        .map(|(name, value)| {
            format!(
                r#"      <saml:Attribute Name="{}">
        <saml:AttributeValue>{}</saml:AttributeValue>
      </saml:Attribute>"#,
                name, value
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Build the Assertion element
    let assertion_xml = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>{entity_id}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="{name_id_format}">{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData{in_response_to} NotOnOrAfter="{not_on_or_after}" Recipient="{acs_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{issue_instant}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{sp_entity_id}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issue_instant}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
{attribute_statement}
    </saml:AttributeStatement>
  </saml:Assertion>"#,
        assertion_id = assertion_id,
        in_response_to = in_response_to_attr,
        issue_instant = issue_instant.naive_utc(),
        not_on_or_after = not_on_or_after.naive_utc(),
        entity_id = entity_id,
        acs_url = saml_state.acs_url,
        name_id_format = name_id_format,
        email = user.email,
        sp_entity_id = saml_state
            .issuer
            .as_deref()
            .or(service.saml_entity_id.as_deref())
            .unwrap_or(&service.client_id),
        attribute_statement = attribute_statement,
    );

    // Check if we should sign the assertion
    let sign_assertions = service.saml_sign_assertions;
    let assertion_with_signature = if sign_assertions {
        // Sign the assertion
        let signature = sign_xml_element(
            &assertion_xml,
            &assertion_id,
            &private_key_pem,
            &signing_key.public_key,
        )?;

        // Insert signature after the Issuer element
        assertion_xml.replace(
            &format!("    <saml:Issuer>{}</saml:Issuer>", entity_id),
            &format!(
                "    <saml:Issuer>{}</saml:Issuer>\n    {}",
                entity_id, signature
            ),
        )
    } else {
        assertion_xml
    };

    // Build the complete SAML Response
    let response_xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0"{in_response_to} IssueInstant="{issue_instant}" Destination="{acs_url}">
  <saml:Issuer>{entity_id}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {assertion}
</samlp:Response>"#,
        response_id = response_id,
        in_response_to = in_response_to_attr,
        issue_instant = issue_instant.naive_utc(),
        acs_url = saml_state.acs_url,
        entity_id = entity_id,
        assertion = assertion_with_signature,
    );

    // Check if we should sign the response
    let sign_response = service.saml_sign_response;
    let saml_response_xml = if sign_response {
        // Sign the response
        let signature = sign_xml_element(
            &response_xml,
            &response_id,
            &private_key_pem,
            &signing_key.public_key,
        )?;

        // Insert signature after the Issuer element
        response_xml.replace(
            &format!("  <saml:Issuer>{}</saml:Issuer>", entity_id),
            &format!(
                "  <saml:Issuer>{}</saml:Issuer>\n  {}",
                entity_id, signature
            ),
        )
    } else {
        response_xml
    };

    // Base64 encode the response
    let saml_response_b64 = BASE64.encode(saml_response_xml.as_bytes());

    // Generate HTML auto-post form
    let relay_state_input = if let Some(ref relay_state) = saml_state.relay_state {
        format!(
            r#"<input type="hidden" name="RelayState" value="{}" />"#,
            relay_state
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
        saml_state.acs_url, saml_response_b64, relay_state_input
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
    use crate::store::{sessions::SessionStore, users::UserStore};

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

    // Decode base64
    let saml_request_bytes = BASE64
        .decode(saml_request_b64)
        .map_err(|e| AppError::BadRequest(format!("Invalid base64 SAMLRequest: {}", e)))?;

    // Try to inflate if deflated (HTTP-Redirect binding)
    let saml_request_xml = if is_deflated {
        use flate2::read::DeflateDecoder;
        use std::io::Read;

        // Check for various compression formats
        if saml_request_bytes.len() > 2
            && saml_request_bytes[0] == 0x78
            && (saml_request_bytes[1] == 0x9C
                || saml_request_bytes[1] == 0xDA
                || saml_request_bytes[1] == 0x01)
        {
            // Looks like deflated data (zlib header)
            let mut decoder = DeflateDecoder::new(&saml_request_bytes[..]);
            let mut inflated = String::new();
            decoder.read_to_string(&mut inflated).map_err(|e| {
                AppError::BadRequest(format!("Failed to inflate SAMLRequest: {}", e))
            })?;
            inflated
        } else {
            // Try raw deflate without zlib header
            let mut decoder =
                flate2::read::DeflateDecoder::new(std::io::Cursor::new(&saml_request_bytes));
            let mut inflated = String::new();
            match decoder.read_to_string(&mut inflated) {
                Ok(_) => inflated,
                Err(_) => {
                    // Not compressed, treat as raw XML
                    String::from_utf8(saml_request_bytes.clone()).map_err(|e| {
                        AppError::BadRequest(format!("Invalid UTF-8 in SAMLRequest: {}", e))
                    })?
                }
            }
        }
    } else {
        // Not compressed (HTTP-POST binding)
        String::from_utf8(saml_request_bytes)
            .map_err(|e| AppError::BadRequest(format!("Invalid UTF-8 in SAMLRequest: {}", e)))?
    };

    // Parse XML to extract important fields
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // Security Audit Item 7: Validate XML for XXE attacks before parsing
    validate_xml_no_xxe(&saml_request_xml)?;

    let mut reader = Reader::from_str(&saml_request_xml);
    reader.trim_text(true);

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
                    issuer = Some(e.unescape().unwrap_or_default().to_string());
                    in_issuer = false;
                } else if in_name_id {
                    name_id = Some(e.unescape().unwrap_or_default().to_string());
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
            tracing::warn!(
                "SAML LogoutRequest destination mismatch: expected {}, got {}",
                expected_slo_url,
                dest
            );
            // Continue anyway - some SPs send incorrect destinations
        }
    }

    // Validate issuer matches configured entity ID if both are present
    if let (Some(ref req_issuer), Some(ref configured_issuer)) = (&issuer, &service.saml_entity_id)
    {
        if req_issuer != configured_issuer {
            tracing::warn!(
                "SAML LogoutRequest issuer mismatch: expected {}, got {}",
                configured_issuer,
                req_issuer
            );
            // Continue anyway for flexibility
        }
    }

    // Find user by NameID (typically email)
    // The NameID format determines how we interpret it
    let user = match name_id_format.as_deref() {
        Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        | Some("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")
        | None => {
            // Assume email format
            UserStore::find_by_email(DB::Conn(&state.db), &name_id).await?
        }
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        | Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified") => {
            // Try to interpret as user ID or email
            if name_id.contains('@') {
                UserStore::find_by_email(DB::Conn(&state.db), &name_id).await?
            } else {
                // Could be a user ID
                UserStore::find_by_id(DB::Conn(&state.db), &name_id).await?
            }
        }
        Some(format) => {
            tracing::warn!("Unsupported NameID format: {}", format);
            // Try email as fallback
            UserStore::find_by_email(DB::Conn(&state.db), &name_id).await?
        }
    };

    // Invalidate user sessions for this service
    let sessions_deleted = if let Some(user) = user {
        tracing::info!(
            "Processing SAML SLO for user {} in service {}",
            user.email,
            service.slug
        );
        SessionStore::delete_user_service_sessions(DB::Conn(&state.db), &user.id, &service.id)
            .await?
    } else {
        tracing::warn!(
            "User not found for SAML SLO NameID: {} (format: {:?})",
            name_id,
            name_id_format
        );
        0
    };

    tracing::info!(
        "SAML SLO: Deleted {} sessions for NameID {} in service {}",
        sessions_deleted,
        name_id,
        service.slug
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

    // Determine SLO response URL
    // Priority: Service's configured SLO URL, or use the issuer
    let slo_response_url = service
        .saml_slo_url
        .as_ref()
        .or(issuer.as_ref())
        .ok_or_else(|| {
            AppError::BadRequest("No SLO URL configured and no issuer in request".into())
        })?;

    // Build the SAML LogoutResponse
    let logout_response_xml = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{slo_url}" InResponseTo="{in_response_to}">
  <saml:Issuer>{entity_id}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>"#,
        response_id = response_id,
        issue_instant = issue_instant.naive_utc(),
        slo_url = slo_response_url,
        in_response_to = request_id,
        entity_id = entity_id,
    );

    // Sign the LogoutResponse if configured
    let sign_response = service.saml_sign_response;
    let saml_response_xml = if sign_response {
        let signature = sign_xml_element(
            &logout_response_xml,
            &response_id,
            &private_key_pem,
            &signing_key.public_key,
        )?;

        // Insert signature after the Issuer element
        logout_response_xml.replace(
            &format!("  <saml:Issuer>{}</saml:Issuer>", entity_id),
            &format!(
                "  <saml:Issuer>{}</saml:Issuer>\n  {}",
                entity_id, signature
            ),
        )
    } else {
        logout_response_xml
    };

    // Base64 encode the response
    let saml_response_b64 = BASE64.encode(saml_response_xml.as_bytes());

    // Generate HTML auto-post form to send LogoutResponse back to SP
    let relay_state_input = if let Some(relay) = relay_state {
        format!(
            r#"<input type="hidden" name="RelayState" value="{}" />"#,
            relay
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
        slo_response_url, saml_response_b64, relay_state_input
    );

    Ok(Html(html).into_response())
}
