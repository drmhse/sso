use crate::error::{AppError, Result};

pub const MAX_RESOURCE_URI_LEN: usize = 2048;

pub fn validate_resource_uri(resource: &str) -> Result<()> {
    if resource.trim() != resource || resource.is_empty() {
        return Err(invalid_target("resource must be a non-empty URI"));
    }
    if resource.len() > MAX_RESOURCE_URI_LEN {
        return Err(invalid_target("resource URI is too long"));
    }
    if resource.eq_ignore_ascii_case("platform") {
        return Err(invalid_target(
            "resource URI uses an AuthOS-reserved audience prefix",
        ));
    }

    let parsed = oauth2::url::Url::parse(resource)
        .map_err(|_| invalid_target("resource must be an absolute URI"))?;
    if parsed.scheme().is_empty() {
        return Err(invalid_target("resource must be an absolute URI"));
    }
    // URI schemes are case-insensitive. Check the parsed scheme so variants
    // such as `ORG:acme` cannot bypass the management-audience reservation.
    if parsed.scheme().eq_ignore_ascii_case("org")
        || parsed.scheme().eq_ignore_ascii_case("service")
    {
        return Err(invalid_target(
            "resource URI uses an AuthOS-reserved audience prefix",
        ));
    }
    if parsed.fragment().is_some() {
        return Err(invalid_target("resource URI must not contain a fragment"));
    }

    Ok(())
}

pub fn validate_requested_resource(
    requested: Option<&str>,
    registered_resources_json: Option<&str>,
) -> Result<Option<String>> {
    let Some(resource) = requested else {
        return Ok(None);
    };

    validate_resource_uri(resource)?;

    let registered_resources = registered_resources_json
        .map(serde_json::from_str::<Vec<String>>)
        .transpose()
        .map_err(|_| AppError::InternalServerError("Invalid service resource URIs".to_string()))?
        .unwrap_or_default();

    if !registered_resources
        .iter()
        .any(|registered| registered == resource)
    {
        return Err(invalid_target(
            "resource is not registered for this service",
        ));
    }

    Ok(Some(resource.to_string()))
}

pub fn resource_from_audience(audience: Option<&str>) -> Option<&str> {
    let audience = audience?;
    // These values are AuthOS's internal management-session audience grammar,
    // even though `org:` and `service:` also happen to parse as URI schemes.
    // Treating them as RFC 8707 resources changes the JWT token profile during
    // MFA completion and can turn a management login into an external token.
    if audience == "platform" || audience.starts_with("org:") || audience.starts_with("service:") {
        return None;
    }
    validate_resource_uri(audience).ok()?;
    Some(audience)
}

fn invalid_target(message: &str) -> AppError {
    AppError::BadRequest(format!("invalid_target: {}", message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_absolute_resource_without_fragment() {
        assert!(validate_resource_uri("https://api.example.com/mcp").is_ok());
        assert!(validate_resource_uri("urn:authos:resource:api").is_ok());
        assert!(validate_resource_uri("/relative").is_err());
        assert!(validate_resource_uri("https://api.example.com/mcp#frag").is_err());
    }

    #[test]
    fn requested_resource_must_be_registered() {
        let registered = serde_json::to_string(&vec!["https://api.example.com/mcp"]).unwrap();

        assert_eq!(
            validate_requested_resource(Some("https://api.example.com/mcp"), Some(&registered))
                .unwrap()
                .as_deref(),
            Some("https://api.example.com/mcp")
        );
        assert!(validate_requested_resource(
            Some("https://other.example.com/mcp"),
            Some(&registered)
        )
        .is_err());
    }

    #[test]
    fn internal_management_audiences_are_not_resource_indicators() {
        assert_eq!(resource_from_audience(Some("platform")), None);
        assert_eq!(resource_from_audience(Some("org:acme")), None);
        assert_eq!(resource_from_audience(Some("service:acme/portal")), None);
        assert_eq!(resource_from_audience(Some("impersonation-session")), None);
        assert_eq!(
            resource_from_audience(Some("https://api.example.com/mcp")),
            Some("https://api.example.com/mcp")
        );
        assert_eq!(
            resource_from_audience(Some("urn:example:custom-resource")),
            Some("urn:example:custom-resource")
        );
        assert!(validate_resource_uri("org:acme").is_err());
        assert!(validate_resource_uri("ORG:acme").is_err());
        assert!(validate_resource_uri("service:acme/portal").is_err());
        assert!(validate_resource_uri("SERVICE:acme/portal").is_err());
    }
}
