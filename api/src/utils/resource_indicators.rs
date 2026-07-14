use crate::error::{AppError, Result};

pub const MAX_RESOURCE_URI_LEN: usize = 2048;

pub fn validate_resource_uri(resource: &str) -> Result<()> {
    if resource.trim() != resource || resource.is_empty() {
        return Err(invalid_target("resource must be a non-empty URI"));
    }
    if resource.len() > MAX_RESOURCE_URI_LEN {
        return Err(invalid_target("resource URI is too long"));
    }

    let parsed = oauth2::url::Url::parse(resource)
        .map_err(|_| invalid_target("resource must be an absolute URI"))?;
    if parsed.scheme().is_empty() {
        return Err(invalid_target("resource must be an absolute URI"));
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
}
