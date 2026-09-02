pub fn normalize_scope_list<I, S>(scopes: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = Vec::new();
    for scope in scopes {
        for part in split_scope_value(scope.as_ref()) {
            if !normalized.iter().any(|existing| existing == &part) {
                normalized.push(part);
            }
        }
    }
    normalized
}

pub fn parse_scope_string(raw: &str) -> Vec<String> {
    match serde_json::from_str::<Vec<String>>(raw) {
        Ok(scopes) => normalize_scope_list(scopes),
        Err(_) => normalize_scope_list([raw]),
    }
}

pub fn parse_optional_scopes(scopes_json: &Option<String>) -> Vec<String> {
    scopes_json
        .as_deref()
        .map(parse_scope_string)
        .unwrap_or_default()
}

pub fn parse_required_scopes(scopes_json: &str) -> Vec<String> {
    parse_scope_string(scopes_json)
}

pub fn scopes_to_json(scopes: &[String]) -> Result<String, serde_json::Error> {
    serde_json::to_string(&normalize_scope_list(scopes))
}

fn split_scope_value(raw: &str) -> impl Iterator<Item = String> + '_ {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_json_scope_array() {
        assert_eq!(
            parse_scope_string(r#"["repo","read:user","user:email"]"#),
            vec!["repo", "read:user", "user:email"]
        );
    }

    #[test]
    fn flattens_comma_joined_json_scope_array_items() {
        assert_eq!(
            parse_scope_string(r#"["read:org,read:user,repo,user:email"]"#),
            vec!["read:org", "read:user", "repo", "user:email"]
        );
    }

    #[test]
    fn parses_space_and_comma_delimited_scope_strings() {
        assert_eq!(
            parse_scope_string("openid, email profile"),
            vec!["openid", "email", "profile"]
        );
    }

    #[test]
    fn normalizes_and_deduplicates_before_serializing() {
        let raw = vec![
            "read:org,read:user".to_string(),
            "read:user".to_string(),
            "repo user:email".to_string(),
        ];
        assert_eq!(
            scopes_to_json(&raw).unwrap(),
            r#"["read:org","read:user","repo","user:email"]"#
        );
    }
}
