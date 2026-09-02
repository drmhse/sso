use crate::crypto::safe_http::is_private_or_reserved_ip;
use crate::error::{AppError, Result};
use reqwest::header::HOST;
use std::net::IpAddr;
use std::time::Duration;

const MAX_VERIFICATION_BODY_BYTES: u64 = 1024;

pub fn normalize_verifiable_domain(domain: &str) -> Result<String> {
    let normalized = domain.trim().trim_end_matches('.').to_lowercase();

    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.contains("..")
        || normalized.contains('/')
        || normalized.contains(':')
        || normalized.contains('@')
        || normalized.contains('\\')
    {
        return Err(AppError::BadRequest("Invalid domain format".to_string()));
    }

    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.len() < 2 {
        return Err(AppError::BadRequest("Invalid domain format".to_string()));
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(AppError::BadRequest("Invalid domain format".to_string()));
        }

        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err(AppError::BadRequest("Invalid domain format".to_string()));
        }

        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(AppError::BadRequest("Invalid domain format".to_string()));
        }
    }

    if !labels
        .last()
        .is_some_and(|tld| tld.as_bytes().iter().any(u8::is_ascii_alphabetic))
    {
        return Err(AppError::BadRequest("Invalid domain format".to_string()));
    }

    Ok(normalized)
}

pub async fn verify_dns_txt_record(domain: &str, expected_token: &str) -> bool {
    use hickory_resolver::TokioResolver;

    let resolver =
        match TokioResolver::builder_tokio().and_then(hickory_resolver::ResolverBuilder::build) {
            Ok(r) => r,
            Err(_) => return false,
        };

    let record_name = format!("_sso-verification.{}", domain);
    match resolver.txt_lookup(&record_name).await {
        Ok(records) => records.answers().iter().any(|record| {
            let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data else {
                return false;
            };
            let txt_value = txt
                .txt_data
                .iter()
                .map(|data| String::from_utf8_lossy(data.as_ref()))
                .collect::<Vec<_>>()
                .join("");
            txt_value.trim() == expected_token
        }),
        Err(_) => false,
    }
}

pub async fn verify_http_file(domain: &str, expected_token: &str) -> bool {
    let domain = match normalize_verifiable_domain(domain) {
        Ok(domain) => domain,
        Err(_) => return false,
    };

    let addrs = match tokio::net::lookup_host(format!("{}:80", domain)).await {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(_) => return false,
    };

    if addrs.is_empty()
        || addrs
            .iter()
            .any(|addr| is_private_or_reserved_ip(&addr.ip()))
    {
        return false;
    }

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };

    for addr in addrs {
        let url = format!(
            "http://{}/.well-known/sso-verification.txt",
            format_ip_for_url(addr.ip())
        );

        let response = match client.get(&url).header(HOST, domain.as_str()).send().await {
            Ok(response) => response,
            Err(_) => continue,
        };

        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|len| len > MAX_VERIFICATION_BODY_BYTES)
        {
            continue;
        }

        let body = match response.bytes().await {
            Ok(body) if body.len() <= MAX_VERIFICATION_BODY_BYTES as usize => body,
            _ => continue,
        };

        if String::from_utf8(body.to_vec()).is_ok_and(|body| body.trim() == expected_token) {
            return true;
        }
    }

    false
}

fn format_ip_for_url(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{}]", ip),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_verifiable_domain;

    #[test]
    fn normalizes_plain_domains() {
        assert_eq!(
            normalize_verifiable_domain(" Example.COM. ").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn rejects_url_like_or_internal_authority_domains() {
        for domain in [
            "http://example.com",
            "example.com/path",
            "example.com:8080",
            "example.com@127.0.0.1",
            "localhost",
            "127.0.0.1",
            "-example.com",
            "example-.com",
        ] {
            assert!(normalize_verifiable_domain(domain).is_err(), "{domain}");
        }
    }
}
