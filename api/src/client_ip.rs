use axum::{
    extract::ConnectInfo,
    http::{header::FORWARDED, HeaderMap, Request},
};
use forwarded_header_value::{ForwardedHeaderValue, Identifier};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tower_governor::{key_extractor::KeyExtractor, GovernorError};

/// Resolves a request's client IP without trusting caller-controlled proxy
/// headers unless the socket peer is an explicitly allowlisted proxy.
#[derive(Clone, Debug)]
pub struct TrustedClientIpKeyExtractor {
    trust_proxy_headers: bool,
    trusted_proxy_ips: Arc<[IpAddr]>,
}

impl TrustedClientIpKeyExtractor {
    pub fn from_env() -> Self {
        let trust_proxy_headers = std::env::var("TRUST_PROXY_HEADERS")
            .map(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let trusted_proxy_ips = std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| value.trim().parse::<IpAddr>().ok())
            .collect::<Vec<_>>()
            .into();

        Self {
            trust_proxy_headers,
            trusted_proxy_ips,
        }
    }

    #[cfg(test)]
    fn new(trust_proxy_headers: bool, trusted_proxy_ips: Vec<IpAddr>) -> Self {
        Self {
            trust_proxy_headers,
            trusted_proxy_ips: trusted_proxy_ips.into(),
        }
    }

    pub fn extract_client_ip<T>(&self, request: &Request<T>) -> Option<IpAddr> {
        let peer_ip = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect_info| connect_info.0.ip())
            .or_else(|| request.extensions().get::<SocketAddr>().map(SocketAddr::ip))?;

        if self.trust_proxy_headers && self.trusted_proxy_ips.contains(&peer_ip) {
            extract_forwarded_ip(request.headers()).or(Some(peer_ip))
        } else {
            Some(peer_ip)
        }
    }
}

impl KeyExtractor for TrustedClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, GovernorError> {
        self.extract_client_ip(request)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

fn extract_forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|header| header.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find_map(|candidate| candidate.parse::<IpAddr>().ok())
        })
        .or_else(|| parse_single_ip_header(headers, "x-real-ip"))
        .or_else(|| extract_standard_forwarded_ip(headers))
        .or_else(|| parse_single_ip_header(headers, "cf-connecting-ip"))
}

fn extract_standard_forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers.get_all(FORWARDED).iter().find_map(|header| {
        header
            .to_str()
            .ok()
            .and_then(|value| ForwardedHeaderValue::from_forwarded(value).ok())
            .and_then(|forwarded| {
                forwarded
                    .iter()
                    .filter_map(|field| field.forwarded_for.as_ref())
                    .find_map(|identifier| match identifier {
                        Identifier::SocketAddr(address) => Some(address.ip()),
                        Identifier::IpAddr(ip) => Some(*ip),
                        _ => None,
                    })
            })
    })
}

fn parse_single_ip_header(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn request(peer: &str, forwarded_for: Option<&str>) -> Request<()> {
        let mut builder = Request::builder();
        if let Some(forwarded_for) = forwarded_for {
            builder = builder.header("x-forwarded-for", forwarded_for);
        }
        let mut request = builder.body(()).expect("request");
        request.extensions_mut().insert(ConnectInfo(
            peer.parse::<SocketAddr>().expect("socket address"),
        ));
        request
    }

    #[test]
    fn ignores_spoofed_forwarded_headers_from_direct_clients() {
        let extractor = TrustedClientIpKeyExtractor::new(
            true,
            vec!["10.0.0.10".parse().expect("trusted proxy")],
        );
        let request = request("203.0.113.8:43120", Some("198.51.100.7"));

        assert_eq!(
            extractor.extract_client_ip(&request),
            Some("203.0.113.8".parse().expect("peer IP"))
        );
    }

    #[test]
    fn accepts_forwarded_ip_from_an_allowlisted_proxy() {
        let extractor = TrustedClientIpKeyExtractor::new(
            true,
            vec!["10.0.0.10".parse().expect("trusted proxy")],
        );
        let request = request("10.0.0.10:43120", Some("198.51.100.7, 10.0.0.9"));

        assert_eq!(
            extractor.extract_client_ip(&request),
            Some("198.51.100.7".parse().expect("client IP"))
        );
    }

    #[test]
    fn falls_back_to_trusted_proxy_peer_when_header_is_missing_or_invalid() {
        let extractor = TrustedClientIpKeyExtractor::new(
            true,
            vec!["10.0.0.10".parse().expect("trusted proxy")],
        );

        for forwarded_for in [None, Some("not-an-ip")] {
            let request = request("10.0.0.10:43120", forwarded_for);
            assert_eq!(
                extractor.extract_client_ip(&request),
                Some("10.0.0.10".parse().expect("proxy IP"))
            );
        }
    }

    #[test]
    fn proxy_headers_stay_disabled_without_the_explicit_switch() {
        let extractor = TrustedClientIpKeyExtractor::new(
            false,
            vec!["10.0.0.10".parse().expect("trusted proxy")],
        );
        let request = request("10.0.0.10:43120", Some("198.51.100.7"));

        assert_eq!(
            extractor.extract_client_ip(&request),
            Some("10.0.0.10".parse().expect("proxy IP"))
        );
    }

    #[test]
    fn accepts_the_standard_forwarded_header_from_an_allowlisted_proxy() {
        let extractor = TrustedClientIpKeyExtractor::new(
            true,
            vec!["10.0.0.10".parse().expect("trusted proxy")],
        );
        let mut request = request("10.0.0.10:43120", None);
        request
            .headers_mut()
            .insert("forwarded", "for=198.51.100.9".parse().expect("header"));

        assert_eq!(
            extractor.extract_client_ip(&request),
            Some("198.51.100.9".parse().expect("client IP"))
        );
    }
}
