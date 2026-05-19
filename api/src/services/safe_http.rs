//! Safe HTTP Client - SSRF Defense (Security Audit Item 5)
//!
//! This module provides a hardened HTTP client that blocks requests to private/internal
//! IP addresses. This prevents Server-Side Request Forgery (SSRF) attacks where attackers
//! could use webhook/SIEM configurations to:
//! - Scan internal networks
//! - Access cloud metadata services (169.254.169.254)
//! - Interact with internal services

#![allow(dead_code)]

use crate::error::{AppError, Result};
use reqwest::Url;
use std::net::IpAddr;

/// A safe HTTP client that validates URLs before making requests.
/// Blocks requests to private IP ranges to prevent SSRF attacks.
pub struct SafeHttpClient {
    client: reqwest::Client,
}

impl SafeHttpClient {
    /// Create a new SafeHttpClient with secure defaults:
    /// - No automatic redirect following (prevents open redirect bypasses)
    /// - Reasonable timeout
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            // Disable automatic redirects to prevent SSRF via open redirect
            .redirect(reqwest::redirect::Policy::none())
            // Set a reasonable timeout
            .timeout(std::time::Duration::from_secs(30))
            // Set connect timeout
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { client })
    }

    /// Validate a URL is safe to fetch (not pointing to internal/private IPs)
    pub async fn validate_url(&self, url: &str) -> Result<Url> {
        let parsed =
            Url::parse(url).map_err(|e| AppError::BadRequest(format!("Invalid URL: {}", e)))?;

        // Only allow HTTP and HTTPS schemes
        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(AppError::BadRequest(format!(
                    "Scheme '{}' not allowed. Only HTTP and HTTPS are permitted.",
                    scheme
                )));
            }
        }

        // Get the host
        let host = parsed
            .host_str()
            .ok_or_else(|| AppError::BadRequest("URL must have a valid host".to_string()))?;

        // Resolve the hostname to IP addresses
        let port = parsed
            .port()
            .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
        let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| {
                AppError::BadRequest(format!("DNS resolution failed for '{}': {}", host, e))
            })?;

        // Check each resolved IP address
        for addr in addrs {
            let ip = addr.ip();
            if is_private_or_reserved_ip(&ip) {
                return Err(AppError::BadRequest(format!(
                    "Requests to private/internal IP addresses are forbidden. Host '{}' resolves to '{}'.",
                    host, ip
                )));
            }
        }

        Ok(parsed)
    }

    /// Fetch a URL after validating it's safe (not a private IP)
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let validated_url = self.validate_url(url).await?;

        self.client
            .get(validated_url.as_str())
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("HTTP request failed: {}", e)))
    }

    /// POST to a URL after validating it's safe (not a private IP)
    pub async fn post(&self, url: &str, body: String) -> Result<reqwest::Response> {
        let validated_url = self.validate_url(url).await?;

        self.client
            .post(validated_url.as_str())
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("HTTP request failed: {}", e)))
    }

    /// POST with custom headers (for webhooks with signatures)
    pub async fn post_with_headers(
        &self,
        url: &str,
        body: String,
        headers: Vec<(&str, &str)>,
    ) -> Result<reqwest::Response> {
        let validated_url = self.validate_url(url).await?;

        let mut request = self.client.post(validated_url.as_str()).body(body);

        for (name, value) in headers {
            request = request.header(name, value);
        }

        request
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("HTTP request failed: {}", e)))
    }

    /// POST with owned custom headers, useful when header names or values are built at runtime.
    pub async fn post_with_owned_headers(
        &self,
        url: &str,
        body: String,
        headers: Vec<(String, String)>,
    ) -> Result<reqwest::Response> {
        let validated_url = self.validate_url(url).await?;

        let mut request = self.client.post(validated_url.as_str()).body(body);

        for (name, value) in headers {
            request = request.header(name.as_str(), value.as_str());
        }

        request
            .send()
            .await
            .map_err(|e| AppError::InternalServerError(format!("HTTP request failed: {}", e)))
    }
}

impl Default for SafeHttpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default SafeHttpClient")
    }
}

/// Check if an IP address is private, loopback, or otherwise not suitable for external requests.
/// Blocks:
/// - Loopback (127.0.0.0/8, ::1)
/// - Private networks (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Link-local (169.254.0.0/16, fe80::/10) - includes AWS metadata service
/// - Multicast addresses
/// - Broadcast addresses
pub(crate) fn is_private_or_reserved_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // Loopback: 127.0.0.0/8
            if v4.is_loopback() {
                return true;
            }

            // Private networks (RFC 1918)
            if v4.is_private() {
                return true;
            }

            // Link-local: 169.254.0.0/16 (includes AWS/GCP/Azure metadata at 169.254.169.254)
            if v4.is_link_local() {
                return true;
            }

            // Multicast: 224.0.0.0/4
            if v4.is_multicast() {
                return true;
            }

            // Broadcast: 255.255.255.255
            if v4.is_broadcast() {
                return true;
            }

            // Documentation addresses: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
            if v4.is_documentation() {
                return true;
            }

            // Shared address space: 100.64.0.0/10 (CGNAT)
            let octets = v4.octets();
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                return true;
            }

            // Unspecified: 0.0.0.0
            if v4.is_unspecified() {
                return true;
            }

            false
        }
        IpAddr::V6(v6) => {
            // Loopback: ::1
            if v6.is_loopback() {
                return true;
            }

            // Unspecified: ::
            if v6.is_unspecified() {
                return true;
            }

            // Multicast
            if v6.is_multicast() {
                return true;
            }

            // Note: Many IPv6 private address checks are still unstable in std
            // We'll check common private ranges manually
            let segments = v6.segments();

            // Link-local: fe80::/10
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }

            // Unique local: fc00::/7 (similar to RFC 1918 for IPv6)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }

            // IPv4-mapped IPv6 addresses (::ffff:0:0/96) - check the mapped IPv4
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0xffff
            {
                let ipv4 = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    (segments[6] & 0xff) as u8,
                    (segments[7] >> 8) as u8,
                    (segments[7] & 0xff) as u8,
                );
                return is_private_or_reserved_ip(&IpAddr::V4(ipv4));
            }

            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_private_ipv4_addresses() {
        // Private
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));

        // Loopback
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));

        // Link-local (includes cloud metadata)
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));

        // Public should be allowed
        assert!(!is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1
        ))));
    }

    #[test]
    fn test_private_ipv6_addresses() {
        // Loopback
        assert!(is_private_or_reserved_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Unique local
        assert!(is_private_or_reserved_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));

        // Link-local
        assert!(is_private_or_reserved_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }
}
