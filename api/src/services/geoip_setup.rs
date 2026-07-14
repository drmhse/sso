use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use reqwest::{header::LOCATION, Url};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use tar::Archive;

use crate::services::safe_http::SafeHttpClient;

const MAX_GEOIP_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const MAX_GEOIP_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_GEOIP_DATABASE_BYTES: u64 = 128 * 1024 * 1024;
const MAXMIND_DOWNLOAD_HOST: &str = "download.maxmind.com";
const MAXMIND_REDIRECT_HOST: &str =
    "mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com";

fn maxmind_download_url(license_key: &str) -> Result<String> {
    let mut url = Url::parse("https://download.maxmind.com/app/geoip_download")?;
    url.query_pairs_mut()
        .append_pair("edition_id", "GeoLite2-City")
        .append_pair("license_key", license_key)
        .append_pair("suffix", "tar.gz");
    Ok(url.into())
}

fn validate_redirect(location: &str) -> Result<String> {
    let url = Url::parse(location).context("GeoIP download returned an invalid redirect")?;
    if url.scheme() != "https"
        || url.host_str() != Some(MAXMIND_REDIRECT_HOST)
        || !url.username().is_empty()
        || url.password().is_some()
        || url
            .query_pairs()
            .any(|(name, _)| name.eq_ignore_ascii_case("license_key"))
    {
        return Err(anyhow::anyhow!("GeoIP download redirect was not trusted"));
    }
    Ok(url.into())
}

fn extract_database(archive_bytes: &[u8]) -> Result<Vec<u8>> {
    extract_database_with_limits(
        archive_bytes,
        MAX_GEOIP_EXPANDED_BYTES,
        MAX_GEOIP_DATABASE_BYTES,
    )
}

fn extract_database_with_limits(
    archive_bytes: &[u8],
    maximum_expanded_bytes: u64,
    maximum_database_bytes: u64,
) -> Result<Vec<u8>> {
    let cursor = Cursor::new(archive_bytes);
    let expanded = GzDecoder::new(cursor).take(maximum_expanded_bytes + 1);
    let mut archive = Archive::new(expanded);

    for entry in archive.entries().context("Failed to read GeoIP archive")? {
        let entry = entry.context("Failed to read GeoIP archive entry")?;
        let path = entry.path().context("GeoIP archive path was invalid")?;
        let is_database = path
            .extension()
            .is_some_and(|extension| extension == "mmdb")
            && path.to_string_lossy().contains("GeoLite2-City");
        if !is_database {
            continue;
        }

        if entry.size() > maximum_database_bytes {
            return Err(anyhow::anyhow!("GeoIP database exceeded its size limit"));
        }
        let mut content = Vec::new();
        entry
            .take(maximum_database_bytes + 1)
            .read_to_end(&mut content)
            .context("Failed to read GeoIP database from archive")?;
        if content.len() as u64 > maximum_database_bytes {
            return Err(anyhow::anyhow!("GeoIP database exceeded its size limit"));
        }
        return Ok(content);
    }

    Err(anyhow::anyhow!(
        "No GeoLite2-City .mmdb file found in archive"
    ))
}

fn install_database(path: &Path, content: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("GeoIP database path has no valid file name"))?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .context("Failed to create temporary GeoIP database")?;
        file.write_all(content)
            .context("Failed to write temporary GeoIP database")?;
        file.sync_all()
            .context("Failed to sync temporary GeoIP database")?;
        fs::rename(&temporary, path).context("Failed to install GeoIP database atomically")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub async fn run_setup() -> Result<()> {
    tracing::info!("=== SSO Platform GeoIP Database Setup ===");

    let db_path =
        env::var("GEOIP_DATABASE_PATH").unwrap_or_else(|_| "data/GeoLite2-City.mmdb".to_string());
    let db_path = Path::new(&db_path);

    tracing::info!("Database path: {}", db_path.display());

    // Check if database exists and is valid
    if db_path.exists() {
        let metadata = fs::metadata(db_path).context("Failed to check database file")?;
        if metadata.len() > 0 {
            tracing::info!("✓ GeoIP database exists and is readable");
            return Ok(());
        } else {
            tracing::warn!("⚠ Database file exists but is empty");
        }
    }

    // Check if explicitly disabled
    if env::var("GEOIP_DISABLED").unwrap_or_default() == "true" {
        tracing::warn!("⚠ GeoIP features are disabled via GEOIP_DISABLED=true");
        return Ok(());
    }

    // Prepare download
    let license_key = match env::var("MAXMIND_LICENSE_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            tracing::error!("✗ No MaxMind license key found");
            tracing::info!("To auto-download, set environment variable: MAXMIND_LICENSE_KEY");
            tracing::info!("Or manually place the .mmdb file at {}", db_path.display());
            return Err(anyhow::anyhow!("Missing MaxMind license key"));
        }
    };

    tracing::info!("Downloading GeoLite2-City database...");
    let url = maxmind_download_url(&license_key)?;
    debug_assert_eq!(Url::parse(&url)?.host_str(), Some(MAXMIND_DOWNLOAD_HOST));
    let client = SafeHttpClient::new().context("Failed to initialize GeoIP downloader")?;
    let mut response = client
        .get(&url)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to request GeoIP database"))?;

    if response.status().is_redirection() {
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("GeoIP download redirect was missing a location"))?;
        let redirect = validate_redirect(location)?;
        response = client
            .get(&redirect)
            .await
            .map_err(|_| anyhow::anyhow!("Failed to follow trusted GeoIP redirect"))?;
    }

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download database: HTTP {}",
            response.status()
        ));
    }

    let (_, bytes) = SafeHttpClient::read_body_limited(response, MAX_GEOIP_ARCHIVE_BYTES)
        .await
        .map_err(|_| anyhow::anyhow!("GeoIP archive exceeded its download limit or failed"))?;

    tracing::info!("✓ Download completed. Extracting...");

    let content = extract_database(&bytes)?;

    // Create parent directory if needed
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).context("Failed to create data directory")?;
    }

    install_database(db_path, &content)?;
    tracing::info!(
        "✓ Database installed successfully at: {}",
        db_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use tar::{Builder, Header};

    fn archive_with_database(content: &[u8]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut builder = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "GeoLite2-City_20990101/GeoLite2-City.mmdb",
                content,
            )
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn license_key_is_encoded_as_one_query_value() {
        let url = Url::parse(&maxmind_download_url("key&suffix=evil").unwrap()).unwrap();
        assert_eq!(url.host_str(), Some(MAXMIND_DOWNLOAD_HOST));
        let values: Vec<_> = url.query_pairs().collect();
        assert_eq!(values.len(), 3);
        assert_eq!(values[1].0, "license_key");
        assert_eq!(values[1].1, "key&suffix=evil");
    }

    #[test]
    fn redirect_policy_accepts_only_the_documented_https_host_without_license_key() {
        let allowed = format!("https://{MAXMIND_REDIRECT_HOST}/signed/object?token=opaque");
        assert!(validate_redirect(&allowed).is_ok());
        for rejected in [
            "http://mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com/object",
            "https://example.com/object",
            "https://127.0.0.1/object",
            "https://mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com/object?license_key=secret",
        ] {
            assert!(validate_redirect(rejected).is_err(), "{rejected}");
        }
    }

    #[test]
    fn extracts_only_the_expected_database() {
        let content = b"maxmind database fixture";
        assert_eq!(
            extract_database(&archive_with_database(content)).unwrap(),
            content
        );
    }

    #[test]
    fn rejects_database_larger_than_the_explicit_bound() {
        let archive = archive_with_database(b"12345");
        let error = extract_database_with_limits(&archive, 1024 * 1024, 4).unwrap_err();
        assert!(error.to_string().contains("size limit"));
    }
}
