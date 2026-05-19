use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::env;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use tar::Archive;

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
    let url = format!(
        "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={}&suffix=tar.gz",
        license_key
    );

    let response = reqwest::get(&url)
        .await
        .context("Failed to request GeoIP database")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download database: HTTP {}",
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to download database bytes")?;

    tracing::info!("✓ Download completed. Extracting...");

    // Create cursor for reading bytes
    let cursor = Cursor::new(bytes);
    let tar = GzDecoder::new(cursor);
    let mut archive = Archive::new(tar);

    // Create parent directory if needed
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).context("Failed to create data directory")?;
    }

    // Iterate through archive entries
    let mut found = false;
    for entry in archive.entries().context("Failed to read tar archive")? {
        let mut entry = entry.context("Failed to read archive entry")?;
        let path = entry.path()?.to_path_buf();

        // Look for the mmdb file
        if let Some(ext) = path.extension() {
            if ext == "mmdb" && path.to_string_lossy().contains("GeoLite2-City") {
                tracing::info!("Found database: {}", path.display());

                // Extract directly to target location using logic that handles the file content
                // We can't just unpack the single file easily with path renaming via `unpack`,
                // so we read it and write it.
                let mut content = Vec::new();
                use std::io::Read;
                entry
                    .read_to_end(&mut content)
                    .context("Failed to read from archive")?;

                fs::write(db_path, content).context("Failed to write database file")?;

                found = true;
                break;
            }
        }
    }

    if found {
        tracing::info!(
            "✓ Database installed successfully at: {}",
            db_path.display()
        );
        Ok(())
    } else {
        Err(anyhow::anyhow!("No .mmdb file found in extracted archive"))
    }
}
