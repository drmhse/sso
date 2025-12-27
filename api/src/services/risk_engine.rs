use crate::error::{AppError, Result};
use crate::store::login_events::LoginEventStore;
use crate::store::risk_rules::RiskRulesStore;
use crate::store::user_devices::UserDevicesStore;
use crate::store::DB;
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// GeoIP database reader (optional, gracefully handles missing database)
pub struct GeoIpReader {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoIpReader {
    pub fn new() -> Self {
        // Try to load GeoIP database from environment variable or default path
        let db_path = std::env::var("GEOIP_DATABASE_PATH")
            .unwrap_or_else(|_| "data/GeoLite2-City.mmdb".to_string());

        match Self::load_database(&db_path) {
            Ok(reader) => {
                tracing::info!(
                    path = %db_path,
                    "GeoIP database loaded successfully"
                );
                Self {
                    reader: Some(Arc::new(reader)),
                }
            }
            Err(e) => {
                // Check if GeoIP is explicitly disabled
                if std::env::var("GEOIP_DISABLED").unwrap_or_default() == "true" {
                    tracing::info!("GeoIP database disabled via GEOIP_DISABLED=true");
                    Self { reader: None }
                } else {
                    tracing::error!(
                        path = %db_path,
                        error = %e,
                        "Failed to load GeoIP database - geographic security features will be unavailable"
                    );
                    tracing::error!("To resolve this issue, run: ./scripts/setup_geoip.sh");
                    tracing::error!("Or disable GeoIP features by setting: GEOIP_DISABLED=true");
                    Self { reader: None }
                }
            }
        }
    }

    fn load_database(
        path: &str,
    ) -> std::result::Result<maxminddb::Reader<Vec<u8>>, maxminddb::MaxMindDBError> {
        maxminddb::Reader::open_readfile(path)
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoLocation> {
        let reader = self.reader.as_ref()?;

        // Parse IP address
        let ip_addr: std::net::IpAddr = ip.parse().ok()?;

        // Query the database for city data
        let city: maxminddb::geoip2::City = reader.lookup(ip_addr).ok()?;

        // Extract location data
        let country = city.country?.iso_code?.to_string();
        let city_name = city.city?.names?.get("en").map(|s| s.to_string());
        let location = city.location?;
        let latitude = location.latitude?;
        let longitude = location.longitude?;

        Some(GeoLocation {
            country,
            city: city_name,
            latitude,
            longitude,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    Allow,
    ChallengeMFA,
    Block,
    LogOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: i32,
    pub factors: Vec<String>,
    pub action: RiskAction,
    pub location: Option<GeoLocation>,
}

#[derive(Debug, Clone)]
pub struct RiskContext<'a> {
    pub user_id: &'a str,
    pub org_id: Option<&'a str>,
    pub ip_address: &'a str,
    pub user_agent: &'a str,
    pub device_cookie: Option<&'a str>,
}

pub struct RiskEngine {
    geoip: GeoIpReader,
    signing_key: [u8; 32],
}

impl RiskEngine {
    pub fn new() -> Result<Self> {
        let geoip = GeoIpReader::new();

        // Load signing key from environment or use a persistent default
        let signing_key = std::env::var("DEVICE_TRUST_SECRET")
            .ok()
            .and_then(|s| {
                let bytes = s.as_bytes();
                if bytes.len() >= 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes[0..32]);
                    Some(key)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                tracing::warn!(
                    "DEVICE_TRUST_SECRET not set or invalid, using fallback (NOT FOR PRODUCTION)"
                );
                // In production, this MUST be a persistent secret
                [0u8; 32]
            });

        Ok(Self { geoip, signing_key })
    }

    /// Main risk evaluation function
    pub async fn evaluate(&self, db: DB<'_>, ctx: RiskContext<'_>) -> Result<RiskAssessment> {
        let mut score: i32 = 0;
        let mut factors = Vec::new();

        // Get org-specific rules if available
        let rules = if let Some(org_id) = ctx.org_id {
            RiskRulesStore::find_by_org(db.clone(), org_id).await?
        } else {
            None
        };

        let new_device_score = rules.as_ref().map(|r| r.new_device_score).unwrap_or(20);
        let impossible_travel_score = rules
            .as_ref()
            .map(|r| r.impossible_travel_score)
            .unwrap_or(50);
        let velocity_threshold = rules.as_ref().map(|r| r.velocity_threshold).unwrap_or(10);
        let velocity_score = rules.as_ref().map(|r| r.velocity_score).unwrap_or(30);

        // 1. Device Trust Check
        if let Some(cookie) = ctx.device_cookie {
            if let Ok(device_user_id) = self.validate_device_token(cookie) {
                if device_user_id == ctx.user_id {
                    // Valid device cookie for this user
                    let token_hash = self.hash_token(cookie);
                    if self
                        .is_trusted_device(db.clone(), ctx.user_id, &token_hash)
                        .await?
                    {
                        score -= 20; // Trusted device reduces risk
                        factors.push("trusted_device".to_string());
                    } else {
                        score += new_device_score;
                        factors.push("untrusted_cookie".to_string());
                    }
                } else {
                    score += new_device_score;
                    factors.push("cookie_mismatch".to_string());
                }
            } else {
                score += new_device_score;
                factors.push("invalid_cookie".to_string());
            }
        } else {
            score += new_device_score;
            factors.push("new_device".to_string());
        }

        // 2. GeoIP and Impossible Travel Detection
        let location = self.lookup_location(ctx.ip_address);
        if let Some(ref loc) = location {
            if self
                .is_impossible_travel(db.clone(), ctx.user_id, loc)
                .await?
            {
                score += impossible_travel_score;
                factors.push("impossible_travel".to_string());
            }
        }

        // 3. Velocity Check
        let recent_logins = self.check_velocity(db.clone(), ctx.ip_address).await?;
        if recent_logins > velocity_threshold {
            score += velocity_score;
            factors.push("velocity_limit".to_string());
        }

        // 4. Determine action based on score and rules
        let action = if let Some(ref rules) = rules {
            let base_action = if score < rules.low_threshold {
                RiskAction::Allow
            } else if score < rules.medium_threshold {
                RiskAction::ChallengeMFA
            } else {
                RiskAction::Block
            };

            // Apply shadow mode if enabled
            if rules.enforcement_mode == "log_only" {
                RiskAction::LogOnly
            } else {
                base_action
            }
        } else {
            // Default thresholds if no org rules
            if score < 30 {
                RiskAction::Allow
            } else if score < 70 {
                RiskAction::ChallengeMFA
            } else {
                RiskAction::Block
            }
        };

        Ok(RiskAssessment {
            score,
            factors,
            action,
            location,
        })
    }

    /// Generate a new device trust token
    pub fn generate_device_token(&self, user_id: &str) -> String {
        let random_bytes: [u8; 16] = rand::thread_rng().gen();
        let timestamp = Utc::now().timestamp();

        let payload = format!("{}:{}:{}", user_id, hex::encode(random_bytes), timestamp);

        // HMAC sign the payload
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();

        format!(
            "{}.{}",
            payload,
            general_purpose::STANDARD.encode(signature)
        )
    }

    /// Validate a device trust token and return the user_id if valid
    pub fn validate_device_token(&self, token: &str) -> Result<String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(AppError::Unauthorized("Invalid device token format".into()));
        }

        let payload = parts[0];
        let signature_b64 = parts[1];

        // Verify HMAC signature
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());

        let expected_signature = mac.finalize().into_bytes();
        let provided_signature = general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|_| AppError::Unauthorized("Invalid signature encoding".into()))?;

        // Constant-time comparison
        if expected_signature[..] != provided_signature[..] {
            return Err(AppError::Unauthorized(
                "Invalid device token signature".into(),
            ));
        }

        // Extract user_id from payload
        let payload_parts: Vec<&str> = payload.split(':').collect();
        if payload_parts.len() != 3 {
            return Err(AppError::Unauthorized("Invalid payload format".into()));
        }

        Ok(payload_parts[0].to_string())
    }

    /// Hash a device token for storage
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Check if a device is trusted
    async fn is_trusted_device(&self, db: DB<'_>, user_id: &str, token_hash: &str) -> Result<bool> {
        if let Some(device) = UserDevicesStore::find_by_token_hash(db, token_hash).await? {
            // Verify it belongs to this user and is still trusted and not expired
            let expires_at: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::from_naive_utc_and_offset(device.expires_at, Utc);

            Ok(device.user_id == user_id && device.is_trusted && Utc::now() < expires_at)
        } else {
            Ok(false)
        }
    }

    /// Lookup geographic location from IP address
    fn lookup_location(&self, ip: &str) -> Option<GeoLocation> {
        self.geoip.lookup(ip)
    }

    /// Check for impossible travel patterns
    async fn is_impossible_travel(
        &self,
        db: DB<'_>,
        user_id: &str,
        current_location: &GeoLocation,
    ) -> Result<bool> {
        // Get the most recent successful login with location data
        let recent_logins = LoginEventStore::find_recent_by_user(db, user_id, 1).await?;

        if let Some(last_login) = recent_logins.first() {
            if let (Some(last_lat), Some(last_long)) = (last_login.geo_lat, last_login.geo_long) {
                // Calculate time difference
                let last_time =
                    chrono::DateTime::from_naive_utc_and_offset(last_login.created_at, Utc);
                let time_diff_secs = (Utc::now() - last_time).num_seconds();
                let time_diff = time_diff_secs as f64 / 3600.0; // Convert seconds to hours

                // Calculate distance using Haversine formula
                let distance_km = self.haversine_distance(
                    last_lat,
                    last_long,
                    current_location.latitude,
                    current_location.longitude,
                );

                // Check if travel speed is physically impossible
                // Assume max speed of 900 km/h (commercial airline + reasonable ground travel)
                if time_diff > 0.0 {
                    let speed_kmh = distance_km / time_diff;
                    if speed_kmh > 900.0 && distance_km > 500.0 {
                        // Only flag if distance is significant (>500km) and speed is impossible
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Calculate Haversine distance between two points
    fn haversine_distance(&self, lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        let r = 6371.0; // Earth's radius in kilometers

        let lat1_rad = lat1.to_radians();
        let lat2_rad = lat2.to_radians();
        let delta_lat = (lat2 - lat1).to_radians();
        let delta_lon = (lon2 - lon1).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        r * c
    }

    /// Check login velocity from an IP address
    async fn check_velocity(&self, db: DB<'_>, ip: &str) -> Result<i32> {
        // Count logins from this IP in the last 5 minutes
        let five_minutes_ago = (Utc::now() - Duration::minutes(5)).naive_utc();

        let count = LoginEventStore::count_by_ip_since(db, ip, five_minutes_ago).await?;

        Ok(count as i32)
    }
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create RiskEngine")
    }
}
