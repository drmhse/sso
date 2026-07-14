#![allow(dead_code)]

use crate::auth::jwt::{Actor, Claims, JwtService};
use crate::entities::{memberships, organizations, users};
use crate::error::{AppError, Result};
use axum::{
    extract::{FromRequestParts, MatchedPath, Path, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use metrics::histogram;
use moka::future::Cache;
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ============================================================================
// Security Audit Item 2: Regex DoS Prevention
// ============================================================================

use std::sync::LazyLock;

/// Static email regex compiled once at startup to prevent Regex DoS attacks
/// from per-request regex compilation overhead
static EMAIL_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .expect("Invalid email regex")
});

/// Validate email format using statically compiled regex
/// This prevents Regex DoS by reusing a single compiled regex instance
pub fn validate_email_format_static(email: &str) -> Result<()> {
    if email.is_empty() {
        return Err(AppError::BadRequest("Email cannot be empty".to_string()));
    }

    if !EMAIL_REGEX.is_match(email) {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Additional checks for specific invalid patterns
    if email.starts_with('.') || email.ends_with('.') || email.contains("..") {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    Ok(())
}

/// Extension type for storing authenticated user claims
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub claims: Claims,
    pub user: users::Model,
    pub permissions: Vec<String>, // Cached permissions from database
    pub ip_address: String,
    pub user_agent: String,
    pub current_session_id: Option<String>,
}

/// Extension type for storing impersonation context
#[derive(Clone, Debug)]
pub struct ImpersonationContext {
    /// The admin user who is performing the impersonation
    pub actor: Actor,
    /// The original claims before impersonation
    pub original_claims: Claims,
    /// Reason for impersonation (if provided)
    pub reason: Option<String>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))
    }
}

/// Fetch permissions from cache, or from DB on cache miss
async fn fetch_and_cache_permissions(
    db: &DatabaseConnection,
    cache: &Cache<String, Vec<String>>,
    user_id: &str,
) -> Result<Vec<String>> {
    use crate::store::{permissions::PermissionsStore, DB};

    // 1. Try cache first (O(1) lookup)
    if let Some(cached_perms) = cache.get(user_id).await {
        return Ok(cached_perms);
    }

    // 2. Cache miss: Fetch from database
    let perms_models = PermissionsStore::list_user_permissions(DB::Conn(db), user_id).await?;

    let perms_strings: Vec<String> = perms_models
        .into_iter()
        .map(|p| format!("{}:{}#{}", p.namespace, p.object_id, p.relation))
        .collect();

    // 3. Store in cache for future requests
    cache
        .insert(user_id.to_string(), perms_strings.clone())
        .await;

    Ok(perms_strings)
}

/// Security Audit Item 8: Fetch permissions with tenant context
/// Uses compound cache key 'org_id:user_id' to prevent cross-tenant cache pollution
pub async fn fetch_and_cache_permissions_with_context(
    db: &DatabaseConnection,
    cache: &Cache<String, Vec<String>>,
    user_id: &str,
    org_id: Option<&str>,
) -> Result<Vec<String>> {
    use crate::store::{permissions::PermissionsStore, DB};

    // Create compound key for tenant-scoped cache
    let cache_key = match org_id {
        Some(org) => format!("{}:{}", org, user_id),
        None => format!("platform:{}", user_id),
    };

    // 1. Try cache first (O(1) lookup)
    if let Some(cached_perms) = cache.get(&cache_key).await {
        return Ok(cached_perms);
    }

    // 2. Cache miss: Fetch from database
    let perms_models = PermissionsStore::list_user_permissions(DB::Conn(db), user_id).await?;

    let perms_strings: Vec<String> = perms_models
        .into_iter()
        .map(|p| format!("{}:{}#{}", p.namespace, p.object_id, p.relation))
        .collect();

    // 3. Store in cache for future requests
    cache.insert(cache_key, perms_strings.clone()).await;

    Ok(perms_strings)
}

/// Fetch user model from cache, or from DB on cache miss
///
/// This reduces database load on authenticated requests by caching User models
/// with a 30-second TTL. Cache is invalidated when user is updated.
async fn fetch_and_cache_user(
    db: &DatabaseConnection,
    cache: &Cache<String, crate::entities::users::Model>,
    user_id: &str,
) -> Result<crate::entities::users::Model> {
    use crate::store::{users::UserStore, DB};

    // 1. Try cache first (O(1) lookup)
    if let Some(cached_user) = cache.get(user_id).await {
        return Ok(cached_user);
    }

    // 2. Cache miss: Fetch from database
    let user = UserStore::find_by_id(DB::Conn(db), user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    // 3. Store in cache for future requests
    cache.insert(user_id.to_string(), user.clone()).await;

    Ok(user)
}

/// Extract and validate JWT from Authorization header
pub async fn extract_user_from_jwt(
    State(state): State<crate::state::AppState>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    let db = &state.db;
    let jwt_service = &state.jwt_service;
    let permission_cache = &state.permission_cache;
    let user_cache = &state.user_cache;
    use crate::store::{sessions::SessionStore, DB};

    // Extract token from Authorization header
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or_else(|| {
            AppError::Unauthorized("Missing or invalid Authorization header".to_string())
        })?;

    // Validate token
    let claims = jwt_service.validate_authos_token(token)?;
    let user_id = claims.sub.clone();

    // Extract IP and User-Agent before modifying request
    let ip_address = extract_ip(&req);
    let user_agent = extract_user_agent(&req);

    // Check if this is an impersonation token
    if let Some((actor, original_claims)) = jwt_service.extract_impersonation_context(token)? {
        // This is an impersonation session
        tracing::warn!(
            admin_user_id = %actor.sub,
            admin_user_email = %actor.email,
            target_user_id = %claims.sub,
            target_user_email = %claims.email,
            reason = ?actor.reason,
            "Processing impersonation request"
        );

        // Load the target user from cache or database
        let user = fetch_and_cache_user(db, user_cache, &claims.sub)
            .await
            .map_err(|_| AppError::Unauthorized("Target user not found".to_string()))?;

        // Fetch permissions for impersonated user
        let permissions = fetch_and_cache_permissions(db, permission_cache, &user_id).await?;

        // Store impersonation context
        req.extensions_mut().insert(ImpersonationContext {
            actor: actor.clone(),
            original_claims: original_claims.clone(),
            reason: actor.reason,
        });

        // Store user in request extensions
        req.extensions_mut().insert(AuthUser {
            claims: claims.clone(),
            user,
            permissions,
            ip_address,
            user_agent,
            current_session_id: None,
        });
    } else {
        // Normal authentication flow
        // Check if session is still valid (not revoked)
        let token_hash = JwtService::hash_token(token);
        let session = SessionStore::find_valid_by_token_hash(DB::Conn(db), &token_hash).await?;

        if session.is_none() {
            return Err(AppError::Unauthorized(
                "Session revoked or expired".to_string(),
            ));
        }
        let current_session_id = session.as_ref().map(|session| session.id.clone());

        // Load user from cache or database
        let user = fetch_and_cache_user(db, user_cache, &claims.sub).await?;

        // Fetch and cache permissions
        let permissions = fetch_and_cache_permissions(db, permission_cache, &user_id).await?;

        // Store user in request extensions
        req.extensions_mut().insert(AuthUser {
            claims: claims.clone(),
            user,
            permissions,
            ip_address,
            user_agent,
            current_session_id,
        });
    }

    Ok(next.run(req).await)
}

/// Extract IP address from request
fn extract_ip(req: &Request) -> String {
    extract_client_ip(req)
}

fn extract_client_ip(req: &Request) -> String {
    let socket_ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|socket_addr| socket_addr.ip());

    if let Some(remote_ip) = socket_ip {
        if proxy_headers_are_trusted(&remote_ip) {
            if let Some(forwarded_ip) = extract_forwarded_ip(req) {
                return forwarded_ip.to_string();
            }
        }

        return remote_ip.to_string();
    }

    "unknown".to_string()
}

fn proxy_headers_are_trusted(remote_ip: &IpAddr) -> bool {
    static TRUST_PROXY_HEADERS: LazyLock<bool> = LazyLock::new(|| {
        std::env::var("TRUST_PROXY_HEADERS")
            .map(|value| matches!(value.as_str(), "true" | "1" | "yes" | "on"))
            .unwrap_or(false)
    });

    static TRUSTED_PROXY_IPS: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
        std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| value.trim().parse::<IpAddr>().ok())
            .collect()
    });

    *TRUST_PROXY_HEADERS && TRUSTED_PROXY_IPS.iter().any(|trusted| trusted == remote_ip)
}

fn extract_forwarded_ip(req: &Request) -> Option<IpAddr> {
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|header| header.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find_map(|candidate| candidate.parse::<IpAddr>().ok())
        })
        .or_else(|| {
            req.headers()
                .get("X-Real-IP")
                .and_then(|header| header.to_str().ok())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
        })
        .or_else(|| {
            req.headers()
                .get("CF-Connecting-IP")
                .and_then(|header| header.to_str().ok())
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
        })
}

/// Extract User-Agent from request
fn extract_user_agent(req: &Request) -> String {
    req.headers()
        .get("User-Agent")
        .and_then(|header| header.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Middleware to require platform owner role
pub async fn require_platform_owner(
    req: Request,
    next: Next,
) -> std::result::Result<Response, (StatusCode, String)> {
    let auth_user = req
        .extensions()
        .get::<AuthUser>()
        .ok_or((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

    if !auth_user.user.is_platform_owner {
        return Err((
            StatusCode::FORBIDDEN,
            "Platform owner access required".to_string(),
        ));
    }

    Ok(next.run(req).await)
}

/// Helper function to check if user has required role in organization
pub async fn check_org_membership(
    db: &DatabaseConnection,
    user_id: &str,
    org_id: &str,
    required_roles: &[&str],
) -> Result<memberships::Model> {
    use crate::store::{memberships::MembershipStore, DB};

    let membership = MembershipStore::find_by_org_and_user(DB::Conn(db), org_id, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    if !required_roles.is_empty() && !required_roles.contains(&membership.role.as_str()) {
        return Err(AppError::Forbidden(format!(
            "Requires one of roles: {}",
            required_roles.join(", ")
        )));
    }

    Ok(membership)
}

/// Helper function to check if user is organization owner
pub async fn check_org_owner(db: &DatabaseConnection, user_id: &str, org_id: &str) -> Result<()> {
    check_org_membership(db, user_id, org_id, &["owner"]).await?;
    Ok(())
}

/// Helper function to check if user is organization admin or owner
pub async fn check_org_admin(
    db: &DatabaseConnection,
    user_id: &str,
    org_id: &str,
) -> Result<memberships::Model> {
    check_org_membership(db, user_id, org_id, &["owner", "admin"]).await
}

/// Extractor struct for organization slug path parameter
#[derive(Deserialize)]
pub struct OrgSlugParam {
    org_slug: String,
}

/// Middleware to require organization to be in active status
/// This prevents access to certain features (services, BYOO credentials, etc.)
/// while organization is pending approval
pub async fn require_active_organization(
    State(state): State<crate::state::AppState>,
    Path(path): Path<OrgSlugParam>,
    req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    use crate::store::{organizations::OrganizationStore, DB};

    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &path.org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if organization is active
    if org.status != "active" {
        return Err(AppError::Forbidden(format!(
            "Organization is not active. Current status: {}. This feature is only available for active organizations.",
            org.status
        )));
    }

    Ok(next.run(req).await)
}

// ===== Email Rate Limiting =====

/// In-memory rate limiter for email operations (password reset, registration, etc.)
#[derive(Clone)]
pub struct EmailRateLimiter {
    /// Tracks email attempts per email address
    email_attempts: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    /// Maximum emails per hour per email address
    max_emails_per_hour: usize,
    /// Time window for rate limiting (1 hour)
    window: Duration,
}

impl EmailRateLimiter {
    pub fn new(max_emails_per_hour: usize) -> Self {
        Self {
            email_attempts: Arc::new(RwLock::new(HashMap::new())),
            max_emails_per_hour,
            window: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Check if email address is rate limited for sending emails
    pub async fn is_rate_limited_email(&self, email: &str) -> bool {
        self.is_rate_limited_email_with_context(email, None).await
    }

    /// Security Audit Item 9: Tenant-aware email rate limiting
    /// Uses compound key 'org_id:email' to partition rate limits by tenant
    pub async fn is_rate_limited_email_with_context(
        &self,
        email: &str,
        org_id: Option<&str>,
    ) -> bool {
        let mut attempts = self.email_attempts.write().await;
        let now = Instant::now();

        // Create compound key for tenant-partitioned rate limiting
        let key = match org_id {
            Some(org) => format!("{}:{}", org, email.to_lowercase()),
            None => format!("platform:{}", email.to_lowercase()),
        };

        let entry = attempts.entry(key).or_insert_with(Vec::new);

        // Remove expired attempts (older than 1 hour)
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);

        // Check if over limit
        if entry.len() >= self.max_emails_per_hour {
            return true;
        }

        // Add current attempt
        entry.push(now);
        false
    }

    /// Cleanup expired entries (call periodically)
    pub async fn cleanup(&self) {
        let now = Instant::now();

        // Cleanup email attempts
        let mut attempts = self.email_attempts.write().await;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
            !timestamps.is_empty()
        });
    }
}

// ===== MFA Rate Limiting Middleware =====

/// In-memory rate limiter for MFA verification attempts
#[allow(dead_code)]
#[derive(Clone)]
pub struct MfaRateLimiter {
    /// Tracks attempts per IP address
    attempts: Arc<RwLock<HashMap<IpAddr, Vec<Instant>>>>,
    /// Tracks attempts per user ID (when authenticated)
    user_attempts: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    /// Maximum attempts per window
    max_attempts: usize,
    /// Time window for rate limiting
    window: Duration,
}

impl MfaRateLimiter {
    #[allow(dead_code)]
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
            user_attempts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            window,
        }
    }

    /// Check if IP is rate limited for MFA attempts
    #[allow(dead_code)]
    pub async fn is_rate_limited_ip(&self, ip: IpAddr) -> bool {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        let entry = attempts.entry(ip).or_insert_with(Vec::new);

        // Remove expired attempts
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);

        // Check if over limit
        if entry.len() >= self.max_attempts {
            return true;
        }

        // Add current attempt
        entry.push(now);
        false
    }

    /// Check if user is rate limited for MFA attempts
    #[allow(dead_code)]
    pub async fn is_rate_limited_user(&self, user_id: &str) -> bool {
        self.is_rate_limited_user_with_context(user_id, None).await
    }

    /// Security Audit Item 9: Tenant-aware MFA rate limiting
    /// Uses compound key 'org_id:user_id' to partition rate limits by tenant
    #[allow(dead_code)]
    pub async fn is_rate_limited_user_with_context(
        &self,
        user_id: &str,
        org_id: Option<&str>,
    ) -> bool {
        let mut attempts = self.user_attempts.write().await;
        let now = Instant::now();

        // Create compound key for tenant-partitioned rate limiting
        let key = match org_id {
            Some(org) => format!("{}:{}", org, user_id),
            None => format!("platform:{}", user_id),
        };

        let entry = attempts.entry(key).or_insert_with(Vec::new);

        // Remove expired attempts
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);

        // Check if over limit
        if entry.len() >= self.max_attempts {
            return true;
        }

        // Add current attempt
        entry.push(now);
        false
    }

    /// Cleanup expired entries (call periodically)
    #[allow(dead_code)]
    pub async fn cleanup(&self) {
        let now = Instant::now();

        // Cleanup IP attempts
        let mut attempts = self.attempts.write().await;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
            !timestamps.is_empty()
        });

        // Cleanup user attempts
        let mut user_attempts = self.user_attempts.write().await;
        user_attempts.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| now.duration_since(timestamp) < self.window);
            !timestamps.is_empty()
        });
    }
}

/// Global MFA rate limiter instance
#[allow(dead_code)]
pub static EMAIL_RATE_LIMITER: std::sync::LazyLock<EmailRateLimiter> =
    std::sync::LazyLock::new(|| {
        EmailRateLimiter::new(5) // Max 5 emails per hour per email address
    });

pub static MFA_RATE_LIMITER: std::sync::LazyLock<MfaRateLimiter> = std::sync::LazyLock::new(|| {
    MfaRateLimiter::new(
        5,                            // Max 5 attempts
        Duration::from_secs(15 * 60), // Per 15 minutes
    )
});

/// Middleware for MFA verification rate limiting
#[allow(dead_code)]
pub async fn mfa_rate_limit_middleware(
    req: Request,
    next: Next,
) -> std::result::Result<Response, (StatusCode, String)> {
    // Extract IP address from connect info
    let ip = req
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    // Check IP-based rate limiting first
    if MFA_RATE_LIMITER.is_rate_limited_ip(ip).await {
        tracing::warn!("MFA rate limit exceeded for IP: {}", ip);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many MFA attempts. Please try again later.".to_string(),
        ));
    }

    // Check if user is authenticated and apply user-based rate limiting
    if let Some(auth_user) = req.extensions().get::<AuthUser>() {
        if MFA_RATE_LIMITER
            .is_rate_limited_user(&auth_user.user.id)
            .await
        {
            tracing::warn!(
                "MFA rate limit exceeded for user: {} ({})",
                auth_user.user.email,
                auth_user.user.id
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Too many MFA attempts. Please try again later.".to_string(),
            ));
        }
    }

    Ok(next.run(req).await)
}

// ===== Request Information Extraction Middleware =====

/// Request information extracted for audit logging and risk assessment
#[derive(Clone, Debug)]
pub struct RequestInfo {
    pub ip_address: String,
    pub user_agent: String,
}

/// Middleware to extract request information and add it to extensions
pub async fn extract_request_info_middleware(mut request: Request, next: Next) -> Response {
    let ip_address = extract_client_ip(&request);

    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let request_info = RequestInfo {
        ip_address,
        user_agent,
    };

    // Add request info to extensions for downstream handlers
    request.extensions_mut().insert(request_info);

    next.run(request).await
}

/// Helper function to get request info from request extensions
#[allow(dead_code)]
pub fn get_request_info(request: &Request) -> &RequestInfo {
    request
        .extensions()
        .get::<RequestInfo>()
        .expect("RequestInfo middleware not applied to request")
}

// ===== HTTP Request Duration Metrics Middleware =====

/// Middleware to track HTTP request duration for observability.
///
/// Records `sso_http_request_duration_seconds` histogram with labels:
/// - `method`: HTTP method (GET, POST, etc.)
/// - `route`: Route pattern (e.g., `/api/organizations/:slug/users`) - NOT the actual path
/// - `status`: HTTP status code class (2xx, 4xx, 5xx)
///
/// **Cardinality Control**: Uses Axum's `MatchedPath` to get route patterns instead of
/// raw paths, preventing metric explosion from path parameters (e.g., `/users/uuid-123`).
///
/// **Placement**: This middleware should be applied as one of the outermost layers
/// to capture the full request lifecycle including auth, parsing, and response generation.
pub async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();

    // Extract route pattern BEFORE processing (MatchedPath is set by Axum router)
    // Fall back to "unknown" if no matched path (e.g., 404s)
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let method = request.method().to_string();

    // Process the request
    let response = next.run(request).await;

    // Calculate duration
    let duration = start.elapsed().as_secs_f64();

    // Categorize status code into classes for reasonable cardinality
    // Using exact status codes would explode cardinality (100+ unique values)
    let status_class = match response.status().as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    };

    // Record the histogram
    histogram!(
        "sso_http_request_duration_seconds",
        duration,
        "method" => method,
        "route" => route,
        "status" => status_class.to_string()
    );

    response
}

// ============================================================================
// Security Audit Item 3: Dynamic Efficient CORS
// ============================================================================

use axum::http::{header, HeaderValue, Method};

/// Middleware to handle CORS dynamically based on organization domains AND service redirect URIs.
///
/// This replaces the permissive `CorsLayer::new().allow_origin(Any)` with
/// a secure, domain-aware CORS policy:
///
/// 1. Platform dashboard URL is always allowed
/// 2. Checks domain_cache (L1) for previously validated origins
/// 3. Falls back to database lookup for organization custom domains (L2)
/// 4. Falls back to service redirect URI origin check (L2)
/// 5. Caches results for 5 minutes to reduce database load
pub async fn dynamic_cors_middleware(
    State(state): State<crate::state::AppState>,
    request: Request,
    next: Next,
) -> Response {
    use crate::store::{organizations::OrganizationStore, services::ServiceStore, DB};

    // 1. Check Origin Header - clone to avoid borrow issues
    let origin_header = match request.headers().get(header::ORIGIN).cloned() {
        Some(h) => h,
        None => return next.run(request).await, // Not a CORS request
    };

    let origin_str = match origin_header.to_str() {
        Ok(s) => s.to_string(), // Clone to owned string
        Err(_) => return next.run(request).await,
    };

    // 2. Check Platform Dashboard URL (Always allowed)
    // Trim trailing slash to match origin format
    let platform_url = state
        .config
        .platform_dashboard_base_url
        .trim_end_matches('/');
    if origin_str == platform_url {
        return allow_cors(request, next, origin_header).await;
    }

    // Also allow the API base URL itself
    let api_base = state.base_url.trim_end_matches('/');
    if origin_str == api_base {
        return allow_cors(request, next, origin_header).await;
    }

    // Parse domain from origin (remove protocol and port)
    // e.g. https://custom.org.com:3000 -> custom.org.com
    let domain = origin_str
        .split("://")
        .nth(1)
        .unwrap_or(&origin_str)
        .split(':')
        .next()
        .unwrap_or(&origin_str)
        .to_string();

    // Skip strict CORS for localhost during development
    if domain == "localhost" || domain.starts_with("127.") || domain.starts_with("192.168.") {
        return allow_cors(request, next, origin_header).await;
    }

    // 3. Check Cache (L1)
    // The cache is keyed by the full origin string (covers both custom domains and redirect URIs)
    if let Some(is_allowed) = state.domain_cache.get(&origin_str).await {
        if is_allowed {
            return allow_cors(request, next, origin_header).await;
        } else {
            // Explicitly denied in cache, proceed without CORS headers (browser will block)
            return next.run(request).await;
        }
    }

    // 4. Check Database (L2)
    let db = DB::Conn(&state.db);
    let mut is_allowed = false;

    // Check A: Is it an Organization Custom Domain?
    if let Ok(Some(org)) = OrganizationStore::find_by_custom_domain(db.clone(), &domain).await {
        if org.status == "active" && org.domain_verified {
            is_allowed = true;
        }
    }

    // Check B: Is it a Service Redirect URI origin?
    // Only check if not already found to save DB calls
    if !is_allowed {
        if let Ok(allowed) = ServiceStore::is_origin_allowed(db, &origin_str).await {
            is_allowed = allowed;
        }
    }

    // 5. Update Cache
    // Cache the full origin string result (unified for both sources)
    state.domain_cache.insert(origin_str, is_allowed).await;

    if is_allowed {
        allow_cors(request, next, origin_header).await
    } else {
        next.run(request).await
    }
}

/// Helper to attach CORS headers to the response
async fn allow_cors(req: Request, next: Next, origin: HeaderValue) -> Response {
    // Handle Preflight OPTIONS
    if req.method() == Method::OPTIONS {
        let mut response = Response::new(axum::body::Body::empty());
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, DELETE, PATCH, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type, X-Api-Key, X-Organization-ID"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"), // 24 hours
        );
        return response;
    }

    // Handle standard request
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    response
}

// ===== Custom Domain Resolution Middleware =====

/// Extension type for storing resolved organization from custom domain
#[derive(Clone, Debug)]
pub struct CustomDomainOrg {
    pub organization: organizations::Model,
}

/// Middleware to resolve organization from custom domain
/// This is optional and primarily used for future enhancements where
/// the org_slug might not be in the URL path
#[allow(dead_code)]
pub async fn resolve_custom_domain(
    State(db): State<DatabaseConnection>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    use crate::store::{organizations::OrganizationStore, DB};

    // Extract Host header
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Remove port if present
    let domain = host.split(':').next().unwrap_or(host);

    // Skip if it's localhost or empty
    if domain.is_empty() || domain == "localhost" || domain.starts_with("127.") {
        return Ok(next.run(req).await);
    }

    // Try to find organization by custom domain
    if let Ok(Some(org)) = OrganizationStore::find_by_custom_domain(DB::Conn(&db), domain).await {
        // Store organization in request extensions
        req.extensions_mut()
            .insert(CustomDomainOrg { organization: org });
    }

    Ok(next.run(req).await)
}

// ===== API Key Authentication Middleware =====

use crate::auth::api_key::ApiKeyService;

/// Service Principal identity for API key authenticated requests
#[derive(Clone, Debug)]
pub struct ServicePrincipal {
    #[allow(dead_code)]
    pub api_key_id: String,
    pub service_id: String,
    #[allow(dead_code)]
    pub service: crate::entities::services::Model,
    pub permissions: Vec<String>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for ServicePrincipal
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        parts
            .extensions
            .get::<ServicePrincipal>()
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("Not authenticated with API key".to_string()))
    }
}

/// Extract and validate API key from X-Api-Key header
pub async fn extract_api_key(
    State(db): State<DatabaseConnection>,
    mut req: Request,
    next: Next,
) -> std::result::Result<Response, AppError> {
    use crate::store::{api_keys::ApiKeyStore, services::ServiceStore, DB};

    let api_key = req
        .headers()
        .get("X-Api-Key")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid X-Api-Key header".to_string()))?;

    let prefix = ApiKeyService::extract_prefix(api_key)
        .ok_or_else(|| AppError::Unauthorized("Invalid API key format".to_string()))?;

    let stored_key = ApiKeyStore::find_by_prefix(DB::Conn(&db), &prefix)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid API key".to_string()))?;

    if !ApiKeyService::verify_key(api_key, &stored_key.key_hash) {
        return Err(AppError::Unauthorized("Invalid API key".to_string()));
    }

    if let Some(expires_at_naive) = &stored_key.expires_at {
        let expires_at: chrono::DateTime<chrono::Utc> =
            chrono::DateTime::from_naive_utc_and_offset(*expires_at_naive, chrono::Utc);
        if expires_at < chrono::Utc::now() {
            return Err(AppError::Unauthorized("API key has expired".to_string()));
        }
    }

    let service = ServiceStore::find_by_id(DB::Conn(&db), &stored_key.service_id)
        .await?
        .ok_or_else(|| {
            AppError::InternalServerError("Service not found for API key".to_string())
        })?;

    let permissions: Vec<String> =
        serde_json::from_str(&stored_key.permissions).unwrap_or_default();

    ApiKeyStore::update_last_used(DB::Conn(&db), &stored_key.id).await?;

    req.extensions_mut().insert(ServicePrincipal {
        api_key_id: stored_key.id,
        service_id: stored_key.service_id,
        service,
        permissions,
    });

    Ok(next.run(req).await)
}

// ============================================================================
// SCIM Authentication
// ============================================================================

/// SCIM Authentication Context
/// Contains the verified SCIM token and associated organization
#[derive(Clone, Debug)]
pub struct ScimAuth {
    pub token: crate::entities::scim_tokens::Model,
    pub org_id: String,
}

/// SCIM Authentication Middleware
///
/// Verifies the Bearer token in the Authorization header and ensures it's a valid SCIM token.
/// The token must:
/// 1. Be present in the Authorization header as "Bearer <token>"
/// 2. Exist in the scim_tokens table
/// 3. Be active (not revoked)
/// 4. Not be expired (if expiration is set)
///
/// On success, adds the ScimAuth to request extensions.
pub async fn scim_auth_middleware(
    State(db): State<DatabaseConnection>,
    mut request: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    use crate::store::{scim_tokens::ScimTokenStore, DB};

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if it's a Bearer token
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = auth_header.trim_start_matches("Bearer ").trim();

    // Verify the token
    let scim_token = ScimTokenStore::verify(DB::Conn(&db), token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate X-Organization-ID header if provided
    if let Some(org_id_header) = request.headers().get("X-Organization-ID") {
        if let Ok(org_id_str) = org_id_header.to_str() {
            if org_id_str != scim_token.org_id {
                // Token belongs to a different organization - unauthorized
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    // Update last_used_at (fire and forget - don't block the request)
    let db_clone = db.clone();
    let token_id = scim_token.id.clone();
    tokio::spawn(async move {
        let _ = ScimTokenStore::update_last_used(DB::Conn(&db_clone), &token_id).await;
    });

    // Add SCIM auth context to request extensions
    let scim_auth = ScimAuth {
        org_id: scim_token.org_id.clone(),
        token: scim_token,
    };
    request.extensions_mut().insert(scim_auth);

    Ok(next.run(request).await)
}
