pub const DEFAULT_TIER_NAME: &str = "free";
pub const DEFAULT_MAX_SERVICES: i64 = 2;
pub const DEFAULT_MAX_USERS: i64 = 3;
pub const INVITATION_EXPIRY_DAYS: i64 = 7;
pub const DEVICE_CODE_EXPIRE_MINUTES: i64 = 15;
pub const JWT_EXPIRE_HOURS: i64 = 24;
pub const OAUTH_STATE_EXPIRE_MINUTES: i64 = 10;
pub const TOKEN_REFRESH_LOCK_TIMEOUT_SECONDS: i64 = 30;

pub const RESERVED_SLUGS: &[&str] = &[
    "api", "www", "mail", "ftp", "admin", "root", "support", "help", "docs", "blog", "news",
    "status", "health", "ping", "cdn", "assets", "static",
];

pub const VALID_ORG_ROLES: &[&str] = &["owner", "admin", "member"];
pub const VALID_INVITATION_ROLES: &[&str] = &["admin", "member"];
pub const VALID_SERVICE_TYPES: &[&str] = &["web", "mobile", "desktop", "api"];

pub const MIN_SLUG_LENGTH: usize = 3;
pub const MAX_SLUG_LENGTH: usize = 50;
pub const MIN_NAME_LENGTH: usize = 2;
pub const MAX_NAME_LENGTH: usize = 100;
