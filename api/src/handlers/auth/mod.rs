// Auth module - handles all authentication-related endpoints
// This module is organized into logical sub-modules:
// - oauth: OAuth2 flows (end-user SSO and admin authentication)
// - device: Device authorization flow (RFC 8628)
// - session: Session management (refresh token, logout)
// - password: Email/password authentication
// - mfa: Multi-factor authentication
// - hrd: Home Realm Discovery (email domain lookup)
// - passkeys: WebAuthn/FIDO2 passkey authentication
// - magic: Passwordless magic link authentication

pub mod device;
pub mod hrd;
pub mod magic;
pub mod mfa;
pub mod oauth;
pub mod passkeys;
pub mod password;
pub mod session;

// Re-export all public handlers from sub-modules

// OAuth handlers
pub use oauth::{
    auth_admin_callback, auth_admin_provider, auth_callback, auth_provider,
    get_authorization_url_for_client,
};

// Device flow handlers
pub use device::{device_code, device_verify, token_exchange};

// Session handlers
pub use session::{logout, refresh_token, revoke_token};

// Password authentication handlers
pub use password::{
    forgot_password, login, register, resend_verification, reset_password, verify_email,
};

// MFA handlers
pub use mfa::verify_mfa_login;

// HRD handlers
pub use hrd::lookup_email;

// Passkey handlers
pub use passkeys::{authenticate_finish, authenticate_start, register_finish, register_start};

// Magic link handlers
pub use magic::{request_magic_link, verify_magic_link};
