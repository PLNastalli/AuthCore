use crate::{error::ApiError, state::AppState};
use argon2::{
    password_hash::{
        rand_core::OsRng as SaltOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, encode, Algorithm, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

const ACCESS_TTL_SECONDS: i64 = 900;
pub const REFRESH_TTL_SECONDS: i64 = 60 * 60 * 24 * 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    sid: String,
    iss: String,
    aud: String,
    iat: usize,
    exp: usize,
    token_type: String,
}

pub fn issue_access(state: &AppState, user_id: Uuid, session_id: Uuid) -> Result<String, ApiError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        sid: session_id.to_string(),
        iss: state.jwt.issuer.clone(),
        aud: state.jwt.audience.clone(),
        iat: now as usize,
        exp: (now + ACCESS_TTL_SECONDS) as usize,
        token_type: "access".into(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("primary".to_string());
    encode(&header, &claims, &state.jwt.encoding).map_err(|_| ApiError::Internal)
}

pub fn verify_access(state: &AppState, headers: &HeaderMap) -> Result<(Uuid, Uuid), ApiError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty())
        .ok_or(ApiError::Unauthorized)?;

    // The configured key is the only accepted signing key until versioned key rotation lands.
    let token_header = decode_header(raw).map_err(|_| ApiError::Unauthorized)?;
    if token_header.alg != Algorithm::RS256 || token_header.kid.as_deref() != Some("primary") {
        return Err(ApiError::Unauthorized);
    }
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[state.jwt.issuer.as_str()]);
    validation.set_audience(&[state.jwt.audience.as_str()]);
    validation.required_spec_claims.insert("sub".into());
    let token = decode::<Claims>(raw, &state.jwt.decoding, &validation)
        .map_err(|_| ApiError::Unauthorized)?;
    if token.claims.token_type != "access" {
        return Err(ApiError::Unauthorized);
    }
    let user = Uuid::parse_str(&token.claims.sub).map_err(|_| ApiError::Unauthorized)?;
    let session = Uuid::parse_str(&token.claims.sid).map_err(|_| ApiError::Unauthorized)?;
    Ok((user, session))
}

/// Bounds memory-hard Argon2 work and keeps blocking CPU work off Tokio workers.
/// A permit is held inside the blocking task, including when HTTP clients cancel.
#[derive(Clone)]
pub struct PasswordService {
    permits: Arc<Semaphore>,
}

impl PasswordService {
    pub fn new(max_concurrent: usize) -> Self {
        Self { permits: Arc::new(Semaphore::new(max_concurrent.max(1))) }
    }

    async fn slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
        tokio::time::timeout(Duration::from_secs(3), self.permits.clone().acquire_owned())
            .await.map_err(|_| ApiError::Unavailable)?
            .map_err(|_| ApiError::Unavailable)
    }

    pub async fn hash(&self, password: String) -> Result<String, ApiError> {
        let permit = self.slot().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let salt = SaltString::generate(&mut SaltOsRng);
            Argon2::default().hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| ApiError::Internal)
        }).await.map_err(|_| ApiError::Internal)?
    }

    pub async fn verify(&self, password: String, encoded: String) -> Result<bool, ApiError> {
        let permit = self.slot().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let parsed = PasswordHash::new(&encoded).map_err(|_| ApiError::Internal)?;
            Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        }).await.map_err(|_| ApiError::Internal)?
    }
}

pub fn generate_refresh() -> (String, String) {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    let value = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh(&value);
    (value, hash)
}

pub fn hash_refresh(token: &str) -> String {
    let result = Sha256::digest(token.as_bytes());
    format!("{result:x}")
}

pub fn refresh_cookie(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    cookie
        .split(';')
        .map(str::trim)
        .find_map(|entry| {
            entry
                .strip_prefix(&format!("{}=", state.cookie_name()))
                .map(str::to_owned)
        })
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .ok_or(ApiError::Unauthorized)
}

pub fn validate_origin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .ok_or(ApiError::Forbidden)?;
    if origin != state.public_origin {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub fn valid_email(input: &str) -> Option<String> {
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.len() < 3 || trimmed.len() > 254 || trimmed.contains(char::is_whitespace) {
        return None;
    }
    let (local, domain) = trimmed.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some(trimmed)
}

pub fn valid_password(password: &str) -> bool {
    password.len() >= 12 && password.len() <= 1024
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_email() {
        assert_eq!(
            valid_email(" Test@Example.com "),
            Some("test@example.com".into())
        );
        assert_eq!(valid_email("not-an-email"), None);
        assert_eq!(valid_email(" a @example.com"), None);
    }
    #[test]
    fn password_bounds() {
        assert!(!valid_password("short"));
        assert!(valid_password("long-password-2026"));
    }
    #[test]
    fn random_refresh_hash() {
        let (a, ah) = generate_refresh();
        let (b, bh) = generate_refresh();
        assert_ne!(a, b);
        assert_ne!(ah, bh);
        assert_eq!(hash_refresh(&a), ah);
    }
    #[tokio::test]
    async fn password_roundtrip() {
        let service = PasswordService::new(2);
        let hash = service.hash("correct horse battery staple".into())
            .await
            .unwrap();
        assert!(
            service.verify("correct horse battery staple".into(), hash.clone())
                .await
                .unwrap()
        );
        assert!(!service.verify("wrong-password".into(), hash).await.unwrap());
    }
}
