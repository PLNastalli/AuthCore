//! Google OpenID Connect client. No homegrown authorization server.
use crate::{
    error::{database_error, ApiError},
    limiter, security,
    state::{AppState, GoogleOAuth},
};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Redirect},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use uuid::Uuid;

const AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[derive(Serialize, Deserialize)]
struct StateData {
    verifier: String,
    nonce: String,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    state: String,
    code: String,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
}

#[derive(Deserialize)]
struct GoogleClaims {
    sub: String,
    email: String,
    email_verified: bool,
    nonce: String,
    // Also require standard claims even if jsonwebtoken validates their values.
    exp: usize,
    iss: String,
    aud: String,
}

fn opaque() -> String {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn oauth_cookie(state: &AppState, token: Option<&str>) -> String {
    let name = if state.cookie_secure {
        "__Host-authcore_oauth_csrf"
    } else {
        "authcore_oauth_csrf"
    };
    match token {
        Some(value) => format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{}",
            if state.cookie_secure { "; Secure" } else { "" }
        ),
        None => format!(
            "{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
            if state.cookie_secure { "; Secure" } else { "" }
        ),
    }
}

pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, ApiError> {
    let google = state.google.as_ref().ok_or(ApiError::Unavailable)?;
    limiter::check(&state.redis, "google-start", &addr.ip().to_string(), 20, 60).await?;

    let csrf = opaque();
    let nonce = opaque();
    let verifier = opaque();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let key = format!("authcore:oidc:{}", security::hash_refresh(&csrf));

    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let serialized = serde_json::to_string(&StateData {
        verifier,
        nonce: nonce.clone(),
    })
    .map_err(|_| ApiError::Internal)?;
    let stored: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg(serialized)
        .arg("NX")
        .arg("EX")
        .arg(600)
        .query_async(&mut conn)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    if stored.as_deref() != Some("OK") {
        return Err(ApiError::Internal);
    }

    let mut url = reqwest::Url::parse(AUTHORIZATION_URL).map_err(|_| ApiError::Internal)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &google.client_id)
        .append_pair("redirect_uri", &google.redirect_uri)
        .append_pair("scope", "openid email")
        .append_pair("state", &csrf)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&oauth_cookie(&state, Some(&csrf)))
            .map_err(|_| ApiError::Internal)?,
    );
    Ok((headers, Redirect::temporary(url.as_str())))
}

fn validate_callback_cookie(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<(), ApiError> {
    let name = if state.cookie_secure {
        "__Host-authcore_oauth_csrf"
    } else {
        "authcore_oauth_csrf"
    };
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .ok_or(ApiError::Forbidden)?;
    let sent = cookie
        .split(';')
        .map(str::trim)
        .find_map(|entry| entry.strip_prefix(&format!("{name}=")))
        .ok_or(ApiError::Forbidden)?;
    // Hash equality compares fixed-length digests, not attacker-controlled string length.
    if security::hash_refresh(sent) != security::hash_refresh(csrf) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn validate_google_id_token(
    state: &AppState,
    google: &GoogleOAuth,
    raw: &str,
    expected_nonce: &str,
) -> Result<GoogleClaims, ApiError> {
    let head = decode_header(raw).map_err(|_| ApiError::Unauthorized)?;
    if head.alg != Algorithm::RS256 {
        return Err(ApiError::Unauthorized);
    }
    let kid = head.kid.ok_or(ApiError::Unauthorized)?;
    let jwks = state
        .http
        .get(JWKS_URL)
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    if !jwks.status().is_success() {
        return Err(ApiError::Unavailable);
    }
    let jwks: Jwks = jwks.json().await.map_err(|_| ApiError::Unavailable)?;
    let jwk = jwks
        .keys
        .into_iter()
        .find(|key| {
            key.kid == kid
                && key.kty == "RSA"
                && key
                    .alg
                    .as_deref()
                    .is_none_or(|algorithm| algorithm == "RS256")
                && key.usage.as_deref().is_none_or(|usage| usage == "sig")
        })
        .ok_or(ApiError::Unauthorized)?;
    let decoding =
        DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|_| ApiError::Unauthorized)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    validation.set_audience(&[google.client_id.as_str()]);
    validation.required_spec_claims.insert("sub".to_string());
    let token =
        decode::<GoogleClaims>(raw, &decoding, &validation).map_err(|_| ApiError::Unauthorized)?;
    let claims = token.claims;
    if claims.nonce != expected_nonce
        || !claims.email_verified
        || claims.sub.is_empty()
        || claims.sub.len() > 256
        || claims.exp == 0
        || claims.iss.is_empty()
        || claims.aud.is_empty()
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(claims)
}

async fn persist_google_identity(state: &AppState, claims: GoogleClaims) -> Result<Uuid, ApiError> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = 'google' AND provider_sub = $1",
    )
    .bind(&claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(database_error)?;
    if let Some((user_id,)) = existing {
        return Ok(user_id);
    }

    let email = security::valid_email(&claims.email).ok_or(ApiError::Unauthorized)?;
    // Never link an external identity to a pre-existing local account based on email alone.
    let collision: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(database_error)?;
    if collision.is_some() {
        return Err(ApiError::Forbidden);
    }

    let unknown_password = opaque();
    let password_hash = security::hash_password(unknown_password).await?;
    let user_id = Uuid::new_v4();
    let mut tx = state.db.begin().await.map_err(database_error)?;
    sqlx::query("INSERT INTO users (id,email,password_hash,email_verified_at) VALUES ($1,$2,$3,NOW())")
        .bind(user_id)
        .bind(&email)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query(
        "INSERT INTO oauth_accounts (provider, provider_sub, user_id, email_at_link)
         VALUES ('google',$1,$2,$3)",
    )
    .bind(&claims.sub)
    .bind(user_id)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    Ok(user_id)
}

pub async fn callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let google: Arc<GoogleOAuth> = state.google.clone().ok_or(ApiError::Unavailable)?;
    limiter::check(
        &state.redis,
        "google-callback",
        &addr.ip().to_string(),
        30,
        60,
    )
    .await?;
    if query.state.len() > 256 || query.code.len() > 4096 || query.code.is_empty() {
        return Err(ApiError::Invalid("invalid_oauth_callback"));
    }
    validate_callback_cookie(&state, &headers, &query.state)?;
    let key = format!("authcore:oidc:{}", security::hash_refresh(&query.state));
    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let saved: Option<String> = redis::cmd("GETDEL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let saved = saved.ok_or(ApiError::Unauthorized)?;
    let context: StateData = serde_json::from_str(&saved).map_err(|_| ApiError::Unauthorized)?;

    let response = state
        .http
        .post(TOKEN_URL)
        .form(&[
            ("code", query.code.as_str()),
            ("client_id", google.client_id.as_str()),
            ("client_secret", google.client_secret.as_str()),
            ("redirect_uri", google.redirect_uri.as_str()),
            ("code_verifier", context.verifier.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    if !response.status().is_success() {
        return Err(ApiError::Unauthorized);
    }
    let tokens: GoogleTokenResponse = response.json().await.map_err(|_| ApiError::Unauthorized)?;
    let claims =
        validate_google_id_token(&state, &google, &tokens.id_token, &context.nonce).await?;
    let user_id = persist_google_identity(&state, claims).await?;

    let session_id = Uuid::new_v4();
    let (refresh, hash) = security::generate_refresh();
    let mut tx = state.db.begin().await.map_err(database_error)?;
    sqlx::query("INSERT INTO sessions (id,user_id) VALUES ($1,$2)")
        .bind(session_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query(
        "INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(session_id)
    .bind(hash)
    .bind(Utc::now() + Duration::seconds(security::REFRESH_TTL_SECONDS))
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    let access_token = security::issue_access(&state, user_id, session_id)?;

    let mut outgoing = HeaderMap::new();
    outgoing.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&state.cookie(Some(&refresh))).map_err(|_| ApiError::Internal)?,
    );
    outgoing.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&oauth_cookie(&state, None)).map_err(|_| ApiError::Internal)?,
    );
    outgoing.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((
        outgoing,
        Json(json!({
            "access_token": access_token, "token_type": "Bearer", "expires_in": 900
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pkce_verifier_generates_unique_sized_tokens() {
        let first = opaque();
        let second = opaque();
        assert!(first.len() >= 43);
        assert_ne!(first, second);
        assert_eq!(
            URL_SAFE_NO_PAD
                .encode(Sha256::digest(first.as_bytes()))
                .len(),
            43
        );
    }
}
