//! Single-use verification tokens: unverified local accounts cannot log in.
use crate::{
    error::{database_error, ApiError},
    limiter, security,
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct VerificationToken {
    token: String,
}
#[derive(Deserialize)]
pub struct ResendRequest {
    email: String,
}
#[derive(sqlx::FromRow)]
struct PendingVerification {
    user_id: Uuid,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

pub async fn send(state: &AppState, user_id: Uuid, email: &str) -> Result<(), ApiError> {
    let mailer = state
        .recovery_mailer
        .as_ref()
        .ok_or(ApiError::Unavailable)?;
    let (token, token_hash) = security::generate_refresh();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO email_verification_tokens (id,user_id,token_hash,expires_at)
         VALUES ($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(Utc::now() + Duration::minutes(30))
    .execute(&state.db)
    .await
    .map_err(database_error)?;
    // Deliver verification through a direct provider API. Never log the token or put it
    // in the HTTP response. API-only clients submit the token with POST /verify-email.
    let body = format!(
        "Your AuthCore email verification token (30 minutes):\n{token}\n\nSubmit it as JSON to POST /api/v1/auth/verify-email. Ignore this message if you did not register."
    );
    let response = state
        .http
        .post("https://api.resend.com/emails")
        .bearer_auth(&mailer.api_key)
        .json(&json!({
            "from": mailer.from_email,
            "to": [email],
            "subject": "Verify your AuthCore email address",
            "text": body,
        }))
        .send()
        .await;
    match response {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            tracing::warn!(status=%resp.status(), "verification provider rejected delivery");
            invalidate_token(state, id).await?;
            Err(ApiError::Unavailable)
        }
        Err(_) => {
            tracing::warn!("verification provider unavailable");
            invalidate_token(state, id).await?;
            Err(ApiError::Unavailable)
        }
    }
}

async fn invalidate_token(state: &AppState, id: Uuid) -> Result<(), ApiError> {
    sqlx::query("UPDATE email_verification_tokens SET consumed_at=NOW() WHERE id=$1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(database_error)?;
    Ok(())
}

pub async fn resend(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ResendRequest>,
) -> Result<StatusCode, ApiError> {
    if state.recovery_mailer.is_none() {
        return Err(ApiError::Unavailable);
    }
    limiter::check(&state.redis, "verify-ip", &addr.ip().to_string(), 5, 60).await?;
    let Some(email) = security::valid_email(&body.email) else {
        return Ok(StatusCode::ACCEPTED);
    };
    limiter::check(&state.redis, "verify-email", &email, 3, 3600).await?;
    let account: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE email=$1 AND email_verified_at IS NULL")
            .bind(&email)
            .fetch_optional(&state.db)
            .await
            .map_err(database_error)?;
    if let Some((user_id,)) = account {
        // Always give a generic response for valid addresses, even on mail failures.
        if let Err(error) = send(&state, user_id, &email).await {
            tracing::warn!(?error, "verification resend failed");
        }
    }
    Ok(StatusCode::ACCEPTED)
}

pub async fn verify(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<VerificationToken>,
) -> Result<StatusCode, ApiError> {
    limiter::check(&state.redis, "verify-token", &addr.ip().to_string(), 15, 60).await?;
    if body.token.len() != 64
        || !body
            .token
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || v == b'_' || v == b'-')
    {
        return Err(ApiError::Unauthorized);
    }
    let hash = security::hash_refresh(&body.token);
    // Lock the account before locking a token row. Concurrent verification of
    // different outstanding tokens otherwise permits a user/token lock inversion.
    let identity: Option<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM email_verification_tokens WHERE token_hash=$1")
            .bind(&hash)
            .fetch_optional(&state.db)
            .await
            .map_err(database_error)?;
    let (user_id,) = identity.ok_or(ApiError::Unauthorized)?;

    let mut tx = state.db.begin().await.map_err(database_error)?;
    let account: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
    if account.is_none() {
        return Err(ApiError::Unauthorized);
    }
    let pending: Option<PendingVerification> = sqlx::query_as(
        "SELECT user_id,expires_at,consumed_at
         FROM email_verification_tokens WHERE token_hash=$1 FOR UPDATE",
    )
    .bind(hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    let pending = pending.ok_or(ApiError::Unauthorized)?;
    if pending.consumed_at.is_some() || pending.expires_at <= Utc::now() {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("UPDATE users SET email_verified_at=COALESCE(email_verified_at,NOW()) WHERE id=$1")
        .bind(pending.user_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query(
        "UPDATE email_verification_tokens SET consumed_at=NOW()
         WHERE user_id=$1 AND consumed_at IS NULL",
    )
    .bind(pending.user_id)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
}
