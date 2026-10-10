//! One-time, database-backed password reset with optional Resend delivery.
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
pub struct ForgotPassword {
    email: String,
}

#[derive(Deserialize)]
pub struct ResetPassword {
    token: String,
    new_password: String,
}

#[derive(sqlx::FromRow)]
struct ResetRecord {
    user_id: Uuid,
    consumed_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

pub async fn forgot_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ForgotPassword>,
) -> Result<StatusCode, ApiError> {
    // Provider configuration is checked without querying user identities.
    let mailer = state
        .recovery_mailer
        .as_ref()
        .ok_or(ApiError::Unavailable)?;
    limiter::check(&state.redis, "forgot-ip", &addr.ip().to_string(), 5, 60).await?;
    let email = match security::valid_email(&body.email) {
        Some(email) => email,
        None => return Ok(StatusCode::ACCEPTED), // Do not reveal account existence.
    };
    limiter::check(&state.redis, "forgot-email", &email, 3, 3600).await?;
    let user: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email=$1 AND email_verified_at IS NOT NULL")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(database_error)?;
    let Some((user_id,)) = user else {
        return Ok(StatusCode::ACCEPTED);
    };

    let (token, token_hash) = security::generate_refresh();
    let reset_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO password_reset_tokens (id,user_id,token_hash,expires_at)
         VALUES ($1,$2,$3,$4)",
    )
    .bind(reset_id)
    .bind(user_id)
    .bind(token_hash)
    .bind(Utc::now() + Duration::minutes(15))
    .execute(&state.db)
    .await
    .map_err(database_error)?;

    // The token goes only to the account's verified mailbox; never log or return it.
    // Email confirmation is not yet implemented, so production use remains unsupported.
    let content = format!(
        "AuthCore password reset request.\n\nYour one-time reset token (valid for 15 minutes):\n{token}\n\nSubmit this token in the JSON body of POST /api/v1/auth/reset-password together with a new_password. If you did not request this, ignore the message."
    );
    let result = state
        .http
        .post("https://api.resend.com/emails")
        .bearer_auth(&mailer.api_key)
        .json(&json!({
            "from": mailer.from_email,
            "to": [email],
            "subject": "AuthCore password reset",
            "text": content,
        }))
        .send()
        .await;
    match result {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            tracing::error!(status=%resp.status(), "password reset mail delivery rejected");
            revoke_failed_delivery(&state, reset_id).await?;
        }
        Err(_) => {
            tracing::error!("password reset mail delivery unavailable");
            revoke_failed_delivery(&state, reset_id).await?;
        }
    }
    Ok(StatusCode::ACCEPTED)
}

async fn revoke_failed_delivery(state: &AppState, id: Uuid) -> Result<(), ApiError> {
    sqlx::query("UPDATE password_reset_tokens SET consumed_at=NOW() WHERE id=$1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(database_error)?;
    Ok(())
}

pub async fn reset_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ResetPassword>,
) -> Result<StatusCode, ApiError> {
    limiter::check(&state.redis, "reset-ip", &addr.ip().to_string(), 10, 60).await?;
    if !security::valid_password(&body.new_password) {
        return Err(ApiError::Invalid("password_must_be_12_to_1024_bytes"));
    }
    if body.token.len() != 64
        || !body
            .token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(ApiError::Unauthorized);
    }
    let token_hash = security::hash_refresh(&body.token);
    let user: Option<(Uuid,)> =
        sqlx::query_as("SELECT user_id FROM password_reset_tokens WHERE token_hash=$1")
            .bind(&token_hash)
            .fetch_optional(&state.db)
            .await
            .map_err(database_error)?;
    let (user_id,) = user.ok_or(ApiError::Unauthorized)?;
    let next_hash = security::hash_password(body.new_password).await?;
    let mut tx = state.db.begin().await.map_err(database_error)?;

    // Acquire the per-user lock *before* checking token state. This serializes
    // concurrent resets using different outstanding tokens for one account.
    let lock: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
    if lock.is_none() {
        return Err(ApiError::Unauthorized);
    }

    let token: Option<ResetRecord> = sqlx::query_as(
        "SELECT user_id, consumed_at, expires_at
         FROM password_reset_tokens WHERE token_hash=$1 FOR UPDATE",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    let token = token.ok_or(ApiError::Unauthorized)?;
    if token.user_id != user_id || token.consumed_at.is_some() || token.expires_at <= Utc::now() {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("UPDATE users SET password_hash=$1 WHERE id=$2")
        .bind(next_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query(
        "UPDATE password_reset_tokens SET consumed_at=NOW()
         WHERE user_id=$1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    sqlx::query("UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
}
