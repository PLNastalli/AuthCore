use crate::{error::{database_error, ApiError}, limiter, security, state::AppState};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(FromRow)]
struct User {
    id: Uuid,
    email: String,
    password_hash: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct UserView {
    id: Uuid,
    email: String,
    created_at: DateTime<Utc>,
}

impl From<User> for UserView {
    fn from(value: User) -> Self {
        Self { id: value.id, email: value.email, created_at: value.created_at }
    }
}

#[derive(Deserialize)]
pub struct Credentials {
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct ChangePassword {
    current_password: String,
    new_password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
}

#[derive(Serialize)]
pub struct SessionView {
    id: Uuid,
    created_at: DateTime<Utc>,
    current: bool,
}

async fn active_user(state: &AppState, headers: &HeaderMap) -> Result<(Uuid, Uuid), ApiError> {
    let (user_id, session_id) = security::verify_access(state, headers)?;
    let valid: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL"
    )
    .bind(session_id).bind(user_id)
    .fetch_optional(&state.db).await.map_err(database_error)?;
    if valid.is_none() { return Err(ApiError::Unauthorized); }
    Ok((user_id, session_id))
}

async fn limit_auth(state: &AppState, address: SocketAddr, scope: &str, max: i64) -> Result<(), ApiError> {
    // Socket peer address only: do not trust client-controlled X-Forwarded-For.
    limiter::check(&state.redis, scope, &address.ip().to_string(), max, 60).await
}

fn cookie_header(state: &AppState, token: Option<&str>) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&state.cookie(token)).map_err(|_| ApiError::Internal)?,
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(headers)
}

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

pub async fn ready(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    sqlx::query("SELECT 1").execute(&state.db).await.map_err(|_| ApiError::Unavailable)?;
    let mut conn = state.redis.get_multiplexed_async_connection().await.map_err(|_| ApiError::Unavailable)?;
    let _: String = redis::cmd("PING").query_async(&mut conn).await.map_err(|_| ApiError::Unavailable)?;
    Ok(Json(json!({ "status": "ready" })))
}

pub async fn openapi() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        include_str!("../openapi.json"),
    )
}

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<Credentials>,
) -> Result<impl IntoResponse, ApiError> {
    limit_auth(&state, addr, "register", 8).await?;
    let email = security::valid_email(&body.email).ok_or(ApiError::Invalid("invalid_email"))?;
    if !security::valid_password(&body.password) {
        return Err(ApiError::Invalid("password_must_be_12_to_1024_bytes"));
    }
    let hash = security::hash_password(body.password).await?;
    let user_id = Uuid::new_v4();
    let result = sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)")
        .bind(user_id).bind(&email).bind(hash).execute(&state.db).await;
    match result {
        Ok(_) => {},
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => return Err(ApiError::Conflict),
        Err(err) => return Err(database_error(err)),
    }
    let user: User = sqlx::query_as("SELECT id, email, password_hash, created_at FROM users WHERE id = $1")
        .bind(user_id).fetch_one(&state.db).await.map_err(database_error)?;
    Ok((StatusCode::CREATED, Json(UserView::from(user))))
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<Credentials>,
) -> Result<impl IntoResponse, ApiError> {
    limit_auth(&state, addr, "login-ip", 15).await?;
    let email = security::valid_email(&body.email).ok_or(ApiError::Unauthorized)?;
    limiter::check(&state.redis, "login-account", &email, 10, 300).await?;
    let user: Option<User> = sqlx::query_as(
        "SELECT id, email, password_hash, created_at FROM users WHERE email = $1"
    ).bind(&email).fetch_optional(&state.db).await.map_err(database_error)?;
    let user = user.ok_or(ApiError::Unauthorized)?;
    if !security::check_password(body.password, user.password_hash).await? {
        return Err(ApiError::Unauthorized);
    }
    let session_id = Uuid::new_v4();
    let (refresh, hash) = security::generate_refresh();
    let mut tx = state.db.begin().await.map_err(database_error)?;
    sqlx::query("INSERT INTO sessions (id, user_id) VALUES ($1, $2)")
        .bind(session_id).bind(user.id).execute(&mut *tx).await.map_err(database_error)?;
    sqlx::query(
        "INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)"
    )
        .bind(Uuid::new_v4()).bind(session_id).bind(hash)
        .bind(Utc::now() + Duration::seconds(security::REFRESH_TTL_SECONDS))
        .execute(&mut *tx).await.map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    let access_token = security::issue_access(&state, user.id, session_id)?;
    Ok((
        cookie_header(&state, Some(&refresh))?,
        Json(TokenResponse { access_token, token_type: "Bearer", expires_in: 900 }),
    ))
}

pub async fn refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    security::validate_origin(&state, &headers)?;
    limit_auth(&state, addr, "refresh", 40).await?;
    let presented = security::refresh_cookie(&state, &headers)?;
    let token_hash = security::hash_refresh(&presented);
    let mut tx = state.db.begin().await.map_err(database_error)?;
    // Lock the parent session so concurrent refresh requests cannot both succeed.
    let row: Option<(Uuid, Uuid, Option<DateTime<Utc>>, Option<DateTime<Utc>>, DateTime<Utc>)> =
        sqlx::query_as(
            "SELECT s.id, s.user_id, s.revoked_at, t.consumed_at, t.expires_at
             FROM refresh_tokens t JOIN sessions s ON s.id = t.session_id
             WHERE t.token_hash = $1 FOR UPDATE OF s"
        )
        .bind(token_hash).fetch_optional(&mut *tx).await.map_err(database_error)?;
    let (session_id, user_id, revoked_at, consumed_at, expires_at) = row.ok_or(ApiError::Unauthorized)?;
    if revoked_at.is_some() { return Err(ApiError::Unauthorized); }
    if consumed_at.is_some() {
        sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL")
            .bind(session_id).execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        return Err(ApiError::Unauthorized);
    }
    if expires_at <= Utc::now() { return Err(ApiError::Unauthorized); }
    sqlx::query("UPDATE refresh_tokens SET consumed_at = NOW() WHERE token_hash = $1")
        .bind(security::hash_refresh(&presented))
        .execute(&mut *tx).await.map_err(database_error)?;
    let (next, next_hash) = security::generate_refresh();
    sqlx::query(
        "INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)"
    )
        .bind(Uuid::new_v4()).bind(session_id).bind(next_hash)
        .bind(Utc::now() + Duration::seconds(security::REFRESH_TTL_SECONDS))
        .execute(&mut *tx).await.map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    let access_token = security::issue_access(&state, user_id, session_id)?;
    Ok((
        cookie_header(&state, Some(&next))?,
        Json(TokenResponse { access_token, token_type: "Bearer", expires_in: 900 }),
    ))
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, _) = active_user(&state, &headers).await?;
    let user: User = sqlx::query_as(
        "SELECT id, email, password_hash, created_at FROM users WHERE id = $1"
    ).bind(user_id).fetch_one(&state.db).await.map_err(database_error)?;
    Ok(Json(UserView::from(user)))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let (_, session_id) = active_user(&state, &headers).await?;
    sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session_id).execute(&state.db).await.map_err(database_error)?;
    Ok((cookie_header(&state, None)?, StatusCode::NO_CONTENT))
}

pub async fn logout_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, _) = active_user(&state, &headers).await?;
    sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id).execute(&state.db).await.map_err(database_error)?;
    Ok((cookie_header(&state, None)?, StatusCode::NO_CONTENT))
}

pub async fn sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, current_session) = active_user(&state, &headers).await?;
    let rows: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, created_at FROM sessions WHERE user_id=$1 AND revoked_at IS NULL
         ORDER BY created_at DESC LIMIT 100"
    ).bind(user_id).fetch_all(&state.db).await.map_err(database_error)?;
    let items: Vec<SessionView> = rows.into_iter().map(|(id, created_at)| SessionView {
        id, created_at, current: id == current_session
    }).collect();
    Ok(Json(json!({ "items": items })))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, _) = active_user(&state, &headers).await?;
    let changed = sqlx::query(
        "UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL"
    ).bind(session_id).bind(user_id)
        .execute(&state.db).await.map_err(database_error)?;
    if changed.rows_affected() == 0 { return Err(ApiError::NotFound); }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChangePassword>,
) -> Result<impl IntoResponse, ApiError> {
    let (user_id, _) = active_user(&state, &headers).await?;
    if !security::valid_password(&body.new_password) {
        return Err(ApiError::Invalid("password_must_be_12_to_1024_bytes"));
    }
    let user: User = sqlx::query_as(
        "SELECT id, email, password_hash, created_at FROM users WHERE id=$1"
    ).bind(user_id).fetch_one(&state.db).await.map_err(database_error)?;
    if !security::check_password(body.current_password, user.password_hash).await? {
        return Err(ApiError::Unauthorized);
    }
    let next_hash = security::hash_password(body.new_password).await?;
    let mut tx = state.db.begin().await.map_err(database_error)?;
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(next_hash).bind(user_id).execute(&mut *tx).await.map_err(database_error)?;
    sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id).execute(&mut *tx).await.map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    Ok((cookie_header(&state, None)?, StatusCode::NO_CONTENT))
}
