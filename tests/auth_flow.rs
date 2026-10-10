use authcore::{app, state::AppState};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, Response, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

async fn call(
    app: &Router,
    method: &str,
    url: &str,
    body: Option<Value>,
    extra_headers: &[(&str, &str)],
) -> Response<Body> {
    let payload = body.map(|v| v.to_string()).unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(url)
        .header(header::CONTENT_TYPE, "application/json");
    for &(key, value) in extra_headers {
        builder = builder.header(key, value);
    }
    let mut req = builder.body(Body::from(payload)).unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:42301".parse::<SocketAddr>().unwrap(),
    ));
    app.clone().oneshot(req).await.unwrap()
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn token_rotation_replay_and_revocation() {
    // Requires the test environment variables from CI and running PostgreSQL/Redis.
    // Skip only when the database is not configured (e.g. a local unit-test run).
    if std::env::var("DATABASE_URL").is_err() {
        eprintln!("Skipping integration test: DATABASE_URL is not configured");
        return;
    }
    let state = AppState::from_env()
        .await
        .expect("test services must be available");
    let app = app(state);
    let email = format!("authcore-test-{}@example.com", Uuid::new_v4());
    let password = "a-strong-development-password-2026";

    let response = call(
        &app,
        "POST",
        "/api/v1/auth/register",
        Some(json!({ "email": email, "password": password })),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = call(
        &app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "email": email, "password": password })),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let old_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let token = json_body(response).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let auth_header = format!("Bearer {token}");
    let response = call(
        &app,
        "GET",
        "/api/v1/auth/me",
        None,
        &[("authorization", &auth_header)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Flip a signature character. A modified JWT must never authenticate.
    let (prefix, signature) = token.rsplit_once('.').unwrap();
    let alternate = if signature.starts_with('A') { "B" } else { "A" };
    let modified = format!("{prefix}.{alternate}{}", &signature[1..]);
    let modified_auth = format!("Bearer {modified}");
    let rejected = call(
        &app,
        "GET",
        "/api/v1/auth/me",
        None,
        &[("authorization", &modified_auth)],
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

    let response = call(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &[("cookie", &old_cookie), ("origin", "http://localhost:3000")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let new_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let new_access = json_body(response).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // A consumed refresh credential indicates token replay. The entire session is revoked.
    let response = call(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &[("cookie", &old_cookie), ("origin", "http://localhost:3000")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = call(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &[("cookie", &new_cookie), ("origin", "http://localhost:3000")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bearer = format!("Bearer {new_access}");
    let response = call(
        &app,
        "GET",
        "/api/v1/auth/me",
        None,
        &[("authorization", &bearer)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_mismatched_origin_before_refresh() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let state = AppState::from_env()
        .await
        .expect("test services must be available");
    let app = app(state);
    let response = call(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &[
            ("cookie", "authcore_refresh=invalid"),
            ("origin", "https://attacker.example"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn password_reset_is_one_time_and_revokes_sessions() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let state = AppState::from_env()
        .await
        .expect("database and Redis required");
    let api = app(state.clone());
    let email = format!("recovery-test-{}@example.com", Uuid::new_v4());
    let old_password = "old-password-strong-2026";
    let new_password = "new-password-strong-2026";
    let registered = call(
        &api,
        "POST",
        "/api/v1/auth/register",
        Some(json!({ "email": email, "password": old_password })),
        &[],
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let user_id: Uuid = json_body(registered).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let logged_in = call(
        &api,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "email": email, "password": old_password })),
        &[],
    )
    .await;
    assert_eq!(logged_in.status(), StatusCode::OK);
    let token = json_body(logged_in).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let bearer = format!("Bearer {token}");

    // Normally the raw token is delivered by the external email provider.
    // Seed it directly here to validate the database and HTTP behavior offline.
    let (raw_reset, digest) = authcore::security::generate_refresh();
    sqlx::query(
        "INSERT INTO password_reset_tokens (id,user_id,token_hash,expires_at)
         VALUES ($1,$2,$3,NOW()+INTERVAL '15 minutes')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(digest)
    .execute(&state.db)
    .await
    .unwrap();

    let response = call(
        &api,
        "POST",
        "/api/v1/auth/reset-password",
        Some(json!({ "token": raw_reset, "new_password": new_password })),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let replay = call(
        &api,
        "POST",
        "/api/v1/auth/reset-password",
        Some(json!({ "token": raw_reset, "new_password": new_password })),
        &[],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let revoked = call(
        &api,
        "GET",
        "/api/v1/auth/me",
        None,
        &[("authorization", &bearer)],
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let old_login = call(
        &api,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "email": email, "password": old_password })),
        &[],
    )
    .await;
    assert_eq!(old_login.status(), StatusCode::UNAUTHORIZED);
    let new_login = call(
        &api,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "email": email, "password": new_password })),
        &[],
    )
    .await;
    assert_eq!(new_login.status(), StatusCode::OK);
}
