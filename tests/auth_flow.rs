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
    let state = AppState::from_env().await.expect("test services must be available");
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
    let old_cookie = response.headers().get(header::SET_COOKIE).unwrap()
        .to_str().unwrap().split(';').next().unwrap().to_owned();
    let token = json_body(response).await["access_token"].as_str().unwrap().to_owned();

    let auth_header = format!("Bearer {token}");
    let response = call(&app, "GET", "/api/v1/auth/me", None,
        &[("authorization", &auth_header)]).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = call(&app, "POST", "/api/v1/auth/refresh", None,
        &[("cookie", &old_cookie), ("origin", "http://localhost:3000")]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let new_cookie = response.headers().get(header::SET_COOKIE).unwrap()
        .to_str().unwrap().split(';').next().unwrap().to_owned();
    let new_access = json_body(response).await["access_token"].as_str().unwrap().to_owned();

    // A consumed refresh credential indicates token replay. The entire session is revoked.
    let response = call(&app, "POST", "/api/v1/auth/refresh", None,
        &[("cookie", &old_cookie), ("origin", "http://localhost:3000")]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = call(&app, "POST", "/api/v1/auth/refresh", None,
        &[("cookie", &new_cookie), ("origin", "http://localhost:3000")]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bearer = format!("Bearer {new_access}");
    let response = call(&app, "GET", "/api/v1/auth/me", None,
        &[("authorization", &bearer)]).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_mismatched_origin_before_refresh() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let state = AppState::from_env().await.expect("test services must be available");
    let app = app(state);
    let response = call(&app, "POST", "/api/v1/auth/refresh", None,
        &[("cookie", "authcore_refresh=invalid"), ("origin", "https://attacker.example")]).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
