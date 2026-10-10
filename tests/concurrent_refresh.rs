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

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut req = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let req = req
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap();
    let mut req = req;
    req.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:30123".parse::<SocketAddr>().unwrap(),
    ));
    app.clone().oneshot(req).await.unwrap()
}

async fn response_json(response: Response<Body>) -> Value {
    let raw = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&raw).unwrap()
}

#[tokio::test]
async fn refresh_token_is_single_use_even_when_requests_race() {
    if std::env::var("DATABASE_URL").is_err() {
        eprintln!("Integration test skipped: DATABASE_URL not configured");
        return;
    }
    let state = AppState::from_env()
        .await
        .expect("PostgreSQL and Redis required");
    let app = app(state);
    let email = format!("race-{}@example.com", Uuid::new_v4());
    let body = json!({ "email": email, "password": "race-specific-password-2026!" });
    let registered = send(
        &app,
        "POST",
        "/api/v1/auth/register",
        Some(body.clone()),
        &[],
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let login = send(&app, "POST", "/api/v1/auth/login", Some(body), &[]).await;
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let headers = [
        ("cookie", cookie.as_str()),
        ("origin", "http://localhost:3000"),
    ];
    let (first, second) = tokio::join!(
        send(&app, "POST", "/api/v1/auth/refresh", None, &headers),
        send(&app, "POST", "/api/v1/auth/refresh", None, &headers)
    );
    let statuses = [first.status(), second.status()];
    assert_eq!(
        statuses.iter().filter(|&&s| s == StatusCode::OK).count(),
        1,
        "both concurrent refresh attempts must never succeed: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::UNAUTHORIZED)
            .count(),
        1,
        "the consumed refresh token must be rejected: {statuses:?}"
    );

    // Replay detection must invalidate the entire session, including the winning
    // request's newly minted JWT. Only one session row is involved.
    let successful = if first.status() == StatusCode::OK {
        first
    } else {
        second
    };
    let access = response_json(successful).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let bearer = format!("Bearer {access}");
    let denied = send(
        &app,
        "GET",
        "/api/v1/auth/me",
        None,
        &[("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}
